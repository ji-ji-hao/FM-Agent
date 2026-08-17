from __future__ import annotations

# noqa: SIZE_OK - focused data tables and interpreter for capability contracts.

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from src.capability_prompts import EffectFact, EvidenceFact, InputFact
from src.capability_scanner import CallExpression, ScannedSource, canonical, scan_source
from src.plugins.base import FunctionUnit


_PREFIX_RE: Final = re.compile(r"^(param|local|global|resource|actual):(.+)$")
_CHAIN_RE: Final = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")
_CALLBACK_SYMBOL_RE: Final = re.compile(r"&?([A-Za-z_]\w*)")
_READ_ONLY_OPEN_FLAG_RE: Final = re.compile(r"(?:^|[^A-Z0-9_])O_RDONLY(?:$|[^A-Z0-9_])")
_WRITE_OPEN_FLAGS: Final = frozenset({
    "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND",
})


@dataclass(frozen=True, slots=True)
class EffectContract:
    kind: str
    source_arg: int | None
    target_arg: int | None
    source_suffix: str = ""
    target_suffix: str = ""
    identity: str = "SAME"
    region: str = "OVERLAP"
    when_arg: int | None = None
    when_value: str | None = None
    target_return: bool = False
    source_resource: str | None = None
    target_resource: str | None = None
    when_result: str | None = None
    failure_terminates_with: str | None = None


@dataclass(frozen=True, slots=True)
class ApiContract:
    symbol: str
    seed_arg: int | None
    effects: tuple[EffectContract, ...]
    seed_requires_formal: bool = True


@dataclass(frozen=True, slots=True)
class RegistrationContract:
    bridge_symbol: str
    bridge_object_arg: int
    assignment_slot: str
    canonical_slot: str


@dataclass(frozen=True, slots=True)
class DispatchContract:
    accessor_symbol: str
    member: str
    target_arg: int
    canonical_slot: str


@dataclass(frozen=True, slots=True)
class ContractPack:
    name: str
    languages: tuple[str, ...]
    contracts: tuple[ApiContract, ...]
    version: str = "1"
    authority: str = "TRUSTED"
    source_path: str | None = None
    source_sha256: str | None = None
    registrations: tuple[RegistrationContract, ...] = ()
    dispatches: tuple[DispatchContract, ...] = ()


class ContractProvider(Protocol):
    def contracts_for(self, language: str) -> tuple[ApiContract, ...]: ...

    def registrations_for(
        self,
        language: str,
    ) -> tuple[RegistrationContract, ...]: ...

    def dispatches_for(self, language: str) -> tuple[DispatchContract, ...]: ...


@dataclass(frozen=True, slots=True)
class StaticContractProvider:
    packs: tuple[ContractPack, ...]

    def contracts_for(self, language: str) -> tuple[ApiContract, ...]:
        return tuple(
            contract
            for pack in self.packs
            if language in pack.languages
            for contract in pack.contracts
        )

    def registrations_for(
        self,
        language: str,
    ) -> tuple[RegistrationContract, ...]:
        return tuple(
            contract
            for pack in self.packs
            if language in pack.languages
            for contract in pack.registrations
        )

    def dispatches_for(self, language: str) -> tuple[DispatchContract, ...]:
        return tuple(
            contract
            for pack in self.packs
            if language in pack.languages
            for contract in pack.dispatches
        )


def formal_resources(unit: FunctionUnit) -> set[str]:
    return {
        item if item.startswith("param:") else f"param:{item}"
        for item in unit.params
    }


def _clean_expression(expression: str) -> str:
    text = expression.strip().replace("->", ".")
    while text.startswith(("&", "*")):
        text = text[1:]
    text = re.sub(r"\[[^\]]*\]", ".item", text)
    match = _CHAIN_RE.search(text)
    return match.group() if match is not None else "unknown"


def normalize_actual(expression: str, caller_formals: set[str]) -> str:
    prefix = _PREFIX_RE.fullmatch(expression)
    if prefix is not None:
        return f"{prefix.group(1)}:{_clean_expression(prefix.group(2))}"
    clean = _clean_expression(expression)
    root = clean.split(".", 1)[0]
    namespace = "param" if f"param:{root}" in caller_formals else "local"
    return f"{namespace}:{clean}"


def resource_root(resource: str) -> tuple[str, str]:
    prefix = _PREFIX_RE.fullmatch(resource)
    if prefix is None:
        return resource, ""
    root, separator, suffix = prefix.group(2).partition(".")
    return f"{prefix.group(1)}:{root}", f".{suffix}" if separator else ""


def substitute_resource(
    resource: str | None,
    bindings: Mapping[str, str],
    caller_formals: set[str],
    namespace: str,
) -> str | None:
    if resource is None:
        return None
    if resource == "return":
        return f"resource:{namespace}.return"
    root, suffix = resource_root(resource)
    if root.startswith("param:") and root in bindings:
        return normalize_actual(bindings[root], caller_formals) + suffix
    if root in caller_formals:
        return root + suffix
    body = _PREFIX_RE.sub(r"\2", resource)
    return f"resource:{namespace}.{_clean_expression(body)}"


def _effect_applies(
    template: EffectContract,
    arguments: Sequence[str],
) -> bool:
    if template.when_arg is None:
        return True
    return (
        template.when_arg < len(arguments)
        and arguments[template.when_arg] == template.when_value
    )


def _read_only_open_effect(
    symbol: str,
    template: EffectContract,
    arguments: Sequence[str],
) -> bool:
    """`open(path, O_RDONLY, ...)` reads a file; it is not a writeback sink."""
    if symbol != "open" or template.kind not in {"REQUIRE_WRITE", "WRITEBACK"}:
        return False
    if len(arguments) < 2:
        return False
    flags = arguments[1]
    return (
        _READ_ONLY_OPEN_FLAG_RE.search(flags) is not None
        and not any(flag in flags for flag in _WRITE_OPEN_FLAGS)
    )


def _call_text(call: CallExpression) -> str:
    arguments = ",".join(canonical(argument) for argument in call.arguments)
    return f"{call.name}({arguments})"


def _call_symbol(call: CallExpression) -> str:
    return call.name.rsplit(".", 1)[-1].rsplit("->", 1)[-1]


def _dispatch_call_matches(
    contract: DispatchContract,
    call: CallExpression,
    scanned: ScannedSource,
) -> bool:
    if not call.is_indirect or call.member != contract.member:
        return False
    if call.accessor is not None:
        return (
            call.accessor.rsplit(".", 1)[-1].rsplit("->", 1)[-1]
            == contract.accessor_symbol
        )
    receiver = _clean_expression(call.receiver or "")
    if not receiver:
        return False
    return any(
        _call_symbol(accessor) == contract.accessor_symbol
        and accessor.result is not None
        and _clean_expression(canonical(accessor.result)) == receiver
        and accessor.start_byte < call.start_byte
        for accessor in scanned.calls
    )


def _guarded_result_applies(
    template: EffectContract,
    call: CallExpression,
    scanned: ScannedSource,
) -> bool:
    if template.when_result is None:
        return True
    terminator = template.failure_terminates_with
    if terminator is None:
        return False
    expression = _call_text(call)
    expected = f"!{expression}" if template.when_result == "TRUTHY" else expression
    outer = next((
        candidate
        for candidate in scanned.calls
        if candidate.name == "if"
        and candidate.start_byte < call.start_byte
        and candidate.end_byte > call.end_byte
        and len(candidate.arguments) == 1
        and canonical(candidate.arguments[0]) == expected
    ), None)
    if outer is None:
        return False
    tokens = scanned.tokens
    outer_end = next(
        index for index, token in enumerate(tokens)
        if token.end_byte == outer.end_byte
    )
    branch_start = outer_end + 1
    if branch_start >= len(tokens):
        return False
    if tokens[branch_start].text == "{":
        depth = 1
        branch_end = branch_start + 1
        while branch_end < len(tokens) and depth:
            if tokens[branch_end].text == "{":
                depth += 1
            elif tokens[branch_end].text == "}":
                depth -= 1
            branch_end += 1
        if depth:
            return False
        statement_start, statement_end = branch_start + 1, branch_end - 1
    else:
        paren_depth = 0
        statement_end = branch_start
        while statement_end < len(tokens):
            text = tokens[statement_end].text
            if text == "(":
                paren_depth += 1
            elif text == ")":
                paren_depth -= 1
            elif text == ";" and paren_depth == 0:
                break
            statement_end += 1
        if statement_end >= len(tokens):
            return False
        statement_start = branch_start

    branch = tokens[statement_start:statement_end]
    brace_depth = 0
    conditional_statement = False
    unconditional_token_starts: set[int] = set()
    for token in branch:
        if token.text == "{":
            brace_depth += 1
        elif token.text == "}":
            brace_depth = max(0, brace_depth - 1)
            if brace_depth == 0:
                conditional_statement = False
        elif brace_depth == 0 and token.text in {"if", "else", "switch", "for", "while"}:
            conditional_statement = True
        elif brace_depth == 0 and not conditional_statement:
            unconditional_token_starts.add(token.start_byte)
        if (
            brace_depth == 0
            and not conditional_statement
            and token.text in {"return", "goto"}
        ):
            return True
        if brace_depth == 0 and token.text == ";":
            conditional_statement = False

    branch_start_byte = (
        tokens[statement_start].start_byte
        if statement_start < statement_end
        else outer.end_byte
    )
    branch_end_byte = (
        tokens[statement_end - 1].end_byte
        if statement_start < statement_end
        else outer.end_byte
    )
    for failure_call in scanned.calls:
        if not (
            branch_start_byte <= failure_call.start_byte
            and failure_call.end_byte <= branch_end_byte
            and failure_call.start_byte in unconditional_token_starts
        ):
            continue
        symbol = _call_symbol(failure_call)
        if symbol == terminator:
            return True
        if symbol in {"ereport", "elog"} and failure_call.arguments:
            severity = canonical(failure_call.arguments[0])
            if severity in {"ERROR", "FATAL", "PANIC"}:
                return True
    return False


def _selected_argument(
    arguments: Sequence[str],
    index: int | None,
    suffix: str,
    formals: set[str],
) -> str | None:
    if index is None or index >= len(arguments):
        return None
    return normalize_actual(arguments[index], formals) + suffix


def _selected_seed(
    arguments: Sequence[str],
    contract: ApiContract,
    formals: set[str],
) -> str | None:
    seed = _selected_argument(arguments, contract.seed_arg, "", formals)
    if seed is None or not contract.seed_requires_formal:
        return seed
    root, _ = resource_root(seed)
    return seed if root in formals else None


def _line_number(source: str, start_byte: int) -> int:
    return source.encode("utf-8")[:start_byte].count(b"\n") + 1


def contract_facts(
    unit: FunctionUnit,
    provider: ContractProvider,
) -> tuple[list[InputFact], list[EffectFact]]:
    language = unit.id.language
    api_contracts = provider.contracts_for(language)
    registrations = provider.registrations_for(language)
    dispatches = provider.dispatches_for(language)
    if not api_contracts and not registrations and not dispatches:
        return [], []
    contracts = {
        contract.symbol: contract
        for contract in api_contracts
    }
    formals = formal_resources(unit)
    inputs: list[InputFact] = []
    effects: list[EffectFact] = []
    scanned = scan_source(unit.source)
    for call in scanned.calls:
        symbol = _call_symbol(call)
        contract = contracts.get(symbol)
        if contract is None:
            continue
        arguments = tuple(canonical(argument) for argument in call.arguments)
        line = _line_number(unit.source, call.start_byte)
        evidence: EvidenceFact = {"authority": "CONTRACT", "lines": [line]}
        seed = _selected_seed(arguments, contract, formals)
        if seed is not None:
            inputs.append({
                "formal": seed,
                "resource_id": seed,
                "reference_origin": "USER_CONTROLLED",
                "possible_backing": [
                    "WRITABLE_PRIVATE",
                    "READONLY_MAPPING",
                    "PROTECTED_SHARED",
                ],
                "write_authority": ["GRANTED", "DENIED"],
                "role": "INPUT",
                "identity": "SAME",
                "evidence": evidence,
            })
        for template in contract.effects:
            if (
                not _effect_applies(template, arguments)
                or _read_only_open_effect(symbol, template, arguments)
                or not _guarded_result_applies(template, call, scanned)
            ):
                continue
            source = template.source_resource or _selected_argument(
                arguments,
                template.source_arg,
                template.source_suffix,
                formals,
            )
            target = (
                template.target_resource
                or (
                    "return"
                    if template.target_return
                    else _selected_argument(
                        arguments,
                        template.target_arg,
                        template.target_suffix,
                        formals,
                    )
                )
            )
            kind, identity = template.kind, template.identity
            if kind == "ROLE_BIND" and source == target:
                kind, identity = "REQUIRE_WRITE", "SAME"
            effects.append({
                "order": len(effects) + 1,
                "kind": kind,
                "source": source,
                "target": target,
                "identity": identity,
                "region": template.region,
                "guard": "FEASIBLE",
                "evidence": evidence,
            })
    for contract in registrations:
        slot_suffix = f".{contract.assignment_slot}"
        for assignment in scanned.assignments:
            left = _clean_expression(canonical(assignment.left))
            assigned = _CALLBACK_SYMBOL_RE.fullmatch(canonical(assignment.right))
            if not left.endswith(slot_suffix) or assigned is None:
                continue
            receiver = left[:-len(slot_suffix)]
            for call in scanned.calls:
                arguments = tuple(canonical(argument) for argument in call.arguments)
                if (
                    _call_symbol(call) != contract.bridge_symbol
                    or contract.bridge_object_arg >= len(arguments)
                    or _clean_expression(arguments[contract.bridge_object_arg])
                    != receiver
                    or assignment.order_byte >= call.start_byte
                ):
                    continue
                effects.append({
                    "order": len(effects) + 1,
                    "kind": "REGISTER",
                    "source": f"resource:function.{assigned.group(1)}",
                    "target": contract.canonical_slot,
                    "identity": "SAME",
                    "region": "OVERLAP",
                    "guard": "FEASIBLE",
                    "evidence": {
                        "authority": "CONTRACT",
                        "lines": sorted({
                            _line_number(unit.source, assignment.order_byte),
                            _line_number(unit.source, call.start_byte),
                        }),
                    },
                })
    for contract in dispatches:
        for call in scanned.calls:
            if not _dispatch_call_matches(contract, call, scanned):
                continue
            arguments = tuple(canonical(argument) for argument in call.arguments)
            target = _selected_argument(arguments, contract.target_arg, "", formals)
            if target is None:
                continue
            effects.append({
                "order": len(effects) + 1,
                "kind": "DISPATCH",
                "source": contract.canonical_slot,
                "target": target,
                "identity": "SAME",
                "region": "OVERLAP",
                "guard": "FEASIBLE",
                "evidence": {
                    "authority": "CONTRACT",
                    "lines": [_line_number(unit.source, call.start_byte)],
                },
            })
    return inputs, effects
