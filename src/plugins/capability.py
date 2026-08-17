from __future__ import annotations

# noqa: SIZE_OK - one plugin SPI surface joins slicing, contracts, and composition.

import hashlib
import json
import os
import re
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Final

from src.capability_contract_loader import (
    configured_contract_provider,
)
from src.capability_contracts import (
    ContractProvider,
    contract_facts,
    formal_resources,
    resource_root,
    substitute_resource,
)
from src.capability_flow import (
    MAX_REGISTERED_ROUTES_PER_SLOT,
    compose_project_chain,
    resolve_registered_implementations,
)
from src.capability_prompts import (
    CapabilityPayload,
    EffectFact,
    InputFact,
    JsonValue,
    ObligationFact,
    ResourceFlow,
    _system_prompt,
    _user_prompt,
    parse_capability_response,
)
from src.capability_reasoner import reason_capability
from src.capability_scanner import ScannedSource, scan_source
from src.languages.registry import REGISTRY as LANGUAGE_FRONTENDS
from src.plugins.base import (
    AbstractionRequest,
    AnalysisPlugin,
    Diagnostic,
    DriverContext,
    FactEnvelope,
    FunctionId,
    FunctionUnit,
    PluginMetadata,
    ProgramIndex,
    RelevanceSlice,
    ResolvedCall,
    Verdict,
)


_DEFAULT_MAX_FUNCTIONS: Final = 2000
_ABSTRACTION_PROTOCOL_VERSION: Final = "capability-prompt-v6"
_SUPPORTED_LANGUAGES: Final = tuple(LANGUAGE_FRONTENDS)
_SOURCE_TERMS: Final = frozenset({
    "borrow", "borrowed", "external", "input", "iterator", "protected",
    "readonly", "read", "shared", "user", "view",
})
_TRANSFER_TERMS: Final = frozenset({
    "alias", "arg", "buffer", "chain", "field", "forward", "handle", "member",
    "page", "param", "pointer", "reference", "request", "resource", "return",
    "slice", "transfer", "view",
})
_SINK_TERMS: Final = frozenset({
    "copy", "decode", "decrypt", "fill", "insert", "modify", "mutate", "output",
    "overwrite", "put", "store", "update", "write",
})
_TOKEN_RE: Final = re.compile(r"[a-z][a-z0-9_]*")
_ASSIGNMENT_RE: Final = re.compile(r"(?:->|\.)[A-Za-z_]\w*\s*=(?!=)")
_SCANNER_RELEVANT_EFFECTS: Final = frozenset({
    "ALIAS", "ARG", "DEEP_COPY", "DISPATCH", "FIELD", "GRANT", "REGISTER",
    "REQUIRE_WRITE", "RETURN", "ROLE_BIND", "WRITE", "WRITEBACK",
})


def _function_key(function_id: FunctionId) -> tuple[str, str, str, str]:
    return (
        function_id.rel,
        function_id.name,
        function_id.base_name,
        function_id.language,
    )


def _compact_summary_path(path: JsonValue) -> list[dict[str, JsonValue]]:
    if type(path) is not list:
        return []
    return [
        {
            "kind": step.get("kind"),
            "function": step.get("function_rel") or step.get("from_function"),
            "from": step.get("from") or step.get("source") or step.get("resource_id"),
            "to": step.get("to") or step.get("target") or step.get("resource_id"),
        }
        for step in path
        if type(step) is dict
    ]


def _strict_summary_signature(path: JsonValue) -> dict[str, JsonValue]:
    steps = [step for step in path if type(step) is dict] if type(path) is list else []
    seed = next((step for step in steps if step.get("kind") == "SEED"), {})
    obligation = next(
        (step for step in steps if step.get("kind") == "REQUIRE_WRITE"),
        {},
    )
    writeback = next(
        (step for step in reversed(steps) if step.get("kind") == "WRITEBACK"),
        {},
    )
    register = next((step for step in steps if step.get("kind") == "REGISTER"), {})
    dispatch = next((step for step in steps if step.get("kind") == "DISPATCH"), {})
    direct: dict[str, JsonValue] = {}
    if not dispatch:
        obligated = False
        for step in steps:
            obligated = obligated or step.get("kind") == "REQUIRE_WRITE"
            if (
                obligated
                and step.get("kind") == "ARG"
                and step.get("from_function") != step.get("to_function")
            ):
                direct = step
                break
    direct_identity = None
    if direct:
        direct_identity = json.dumps(
            {
                "from_function": direct.get("from_function"),
                "to_function": direct.get("to_function"),
                "source": direct.get("source"),
                "target": direct.get("target"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    return {
        "seed_function": seed.get("from_function"),
        "seed_resource": seed.get("resource_id") or seed.get("source"),
        "obligation_function": obligation.get("from_function"),
        "obligation_resource": obligation.get("target") or obligation.get("source"),
        "route": {
            "kind": "REGISTER" if dispatch else "DIRECT",
            "implementation": (
                dispatch.get("to_function") if dispatch else direct.get("to_function")
            ),
            "slot": register.get("target") if dispatch else None,
            "direct_identity": None if dispatch else direct_identity,
        },
        "writeback_function": writeback.get("from_function"),
        "writeback_resource": writeback.get("target") or writeback.get("source"),
    }


def _max_functions() -> int:
    raw = os.environ.get("CAPABILITY_MAX_FUNCTIONS", "")
    try:
        return max(1, int(raw) if raw else _DEFAULT_MAX_FUNCTIONS)
    except ValueError:
        return _DEFAULT_MAX_FUNCTIONS


def _configured_contract_provider() -> ContractProvider:
    return configured_contract_provider()


def _scanner_contract_symbols(
    provider: ContractProvider,
    language: str,
) -> frozenset[str]:
    return frozenset({
        *(contract.symbol for contract in provider.contracts_for(language)),
        *(
            symbol
            for contract in provider.registrations_for(language)
            for symbol in (contract.bridge_symbol, contract.assignment_slot)
        ),
        *(
            symbol
            for contract in provider.dispatches_for(language)
            for symbol in (contract.accessor_symbol, contract.member)
        ),
    })


def _scanner_uncertainty_is_relevant(
    scanned: ScannedSource,
    provider: ContractProvider,
    language: str,
    contract_inputs: Sequence[InputFact],
    contract_effects: Sequence[EffectFact],
    parsed: CapabilityPayload,
) -> bool:
    identifiers = getattr(scanned, "identifier_symbols", frozenset())
    callbacks = getattr(scanned, "callback_symbols", frozenset())
    anchored = bool(
        _scanner_contract_symbols(provider, language)
        & (identifiers | callbacks)
    )
    semantic_effect = any(
        effect["kind"] in _SCANNER_RELEVANT_EFFECTS
        for effect in parsed["effects"]
    )
    return bool(
        anchored
        or contract_inputs
        or contract_effects
        or parsed["resource_flows"]
        or semantic_effect
    )


def _contract_pack_names(provider: ContractProvider) -> list[str]:
    packs = getattr(provider, "packs", None)
    if packs is None:
        return ["custom"]
    return [pack.name for pack in packs]


def _contract_pack_sources(provider: ContractProvider) -> list[dict[str, JsonValue]]:
    packs = getattr(provider, "packs", None)
    if packs is None:
        return []
    return [
        {
            "name": pack.name,
            "version": pack.version,
            "authority": pack.authority,
            "path": pack.source_path,
            "sha256": pack.source_sha256,
        }
        for pack in packs
    ]


def _contract_material(
    provider: ContractProvider,
    languages: Sequence[str],
) -> list[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]]:
    return [
        (
            language,
            tuple(repr(item) for item in provider.contracts_for(language)),
            tuple(repr(item) for item in provider.registrations_for(language)),
            tuple(repr(item) for item in provider.dispatches_for(language)),
        )
        for language in sorted(set(languages))
    ]


def _profile(
    unit: FunctionUnit,
    contract_symbols: frozenset[str],
) -> tuple[int, int, int]:
    text = " ".join((unit.id.name, unit.signature_line, unit.source)).lower()
    tokens = [
        part
        for token in _TOKEN_RE.findall(text)
        for part in (token, *token.split("_"))
    ]
    source = sum(token in _SOURCE_TERMS for token in tokens)
    transfer = sum(token in _TRANSFER_TERMS for token in tokens)
    sink = sum(token in _SINK_TERMS for token in tokens)
    sink += len(_ASSIGNMENT_RE.findall(unit.source)) * 3
    scanned = scan_source(unit.source)
    lexical_symbols = scanned.identifier_symbols | scanned.callback_symbols
    contract = len(contract_symbols & lexical_symbols) * 8
    return source * 3, sink * 3 + contract, source * 3 + transfer + sink * 3 + contract


def _adjacency(program: ProgramIndex) -> dict[FunctionId, tuple[FunctionId, ...]]:
    graph = {function_id: set() for function_id in program.functions}
    for caller, sites in program.calls_by_caller.items():
        for site in sites:
            if caller in graph and site.callee in graph:
                graph[caller].add(site.callee)
                graph[site.callee].add(caller)
    return {
        function_id: tuple(sorted(neighbors, key=_function_key))
        for function_id, neighbors in graph.items()
    }


def _path_to_sink(
    start: FunctionId,
    sinks: set[FunctionId],
    graph: Mapping[FunctionId, Sequence[FunctionId]],
) -> tuple[FunctionId, ...]:
    pending = deque((start,))
    previous: dict[FunctionId, FunctionId | None] = {start: None}
    while pending:
        current = pending.popleft()
        if current in sinks:
            path: list[FunctionId] = []
            cursor: FunctionId | None = current
            while cursor is not None:
                path.append(cursor)
                cursor = previous[cursor]
            return tuple(reversed(path))
        for neighbor in graph.get(current, ()):
            if neighbor not in previous:
                previous[neighbor] = current
                pending.append(neighbor)
    return ()


def _select_ids(
    program: ProgramIndex,
    cap: int,
    provider: ContractProvider,
) -> tuple[tuple[FunctionId, ...], bool]:
    ordered = tuple(sorted(program.functions, key=_function_key))
    if len(ordered) <= cap:
        return ordered, False
    profiles = {
        function_id: _profile(
            program.functions[function_id],
            frozenset(
                contract.symbol
                for contract in provider.contracts_for(function_id.language)
            ),
        )
        for function_id in ordered
    }
    ranked = sorted(
        ordered,
        key=lambda item: (
            -profiles[item][2],
            -profiles[item][0],
            -profiles[item][1],
            _function_key(item),
        ),
    )
    sources = {item for item in ordered if profiles[item][0] > 0}
    sinks = {item for item in ordered if profiles[item][1] > 0}
    graph = _adjacency(program)
    selected: set[FunctionId] = set()
    connected = False
    for source in sorted(sources, key=_function_key):
        path = _path_to_sink(source, sinks, graph)
        connected = connected or len(path) > 1
        for function_id in path:
            if len(selected) < cap:
                selected.add(function_id)
    for function_id in ranked:
        if len(selected) >= cap:
            break
        if profiles[function_id][2] > 0:
            selected.add(function_id)
    if not selected:
        selected.update(ranked[:cap])
    return tuple(sorted(selected, key=_function_key)), not connected


def _close_dispatch_ids(
    program: ProgramIndex,
    selected: Sequence[FunctionId],
    provider: ContractProvider,
) -> tuple[FunctionId, ...]:
    ordered = tuple(sorted(program.functions, key=_function_key))
    effects_by_function: dict[FunctionId, tuple[EffectFact, ...]] = {}
    registrations: dict[str, list[tuple[FunctionId, str]]] = {}
    for function_id in ordered:
        _, effects = contract_facts(program.functions[function_id], provider)
        effects_by_function[function_id] = tuple(effects)
        for effect in effects:
            source, target = effect["source"], effect["target"]
            if (
                effect["kind"] == "REGISTER"
                and source is not None
                and source.startswith("resource:function.")
                and target is not None
            ):
                registrations.setdefault(target, []).append((
                    function_id,
                    source.removeprefix("resource:function."),
                ))
    closed = set(selected)
    pending = deque(sorted(selected, key=_function_key))
    while pending:
        function_id = pending.popleft()
        slots = sorted({
            effect["source"]
            for effect in effects_by_function[function_id]
            if effect["kind"] == "DISPATCH" and effect["source"] is not None
        })
        for slot in slots:
            matches = registrations.get(slot, [])
            route_count = 0
            for registrar, implementation_name in matches:
                resolution = resolve_registered_implementations(
                    program,
                    registrar,
                    implementation_name,
                )
                remaining = MAX_REGISTERED_ROUTES_PER_SLOT - route_count
                if remaining <= 0:
                    break
                implementations = resolution.implementations[:remaining]
                route_count += len(implementations)
                for addition in (registrar, *implementations):
                    if addition not in closed:
                        closed.add(addition)
                        pending.append(addition)
    return tuple(sorted(closed, key=_function_key))


def _fingerprint(
    program: ProgramIndex,
    selected: Sequence[FunctionId],
    cap: int,
    provider: ContractProvider,
) -> str:
    material = [
        (
            _function_key(function_id),
            hashlib.sha256(
                program.functions[function_id].source.encode("utf-8")
            ).hexdigest(),
        )
        for function_id in selected
    ]
    encoded = json.dumps(
        {
            "abstraction_protocol": _ABSTRACTION_PROTOCOL_VERSION,
            "cap": cap,
            "contract_pack_sources": _contract_pack_sources(provider),
            "contracts": _contract_material(
                provider,
                tuple(function_id.language for function_id in program.functions),
            ),
            "functions": material,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _empty_payload(reason: str, coverage: str = "unknown") -> CapabilityPayload:
    return {
        "schema_version": "capability.v3",
        "coverage": coverage,
        "inputs": [],
        "effects": [],
        "unknowns": [reason],
        "obligations": [],
        "resource_flows": [],
        "propagation_chain": [],
    }




def _dedupe_inputs(items: Sequence[InputFact]) -> list[InputFact]:
    found: dict[str, InputFact] = {}
    for item in items:
        key = json.dumps(item, sort_keys=True, separators=(",", ":"))
        found.setdefault(key, item)
    return list(found.values())


def _dedupe_effects(items: Sequence[EffectFact]) -> list[EffectFact]:
    found: dict[str, EffectFact] = {}
    for item in items:
        body = {key: value for key, value in item.items() if key != "order"}
        key = json.dumps(body, sort_keys=True, separators=(",", ":"))
        found.setdefault(key, item)
    return [
        {**item, "order": order}
        for order, item in enumerate(found.values(), start=1)
    ]


def _dedupe_flows(items: Sequence[ResourceFlow]) -> list[ResourceFlow]:
    found: dict[str, ResourceFlow] = {}
    for item in items:
        key = json.dumps(item, sort_keys=True, separators=(",", ":"))
        found.setdefault(key, item)
    return list(found.values())


def _obligations(effects: Sequence[EffectFact]) -> list[ObligationFact]:
    found: dict[str, ObligationFact] = {}
    for effect in effects:
        if (
            effect["kind"] not in {"ROLE_BIND", "REQUIRE_WRITE"}
            or effect["source"] is None
            or effect["target"] is None
        ):
            continue
        item: ObligationFact = {
            "resource_id": effect["target"],
            "source": effect["source"],
            "target": effect["target"],
            "identity": effect["identity"],
            "region": effect["region"],
            "guard": effect["guard"],
            "evidence": effect["evidence"],
        }
        key = json.dumps(item, sort_keys=True, separators=(",", ":"))
        found.setdefault(key, item)
    return list(found.values())


def _finalize(
    payload: CapabilityPayload,
    inputs: Sequence[InputFact],
    effects: Sequence[EffectFact],
    flows: Sequence[ResourceFlow],
    unknowns: Sequence[str],
) -> CapabilityPayload:
    deduped_flows = _dedupe_flows(flows)
    deduped_effects = _dedupe_effects(effects)
    chains = list(dict.fromkeys(
        f"{item['from_function']}:{item['formal']} -> "
        f"{item['to_function']}:{item['actual']} "
        f"[{item['effect']}, {item['identity']}]"
        for item in deduped_flows
    ))
    return {
        "schema_version": "capability.v3",
        "coverage": payload["coverage"],
        "inputs": _dedupe_inputs(inputs),
        "effects": deduped_effects,
        "unknowns": list(dict.fromkeys(unknowns)),
        "obligations": _obligations(deduped_effects),
        "resource_flows": deduped_flows,
        "propagation_chain": chains,
    }


class CapabilityPlugin(AnalysisPlugin[CapabilityPayload, None]):
    disable_llm_thinking: Final = True

    def __init__(
        self,
        contract_provider: ContractProvider | None = None,
    ) -> None:
        self._contracts = contract_provider or _configured_contract_provider()
        self._contract_pack_names = _contract_pack_names(self._contracts)
        self._contract_pack_sources = _contract_pack_sources(self._contracts)
        self._unsupported_syntax_by_function: dict[FunctionId, tuple[str, ...]] = {}
        contract_material = _contract_material(
            self._contracts,
            _SUPPORTED_LANGUAGES,
        )
        self._contract_mode = (
            "enabled"
            if any(contracts or registrations or dispatches for (
                _language,
                contracts,
                registrations,
                dispatches,
            ) in contract_material)
            else "disabled"
        )
        self._rendered: dict[str, dict[str, JsonValue]] = {}
        self._program: ProgramIndex | None = None
        self._facts_by_function: dict[
            FunctionId,
            FactEnvelope[CapabilityPayload],
        ] = {}
        self._raw_facts_by_function: dict[
            FunctionId,
            FactEnvelope[CapabilityPayload],
        ] = {}
        self._slice_metrics: dict[str, JsonValue] = {
            "program_functions": 0,
            "selected_functions": 0,
            "skipped_functions": 0,
            "fallback": False,
            "cap": _max_functions(),
            "contract_mode": self._contract_mode,
            "contract_packs": self._contract_pack_names,
            "contract_pack_sources": self._contract_pack_sources,
        }

    @property
    def analysis_scope(self) -> dict[str, JsonValue]:
        scope = dict(self._slice_metrics)
        scope["unsupported_syntax_functions"] = len(
            self._unsupported_syntax_by_function
        )
        scope["unsupported_syntax_kinds"] = sorted({
            kind
            for kinds in self._unsupported_syntax_by_function.values()
            for kind in kinds
        })
        return scope

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="capability",
            version="0.7.0",
            schema_version="capability.v3",
            supported_languages=_SUPPORTED_LANGUAGES,
            verdicts=("VULNERABLE", "NEEDS_REVIEW", "SAFE", "ERROR"),
            aggregate_only=True,
        )

    def select_relevance_slice(self, program: ProgramIndex) -> RelevanceSlice:
        self._program = program
        self._unsupported_syntax_by_function.clear()
        cap = _max_functions()
        selected, fallback = _select_ids(program, cap, self._contracts)
        selected = _close_dispatch_ids(program, selected, self._contracts)
        total = len(program.functions)
        self._slice_metrics = {
            "program_functions": total,
            "selected_functions": len(selected),
            "skipped_functions": total - len(selected),
            "fallback": fallback,
            "cap": cap,
            "contract_mode": self._contract_mode,
            "contract_packs": self._contract_pack_names,
            "contract_pack_sources": self._contract_pack_sources,
        }
        return RelevanceSlice(
            selected,
            _fingerprint(program, selected, cap, self._contracts),
        )

    def build_abstraction_prompt(
        self,
        request: AbstractionRequest,
    ) -> list[dict[str, str]]:
        unit = request.function
        numbered = "\n".join(
            f"Line {number}: {line}"
            for number, line in enumerate(unit.source.splitlines(), start=1)
        )
        summaries = "\n".join(
            request.callee_context[function_id]
            for function_id in sorted(request.callee_context, key=_function_key)
        )
        return [
            {"role": "system", "content": _system_prompt(unit.id.language)},
            {
                "role": "user",
                "content": _user_prompt(
                    numbered,
                    unit.signature_line,
                    unit.id.language,
                    summaries,
                ),
            },
        ]

    def parse_abstraction_response(
        self,
        request: AbstractionRequest,
        raw_response: str,
    ) -> FactEnvelope[CapabilityPayload] | None:
        parsed = parse_capability_response(
            raw_response,
            line_count=max(1, len(request.function.source.splitlines())),
        )
        if parsed is None:
            return None
        contract_inputs, contract_effects = contract_facts(
            request.function,
            self._contracts,
        )
        scanned = scan_source(request.function.source)
        diagnostics: list[Diagnostic] = []
        unknowns = list(parsed["unknowns"])
        if scanned.has_unsupported_syntax:
            kinds = scanned.unsupported_syntax_kinds
            self._unsupported_syntax_by_function[request.function.id] = kinds
            relevant = _scanner_uncertainty_is_relevant(
                scanned,
                self._contracts,
                request.function.id.language,
                contract_inputs,
                contract_effects,
                parsed,
            )
            diagnostics.append(Diagnostic(
                "warning",
                "scanner-unsupported-syntax",
                {
                    "kinds": list(kinds),
                    "resource_flow_relevant": relevant,
                    "source_sha256": scanned.source_sha256,
                },
            ))
            if relevant:
                unknowns.append(
                    "scanner unsupported syntax may hide resource-flow edges: "
                    + ", ".join(kinds)
                )
        payload = _finalize(
            parsed,
            (*contract_inputs, *parsed["inputs"]),
            (*contract_effects, *parsed["effects"]),
            parsed["resource_flows"],
            unknowns,
        )
        return FactEnvelope(
            "capability",
            "capability.v3",
            request.function.id,
            "ok",
            payload,
            diagnostics=diagnostics,
        )

    def make_error_facts(
        self,
        request: AbstractionRequest,
        error: str,
    ) -> FactEnvelope[CapabilityPayload]:
        return FactEnvelope(
            "capability",
            "capability.v3",
            request.function.id,
            "error",
            _empty_payload("runtime-failure"),
            confidence=0.0,
            diagnostics=[
                Diagnostic(
                    "error",
                    "capability-abstraction-failed",
                    {"detail": error},
                )
            ],
        )

    def make_format_exhausted_facts(
        self,
        request: AbstractionRequest,
        error: str,
        trace_ids: Sequence[str],
    ) -> FactEnvelope[CapabilityPayload]:
        contract_inputs, contract_effects = contract_facts(
            request.function,
            self._contracts,
        )
        empty = _empty_payload("model-format-exhausted")
        payload = _finalize(
            empty,
            contract_inputs,
            contract_effects,
            (),
            empty["unknowns"],
        )
        return FactEnvelope(
            "capability",
            "capability.v3",
            request.function.id,
            "partial",
            payload,
            confidence=0.0,
            diagnostics=[
                Diagnostic(
                    "warning",
                    "model-format-exhausted",
                    {"detail": error},
                )
            ],
            trace_ids=list(trace_ids),
        )

    def summarize_for_caller(
        self,
        facts: FactEnvelope[CapabilityPayload],
    ) -> str:
        payload = facts.payload
        summary: dict[str, JsonValue] = {
            "function": facts.function.rel,
            "status": facts.status,
            "coverage": payload["coverage"],
            "inputs": payload["inputs"][:32],
            "effects": payload["effects"][:64],
            "obligations": payload["obligations"][:32],
            "resource_flows": payload["resource_flows"][:64],
            "unknowns": payload["unknowns"][:32],
        }
        return json.dumps(
            summary,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def compose_calls(
        self,
        caller_facts: FactEnvelope[CapabilityPayload],
        resolved_calls: Sequence[ResolvedCall[CapabilityPayload]],
        context: DriverContext,
    ) -> FactEnvelope[CapabilityPayload]:
        self._raw_facts_by_function[caller_facts.function] = caller_facts
        if caller_facts.status == "error":
            return caller_facts
        source = caller_facts.payload
        inputs = list(source["inputs"])
        effects = list(source["effects"])
        flows = list(source["resource_flows"])
        unknowns = list(source["unknowns"])
        status, coverage = caller_facts.status, source["coverage"]
        caller_formals = formal_resources(context.function)
        seen_calls: set[tuple[int, str, str]] = set()
        ordered = sorted(
            resolved_calls,
            key=lambda item: (
                item.call_site.order_index,
                item.call_site.callee.rel,
                item.call_site.callee.name,
            ),
        )
        for resolved in ordered:
            call_key = (
                resolved.call_site.order_index,
                resolved.call_site.callee.rel,
                resolved.call_site.callee.name,
            )
            if call_key in seen_calls:
                continue
            seen_calls.add(call_key)
            callee = resolved.callee_facts
            namespace = "call_" + hashlib.sha256(
                repr(call_key).encode("utf-8")
            ).hexdigest()[:12]
            if callee.status == "error":
                status, coverage = "partial", "partial"
                unknowns.append(f"callee abstraction failed: {callee.function.rel}")
                continue
            payload = callee.payload
            if callee.status != "ok" or payload["coverage"] != "complete":
                status, coverage = "partial", "partial"
            bindings = resolved.call_site.arg_bindings
            for item in payload["inputs"]:
                formal = item["formal"]
                actual = substitute_resource(
                    formal,
                    bindings,
                    caller_formals,
                    namespace,
                )
                resource_id = substitute_resource(
                    item["resource_id"],
                    bindings,
                    caller_formals,
                    namespace,
                )
                if actual is None or resource_id is None:
                    continue
                inputs.append({
                    **item,
                    "formal": actual,
                    "resource_id": resource_id,
                })
                root, _ = resource_root(formal)
                if root in bindings:
                    flows.append({
                        "from_function": caller_facts.function.rel,
                        "to_function": callee.function.rel,
                        "formal": formal,
                        "actual": actual,
                        "resource_id": resource_id,
                        "identity": item["identity"],
                        "effect": "ARG",
                        "evidence": item["evidence"],
                        "uncertainty": (
                            None
                            if item["identity"] == "SAME"
                            else f"identity={item['identity']}"
                        ),
                    })
            for effect in payload["effects"]:
                instantiated: EffectFact = {
                    **effect,
                    "source": substitute_resource(
                        effect["source"],
                        bindings,
                        caller_formals,
                        namespace,
                    ),
                    "target": substitute_resource(
                        effect["target"],
                        bindings,
                        caller_formals,
                        namespace,
                    ),
                }
                effects.append(instantiated)
                for endpoint in (effect["source"], effect["target"]):
                    if endpoint is None or endpoint == "return":
                        continue
                    root, _ = resource_root(endpoint)
                    if root not in bindings:
                        continue
                    actual = substitute_resource(
                        endpoint,
                        bindings,
                        caller_formals,
                        namespace,
                    )
                    if actual is None:
                        continue
                    flows.append({
                        "from_function": caller_facts.function.rel,
                        "to_function": callee.function.rel,
                        "formal": endpoint,
                        "actual": actual,
                        "resource_id": actual,
                        "identity": effect["identity"],
                        "effect": effect["kind"],
                        "evidence": effect["evidence"],
                        "uncertainty": (
                            None
                            if effect["identity"] == "SAME"
                            else f"identity={effect['identity']}"
                        ),
                    })
            flows.extend(payload["resource_flows"])
            unknowns.extend(
                f"{callee.function.rel}: {item}"
                for item in payload["unknowns"]
            )
        base = {**source, "coverage": coverage}
        composed = _finalize(base, inputs, effects, flows, unknowns)
        return FactEnvelope(
            "capability",
            "capability.v3",
            caller_facts.function,
            status,
            composed,
            caller_facts.confidence,
            list(caller_facts.evidence),
            list(caller_facts.diagnostics),
            list(caller_facts.trace_ids),
        )

    def check(
        self,
        facts: FactEnvelope[CapabilityPayload],
        context: DriverContext,
        propagated_contexts: Sequence[None] = (),
    ) -> Verdict:
        del context
        return reason_capability(facts, propagated_contexts)

    def render_result(
        self,
        unit: FunctionUnit,
        facts: FactEnvelope[CapabilityPayload],
        verdict: Verdict,
        context: DriverContext,
    ) -> dict[str, JsonValue]:
        del context
        path = verdict.data.get("path", [])
        missing = verdict.data.get("missing_premise")
        result: dict[str, JsonValue] = {
            "function": unit.id.rel,
            "verdict": verdict.verdict,
            "status": verdict.status,
            "facts_status": facts.status,
            "findings": [
                {
                    "rule_id": item.rule_id,
                    "title": item.title,
                    "message": item.message,
                    "severity": item.severity,
                }
                for item in verdict.findings
            ],
            "path": path,
            "missing_premise": missing,
            "resource_flows": facts.payload["resource_flows"],
        }
        self._rendered[unit.id.rel] = result
        self._raw_facts_by_function.setdefault(unit.id, facts)
        self._facts_by_function[unit.id] = facts
        return result

    def render_summary(
        self,
        results: Sequence[dict[str, JsonValue]],
        counts: Mapping[str, int],
    ) -> dict[str, JsonValue]:
        project_verdict = next(
            (
                verdict
                for verdict in ("VULNERABLE", "NEEDS_REVIEW", "ERROR")
                if counts.get(verdict, 0)
            ),
            "SAFE",
        )
        missing: JsonValue = None
        project_chain = (
            compose_project_chain(self._raw_facts_by_function, self._program)
            if self._program is not None and self._raw_facts_by_function
            else None
        )
        if project_verdict != "ERROR" and project_chain is not None:
            project_verdict = project_chain["verdict"]
            missing = project_chain["missing_premise"]
        if project_verdict == "SAFE" and self._slice_metrics["fallback"]:
            project_verdict = "NEEDS_REVIEW"
            missing = "connected source-to-sink relevance coverage"
        ordered = sorted(
            (
                self._rendered.get(str(result.get("function", "")), result)
                for result in results
            ),
            key=lambda item: str(item.get("function", "")),
        )
        candidates = [
            item.get("path", [])
            for item in ordered
            if item.get("verdict") == project_verdict and item.get("path")
        ]
        path = (
            project_chain["path"]
            if project_chain is not None
            else max(
                candidates,
                key=lambda item: (
                    len(item) if type(item) is list else 0,
                    json.dumps(item, sort_keys=True, separators=(",", ":")),
                ),
                default=[],
            )
        )
        candidate_path_count = (
            project_chain["candidate_path_count"]
            if project_chain is not None
            else 0
        )
        candidate_paths_truncated = (
            project_chain["candidate_paths_truncated"]
            if project_chain is not None
            else False
        )
        candidate_findings = (
            project_chain["candidate_findings"]
            if project_chain is not None
            else []
        )
        strict_paths = (
            project_chain["strict_paths"]
            if project_chain is not None
            else []
        )
        strict_findings = [
            {
                "chain_id": f"strict:{index + 1}",
                "signature": _strict_summary_signature(strict_path),
                "path": _compact_summary_path(strict_path),
            }
            for index, strict_path in enumerate(strict_paths)
        ]
        if missing is None:
            missing = next(
                (
                    item.get("missing_premise")
                    for item in ordered
                    if item.get("verdict") == project_verdict
                    and item.get("missing_premise")
                ),
                None,
            )
        findings: list[JsonValue] = []
        if project_verdict == "VULNERABLE":
            findings.extend({
                "rule_id": "capability.resource-write",
                "title": "Unauthorized same-resource write (strict)",
                "chain_id": finding["chain_id"],
                "path": finding["path"],
            } for finding in strict_findings)
            findings.extend({
                "rule_id": "capability.resource-write",
                "title": "Potential unauthorized same-resource write (candidate)",
                "chain_id": finding["chain_id"],
                "signature": finding["signature"],
                "path": _compact_summary_path(finding["path"]),
            } for finding in candidate_findings)
            if not findings:
                findings.append({
                    "rule_id": "capability.resource-write",
                    "title": "Unauthorized same-resource write",
                    "path": _compact_summary_path(path),
                })
        return {
            "plugin": "capability",
            "total": len(results),
            "verdict": project_verdict,
            "status": "error" if project_verdict == "ERROR" else "ok",
            "counts": dict(counts),
            "findings": findings,
            "candidate_path_count": candidate_path_count,
            "candidate_paths_truncated": candidate_paths_truncated,
            "candidate_findings": [
                {
                    **finding,
                    "path": _compact_summary_path(finding["path"]),
                }
                for finding in candidate_findings
            ],
            "strict_path_count": len(strict_findings),
            "strict_paths_truncated": (
                False
                if project_chain is None
                else project_chain["strict_paths_truncated"]
            ),
            "strict_findings": strict_findings,
            "missing_premise": missing,
            "gaps": [] if project_chain is None else project_chain["gaps"],
            "reason": None if project_chain is None else project_chain["reason"],
            "confidence": (
                None if project_chain is None else project_chain["confidence"]
            ),
            "analysis_scope": self.analysis_scope,
        }
