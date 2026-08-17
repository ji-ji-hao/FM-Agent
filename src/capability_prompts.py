from __future__ import annotations

# noqa: SIZE_OK - one strict Capability v3 boundary owns its parser and prompt.

import json
import re
from typing import Final, TypedDict


JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


class EvidenceFact(TypedDict):
    authority: str
    lines: list[int]


class InputFact(TypedDict):
    formal: str
    resource_id: str
    reference_origin: str
    possible_backing: list[str]
    write_authority: list[str]
    role: str
    identity: str
    evidence: EvidenceFact


class EffectFact(TypedDict):
    order: int
    kind: str
    source: str | None
    target: str | None
    identity: str
    region: str
    guard: str
    evidence: EvidenceFact


class ObligationFact(TypedDict):
    resource_id: str
    source: str
    target: str
    identity: str
    region: str
    guard: str
    evidence: EvidenceFact


class ResourceFlow(TypedDict):
    from_function: str
    to_function: str
    formal: str
    actual: str
    resource_id: str
    identity: str
    effect: str
    evidence: EvidenceFact
    uncertainty: str | None


class CapabilityPayload(TypedDict):
    schema_version: str
    coverage: str
    inputs: list[InputFact]
    effects: list[EffectFact]
    unknowns: list[str]
    obligations: list[ObligationFact]
    resource_flows: list[ResourceFlow]
    propagation_chain: list[str]


_OPEN: Final = "[CAPABILITY_JSON]"
_CLOSE: Final = "[/CAPABILITY_JSON]"
_MAX_BODY_BYTES: Final = 65_536
_ROOT_KEYS: Final = {"schema_version", "coverage", "inputs", "effects", "unknowns"}
_INPUT_KEYS: Final = {
    "formal",
    "resource_id",
    "reference_origin",
    "possible_backing",
    "write_authority",
    "role",
    "identity",
    "evidence",
}
_EFFECT_KEYS: Final = {
    "order", "kind", "source", "target", "identity", "region", "guard", "evidence",
}
_EFFECT_EXTRA_KEYS: Final = {"write_authority", "possible_backing", "callee_info"}
_EFFECT_KINDS: Final = {
    "ALIAS", "FIELD", "RETURN", "ROLE_BIND", "REQUIRE_WRITE",
    "WRITE", "WRITEBACK", "GRANT", "DEEP_COPY", "REGISTER", "DISPATCH",
}
_EFFECT_KIND_ALIASES: Final = {"FLOW", "ARG", "INTERLEAVE"}
_IGNORED_EFFECT_KINDS: Final = {"READ"}
_IDENTITIES: Final = {"SAME", "MAY_SAME", "FRESH", "UNKNOWN"}
_REGIONS: Final = {"OVERLAP", "DISJOINT", "UNKNOWN"}
_RESOURCE: Final = re.compile(
    r"(?:param|local|global|resource|actual):"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,16}|return"
)
_TYPED_RESOURCE: Final = re.compile(
    r"(?P<prefix>[A-Za-z_][A-Za-z0-9_]*):"
    r"[A-Za-z_][A-Za-z0-9_]*"
    r"(?P<suffix>(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*){0,16})"
)
_PARAM_DECLARATION: Final = re.compile(r"param:([A-Za-z_][A-Za-z0-9_]*)")
_SCHEMA: Final = """{
"schema_version":"capability.v3",
"coverage":"complete",
"inputs":[{"formal":"param:src","resource_id":"param:src",
"reference_origin":"USER_CONTROLLED",
"possible_backing":["WRITABLE_PRIVATE","READONLY_MAPPING"],
"write_authority":["GRANTED","DENIED"],"role":"INPUT","identity":"SAME",
"evidence":{"authority":"SOURCE","lines":[1]}}],
"effects":[
{"order":1,"kind":"FIELD","source":"param:src","target":"param:req.src",
"identity":"SAME","region":"OVERLAP","guard":"FEASIBLE",
"evidence":{"authority":"SOURCE","lines":[2]}},
{"order":2,"kind":"RETURN","source":"param:req.src","target":"return",
"identity":"SAME","region":"OVERLAP","guard":"FEASIBLE",
"evidence":{"authority":"SOURCE","lines":[3]}}],
"unknowns":[]
}"""


class _InvalidCapability(ValueError):
    pass


def _fail() -> None:
    raise _InvalidCapability


def _mapping(value: JsonValue, keys: set[str]) -> dict[str, JsonValue]:
    if type(value) is not dict or set(value) != keys:
        _fail()
    return value


def _array(value: JsonValue, maximum: int) -> list[JsonValue]:
    if type(value) is not list or len(value) > maximum:
        _fail()
    return value


def _text(
    value: JsonValue,
    allowed: set[str] | None = None,
    limit: int = 256,
) -> str:
    if type(value) is not str or not value or len(value) > limit:
        _fail()
    if allowed is not None and value not in allowed:
        _fail()
    return value


def _resource(
    value: JsonValue,
    *,
    nullable: bool = False,
    declared_params: set[str] | None = None,
) -> str | None:
    if nullable and (value is None or value == "null"):
        return None
    text = _text(value)
    if _RESOURCE.fullmatch(text) is not None:
        return text
    if declared_params is not None:
        typed = _TYPED_RESOURCE.fullmatch(text)
        if typed is not None and typed["prefix"] in declared_params:
            suffix = typed["suffix"].replace("->", ".")
            canonical = f"param:{typed['prefix']}{suffix}"
            if _RESOURCE.fullmatch(canonical) is not None:
                return canonical
    _fail()
    return None


def _declared_param_names(values: list[JsonValue]) -> set[str]:
    names: set[str] = set()
    for value in values:
        if type(value) is not dict:
            continue
        formal = value.get("formal")
        if type(formal) is not str:
            continue
        match = _PARAM_DECLARATION.fullmatch(formal)
        if match is not None:
            names.add(match[1])
    return names


def _enum_set(value: JsonValue, allowed: set[str]) -> list[str]:
    values = _array(value, 8)
    parsed = [_text(item, allowed) for item in values]
    if not parsed or len(parsed) != len(set(parsed)):
        _fail()
    return parsed


def _evidence(value: JsonValue, line_count: int | None) -> EvidenceFact:
    item = _mapping(value, {"authority", "lines"})
    authority_value = item["authority"]
    if authority_value == "CALL":
        authority_value = "SOURCE"
    authority = _text(authority_value, {"SOURCE", "CONTRACT", "EXPLICIT", "MODEL"})
    raw_lines = _array(item["lines"], 16)
    lines: list[int] = []
    for raw in raw_lines:
        if type(raw) is not int or raw < 1:
            _fail()
        if line_count is not None and raw > line_count:
            _fail()
        lines.append(raw)
    if not lines or lines != sorted(set(lines)):
        _fail()
    return {"authority": authority, "lines": lines}


def _input(
    value: JsonValue,
    line_count: int | None,
    declared_params: set[str],
) -> InputFact | None:
    item = _mapping(value, _INPUT_KEYS)
    formal = _resource(item["formal"], declared_params=declared_params)
    resource_id = _resource(item["resource_id"], declared_params=declared_params)
    if formal is None or resource_id is None:
        _fail()
    parsed: InputFact = {
        "formal": formal,
        "resource_id": resource_id,
        "reference_origin": _text(
            item["reference_origin"],
            {"USER_CONTROLLED", "KERNEL_CONTROLLED", "UNKNOWN"},
        ),
        "possible_backing": _enum_set(
            item["possible_backing"],
            {
                "WRITABLE_PRIVATE",
                "READONLY_MAPPING",
                "PROTECTED_SHARED",
                "KERNEL_PRIVATE",
                "UNKNOWN",
            },
        ),
        "write_authority": _enum_set(
            item["write_authority"],
            {"GRANTED", "DENIED", "UNKNOWN"},
        ),
        "role": _text(item["role"], {"INPUT", "OUTPUT", "INOUT", "UNKNOWN"}),
        "identity": _identity(item["identity"]),
        "evidence": _evidence(item["evidence"], line_count),
    }
    if formal.startswith("local:"):
        return None
    if not formal.startswith("param:"):
        _fail()
    return parsed


def _identity(value: JsonValue) -> str:
    if value == "OTHER":
        value = "UNKNOWN"
    return _text(value, _IDENTITIES)


def _region(value: JsonValue) -> str:
    if value in {"EXACT", "SAME"}:
        value = "OVERLAP"
    return _text(value, _REGIONS)


def _guard(value: JsonValue) -> str:
    if value == "ALWAYS":
        return "FEASIBLE"
    if value == "CALL":
        return "UNKNOWN"
    return _text(value, {"FEASIBLE", "IMPOSSIBLE", "UNKNOWN"})


def _effect_mapping(value: JsonValue) -> dict[str, JsonValue]:
    if type(value) is not dict:
        _fail()
    keys = set(value)
    if not _EFFECT_KEYS <= keys or keys - _EFFECT_KEYS - _EFFECT_EXTRA_KEYS:
        _fail()
    return value


def _nested_resource_pair(source: str | None, target: str | None) -> bool:
    if source is None or target is None or source == target:
        return False
    return target.startswith(f"{source}.") or source.startswith(f"{target}.")


def _effect_kind(
    value: JsonValue,
    source: str | None,
    target: str | None,
) -> str:
    raw = _text(value)
    if raw in _EFFECT_KIND_ALIASES:
        return "FIELD" if _nested_resource_pair(source, target) else "ALIAS"
    return _text(raw, _EFFECT_KINDS)


def _effect(
    value: JsonValue,
    line_count: int | None,
    declared_params: set[str],
) -> EffectFact:
    item = _effect_mapping(value)
    order = item["order"]
    if type(order) is not int or not 1 <= order <= 1_000_000:
        _fail()
    source = _resource(
        item["source"],
        nullable=True,
        declared_params=declared_params,
    )
    target = _resource(
        item["target"],
        nullable=True,
        declared_params=declared_params,
    )
    kind = _effect_kind(item["kind"], source, target)
    if kind in {"WRITE", "WRITEBACK", "GRANT"} and target is None:
        _fail()
    if kind in {
        "ALIAS", "FIELD", "ROLE_BIND", "REQUIRE_WRITE", "DEEP_COPY",
        "REGISTER", "DISPATCH",
    }:
        if source is None or target is None:
            _fail()
    if kind == "RETURN" and (source is None or target != "return"):
        _fail()
    return {
        "order": order,
        "kind": kind,
        "source": source,
        "target": target,
        "identity": _identity(item["identity"]),
        "region": _region(item["region"]),
        "guard": _guard(item["guard"]),
        "evidence": _evidence(item["evidence"], line_count),
    }


def _reject_duplicate_keys(
    pairs: list[tuple[str, JsonValue]],
) -> dict[str, JsonValue]:
    if len(pairs) != len({key for key, _ in pairs}):
        _fail()
    return dict(pairs)


def _is_optional_return(value: JsonValue) -> bool:
    return type(value) is dict and value.get("kind") == "RETURN"


def _is_ignored_read(
    value: JsonValue,
    line_count: int | None,
    declared_params: set[str],
) -> bool:
    if type(value) is not dict:
        return False
    kind = value.get("kind")
    if type(kind) is not str or kind not in _IGNORED_EFFECT_KINDS:
        return False
    item = _effect_mapping(value)
    order = item["order"]
    if type(order) is not int or not 1 <= order <= 1_000_000:
        _fail()
    _resource(item["source"], nullable=True, declared_params=declared_params)
    _resource(item["target"], nullable=True, declared_params=declared_params)
    _identity(item["identity"])
    _region(item["region"])
    _guard(item["guard"])
    _evidence(item["evidence"], line_count)
    return True


def parse_capability_response(
    text: str,
    function_rel: str | None = None,
    *,
    line_count: int | None = None,
) -> CapabilityPayload | None:
    del function_rel
    if (
        type(text) is not str
        or not text.startswith(_OPEN)
        or not text.endswith(_CLOSE)
        or text.count(_OPEN) != 1
        or text.count(_CLOSE) != 1
    ):
        return None
    body = text[len(_OPEN):-len(_CLOSE)]
    try:
        if len(body.encode("utf-8")) > _MAX_BODY_BYTES:
            _fail()
        root = _mapping(
            json.loads(body, object_pairs_hook=_reject_duplicate_keys),
            _ROOT_KEYS,
        )
        if root["schema_version"] != "capability.v3":
            _fail()
        coverage = _text(root["coverage"], {"complete", "partial", "unknown"})
        raw_inputs = _array(root["inputs"], 64)
        declared_params = _declared_param_names(raw_inputs)
        inputs: list[InputFact] = []
        for item in raw_inputs:
            parsed_input = _input(item, line_count, declared_params)
            if parsed_input is not None:
                inputs.append(parsed_input)
        effects: list[EffectFact] = []
        salvaged: list[str] = []
        for index, item in enumerate(_array(root["effects"], 128), start=1):
            if _is_ignored_read(item, line_count, declared_params):
                continue
            try:
                effects.append(_effect(item, line_count, declared_params))
            except _InvalidCapability:
                if not _is_optional_return(item):
                    raise
                salvaged.append(f"malformed optional RETURN effect at index {index}")
        unknowns = [
            _text(item, limit=512) for item in _array(root["unknowns"], 64)
        ] + salvaged
        if len({item["formal"] for item in inputs}) != len(inputs):
            _fail()
        if len({item["order"] for item in effects}) != len(effects):
            _fail()
        return {
            "schema_version": "capability.v3",
            "coverage": coverage,
            "inputs": inputs,
            "effects": sorted(effects, key=lambda item: item["order"]),
            "unknowns": unknowns,
            "obligations": [],
            "resource_flows": [],
            "propagation_chain": [],
        }
    except (
        json.JSONDecodeError,
        UnicodeEncodeError,
        RecursionError,
        _InvalidCapability,
    ):
        return None


_extract_capability_json = parse_capability_response


def _system_prompt(language: str) -> str:
    return (
        f"Analyze one {language} function as resource-identity flow. For each "
        "resource answer three independent questions: (1) who selects the "
        "reference: USER_CONTROLLED, KERNEL_CONTROLLED, or UNKNOWN; (2) which "
        "write_authority alternatives are feasible: GRANTED, DENIED, or UNKNOWN; "
        "(3) which possible_backing alternatives are feasible: WRITABLE_PRIVATE, "
        "READONLY_MAPPING, PROTECTED_SHARED, KERNEL_PRIVATE, or UNKNOWN. "
        "USER_CONTROLLED may select writable or readonly backing. Record role as "
        "INPUT, OUTPUT, INOUT, or UNKNOWN. The inputs array describes function "
        "parameters only: formal and resource_id must both start with param:. "
        "Never put local:, global:, resource:, actual:, or return in inputs; use "
        "those only as effect endpoints. Inputs are assumptions and an observed "
        "WRITE never implies GRANTED. Return candidates with evidence; MODEL "
        "candidates are untrusted unless source, contract, or explicit proof "
        "establishes them. Effect kind must be exactly one of ALIAS, FIELD, "
        "RETURN, ROLE_BIND, REQUIRE_WRITE, WRITE, WRITEBACK, GRANT, DEEP_COPY, "
        "REGISTER, or DISPATCH. Never emit CALL, CALL_ARG, COPY, or any other "
        "effect kind. identity must be exactly SAME, MAY_SAME, FRESH, or UNKNOWN; "
        "never use DERIVED, ALIAS, CHILD, TRANSITIVE, or FULL. region must be "
        "exactly OVERLAP, DISJOINT, or UNKNOWN. ALIAS, FIELD, ROLE_BIND, "
        "REQUIRE_WRITE, DEEP_COPY, REGISTER, and DISPATCH require both source and "
        "target to be non-null; for REQUIRE_WRITE, target is the resource requiring "
        "authority. Every non-null effect endpoint must be return or use exactly "
        "one prefix from param:, local:, global:, resource:, or actual:, followed "
        "by an identifier and optional dot-separated fields. Never emit callee:, "
        "call:, callback:, or other endpoint prefixes. Calls and argument mapping "
        "are resolved by the call graph, contracts, and composition stage; express "
        "only direct current-function resource facts in this schema. If a fact "
        "cannot be expressed safely, put the uncertainty in unknowns. guard must be "
        "exactly FEASIBLE, IMPOSSIBLE, or UNKNOWN; use UNKNOWN when the condition is "
        "not source-proved. Never use CALL, CONDITIONAL, ALWAYS, or a function name "
        "for guard. REGISTER and DISPATCH describe indirect callback slots only, never "
        "ordinary named calls. "
        "A DISPATCH source must be the same canonical slot used as a REGISTER target; "
        "never put a filename or path in a resource. REGISTER maps source "
        "resource:function.<name> to a "
        "normalized abstract-slot target; DISPATCH uses that same slot as source "
        "and the dispatched resource argument as target. JSON null and the string "
        "\"null\" are equivalent only "
        "for nullable effect endpoints. RETURN requires a non-null source and "
        "target \"return\". A resource contains exactly one colon, no slash, "
        "hyphen, or second colon. Every evidence object has exactly authority and "
        "lines; authority is SOURCE, CONTRACT, EXPLICIT, or MODEL, and lines is a "
        "non-empty array of source line integers. unknowns is an array of plain "
        "strings only, never objects. Emit only the tagged JSON block and no verdict.\n"
        f"{_OPEN}{_SCHEMA}{_CLOSE}"
    )


def _user_prompt(
    numbered_source: str,
    signature_line: str,
    language: str,
    callee_summaries: str,
) -> str:
    context = (
        f"\nCallee resource summaries:\n{callee_summaries}"
        if callee_summaries
        else ""
    )
    return (
        f"Language: {language}\nSignature: {signature_line}\n"
        f"Source:\n{numbered_source}{context}\n"
        f"Return exactly {_OPEN}<valid JSON>{_CLOSE} matching:\n{_SCHEMA}"
    )
