from __future__ import annotations

# noqa: SIZE_OK - project-chain graph traversal and sink proof stay co-located.

import hashlib
import json
import re
from collections import deque
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, TypedDict

from src.capability_contracts import formal_resources, normalize_actual, resource_root
from src.capability_scanner import canonical, scan_source
from src.capability_prompts import (
    CapabilityPayload,
    EffectFact,
    EvidenceFact,
    InputFact,
    JsonValue,
)
from src.plugins.base import (
    CallSite,
    FactEnvelope,
    FunctionId,
    FunctionUnit,
    ProgramIndex,
)


class CandidateRouteSignature(TypedDict):
    kind: str
    implementation: str | None
    slot: str | None
    direct_identity: str | None


class CandidateSignature(TypedDict):
    seed_function: str
    seed_resource: str
    obligation_function: str
    obligation_resource: str
    route: CandidateRouteSignature
    writeback_function: str
    writeback_resource: str


class CandidateFinding(TypedDict):
    chain_id: str
    signature: CandidateSignature
    path: list[dict[str, JsonValue]]


class ProjectChain(TypedDict):
    verdict: str
    path: list[dict[str, JsonValue]]
    candidate_path: list[dict[str, JsonValue]]
    candidate_paths: list[list[dict[str, JsonValue]]]
    candidate_path_count: int
    candidate_paths_truncated: bool
    candidate_findings: list[CandidateFinding]
    strict_paths: list[list[dict[str, JsonValue]]]
    strict_path_count: int
    strict_paths_truncated: bool
    propagation_chain: list[dict[str, JsonValue]]
    missing_premise: str | None
    gaps: list[str]
    reason: str | None
    confidence: str | None


@dataclass(frozen=True, slots=True)
class _Node:
    function: FunctionId
    resource: str


@dataclass(frozen=True, slots=True)
class _Hop:
    kind: str
    from_function: FunctionId
    to_function: FunctionId
    source: str
    target: str
    evidence: EvidenceFact
    order: int = 0


@dataclass(frozen=True, slots=True)
class _Edge:
    source: _Node
    target: _Node
    hops: tuple[_Hop, ...]
    obligation: bool = False
    cut: bool = False
    callsite: str | None = None
    call_direction: int = 0


@dataclass(frozen=True, slots=True)
class _CandidateSearch:
    findings: tuple[CandidateFinding, ...]
    partial_path: list[dict[str, JsonValue]]
    missing_premise: str | None
    truncated: bool


MAX_CANDIDATE_FINDINGS: Final = 100
MAX_CANDIDATE_STATES: Final = 100_000
MAX_CANDIDATE_RESOURCE_DEPTH: Final = 16
MAX_CANDIDATE_CALL_DEPTH: Final = 16
MAX_STRICT_FINDINGS: Final = 100
MAX_REGISTERED_IMPLEMENTATIONS: Final = 32
MAX_REGISTERED_ROUTES_PER_SLOT: Final = 32
_TRUSTED = {"SOURCE", "CONTRACT", "EXPLICIT"}
_BACKING_AT_RISK = {"READONLY_MAPPING", "PROTECTED_SHARED"}
_TRANSFER = {"ALIAS", "FIELD", "RETURN"}
_WRITES = {"WRITE", "WRITEBACK"}
_LIFECYCLE_PREFIX = "global:lifecycle_"


@dataclass(frozen=True, slots=True)
class RegisteredImplementationResolution:
    implementations: tuple[FunctionId, ...]
    total: int
    truncated: bool


def _compilation_unit_key(unit: FunctionUnit) -> str:
    if unit.original_rel:
        return unit.original_rel.replace("\\", "/")
    rel = unit.id.rel.replace("\\", "/")
    return rel.rsplit("/", 1)[0] if "/" in rel else rel


def _is_static_function(unit: FunctionUnit) -> bool:
    declaration = unit.signature_line or unit.source.split("{", 1)[0]
    return re.search(r"\bstatic\b", declaration) is not None


def resolve_registered_implementations(
    program: ProgramIndex,
    register_fn: FunctionId,
    implementation_name: str,
    eligible: Collection[FunctionId] | None = None,
) -> RegisteredImplementationResolution:
    """Resolve a REGISTER target using C translation-unit name binding."""
    candidates = [
        function_id
        for function_id in program.functions
        if function_id.base_name == implementation_name
        and (eligible is None or function_id in eligible)
    ]
    registrar = program.functions.get(register_fn)
    if registrar is not None:
        registrar_key = _compilation_unit_key(registrar)
        local = [
            function_id
            for function_id in candidates
            if _compilation_unit_key(program.functions[function_id]) == registrar_key
        ]
        local_static = [
            function_id
            for function_id in local
            if _is_static_function(program.functions[function_id])
        ]
        if local_static:
            candidates = local_static
        elif local:
            candidates = local
    ordered = tuple(sorted(set(candidates), key=lambda item: item.rel))
    return RegisteredImplementationResolution(
        ordered[:MAX_REGISTERED_IMPLEMENTATIONS],
        len(ordered),
        len(ordered) > MAX_REGISTERED_IMPLEMENTATIONS,
    )


def _trusted(evidence: EvidenceFact) -> bool:
    return evidence["authority"] in _TRUSTED and bool(evidence["lines"])


def _strictly_denied(input_fact: InputFact) -> bool:
    authorities = set(input_fact["write_authority"])
    backing = set(input_fact["possible_backing"])
    if input_fact["evidence"]["authority"] in {"CONTRACT", "EXPLICIT"}:
        return "DENIED" in authorities
    return authorities == {"DENIED"} and bool(backing) and backing <= _BACKING_AT_RISK


def _seed(
    input_fact: InputFact,
    entry_formals: set[str],
    is_entrypoint: bool,
) -> bool:
    formal_root, _ = resource_root(input_fact["formal"])
    return (
        is_entrypoint
        and input_fact["formal"].startswith("param:")
        and formal_root in entry_formals
        and input_fact["reference_origin"] == "USER_CONTROLLED"
        and _strictly_denied(input_fact)
        and bool(_BACKING_AT_RISK & set(input_fact["possible_backing"]))
        and input_fact["role"] == "INPUT"
        and input_fact["identity"] == "SAME"
        and input_fact["evidence"]["authority"] in {"CONTRACT", "EXPLICIT"}
        and _trusted(input_fact["evidence"])
    )


def _step(
    hop: _Hop,
    seed: InputFact,
    resource_id: str,
) -> dict[str, JsonValue]:
    return {
        "kind": hop.kind,
        "edge_kind": hop.kind,
        "from_function": hop.from_function.rel,
        "to_function": hop.to_function.rel,
        "source": hop.source,
        "target": hop.target,
        "resource_id": resource_id,
        "identity": "SAME",
        "reference_origin": seed["reference_origin"],
        "possible_backing": seed["possible_backing"],
        "write_authority": seed["write_authority"],
        "role": seed["role"],
        "authority": hop.evidence["authority"],
        "lines": hop.evidence["lines"],
    }


def _seed_step(function: FunctionId, item: InputFact) -> dict[str, JsonValue]:
    hop = _Hop(
        "SEED",
        function,
        function,
        item["formal"],
        item["formal"],
        item["evidence"],
    )
    return _step(hop, item, item["resource_id"])


def _candidate_step(
    hop: _Hop,
    seed: InputFact,
) -> dict[str, JsonValue]:
    step = _step(hop, seed, seed["resource_id"])
    step.update({
        "function_rel": hop.from_function.rel,
        "from": hop.source,
        "to": hop.target,
        "evidence": {
            "authority": hop.evidence["authority"],
            "lines": hop.evidence["lines"],
        },
        "confidence": "candidate",
    })
    return step


def _candidate_effect_key(effect: EffectFact) -> tuple[
    int,
    str,
    str,
    str,
    str,
    tuple[int, ...],
]:
    return (
        effect["order"],
        effect["kind"],
        effect["source"] or "",
        effect["target"] or "",
        effect["evidence"]["authority"],
        tuple(effect["evidence"]["lines"]),
    )


def _candidate_signature_key(signature: CandidateSignature) -> str:
    return json.dumps(signature, sort_keys=True, separators=(",", ":"))


def _candidate_finding(
    signature: CandidateSignature,
    path: list[dict[str, JsonValue]],
) -> CandidateFinding:
    signature_key = _candidate_signature_key(signature)
    digest = hashlib.sha256(signature_key.encode("utf-8")).hexdigest()
    return {
        "chain_id": f"candidate:{digest}",
        "signature": signature,
        "path": path,
    }


def _call_site_key(site: CallSite) -> tuple[
    int,
    str,
    str,
    tuple[tuple[str, str], ...],
    int,
]:
    return (
        site.order_index,
        site.callee.rel,
        site.callee.name,
        tuple(sorted(site.arg_bindings.items())),
        0 if site.span is None else site.span.start_line,
    )


def _callsite_token(site: CallSite) -> str:
    return json.dumps(
        (site.caller.rel, _call_site_key(site)),
        separators=(",", ":"),
    )


def _compose_candidate_chains(
    facts: Mapping[FunctionId, FactEnvelope[CapabilityPayload]],
    program: ProgramIndex,
) -> _CandidateSearch:
    """Enumerate candidate findings over explicit resource-state edges."""
    effect_edges, writes, registrations = _effect_edges(facts)
    edges = [
        edge for edge in effect_edges
        if all(hop.kind in {"FIELD", "ALIAS", "RETURN", "REQUIRE_WRITE"} for hop in edge.hops)
    ]
    edges.extend(_candidate_assignment_edges(facts, program))
    edges.extend(_candidate_reverse_alias_edges(edges, facts))
    edges.extend(_flow_edges(facts, program))
    edges.extend(_candidate_call_return_edges(facts, program))
    dispatch_edges, dispatch_gaps = _dispatch_edges(facts, program, registrations)
    edges.extend(dispatch_edges)
    adjacency: dict[_Node, list[_Edge]] = {}
    edges_by_function: dict[FunctionId, list[_Edge]] = {}
    for edge in edges:
        adjacency.setdefault(edge.source, []).append(edge)
        edges_by_function.setdefault(edge.source.function, []).append(edge)
    for outgoing in adjacency.values():
        outgoing.sort(key=lambda edge: (
            edge.hops[0].kind,
            edge.target.function.rel,
            edge.target.resource,
        ))

    findings: dict[str, CandidateFinding] = {}
    best_partial: list[dict[str, JsonValue]] = []
    truncated = any(" truncated from " in gap for gap in dispatch_gaps)
    explored_states = 0
    entrypoints = frozenset(program.entrypoints)
    for function, envelope in sorted(facts.items(), key=lambda row: row[0].rel):
        formals = formal_resources(program.functions[function])
        for seed in sorted(envelope.payload["inputs"], key=lambda item: item["resource_id"]):
            if not _candidate_seed(
                seed,
                envelope,
                formals,
                function in entrypoints,
            ):
                continue
            start_node = _Node(function, seed["formal"])
            start_path = [_candidate_step(_Hop(
                "SEED", function, function, seed["formal"], seed["formal"], seed["evidence"]
            ), seed)]
            start_state = (start_node, None, None, ())
            pending = deque(((start_node, None, None, (), start_path),))
            seen_states: set[tuple[
                _Node,
                tuple[str, str] | None,
                tuple[str, str] | None,
                tuple[str, ...],
            ]] = {start_state}
            while pending:
                (
                    node,
                    obligation_key,
                    dispatch_key,
                    call_stack,
                    path,
                ) = pending.popleft()
                explored_states += 1
                if explored_states > MAX_CANDIDATE_STATES:
                    ordered = tuple(findings[key] for key in sorted(findings))
                    missing = None if ordered else "candidate resource-state search limit"
                    return _CandidateSearch(
                        ordered,
                        _dedupe_path(best_partial),
                        missing,
                        True,
                    )
                if len(path) > len(best_partial):
                    best_partial = path
                writebacks = (
                    _candidate_writebacks(node, writes)
                    if obligation_key is not None
                    else ()
                )
                valid_writebacks = tuple(
                    (write_node, write)
                    for write_node, write in writebacks
                    if write["identity"] == "SAME"
                    and write["region"] == "OVERLAP"
                    and write["guard"] == "FEASIBLE"
                    and _trusted(write["evidence"])
                )
                for write_node, write in valid_writebacks:
                    completed = [*path, _candidate_step(_Hop(
                        "WRITEBACK", node.function, node.function,
                        node.resource, write_node.resource, write["evidence"],
                    ), seed)]
                    dispatch = next((step for step in completed if step["kind"] == "DISPATCH"), None)
                    obligation_index = next(
                        index
                        for index, step in enumerate(completed)
                        if step["kind"] == "REQUIRE_WRITE"
                    )
                    direct = next((
                        step
                        for step in completed[obligation_index + 1:]
                        if step["kind"] == "ARG"
                        and step["from_function"] != step["to_function"]
                    ), None)
                    direct_identity = (
                        None
                        if direct is None
                        else json.dumps(
                            {
                                "from_function": direct["from_function"],
                                "to_function": direct["to_function"],
                                "source": direct["source"],
                                "target": direct["target"],
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    )
                    route: CandidateRouteSignature = {
                        "kind": "REGISTER" if dispatch is not None else "DIRECT",
                        "implementation": (
                            dispatch_key[0]
                            if dispatch_key is not None
                            else None if direct is None else str(direct["to_function"])
                        ),
                        "slot": None if dispatch_key is None else dispatch_key[1],
                        "direct_identity": (
                            None if dispatch_key is not None else direct_identity
                        ),
                    }
                    signature: CandidateSignature = {
                        "seed_function": function.rel,
                        "seed_resource": seed["resource_id"],
                        "obligation_function": obligation_key[0],
                        "obligation_resource": obligation_key[1],
                        "route": route,
                        "writeback_function": node.function.rel,
                        "writeback_resource": write_node.resource,
                    }
                    key = _candidate_signature_key(signature)
                    if key not in findings:
                        if len(findings) >= MAX_CANDIDATE_FINDINGS:
                            ordered = tuple(
                                findings[item] for item in sorted(findings)
                            )
                            return _CandidateSearch(
                                ordered,
                                _dedupe_path(best_partial),
                                None,
                                True,
                            )
                        findings[key] = _candidate_finding(signature, _dedupe_path(completed))
                if valid_writebacks:
                    continue
                for edge in _candidate_outgoing(
                    node,
                    adjacency,
                    edges_by_function,
                ):
                    next_stack = call_stack
                    if edge.call_direction > 0 and edge.callsite is not None:
                        if len(call_stack) >= MAX_CANDIDATE_CALL_DEPTH:
                            continue
                        next_stack = (*call_stack, edge.callsite)
                    elif edge.call_direction < 0 and edge.callsite is not None:
                        if call_stack:
                            if call_stack[-1] != edge.callsite:
                                continue
                            next_stack = call_stack[:-1]
                        elif obligation_key is not None or dispatch_key is not None:
                            continue
                    next_obligation = obligation_key
                    if (
                        next_obligation is None
                        and dispatch_key is not None
                        and edge.obligation
                    ):
                        continue
                    if next_obligation is None and edge.obligation:
                        obligation_hop = next(
                            (hop for hop in edge.hops if hop.kind == "REQUIRE_WRITE"),
                            edge.hops[-1],
                        )
                        next_obligation = (
                            obligation_hop.from_function.rel,
                            obligation_hop.target,
                        )
                    next_dispatch = dispatch_key
                    dispatch_hop = next(
                        (hop for hop in edge.hops if hop.kind == "DISPATCH"),
                        None,
                    )
                    if dispatch_hop is not None:
                        register_hop = next(
                            (hop for hop in edge.hops if hop.kind == "REGISTER"),
                            None,
                        )
                        next_dispatch = (
                            dispatch_hop.to_function.rel,
                            register_hop.target if register_hop is not None else "",
                        )
                    state = (
                        edge.target,
                        next_obligation,
                        next_dispatch,
                        next_stack,
                    )
                    if state in seen_states:
                        continue
                    seen_states.add(state)
                    next_path = [*path, *(
                        _candidate_step(hop, seed) for hop in edge.hops
                    )]
                    pending.append((
                        edge.target,
                        next_obligation,
                        next_dispatch,
                        next_stack,
                        next_path,
                    ))
    ordered = tuple(findings[key] for key in sorted(findings))
    missing = None if ordered else (
        dispatch_gaps[0] if dispatch_gaps else "continuous explicit resource path to REQUIRE_WRITE and WRITEBACK"
    )
    return _CandidateSearch(ordered, _dedupe_path(best_partial), missing, truncated)


def _candidate_seed(
    item: InputFact,
    envelope: FactEnvelope[CapabilityPayload],
    formals: set[str],
    is_entrypoint: bool,
) -> bool:
    if _seed(item, formals, is_entrypoint):
        return True
    if (
        item["evidence"]["authority"] != "CONTRACT"
        or not _trusted(item["evidence"])
        or item["reference_origin"] != "USER_CONTROLLED"
        or not _strictly_denied(item)
        or not (_BACKING_AT_RISK & set(item["possible_backing"]))
        or item["role"] != "INPUT"
        or item["identity"] != "SAME"
    ):
        return False
    formal_root, _ = resource_root(item["formal"])
    if formal_root not in formals:
        return False
    return any(
        effect["evidence"]["authority"] == "CONTRACT"
        and _trusted(effect["evidence"])
        and effect["identity"] == "SAME"
        and any(
            resource is not None
            and (
                resource == item["formal"]
                or resource.startswith(f'{item["formal"]}.')
                or item["formal"].startswith(f'{resource}.')
            )
            for resource in (effect["source"], effect["target"])
        )
        for effect in envelope.payload["effects"]
    )


def _resource_suffix(resource: str, prefix: str) -> str | None:
    if resource == prefix:
        return ""
    marker = f"{prefix}."
    if resource.startswith(marker):
        return resource[len(prefix):]
    return None


def _candidate_assignment_edges(
    facts: Mapping[FunctionId, FactEnvelope[CapabilityPayload]],
    program: ProgramIndex,
) -> list[_Edge]:
    edges: list[_Edge] = []
    for function, envelope in facts.items():
        unit = program.functions.get(function)
        if unit is None:
            continue
        anchored_resources = {
            resource
            for resource in _candidate_contract_anchors(envelope)
            if resource.startswith("local:")
        }
        if not anchored_resources:
            continue
        formals = formal_resources(unit)
        scanned = scan_source(unit.source)
        source_bytes = unit.source.encode("utf-8")
        for assignment in scanned.assignments:
            left_text = canonical(assignment.left)
            right_text = canonical(assignment.right)
            target = normalize_actual(left_text, formals)
            if not _candidate_resource_is_anchored(target, anchored_resources):
                continue
            if any(token.text in {"(", ")"} for token in assignment.right):
                continue
            source = normalize_actual(right_text, formals)
            if (
                source in {"local:unknown", "param:unknown"}
                or target in {"local:unknown", "param:unknown"}
                or source == target
            ):
                continue
            line = source_bytes[:assignment.order_byte].count(b"\n") + 1
            evidence: EvidenceFact = {
                "authority": "CONTRACT",
                "lines": [line],
            }
            kind = "ALIAS" if right_text.lstrip().startswith("&") else "FIELD"
            hop = _Hop(
                kind,
                function,
                function,
                source,
                target,
                evidence,
            )
            edges.append(_Edge(
                _Node(function, source),
                _Node(function, target),
                (hop,),
            ))
    return edges


def _candidate_contract_anchors(
    envelope: FactEnvelope[CapabilityPayload],
) -> frozenset[str]:
    return frozenset(
        resource
        for effect in envelope.payload["effects"]
        if effect["evidence"]["authority"] == "CONTRACT"
        and _trusted(effect["evidence"])
        and effect["identity"] == "SAME"
        and effect["region"] == "OVERLAP"
        and effect["guard"] == "FEASIBLE"
        for resource in (effect["source"], effect["target"])
        if resource is not None
    )


def _candidate_resource_is_anchored(
    resource: str,
    anchors: Collection[str],
) -> bool:
    return any(
        _resource_suffix(resource, anchor) is not None
        or _resource_suffix(anchor, resource) is not None
        for anchor in anchors
    )


def _candidate_reverse_alias_edges(
    edges: Sequence[_Edge],
    facts: Mapping[FunctionId, FactEnvelope[CapabilityPayload]],
) -> list[_Edge]:
    reversed_edges: list[_Edge] = []
    anchors_by_function = {
        function: _candidate_contract_anchors(envelope)
        for function, envelope in facts.items()
    }
    seen: set[tuple[FunctionId, str, FunctionId, str]] = set()
    for edge in edges:
        if len(edge.hops) != 1 or edge.hops[0].kind != "ALIAS":
            continue
        hop = edge.hops[0]
        if hop.evidence["authority"] != "CONTRACT":
            continue
        if not _candidate_resource_is_anchored(
            edge.target.resource,
            anchors_by_function.get(edge.target.function, frozenset()),
        ):
            continue
        signature = (
            edge.target.function,
            edge.target.resource,
            edge.source.function,
            edge.source.resource,
        )
        if signature in seen:
            continue
        seen.add(signature)
        reversed_edges.append(_Edge(
            edge.target,
            edge.source,
            (_Hop(
                "ALIAS",
                hop.to_function,
                hop.from_function,
                hop.target,
                hop.source,
                hop.evidence,
                hop.order,
            ),),
            edge.obligation,
            edge.cut,
        ))
    return sorted(
        reversed_edges,
        key=lambda edge: (
            edge.source.function.rel,
            edge.source.resource,
            edge.target.function.rel,
            edge.target.resource,
        ),
    )


def _candidate_call_return_edges(
    facts: Mapping[FunctionId, FactEnvelope[CapabilityPayload]],
    program: ProgramIndex,
) -> list[_Edge]:
    edges: list[_Edge] = []
    seen: set[tuple[FunctionId, str, FunctionId, str]] = set()
    for caller, sites in program.calls_by_caller.items():
        if caller not in facts:
            continue
        caller_formals = formal_resources(program.functions[caller])
        for site in sites:
            callee = site.callee
            if callee not in facts:
                continue
            envelope = facts[callee]
            for formal, expression in site.arg_bindings.items():
                actual = normalize_actual(expression, caller_formals)
                if actual.endswith(":unknown") or actual == "local:unknown":
                    continue
                evidence: EvidenceFact | None = None
                for effect in sorted(
                    envelope.payload["effects"],
                    key=_candidate_effect_key,
                ):
                    if (
                        effect["identity"] != "SAME"
                        or effect["guard"] != "FEASIBLE"
                        or not _trusted(effect["evidence"])
                    ):
                        continue
                    touches_formal = any(
                        resource is not None
                        and resource_root(resource)[0] == formal
                        for resource in (effect["source"], effect["target"])
                    )
                    if touches_formal:
                        evidence = effect["evidence"]
                        break
                if evidence is None:
                    evidence = next((
                        item["evidence"]
                        for item in envelope.payload["inputs"]
                        if resource_root(item["formal"])[0] == formal
                        and _trusted(item["evidence"])
                    ), None)
                if evidence is None:
                    continue
                key = (callee, formal, caller, actual)
                if key in seen:
                    continue
                seen.add(key)
                hop = _Hop(
                    "CALL_RETURN",
                    callee,
                    caller,
                    formal,
                    actual,
                    evidence,
                )
                edges.append(_Edge(
                    _Node(callee, formal),
                    _Node(caller, actual),
                    (hop,),
                    callsite=_callsite_token(site),
                    call_direction=-1,
                ))
    return edges


def _candidate_rebase_edge(node: _Node, edge: _Edge) -> _Edge | None:
    carried = _resource_suffix(node.resource, edge.source.resource)
    if carried is not None:
        can_carry_suffix = any(
            hop.kind in {"ALIAS", "ARG", "CALL_RETURN", "DISPATCH"}
            for hop in edge.hops
        )
        if carried and not can_carry_suffix:
            return None
        target_resource = f"{edge.target.resource}{carried}"
    elif _resource_suffix(edge.source.resource, node.resource) is not None:
        target_resource = edge.target.resource
    else:
        return None
    if target_resource.count(".") > MAX_CANDIDATE_RESOURCE_DEPTH:
        return None
    hops = list(edge.hops)
    first, last = hops[0], hops[-1]
    hops[0] = _Hop(
        first.kind,
        first.from_function,
        first.to_function,
        node.resource,
        first.target if len(hops) > 1 else target_resource,
        first.evidence,
        first.order,
    )
    if len(hops) > 1:
        hops[-1] = _Hop(
            last.kind,
            last.from_function,
            last.to_function,
            last.source,
            target_resource,
            last.evidence,
            last.order,
        )
    return _Edge(
        node,
        _Node(edge.target.function, target_resource),
        tuple(hops),
        edge.obligation,
        edge.cut,
        edge.callsite,
        edge.call_direction,
    )


def _candidate_outgoing(
    node: _Node,
    adjacency: Mapping[_Node, Sequence[_Edge]],
    edges_by_function: Mapping[FunctionId, Sequence[_Edge]],
) -> tuple[_Edge, ...]:
    found: dict[tuple[str, str, tuple[str, ...]], _Edge] = {}
    for edge in adjacency.get(node, ()):
        key = (
            edge.target.function.rel,
            edge.target.resource,
            tuple(hop.kind for hop in edge.hops),
        )
        found.setdefault(key, edge)
    for edge in edges_by_function.get(node.function, ()):
        if edge.source == node:
            continue
        rebased = _candidate_rebase_edge(node, edge)
        if rebased is None:
            continue
        key = (
            rebased.target.function.rel,
            rebased.target.resource,
            tuple(hop.kind for hop in rebased.hops),
        )
        found.setdefault(key, rebased)
    return tuple(found[key] for key in sorted(found))


def _candidate_writebacks(
    node: _Node,
    writes: Mapping[_Node, Sequence[EffectFact]],
) -> tuple[tuple[_Node, EffectFact], ...]:
    candidates = (
        (write_node, write)
        for write_node, node_writes in writes.items()
        if write_node.function == node.function
        and (
            write_node == node
            or _resource_suffix(write_node.resource, node.resource) is not None
            or _resource_suffix(node.resource, write_node.resource) is not None
        )
        for write in node_writes
    )
    return tuple(sorted(
        candidates,
        key=lambda item: (
            0 if item[0] == node else 1,
            item[0].resource,
            item[1]["order"],
            json.dumps(item[1], sort_keys=True, separators=(",", ":")),
        ),
    ))


def _effect_edges(
    facts: Mapping[FunctionId, FactEnvelope[CapabilityPayload]],
) -> tuple[
    list[_Edge],
    dict[_Node, list[EffectFact]],
    list[tuple[FunctionId, EffectFact]],
]:
    edges: list[_Edge] = []
    writes: dict[_Node, list[EffectFact]] = {}
    registrations: list[tuple[FunctionId, EffectFact]] = []
    for function, envelope in facts.items():
        for effect in envelope.payload["effects"]:
            source, target = effect["source"], effect["target"]
            kind = effect["kind"]
            if kind == "REGISTER":
                if _trusted(effect["evidence"]):
                    registrations.append((function, effect))
                continue
            if kind == "WRITEBACK" and target is not None:
                node = _Node(function, target)
                writes.setdefault(node, []).append(effect)
                continue
            if (
                target is None
                or not _trusted(effect["evidence"])
                or effect["guard"] != "FEASIBLE"
            ):
                continue
            if kind == "GRANT" and source is None:
                source = target
            if source is None:
                continue
            if kind in _TRANSFER and effect["identity"] == "SAME":
                edge_kind, obligation, cut = kind, False, False
            elif kind in {"ROLE_BIND", "REQUIRE_WRITE"}:
                if effect["identity"] != "SAME" or effect["region"] != "OVERLAP":
                    continue
                edge_kind, obligation, cut = "REQUIRE_WRITE", True, False
            elif kind == "DEEP_COPY":
                if effect["identity"] != "FRESH":
                    continue
                edge_kind, obligation, cut = "DEEP_COPY", False, True
            elif kind == "GRANT":
                edge_kind, obligation, cut = "GRANT", False, True
            else:
                continue
            source_node, target_node = _Node(function, source), _Node(function, target)
            hop = _Hop(
                edge_kind,
                function,
                function,
                source,
                target,
                effect["evidence"],
                effect["order"],
            )
            edges.append(_Edge(source_node, target_node, (hop,), obligation, cut))
    return edges, writes, registrations


def _grant_orders(
    facts: Mapping[FunctionId, FactEnvelope[CapabilityPayload]],
) -> dict[_Node, int]:
    grants: dict[_Node, int] = {}
    for function, envelope in facts.items():
        for effect in envelope.payload["effects"]:
            target = effect["target"]
            if (
                effect["kind"] != "GRANT"
                or target is None
                or effect["guard"] != "FEASIBLE"
                or not _trusted(effect["evidence"])
            ):
                continue
            node = _Node(function, target)
            grants[node] = min(grants.get(node, effect["order"]), effect["order"])
    return grants


def _granted_before(grants: Mapping[_Node, int], node: _Node, order: int) -> bool:
    return order > 0 and grants.get(node, order) < order


def _lifecycle_edges(edges: Sequence[_Edge]) -> list[_Edge]:
    publishers: dict[str, list[_Node]] = {}
    subscribers: dict[str, list[_Node]] = {}
    evidence_by_subscriber: dict[_Node, EvidenceFact] = {}
    for edge in edges:
        if edge.target.resource.startswith(_LIFECYCLE_PREFIX):
            publishers.setdefault(edge.target.resource, []).append(edge.target)
        if edge.source.resource.startswith(_LIFECYCLE_PREFIX):
            subscribers.setdefault(edge.source.resource, []).append(edge.source)
            evidence_by_subscriber.setdefault(edge.source, edge.hops[0].evidence)
    bridges: list[_Edge] = []
    for resource in sorted(set(publishers) & set(subscribers)):
        for publisher in publishers[resource]:
            for subscriber in subscribers[resource]:
                if publisher == subscriber:
                    continue
                hop = _Hop(
                    "LIFECYCLE",
                    publisher.function,
                    subscriber.function,
                    resource,
                    resource,
                    evidence_by_subscriber[subscriber],
                )
                bridges.append(_Edge(publisher, subscriber, (hop,)))
    return bridges


def _flow_edges(
    facts: Mapping[FunctionId, FactEnvelope[CapabilityPayload]],
    program: ProgramIndex,
) -> list[_Edge]:
    by_rel = {function.rel: function for function in facts}
    edges: list[_Edge] = []
    seen: set[tuple[FunctionId, str, FunctionId, str, str]] = set()
    for envelope in facts.values():
        for flow in envelope.payload["resource_flows"]:
            source_fn = by_rel.get(flow["from_function"])
            target_fn = by_rel.get(flow["to_function"])
            if (
                source_fn is None
                or target_fn is None
                or flow["identity"] != "SAME"
                or not _trusted(flow["evidence"])
            ):
                continue
            key = (
                source_fn,
                flow["actual"],
                target_fn,
                flow["formal"],
                flow["effect"],
            )
            if key in seen:
                continue
            seen.add(key)
            source = _Node(source_fn, flow["actual"])
            target = _Node(target_fn, flow["formal"])
            hop = _Hop(
                flow["effect"],
                source_fn,
                target_fn,
                flow["actual"],
                flow["formal"],
                flow["evidence"],
            )
            edges.append(_Edge(source, target, (hop,)))
    for caller, sites in program.calls_by_caller.items():
        if caller not in facts:
            continue
        caller_formals = formal_resources(program.functions[caller])
        for site in sites:
            callee = site.callee
            if callee not in facts:
                continue
            for item in facts[callee].payload["inputs"]:
                root, suffix = resource_root(item["formal"])
                if root not in site.arg_bindings or not _trusted(item["evidence"]):
                    continue
                actual = normalize_actual(site.arg_bindings[root], caller_formals) + suffix
                key = (caller, actual, callee, item["formal"], "ARG")
                if key in seen:
                    continue
                seen.add(key)
                hop = _Hop(
                    "ARG",
                    caller,
                    callee,
                    actual,
                    item["formal"],
                    item["evidence"],
                )
                edges.append(
                    _Edge(
                        _Node(caller, actual),
                        _Node(callee, item["formal"]),
                        (hop,),
                        callsite=_callsite_token(site),
                        call_direction=1,
                    )
                )
            caller_args = {
                effect["target"]: effect["evidence"]
                for effect in facts[caller].payload["effects"]
                if (
                    effect["kind"] == "ARG"
                    and effect["target"] is not None
                    and effect["identity"] == "SAME"
                    and effect["guard"] == "FEASIBLE"
                    and _trusted(effect["evidence"])
                )
            }
            demanded: list[tuple[str, EvidenceFact]] = []
            for effect in facts[callee].payload["effects"]:
                if not _trusted(effect["evidence"]):
                    continue
                if effect["kind"] not in _TRANSFER | {"ROLE_BIND", "REQUIRE_WRITE"} | _WRITES:
                    continue
                for resource in (effect["source"], effect["target"]):
                    if resource is not None and resource.startswith("param:"):
                        demanded.append((resource, effect["evidence"]))
            for formal, expression in site.arg_bindings.items():
                actual = normalize_actual(expression, caller_formals)
                candidates: list[tuple[str, EvidenceFact]] = []
                if actual in caller_args:
                    candidates.append((formal, caller_args[actual]))
                candidates.extend(
                    (resource, evidence)
                    for resource, evidence in demanded
                    if resource_root(resource)[0] == formal
                )
                for resource, evidence in candidates:
                    _, suffix = resource_root(resource)
                    bound_actual = actual + suffix
                    key = (caller, bound_actual, callee, resource, "ARG")
                    if key in seen:
                        continue
                    seen.add(key)
                    hop = _Hop("ARG", caller, callee, bound_actual, resource, evidence)
                    edges.append(_Edge(
                        _Node(caller, bound_actual),
                        _Node(callee, resource),
                        (hop,),
                        callsite=_callsite_token(site),
                        call_direction=1,
                    ))
    return edges


def _dispatch_edges(
    facts: Mapping[FunctionId, FactEnvelope[CapabilityPayload]],
    program: ProgramIndex,
    registrations: Sequence[tuple[FunctionId, EffectFact]],
) -> tuple[list[_Edge], list[str]]:
    by_slot: dict[str, list[tuple[FunctionId, FunctionId, EffectFact]]] = {}
    gaps: list[str] = []
    for register_fn, effect in registrations:
        source, slot = effect["source"], effect["target"]
        if source is None or slot is None or not source.startswith("resource:function."):
            gaps.append(f"malformed REGISTER in {register_fn.rel}")
            continue
        name = source.removeprefix("resource:function.")
        resolution = resolve_registered_implementations(
            program,
            register_fn,
            name,
            facts.keys(),
        )
        if not resolution.implementations:
            gaps.append(f"registered implementation {name} resolved to 0 functions")
            continue
        if resolution.truncated:
            gaps.append(
                f"registered implementation {name} truncated from "
                f"{resolution.total} to {len(resolution.implementations)} functions"
            )
        for implementation in resolution.implementations:
            by_slot.setdefault(slot, []).append((register_fn, implementation, effect))
    for slot, routes in tuple(by_slot.items()):
        unique = {
            (register_fn.rel, implementation.rel, _candidate_effect_key(effect)):
                (register_fn, implementation, effect)
            for register_fn, implementation, effect in routes
        }
        ordered = [unique[key] for key in sorted(unique)]
        if len(ordered) > MAX_REGISTERED_ROUTES_PER_SLOT:
            gaps.append(
                f"dispatch slot {slot} registrations truncated from {len(ordered)} "
                f"to {MAX_REGISTERED_ROUTES_PER_SLOT} routes"
            )
        by_slot[slot] = ordered[:MAX_REGISTERED_ROUTES_PER_SLOT]
    edges: list[_Edge] = []
    for dispatch_fn, envelope in facts.items():
        for dispatch in envelope.payload["effects"]:
            if dispatch["kind"] != "DISPATCH" or not _trusted(dispatch["evidence"]):
                continue
            slot, actual = dispatch["source"], dispatch["target"]
            matches = by_slot.get(slot or "", [])
            if not matches or actual is None:
                gaps.append(f"dispatch slot {slot} in {dispatch_fn.rel} has {len(matches)} registrations")
                continue
            for register_fn, implementation, register in matches:
                implementation_unit = program.functions.get(implementation)
                actual_formals = (
                    formal_resources(implementation_unit)
                    if implementation_unit is not None
                    else set()
                )
                inputs = facts[implementation].payload["inputs"]
                valid_inputs = [
                    item
                    for item in inputs
                    if resource_root(item["formal"])[0] in actual_formals
                ]
                exact = next((item for item in valid_inputs if item["formal"] == actual), None)
                selected = exact or next(
                    (item for item in valid_inputs if item["role"] in {"INPUT", "INOUT"}),
                    None,
                )
                target_formal = selected["formal"] if selected is not None else None
                if (
                    target_formal is None
                    and implementation_unit is not None
                    and len(implementation_unit.params) == 1
                ):
                    if len(actual_formals) == 1:
                        target_formal = next(iter(actual_formals))
                if target_formal is None:
                    gaps.append(f"dispatch target {implementation.rel} has no resource input")
                    continue
                register_hop = _Hop(
                    "REGISTER",
                    register_fn,
                    implementation,
                    register["source"] or "",
                    register["target"] or "",
                    register["evidence"],
                )
                dispatch_hop = _Hop(
                    "DISPATCH",
                    dispatch_fn,
                    implementation,
                    actual,
                    target_formal,
                    dispatch["evidence"],
                )
                edges.append(
                    _Edge(
                        _Node(dispatch_fn, actual),
                        _Node(implementation, target_formal),
                        (register_hop, dispatch_hop),
                    )
                )
    return edges, sorted(set(gaps))


def _dedupe_path(
    path: Sequence[dict[str, JsonValue]],
) -> list[dict[str, JsonValue]]:
    found: dict[str, dict[str, JsonValue]] = {}
    for step in path:
        key = repr(sorted(step.items()))
        found.setdefault(key, step)
    return list(found.values())


def compose_project_chain(
    facts: Mapping[FunctionId, FactEnvelope[CapabilityPayload]],
    program: ProgramIndex,
) -> ProjectChain:
    incomplete = sorted(
        function.rel
        for function, envelope in facts.items()
        if (
            envelope.status != "ok"
            or envelope.payload["coverage"] != "complete"
            or envelope.payload["unknowns"]
        )
    )
    errored = sorted(
        function.rel
        for function, envelope in facts.items()
        if envelope.status not in {"ok", "partial"}
    )
    if errored:
        gap = f"incomplete v3 facts: {', '.join(incomplete)}"
        return {
            "verdict": "NEEDS_REVIEW",
            "path": [],
            "candidate_path": [],
            "candidate_paths": [],
            "candidate_path_count": 0,
            "candidate_paths_truncated": False,
            "candidate_findings": [],
            "strict_paths": [],
            "strict_path_count": 0,
            "strict_paths_truncated": False,
            "propagation_chain": [],
            "missing_premise": gap,
            "gaps": [gap],
            "reason": None,
            "confidence": None,
        }
    edges, writes, registrations = _effect_edges(facts)
    grants = _grant_orders(facts)
    edges.extend(_lifecycle_edges(edges))
    edges.extend(_flow_edges(facts, program))
    dispatch_edges, gaps = _dispatch_edges(facts, program, registrations)
    edges.extend(dispatch_edges)
    adjacency: dict[_Node, list[_Edge]] = {}
    for edge in edges:
        adjacency.setdefault(edge.source, []).append(edge)
    for outgoing in adjacency.values():
        outgoing.sort(
            key=lambda edge: (
                edge.hops[0].kind,
                edge.target.function.rel,
                edge.target.resource,
            )
        )
    partial: list[dict[str, JsonValue]] = []
    safe_cut = False
    strict_by_signature: dict[str, list[dict[str, JsonValue]]] = {}
    strict_truncated = any(" truncated from " in gap for gap in gaps)
    entrypoints = frozenset(program.entrypoints)
    for function, envelope in sorted(facts.items(), key=lambda item: item[0].rel):
        entry_formals = formal_resources(program.functions[function])
        for item in envelope.payload["inputs"]:
            if not _seed(item, entry_formals, function in entrypoints):
                continue
            seed_node = _Node(function, item["formal"])
            start = [_seed_step(function, item)]
            pending = deque(((seed_node, False, start, frozenset(((seed_node, False),))),))
            while pending:
                node, obligated, path, visited = pending.popleft()
                if len(path) > len(partial):
                    partial = path
                matched_writeback = False
                for write_node, write in (
                    _candidate_writebacks(node, writes) if obligated else ()
                ):
                    if (
                        write["identity"] != "SAME"
                        or write["region"] != "OVERLAP"
                        or write["guard"] != "FEASIBLE"
                        or not _trusted(write["evidence"])
                    ):
                        continue
                    if _granted_before(grants, write_node, write["order"]):
                        safe_cut = True
                        continue
                    matched_writeback = True
                    sink = _Hop(
                        "WRITEBACK",
                        node.function,
                        node.function,
                        node.resource,
                        write_node.resource,
                        write["evidence"],
                    )
                    result = _dedupe_path((*path, _step(sink, item, item["resource_id"])))
                    signature = json.dumps(
                        result,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    if signature not in strict_by_signature:
                        if len(strict_by_signature) >= MAX_STRICT_FINDINGS:
                            strict_truncated = True
                            continue
                        strict_by_signature[signature] = result
                if matched_writeback:
                    continue
                for edge in adjacency.get(node, ()):
                    if _granted_before(grants, node, edge.hops[0].order):
                        safe_cut = True
                        continue
                    next_path = [
                        *path,
                        *(_step(hop, item, item["resource_id"]) for hop in edge.hops),
                    ]
                    if edge.cut:
                        safe_cut = True
                        if len(next_path) > len(partial):
                            partial = next_path
                        continue
                    next_obligated = obligated or edge.obligation
                    if (edge.target, next_obligated) in visited:
                        continue
                    pending.append(
                        (
                            edge.target,
                            next_obligated,
                            next_path,
                            visited | frozenset(((edge.target, next_obligated),)),
                        )
                    )
    strict_paths = [
        strict_by_signature[key]
        for key in sorted(strict_by_signature)
    ]
    if strict_paths:
        result = strict_paths[0]
        return {
            "verdict": "VULNERABLE",
            "path": result,
            "candidate_path": [],
            "candidate_paths": [],
            "candidate_path_count": 0,
            "candidate_paths_truncated": False,
            "candidate_findings": [],
            "strict_paths": strict_paths,
            "strict_path_count": len(strict_paths),
            "strict_paths_truncated": strict_truncated,
            "propagation_chain": result,
            "missing_premise": None,
            "gaps": gaps,
            "reason": "strict_identity_path",
            "confidence": "strict",
        }
    uncertain_seed = any(
        item["reference_origin"] == "USER_CONTROLLED"
        and (
            "UNKNOWN" in item["write_authority"]
            or "UNKNOWN" in item["possible_backing"]
        )
        for envelope in facts.values()
        for item in envelope.payload["inputs"]
    )
    unproved_backing = any(
        item["reference_origin"] == "USER_CONTROLLED"
        and "DENIED" in item["write_authority"]
        and not _strictly_denied(item)
        for envelope in facts.values()
        for item in envelope.payload["inputs"]
    )
    relevant_inputs = [
        item
        for envelope in facts.values()
        for item in envelope.payload["inputs"]
        if item["reference_origin"] == "USER_CONTROLLED"
    ]
    all_granted = bool(relevant_inputs) and all(
        set(item["write_authority"]) == {"GRANTED"}
        and "UNKNOWN" not in item["possible_backing"]
        and _trusted(item["evidence"])
        for item in relevant_inputs
    )
    if incomplete:
        missing = f"incomplete v3 facts: {', '.join(incomplete)}"
    elif gaps:
        missing = gaps[0]
    elif uncertain_seed:
        missing = "trusted proof that non-writable backing is feasible"
    elif unproved_backing:
        missing = "trusted non-writable or protected backing alternative"
    elif partial and not safe_cut:
        missing = "continuous trusted path to REQUIRE_WRITE and WRITEBACK"
    else:
        missing = None
    verdict = (
        "SAFE"
        if not incomplete and (safe_cut or all_granted) and missing is None
        else "NEEDS_REVIEW"
    )
    strict_path = _dedupe_path(partial)
    candidate_search = _compose_candidate_chains(facts, program)
    candidate_findings = list(candidate_search.findings)
    candidate_paths = [
        finding["path"]
        for finding in candidate_findings
    ]
    candidate_path = (
        candidate_paths[0]
        if candidate_paths
        else candidate_search.partial_path
    )
    candidate_gap = candidate_search.missing_premise
    if candidate_findings:
        return {
            "verdict": "VULNERABLE",
            "path": candidate_path,
            "candidate_path": candidate_path,
            "candidate_paths": candidate_paths,
            "candidate_path_count": len(candidate_paths),
            "candidate_paths_truncated": candidate_search.truncated,
            "candidate_findings": candidate_findings,
            "strict_paths": [],
            "strict_path_count": 0,
            "strict_paths_truncated": False,
            "propagation_chain": candidate_path,
            "missing_premise": None,
            "gaps": [],
            "reason": "candidate_source_backed",
            "confidence": "candidate_source_backed",
        }
    candidate_is_stronger = len(candidate_path) > len(strict_path)
    selected_missing = candidate_gap if candidate_is_stronger else missing
    selected_gaps = sorted(set((
        *gaps,
        *((candidate_gap,) if candidate_is_stronger else ()),
    )))
    return {
        "verdict": verdict,
        "path": strict_path,
        "candidate_path": candidate_path,
        "candidate_paths": candidate_paths,
        "candidate_path_count": len(candidate_paths),
        "candidate_paths_truncated": candidate_search.truncated,
        "candidate_findings": candidate_findings,
        "strict_paths": [],
        "strict_path_count": 0,
        "strict_paths_truncated": False,
        "propagation_chain": candidate_path or strict_path,
        "missing_premise": selected_missing,
        "gaps": selected_gaps,
        "reason": None,
        "confidence": None,
    }
