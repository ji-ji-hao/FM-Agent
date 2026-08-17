from __future__ import annotations

# noqa: SIZE_OK - local resource-path proof and verdict construction stay co-located.

from collections.abc import Sequence
from dataclasses import dataclass

from src.capability_prompts import (
    CapabilityPayload,
    EffectFact,
    EvidenceFact,
    InputFact,
    JsonValue,
)
from src.plugins.base import Diagnostic, FactEnvelope, Finding, Verdict


_TRANSFER_KINDS = {"ALIAS", "FIELD", "RETURN"}
_WRITE_KINDS = {"WRITE", "WRITEBACK"}
_TRUSTED_AUTHORITIES = {"SOURCE", "CONTRACT", "EXPLICIT"}
_BACKING_AT_RISK = {"READONLY_MAPPING", "PROTECTED_SHARED"}


@dataclass(frozen=True, slots=True)
class _ResourcePath:
    seed: InputFact
    steps: tuple[dict[str, JsonValue], ...]


def _trusted(evidence: EvidenceFact) -> bool:
    return (
        evidence["authority"] in _TRUSTED_AUTHORITIES
        and bool(evidence["lines"])
    )


def _strictly_denied(item: InputFact) -> bool:
    authorities = set(item["write_authority"])
    backing = set(item["possible_backing"])
    if item["evidence"]["authority"] in {"CONTRACT", "EXPLICIT"}:
        return "DENIED" in authorities
    return authorities == {"DENIED"} and bool(backing) and backing <= _BACKING_AT_RISK


def _ordered_effects(payload: CapabilityPayload) -> tuple[EffectFact, ...]:
    return tuple(sorted(payload["effects"], key=lambda item: item["order"]))


def _is_seed(item: InputFact) -> bool:
    return (
        item["reference_origin"] == "USER_CONTROLLED"
        and "UNKNOWN" not in item["possible_backing"]
        and _strictly_denied(item)
        and bool(_BACKING_AT_RISK & set(item["possible_backing"]))
        and item["role"] == "INPUT"
        and item["identity"] == "SAME"
    )


def _uncertain_input(item: InputFact) -> bool:
    return (
        item["reference_origin"] == "UNKNOWN"
        or "UNKNOWN" in item["possible_backing"]
        or "UNKNOWN" in item["write_authority"]
        or item["role"] == "UNKNOWN"
        or item["identity"] in {"MAY_SAME", "UNKNOWN"}
        or (
            item["reference_origin"] == "USER_CONTROLLED"
            and "DENIED" in item["write_authority"]
            and not _strictly_denied(item)
        )
        or (
            "DENIED" in item["write_authority"]
            and not (_BACKING_AT_RISK & set(item["possible_backing"]))
        )
    )


def _step(kind: str, resource: str, effect: EffectFact | None) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {"kind": kind, "resource_id": resource}
    if effect is not None:
        result["order"] = effect["order"]
        result["source"] = effect["source"]
        result["target"] = effect["target"]
        result["identity"] = effect["identity"]
        result["authority"] = effect["evidence"]["authority"]
    return result


def _review(
    reason: str,
    payload: CapabilityPayload | None = None,
    path: Sequence[dict[str, JsonValue]] = (),
) -> Verdict:
    data: dict[str, JsonValue] = {
        "missing_premise": reason,
        "path": list(path),
    }
    if payload is not None:
        data["resource_flows"] = payload["resource_flows"]
        data["propagation_chain"] = payload["propagation_chain"]
        data["obligations"] = payload["obligations"]
    return Verdict(
        "capability",
        "NEEDS_REVIEW",
        diagnostics=[Diagnostic("warning", reason)],
        data=data,
    )


def _complete(facts: FactEnvelope[CapabilityPayload]) -> bool:
    payload = facts.payload
    return (
        facts.status == "ok"
        and payload["coverage"] == "complete"
        and not payload["unknowns"]
    )


def _all_trusted(payload: CapabilityPayload) -> bool:
    return all(_trusted(item["evidence"]) for item in payload["inputs"]) and all(
        _trusted(item["evidence"]) for item in payload["effects"]
    )


def _resource_paths(
    payload: CapabilityPayload,
) -> tuple[
    dict[str, _ResourcePath],
    dict[str, _ResourcePath],
    list[_ResourcePath],
    str | None,
]:
    reached = {
        item["formal"]: _ResourcePath(
            item,
            (
                {
                    "kind": "SEED",
                    "resource_id": item["resource_id"],
                    "reference_origin": item["reference_origin"],
                    "possible_backing": item["possible_backing"],
                    "write_authority": item["write_authority"],
                    "role": item["role"],
                    "authority": item["evidence"]["authority"],
                },
            ),
        )
        for item in payload["inputs"]
        if _is_seed(item) and _trusted(item["evidence"])
    }
    obligations: dict[str, _ResourcePath] = {}
    safe_cuts: list[_ResourcePath] = []
    safe_keys: set[tuple[str, int]] = set()
    cut_targets: set[str] = set()
    missing: str | None = None
    effects = _ordered_effects(payload)
    changed = True
    while changed:
        changed = False
        for effect in effects:
            source = effect["source"]
            target = effect["target"]
            source_path = reached.get(source) if source is not None else None
            if effect["kind"] in _TRANSFER_KINDS and source_path is not None:
                if (
                    effect["identity"] == "SAME"
                    and effect["guard"] == "FEASIBLE"
                    and _trusted(effect["evidence"])
                    and target is not None
                    and target not in reached
                    and target not in cut_targets
                ):
                    reached[target] = _ResourcePath(
                        source_path.seed,
                        source_path.steps + (_step(effect["kind"], target, effect),),
                    )
                    changed = True
                elif effect["identity"] in {"MAY_SAME", "UNKNOWN"}:
                    missing = "trusted SAME resource identity"
            if effect["kind"] in {"ROLE_BIND", "REQUIRE_WRITE"}:
                target_path = reached.get(target) if target is not None else None
                derived_same = (
                    effect["identity"] == "SAME"
                    or (
                        target_path is not None
                        and source_path is not None
                        and target_path.seed["resource_id"]
                        == source_path.seed["resource_id"]
                    )
                )
                if (
                    source_path is not None
                    and target is not None
                    and derived_same
                    and effect["region"] == "OVERLAP"
                    and effect["guard"] == "FEASIBLE"
                    and _trusted(effect["evidence"])
                ):
                    obligation = _ResourcePath(
                        source_path.seed,
                        source_path.steps + (_step("REQUIRE_WRITE", target, effect),),
                    )
                    if target not in reached and target not in cut_targets:
                        reached[target] = obligation
                        changed = True
                    obligations.setdefault(target, obligation)
                elif source_path is not None:
                    missing = "trusted feasible same-identity REQUIRE_WRITE obligation"
            if effect["kind"] == "DEEP_COPY" and source_path is not None:
                if (
                    target is not None
                    and effect["identity"] == "FRESH"
                    and effect["region"] == "DISJOINT"
                    and effect["guard"] == "FEASIBLE"
                    and _trusted(effect["evidence"])
                    and (target, effect["order"]) not in safe_keys
                ):
                    safe_keys.add((target, effect["order"]))
                    safe_cuts.append(
                        _ResourcePath(
                            source_path.seed,
                            source_path.steps + (_step("DEEP_COPY", target, effect),),
                        )
                    )
                else:
                    missing = "trusted FRESH deep-copy boundary"
            if effect["kind"] == "GRANT" and target in reached:
                if (
                    effect["guard"] == "FEASIBLE"
                    and _trusted(effect["evidence"])
                ):
                    path = reached[target]
                    safe_cuts.append(
                        _ResourcePath(
                            path.seed,
                            path.steps + (_step("GRANT", target, effect),),
                        )
                    )
                    cut_targets.add(target)
                    reached.pop(target)
                    obligations.pop(target, None)
                else:
                    missing = "trusted write-authority grant"
    return reached, obligations, safe_cuts, missing


def reason_capability(
    facts: FactEnvelope[CapabilityPayload],
    propagated_contexts: Sequence[None] = (),
) -> Verdict:
    del propagated_contexts
    if facts.status == "error":
        return Verdict(
            "capability",
            "ERROR",
            status="error",
            diagnostics=list(facts.diagnostics),
            data={"error": "capability abstraction failed"},
        )
    payload = facts.payload
    if payload.get("schema_version") != "capability.v3":
        return _review("invalid capability.v3 facts")
    if not _complete(facts):
        return _review("complete resource-flow coverage", payload)
    if not payload["inputs"] and not payload["effects"]:
        return _review("trusted body or contract proof", payload)

    reached, obligations, safe_cuts, missing = _resource_paths(payload)
    for effect in _ordered_effects(payload):
        if effect["kind"] not in _WRITE_KINDS or effect["target"] is None:
            continue
        target = effect["target"]
        path = reached.get(target)
        obligation = obligations.get(target)
        if path is None:
            continue
        if obligation is None:
            missing = "trusted REQUIRE_WRITE obligation on the written identity"
            continue
        if (
            effect["identity"] == "SAME"
            and effect["region"] == "OVERLAP"
            and effect["guard"] == "FEASIBLE"
            and _trusted(effect["evidence"])
        ):
            steps = obligation.steps + (_step(effect["kind"], target, effect),)
            finding = Finding(
                "capability.resource-write",
                "Unauthorized same-resource write",
                "A user-controlled input resource is rebound for output and written "
                "without a trusted write grant or fresh-copy boundary.",
                "high",
                function=facts.function,
                data={"target": target, "effect_order": effect["order"]},
            )
            return Verdict(
                "capability",
                "VULNERABLE",
                findings=[finding],
                data={
                    "path": list(steps),
                    "resource_flows": payload["resource_flows"],
                    "propagation_chain": payload["propagation_chain"],
                    "obligations": payload["obligations"],
                },
            )
        missing = "trusted feasible overlapping WRITE on the obligated identity"

    if not _all_trusted(payload):
        return _review("trusted source, contract, or explicit evidence", payload)
    if any(_uncertain_input(item) for item in payload["inputs"]):
        return _review(
            "trusted feasible backing and write-authority alternatives",
            payload,
        )
    if safe_cuts:
        best = min(
            safe_cuts,
            key=lambda item: (
                len(item.steps),
                tuple(str(step["resource_id"]) for step in item.steps),
            ),
        )
        return Verdict(
            "capability",
            "SAFE",
            data={
                "path": list(best.steps),
                "resource_flows": payload["resource_flows"],
                "propagation_chain": payload["propagation_chain"],
                "obligations": payload["obligations"],
            },
        )
    if missing is not None:
        candidate = min(
            reached.values(),
            key=lambda item: len(item.steps),
            default=None,
        )
        return _review(
            missing,
            payload,
            () if candidate is None else candidate.steps,
        )
    if reached and any(effect["kind"] in _WRITE_KINDS for effect in payload["effects"]):
        candidate = min(reached.values(), key=lambda item: len(item.steps))
        return _review(
            "trusted same-resource path to a write obligation",
            payload,
            candidate.steps,
        )
    return Verdict(
        "capability",
        "SAFE",
        data={
            "path": [],
            "resource_flows": payload["resource_flows"],
            "propagation_chain": payload["propagation_chain"],
            "obligations": payload["obligations"],
        },
    )
