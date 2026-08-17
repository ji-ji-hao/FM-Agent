"""Generic plugin driver: orchestrates one AnalysisPlugin over a project.

Pipeline (theory-agnostic):
  1. scan + extract + build call graph (callgraph.load_function_units / build_program_index)
  2. order functions bottom-up (callees before callers)
  3. for each function in order:
       a. build callee context from already-derived callees referenced in the body
       b. call the LLM with the plugin's prompt, retrying on parse failure
          (fail-closed: exhausted retries -> plugin.make_error_facts)
       c. plugin.compose_calls(caller_facts, resolved_callee_facts)
  4. [optional] if plugin.metadata.requires_top_down_context:
       run a worklist from entrypoints (initial/propagate/merge_contexts)
  5. plugin.check(facts, context, propagated) -> Verdict
  6. write per-function result JSON + summary.json

The driver never inspects plugin payload schemas; it only reads envelope-level
fields (status, function id) and Verdict.verdict.

Raw abstraction is parallel within dependency-safe SCC layers. Composition
remains deterministic and single-threaded after each layer completes.
"""

from __future__ import annotations

import os
import re
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from config import (
    MAX_IFC_ITER,
    MAX_WORKERS,
    IFC_FLOW_SIGNATURE_MODEL as _DEFAULT_MODEL,
)
from src.llm_client import _openrouter_client, _retry_create
from src.trace_writer import new_event_id, record_llm_exchange, utc_now_iso
from src.plugins.base import (
    AbstractionRequest,
    AnalysisPlugin,
    CallSite,
    Diagnostic,
    DriverContext,
    Evidence,
    FactEnvelope,
    FunctionId,
    FunctionUnit,
    ProgramIndex,
    RelevanceSlice,
    ResolvedCall,
    SourceSpan,
    Verdict,
)
from src.plugins import callgraph


# --- facts checkpointing (crash/rate-limit resume) ---------------------------
# Stage 3 (per-function LLM abstraction) is the long, failure-prone phase: an
# unstable relay or rate limit can kill the process after hundreds of calls,
# losing ALL in-memory facts because results are only written in Stage 4. We
# persist each function's pre-compose FactEnvelope to <work_dir>/facts_cache/
# as it is produced, and reload it on restart, so a resumed run only re-derives
# the functions still missing. The cache is plugin-agnostic: the core serializes
# only envelope-level fields; `payload` is the plugin's own JSON (guaranteed
# JSON-serializable by the SPI contract).

_FACTS_CACHE_SUBDIR = "facts_cache"
_DEFAULT_STAGE3_WORKERS = 4


@dataclass(frozen=True, slots=True)
class _RelevanceSliceContractError(ValueError):
    plugin_name: str
    detail: str

    def __str__(self) -> str:
        return f"{self.plugin_name}: {self.detail}"


def _facts_cache_path(cache_dir: str, unit: FunctionUnit) -> str:
    return os.path.join(cache_dir, os.path.splitext(unit.id.rel)[0] + ".json")


def _span_to_json(span: Optional[SourceSpan]):
    if span is None:
        return None
    return {"path": span.path, "start_line": span.start_line, "end_line": span.end_line}


def _span_from_json(d):
    if not d:
        return None
    return SourceSpan(path=d.get("path", ""), start_line=d.get("start_line", 0),
                      end_line=d.get("end_line", 0))


def _serialize_facts(
    facts: FactEnvelope, analysis_fingerprint: Optional[str] = None
) -> Dict[str, Any]:
    fid = facts.function
    serialized = {
        "plugin_name": facts.plugin_name,
        "schema_version": facts.schema_version,
        "function": {"rel": fid.rel, "name": fid.name,
                     "base_name": fid.base_name, "language": fid.language},
        "status": facts.status,
        "payload": facts.payload,
        "confidence": facts.confidence,
        "evidence": [{"kind": e.kind, "message": e.message,
                      "span": _span_to_json(e.span), "data": e.data}
                     for e in facts.evidence],
        "diagnostics": [{"level": d.level, "message": d.message, "data": d.data}
                        for d in facts.diagnostics],
        "trace_ids": list(facts.trace_ids),
    }
    if analysis_fingerprint is not None:
        serialized["analysis_fingerprint"] = analysis_fingerprint
    return serialized


def _deserialize_facts(d: Dict[str, Any]) -> FactEnvelope:
    f = d.get("function") or {}
    fid = FunctionId(rel=f.get("rel", ""), name=f.get("name", ""),
                     base_name=f.get("base_name", ""), language=f.get("language", ""))
    return FactEnvelope(
        plugin_name=d.get("plugin_name", ""),
        schema_version=d.get("schema_version", ""),
        function=fid,
        status=d.get("status", "error"),
        payload=d.get("payload"),
        confidence=d.get("confidence", 1.0),
        evidence=[Evidence(kind=e.get("kind", ""), message=e.get("message", ""),
                           span=_span_from_json(e.get("span")), data=e.get("data") or {})
                  for e in (d.get("evidence") or [])],
        diagnostics=[Diagnostic(level=x.get("level", "info"), message=x.get("message", ""),
                                data=x.get("data") or {})
                     for x in (d.get("diagnostics") or [])],
        trace_ids=list(d.get("trace_ids") or []),
    )


def _write_facts_checkpoint(
    cache_dir: str,
    unit: FunctionUnit,
    facts: FactEnvelope,
    analysis_fingerprint: Optional[str] = None,
) -> None:
    """Atomically persist one function's facts so a resumed run can skip it."""
    path = _facts_cache_path(cache_dir, unit)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fp:
        json.dump(
            _serialize_facts(facts, analysis_fingerprint), fp, ensure_ascii=False
        )
    os.replace(tmp, path)


def _load_facts_checkpoint(
    cache_dir: str,
    unit: FunctionUnit,
    expected_fingerprint: Optional[str] = None,
) -> Optional[FactEnvelope]:
    """Load a previously-checkpointed FactEnvelope for `unit`, or None if absent
    or unreadable (a corrupt/partial file is ignored so the unit is re-derived)."""
    path = _facts_cache_path(cache_dir, unit)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as fp:
            serialized = json.load(fp)
        if not isinstance(serialized, dict):
            return None
        if expected_fingerprint is not None:
            cached_fingerprint = serialized.get("analysis_fingerprint")
            if (
                not isinstance(cached_fingerprint, str)
                or re.fullmatch(r"[0-9a-f]{64}", cached_fingerprint) is None
                or cached_fingerprint != expected_fingerprint
            ):
                return None
        return _deserialize_facts(serialized)
    except (OSError, json.JSONDecodeError, ValueError, KeyError, TypeError):
        return None


def _validated_relevance_slice(
    plugin: AnalysisPlugin,
    selected: RelevanceSlice | None,
    program: ProgramIndex,
) -> RelevanceSlice | None:
    name = plugin.metadata.name
    if selected is None:
        return None
    if not isinstance(selected, RelevanceSlice):
        raise _RelevanceSliceContractError(
            name, "relevance slice must be RelevanceSlice"
        )
    if not isinstance(selected.function_ids, tuple):
        raise _RelevanceSliceContractError(
            name, "relevance slice function_ids must be a tuple"
        )
    if not all(isinstance(fid, FunctionId) for fid in selected.function_ids):
        raise _RelevanceSliceContractError(
            name, "relevance slice IDs must be FunctionId values"
        )
    if len(set(selected.function_ids)) != len(selected.function_ids):
        raise _RelevanceSliceContractError(
            name, "relevance slice contains duplicate function IDs"
        )
    unknown = [fid for fid in selected.function_ids if fid not in program.functions]
    if unknown:
        raise _RelevanceSliceContractError(
            name, "relevance slice contains unknown function IDs"
        )
    if (
        not isinstance(selected.fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{64}", selected.fingerprint) is None
    ):
        raise _RelevanceSliceContractError(
            name, "relevance slice fingerprint must be lowercase SHA-256"
        )
    return selected


def _resolved_artifact_path(work_dir: str, target: str) -> str:
    work_root = os.path.realpath(work_dir)
    resolved = os.path.realpath(os.path.abspath(target))
    try:
        contained = os.path.commonpath((work_root, resolved)) == work_root
    except ValueError:
        contained = False
    if not contained:
        raise ValueError(f"plugin artifact escapes work directory: {target}")
    return os.path.abspath(target)


def _prune_skipped_function_artifacts(
    plugin: AnalysisPlugin,
    program: ProgramIndex,
    selected_ids: set[FunctionId],
    work_dir: str,
    cache_dir: str,
    results_dir: str,
    trace_dir: str,
) -> None:
    selected_units = [program.functions[fid] for fid in selected_ids]
    skipped_units = [
        unit for fid, unit in program.functions.items() if fid not in selected_ids
    ]
    selected_paths = {
        _resolved_artifact_path(cache_dir, _facts_cache_path(cache_dir, unit))
        for unit in selected_units
    }
    selected_paths.update(
        _resolved_artifact_path(
            results_dir,
            os.path.join(
                results_dir, os.path.splitext(unit.id.rel)[0] + ".json"
            ),
        )
        for unit in selected_units
    )
    removable = {
        _resolved_artifact_path(cache_dir, _facts_cache_path(cache_dir, unit))
        for unit in skipped_units
    }
    removable.update(
        _resolved_artifact_path(
            results_dir,
            os.path.join(
                results_dir, os.path.splitext(unit.id.rel)[0] + ".json"
            ),
        )
        for unit in skipped_units
    )
    removable.difference_update(selected_paths)

    events_path = os.path.join(trace_dir, "events.jsonl")
    retained_lines: List[str] = []
    pruned_trace = False
    if os.path.isfile(events_path):
        selected_rels = {unit.id.rel for unit in selected_units}
        skipped_rels = {unit.id.rel for unit in skipped_units} - selected_rels
        payload_dir = os.path.realpath(os.path.join(trace_dir, "payloads"))
        with open(events_path, encoding="utf-8") as events_file:
            for line in events_file:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    retained_lines.append(line)
                    continue
                metadata = event.get("metadata") if isinstance(event, dict) else None
                children = event.get("children") if isinstance(event, dict) else None
                event_id = event.get("event_id") if isinstance(event, dict) else None
                recognized = (
                    isinstance(metadata, dict)
                    and isinstance(metadata.get("function_id"), str)
                    and metadata.get("function_id") in skipped_rels
                    and event.get("stage")
                    == f"{plugin.metadata.name}_abstraction"
                    and isinstance(event_id, str)
                    and event_id.startswith(f"{plugin.metadata.name}_")
                    and isinstance(children, list)
                    and all(
                        isinstance(child, dict)
                        and isinstance(child.get("content_ref"), str)
                        for child in children
                    )
                )
                if not recognized:
                    retained_lines.append(line)
                    continue
                trace_payloads = [
                    _resolved_artifact_path(
                        work_dir, os.path.join(work_dir, child["content_ref"])
                    )
                    for child in children
                ]
                if not all(
                    os.path.dirname(os.path.realpath(path)) == payload_dir
                    and os.path.basename(path).startswith(f"{event_id}_")
                    for path in trace_payloads
                ):
                    retained_lines.append(line)
                    continue
                removable.update(trace_payloads)
                pruned_trace = True

    resolved_events_path = _resolved_artifact_path(work_dir, events_path)
    tmp_path = _resolved_artifact_path(work_dir, events_path + ".tmp")
    for path in removable:
        if os.path.isfile(path) or os.path.islink(path):
            os.unlink(path)
    if pruned_trace:
        with open(tmp_path, "w", encoding="utf-8") as events_file:
            events_file.writelines(retained_lines)
        os.replace(tmp_path, resolved_events_path)


def _model_for(plugin: AnalysisPlugin) -> str:
    """Resolve the LLM model id a plugin's prompts should use.

    Plugins may expose `model` on their metadata-like object; fall back to the
    plugin attribute `model`, else the IFC default model.
    """
    return getattr(plugin, "model", None) or _DEFAULT_MODEL


def _stage3_worker_count() -> int:
    default = max(1, min(_DEFAULT_STAGE3_WORKERS, MAX_WORKERS))
    raw = os.environ.get("FM_AGENT_STAGE3_WORKERS")
    if raw is None:
        return default
    try:
        requested = int(raw)
    except ValueError:
        return default
    return max(1, min(requested, max(1, MAX_WORKERS)))


def _bottom_up_layers(
    program: ProgramIndex,
    ordered: Sequence[FunctionUnit],
) -> tuple[tuple[FunctionUnit, ...], ...]:
    """Condense recursive functions and return deterministic callee-first layers."""
    by_id = {unit.id: unit for unit in ordered}
    rank = {unit.id: position for position, unit in enumerate(ordered)}
    dependencies = {
        unit.id: tuple(
            sorted(
                {
                    site.callee
                    for site in program.calls_by_caller.get(unit.id, ())
                    if site.callee in by_id
                },
                key=rank.__getitem__,
            )
        )
        for unit in ordered
    }
    next_index = 0
    indices: Dict[FunctionId, int] = {}
    lowlinks: Dict[FunctionId, int] = {}
    stack: List[FunctionId] = []
    active: set[FunctionId] = set()
    components: List[tuple[FunctionId, ...]] = []

    def connect(function_id: FunctionId) -> None:
        nonlocal next_index
        indices[function_id] = next_index
        lowlinks[function_id] = next_index
        next_index += 1
        stack.append(function_id)
        active.add(function_id)

        for callee in dependencies[function_id]:
            if callee not in indices:
                connect(callee)
                lowlinks[function_id] = min(
                    lowlinks[function_id], lowlinks[callee]
                )
            elif callee in active:
                lowlinks[function_id] = min(
                    lowlinks[function_id], indices[callee]
                )

        if lowlinks[function_id] != indices[function_id]:
            return
        members: List[FunctionId] = []
        while stack:
            member = stack.pop()
            active.remove(member)
            members.append(member)
            if member == function_id:
                break
        components.append(tuple(sorted(members, key=rank.__getitem__)))

    for unit in ordered:
        if unit.id not in indices:
            connect(unit.id)

    component_by_function = {
        function_id: component_index
        for component_index, component in enumerate(components)
        for function_id in component
    }
    component_dependencies = [set() for _ in components]
    for caller, callees in dependencies.items():
        caller_component = component_by_function[caller]
        component_dependencies[caller_component].update(
            component_by_function[callee]
            for callee in callees
            if component_by_function[callee] != caller_component
        )

    completed: set[int] = set()
    layers: List[tuple[FunctionUnit, ...]] = []
    while len(completed) < len(components):
        ready = sorted(
            (
                component_index
                for component_index, required in enumerate(component_dependencies)
                if component_index not in completed and required <= completed
            ),
            key=lambda component_index: min(
                rank[function_id] for function_id in components[component_index]
            ),
        )
        layer_ids = sorted(
            (
                function_id
                for component_index in ready
                for function_id in components[component_index]
            ),
            key=rank.__getitem__,
        )
        layers.append(tuple(by_id[function_id] for function_id in layer_ids))
        completed.update(ready)
    return tuple(layers)


def _format_correction_message(messages: Sequence[Mapping[str, str]]) -> str:
    system_contract = "\n".join(
        message["content"]
        for message in messages
        if message.get("role") == "system" and message.get("content")
    )
    return (
        "Your output was not in the required format. Re-emit ONLY the requested "
        "structured block, using both exact opening and closing tags and the exact "
        "schema below. Do not simplify, normalize, or rename any field.\n"
        + system_contract
    )


def _call_llm_with_retries(
    plugin: AnalysisPlugin,
    request: AbstractionRequest,
    model: str,
    max_iter: int,
) -> FactEnvelope:
    """Run build_prompt -> LLM -> parse, retrying on parse failure.

    Format exhaustion is plugin-owned; raised LLM-call exceptions return error facts.
    """
    messages = plugin.build_abstraction_prompt(request)
    trace_dir = request.trace_dir
    trace_meta = dict(request.trace_meta or {})
    format_trace_ids: List[str] = []

    for attempt in range(1, max_iter + 1):
        event_id = new_event_id(plugin.metadata.name)
        started = utc_now_iso()
        try:
            response, usage = _retry_create(
                _openrouter_client,
                model,
                messages,
                disable_thinking=bool(
                    getattr(plugin, "disable_llm_thinking", False)
                ),
            )
        except Exception as exc:  # noqa: BLE001 — fault isolation per function
            event = {
                "event_id": event_id, "type": "llm_call",
                "stage": f"{plugin.metadata.name}_abstraction", "status": "error",
                "start_time": started, "end_time": utc_now_iso(),
                "summary": f"{plugin.metadata.name} abstraction call failed: {exc}",
                "metadata": {**trace_meta, "model": model, "attempt": attempt,
                             "error": str(exc)},
            }
            record_llm_exchange(trace_dir, event_id, event, messages)
            logging.warning("%s abstraction failed for %s: %s",
                            plugin.metadata.name, request.function.id.rel, exc)
            return plugin.make_error_facts(request, str(exc))

        facts = plugin.parse_abstraction_response(request, response)
        status = "success" if facts is not None else "format_error"
        event_metadata = {
            **trace_meta,
            "model": model,
            "attempt": attempt,
            "usage": usage,
        }
        if facts is None and attempt == max_iter:
            event_metadata["format_outcome"] = "model-format-exhausted"
        event = {
            "event_id": event_id, "type": "llm_call",
            "stage": f"{plugin.metadata.name}_abstraction", "status": status,
            "start_time": started, "end_time": utc_now_iso(),
            "summary": f"Derived {plugin.metadata.name} abstraction",
            "metadata": event_metadata,
        }
        record_llm_exchange(trace_dir, event_id, event, messages, response)
        if facts is not None:
            facts.trace_ids.append(event_id)
            return facts
        format_trace_ids.append(event_id)
        # Retry with a format-correction turn.
        messages = messages + [
            {"role": "assistant", "content": response or ""},
            {"role": "user", "content": _format_correction_message(messages)},
        ]
    return plugin.make_format_exhausted_facts(
        request,
        "no valid abstraction after retries",
        tuple(format_trace_ids),
    )


def _make_context(program: ProgramIndex, unit: FunctionUnit, entrypoints: set) -> DriverContext:
    return DriverContext(
        program=program,
        function=unit,
        is_entrypoint=unit.id in entrypoints,
        callers=program.callers_by_callee.get(unit.id, ()),
        callees=program.calls_by_caller.get(unit.id, ()),
    )


def _referenced_callee_context(
    plugin: AnalysisPlugin,
    unit: FunctionUnit,
    facts_by_fn: Mapping[FunctionId, FactEnvelope],
    program: ProgramIndex,
) -> Dict[FunctionId, str]:
    """Build {callee_id: summary_text} for callees referenced in this function's
    body that have already been analyzed."""
    ctx: Dict[FunctionId, str] = {}
    for site in program.calls_by_caller.get(unit.id, ()):
        cf = facts_by_fn.get(site.callee)
        if cf is not None and site.callee not in ctx:
            ctx[site.callee] = plugin.summarize_for_caller(cf)
    return ctx


def _resolved_calls(
    unit: FunctionUnit,
    facts_by_fn: Mapping[FunctionId, FactEnvelope],
    program: ProgramIndex,
) -> List[ResolvedCall]:
    out: List[ResolvedCall] = []
    for site in program.calls_by_caller.get(unit.id, ()):
        cf = facts_by_fn.get(site.callee)
        if cf is not None:
            out.append(ResolvedCall(call_site=site, callee_facts=cf))
    return out


def _run_top_down_context_worklist(
    plugin: AnalysisPlugin,
    program: ProgramIndex,
    facts_by_fn: Mapping[FunctionId, FactEnvelope],
    entrypoints: set,
) -> Dict[FunctionId, Sequence[Any]]:
    """Propagate plugin-defined context from entrypoints down the call graph.

    Used by theories whose property is not a pure bottom-up value computation
    (e.g. access control: "is the guard established by SOME ancestor?").
    """
    contexts: Dict[FunctionId, Sequence[Any]] = {}
    worklist: List[FunctionId] = []

    for eid in program.entrypoints:
        if eid not in facts_by_fn:
            continue
        unit = program.functions[eid]
        ctx = _make_context(program, unit, entrypoints)
        initial = plugin.initial_context(facts_by_fn[eid], ctx)
        if initial is not None:
            contexts[eid] = plugin.merge_contexts((), (initial,))
            worklist.append(eid)

    # Bound the worklist to avoid pathological loops on cyclic graphs.
    max_steps = max(1000, 50 * len(program.functions))
    steps = 0
    while worklist and steps < max_steps:
        steps += 1
        caller_id = worklist.pop(0)
        caller_unit = program.functions[caller_id]
        caller_ctx = _make_context(program, caller_unit, entrypoints)
        for site in program.calls_by_caller.get(caller_id, ()):
            callee_facts = facts_by_fn.get(site.callee)
            if callee_facts is None:
                continue
            for cctx in contexts.get(caller_id, ()):
                nxt = plugin.propagate_context(
                    facts_by_fn[caller_id], callee_facts, site, cctx, caller_ctx
                )
                if nxt is None:
                    continue
                old = contexts.get(site.callee, ())
                merged = plugin.merge_contexts(old, (nxt,))
                if list(map(repr, merged)) != list(map(repr, old)):
                    contexts[site.callee] = merged
                    worklist.append(site.callee)
    return contexts


def run_plugin(plugin: AnalysisPlugin, proj_dir: str, work_subdir: Optional[str] = None,
               results_subdir: str = "results", max_iter: int = MAX_IFC_ITER,
               verbose: bool = True) -> Dict[str, Any]:
    """Run one analysis plugin over a project directory.

    Outputs under <proj_dir>/<work_subdir>/:
      extracted_functions/**              (reused extraction machinery)
      <results_subdir>/**/<func>.json     per-function result (plugin.render_result)
      <results_subdir>/summary.json       aggregate (plugin.render_summary)

    work_subdir defaults to "fm_agent_<name>"; results_subdir defaults to
    "results". The IFC migration passes work_subdir="fm_agent_ifc",
    results_subdir="ifc_results" so ifc_eval.py / ifc_viewer.py keep working.

    Returns the summary dict.
    """
    if not os.path.isdir(proj_dir):
        raise NotADirectoryError(proj_dir)

    name = plugin.metadata.name
    work_subdir = work_subdir or f"fm_agent_{name}"
    work_dir = os.path.abspath(os.path.join(proj_dir, work_subdir))
    results_dir = os.path.join(work_dir, results_subdir)
    trace_dir = os.path.join(work_dir, "trace")
    cache_dir = os.path.join(work_dir, _FACTS_CACHE_SUBDIR)
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)

    if verbose:
        print(f"[{name}] Stage 1/4: scan + extract...")
    units = callgraph.load_function_units(
        proj_dir, work_dir, excluded_root=work_dir
    )
    if not units:
        print(f"[{name}] No functions extracted.")
        return {"total": 0, "results": []}

    if verbose:
        print(f"[{name}] Stage 2/4: build call graph ({len(units)} functions)...")
    program = callgraph.build_program_index(units)
    selected = _validated_relevance_slice(
        plugin, plugin.select_relevance_slice(program), program
    )
    full_order = callgraph.order_bottom_up(units)
    fingerprint = selected.fingerprint if selected is not None else None
    selected_ids = set(selected.function_ids) if selected is not None else None
    if selected_ids is not None:
        _prune_skipped_function_artifacts(
            plugin,
            program,
            selected_ids,
            work_dir,
            cache_dir,
            results_dir,
            trace_dir,
        )
    ordered = (
        [unit for unit in full_order if unit.id in selected_ids]
        if selected_ids is not None
        else full_order
    )
    context_program = (
        ProgramIndex(
            functions={
                fid: unit
                for fid, unit in program.functions.items()
                if fid in selected_ids
            },
            calls_by_caller={
                caller: tuple(
                    site
                    for site in sites
                    if site.caller in selected_ids and site.callee in selected_ids
                )
                for caller, sites in program.calls_by_caller.items()
                if caller in selected_ids
            },
            callers_by_callee={
                callee: tuple(
                    site
                    for site in sites
                    if site.caller in selected_ids and site.callee in selected_ids
                )
                for callee, sites in program.callers_by_callee.items()
                if callee in selected_ids
            },
            entrypoints=tuple(
                fid for fid in program.entrypoints if fid in selected_ids
            ),
        )
        if selected_ids is not None
        else program
    )
    entrypoints = set(context_program.entrypoints)
    model = _model_for(plugin)
    layers = _bottom_up_layers(context_program, ordered)
    workers = _stage3_worker_count()

    if verbose:
        print(
            f"[{name}] Stage 3/4: derive + compose "
            f"(layers={len(layers)}, workers={workers})..."
        )
    facts_by_fn: Dict[FunctionId, FactEnvelope] = {}
    resumed = 0
    derived = 0

    def derive_raw(unit: FunctionUnit) -> tuple[FactEnvelope, bool]:
        # Checkpoint stores ONLY the pre-compose abstraction (the sole expensive,
        # rate-limit-prone LLM step). Composition is deterministic and cheap, so
        # it is ALWAYS re-run below over the current facts_by_fn — this keeps the
        # cache independent of call-graph/compose changes and lets a resumed run
        # rebuild composition consistently from callees that may also be cached.
        facts = _load_facts_checkpoint(cache_dir, unit, fingerprint)
        if facts is not None:
            return facts, True
        ctx = _make_context(context_program, unit, entrypoints)
        callee_ctx = _referenced_callee_context(
            plugin, unit, facts_by_fn, context_program
        )
        request = AbstractionRequest(
            function=unit, context=ctx, callee_context=callee_ctx,
            trace_dir=trace_dir,
            trace_meta={"function_id": unit.id.rel, "language": unit.id.language},
        )
        facts = _call_llm_with_retries(plugin, request, model, max_iter)
        # Persist raw facts before composition so a crash never loses LLM work.
        _write_facts_checkpoint(cache_dir, unit, facts, fingerprint)
        return facts, False

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for layer in layers:
            raw_results = (
                [derive_raw(unit) for unit in layer]
                if workers == 1
                else list(executor.map(derive_raw, layer))
            )
            raw_by_fn = {
                unit.id: facts
                for unit, (facts, _) in zip(layer, raw_results)
            }
            resumed += sum(from_cache for _, from_cache in raw_results)
            derived += sum(not from_cache for _, from_cache in raw_results)

            composition_inputs = dict(facts_by_fn)
            composition_inputs.update(raw_by_fn)
            composed_by_fn: Dict[FunctionId, FactEnvelope] = {}
            for unit in layer:
                facts = raw_by_fn[unit.id]
                ctx = _make_context(context_program, unit, entrypoints)
                resolved = _resolved_calls(
                    unit, composition_inputs, context_program
                )
                if resolved:
                    facts = plugin.compose_calls(facts, resolved, ctx)
                composed_by_fn[unit.id] = facts
            facts_by_fn.update(composed_by_fn)
    if verbose and resumed:
        print(f"[{name}]   resumed {resumed} cached, derived {derived} new")

    propagated: Dict[FunctionId, Sequence[Any]] = {}
    if plugin.metadata.requires_top_down_context:
        if verbose:
            print(f"[{name}] Stage 3.5/4: top-down context propagation...")
        propagated = _run_top_down_context_worklist(
            plugin, context_program, facts_by_fn, entrypoints
        )

    if verbose:
        print(f"[{name}] Stage 4/4: check + write results...")
    results = []
    counts: Dict[str, int] = {}
    for unit in ordered:
        ctx = _make_context(context_program, unit, entrypoints)
        facts = facts_by_fn[unit.id]
        verdict = plugin.check(facts, ctx, propagated.get(unit.id, ()))
        counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1

        out = plugin.render_result(unit, facts, verdict, ctx)
        out_path = os.path.join(results_dir, os.path.splitext(unit.id.rel)[0] + ".json")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as fp:
            json.dump(out, fp, indent=2, ensure_ascii=False)

        if verbose and not getattr(plugin.metadata, "aggregate_only", False):
            color = {"LEAK": "\033[31m", "DECLASSIFIED": "\033[33m",
                     "POLYMORPHIC": "\033[36m", "SECURE": "\033[32m",
                     "ERROR": "\033[35m", "VULNERABLE": "\033[31m",
                     "SAFE": "\033[32m", "NEEDS_REVIEW": "\033[33m"}.get(verdict.verdict, "")
            print(f"  {unit.id.rel}: {color}{verdict.verdict}\033[0m")
        results.append({"function": unit.id.rel, "name": unit.id.name,
                        "verdict": verdict.verdict})

    summary = plugin.render_summary(results, counts)
    with open(os.path.join(results_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    if verbose:
        if getattr(plugin.metadata, "aggregate_only", False):
            project_verdict = summary.get(
                "verdict", summary.get("project_verdict")
            )
            if not isinstance(project_verdict, str) or not project_verdict:
                project_verdict = "UNKNOWN"
            scope_suffix = ""
            scope = summary.get("analysis_scope")
            if isinstance(scope, Mapping):
                selected_count = scope.get("selected_functions", scope.get("selected"))
                program_count = scope.get("program_functions", scope.get("program"))
                if isinstance(selected_count, int) and isinstance(program_count, int):
                    scope_suffix = (
                        f" (selected={selected_count}/program={program_count})"
                    )
            print(f"[{name}] Project verdict: {project_verdict}{scope_suffix}")
        print(f"[{name}] Done. " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return summary
