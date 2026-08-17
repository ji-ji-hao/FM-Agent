import hashlib
from contextlib import redirect_stdout
from io import StringIO
import json
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from src.plugins import base, registry
from src.plugins.base import (
    CallSite,
    FactEnvelope,
    FunctionId,
    FunctionUnit,
    PluginMetadata,
    Verdict,
)

with mock.patch.dict(
    sys.modules,
    {
        "src.llm_client": SimpleNamespace(
            _openrouter_client=None,
            _retry_create=lambda client, model, messages, disable_thinking=False: ("", {}),
        )
    },
):
    from src.plugins import driver
from src.plugins.callgraph import (
    build_program_index,
    load_function_units,
    order_bottom_up,
    scan_source_files,
)


class CapabilityRegistryDiscoveryTests(unittest.TestCase):
    def test_capability_manifest_is_pure_data_and_loads_lazily(self):
        self.assertIn("capability", registry.plugin_names())
        manifest = registry.get_manifest("capability")
        self.assertEqual("src.plugins.capability", manifest["module"])
        self.assertEqual("CapabilityPlugin", manifest["class_name"])
        self.assertEqual(["CWE-669"], manifest["cwes"])
        plugin_class = registry.load_plugin_class("capability")
        self.assertEqual("capability", plugin_class().metadata.name)


class PluginWorkDirectoryDiscoveryTests(unittest.TestCase):
    def test_function_unit_existing_positional_construction_keeps_defaults(self):
        # Given / When
        function_id = FunctionId("sample-c/f.c", "f", "f", "c")
        unit = FunctionUnit(
            function_id,
            "void f(void) {}",
            "void f(void) {}",
        )

        # Then
        self.assertEqual(function_id, unit.id)
        self.assertEqual((), unit.params)
        self.assertIsNone(unit.abs_path)

    def test_extraction_populates_immutable_original_translation_unit_source(self):
        # Given
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "crypto" / "sample.c"
            source.parent.mkdir()
            original = (
                "static const struct ops table = { .send = send_impl };\n"
                "int send_impl(char *buf) { return buf[0]; }\n"
            )
            source.write_text(original, encoding="utf-8")
            work = project / "analysis-state"
            work.mkdir()

            # When
            units = load_function_units(
                str(project), str(work), excluded_root=str(work.resolve())
            )

            # Then
            self.assertEqual(1, len(units))
            self.assertEqual("crypto/sample.c", units[0].original_rel)
            self.assertEqual(original, units[0].original_source)
            self.assertEqual(
                hashlib.sha256(original.encode("utf-8")).hexdigest(),
                units[0].original_sha256,
            )

    def test_first_and_resumed_extraction_exclude_existing_work_tree_without_growth(self):
        """Regression for authn's recorded 568-call pre-fix aggregation growth."""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "src"
            source.mkdir()
            (source / "alpha.py").write_text("def handle():\n    return first()\n")
            (source / "beta.py").write_text("def handle():\n    return 2\n")
            (source / "cycle.py").write_text(
                "def first():\n    return second()\n\n"
                "def second():\n    return first()\n"
            )

            work = project / "plugin-state"
            generated = {
                work / "results/nested/rendered.py": "def generated_result():\n    return 1\n",
                work / "facts_cache/nested/cached.py": "def generated_fact():\n    return 1\n",
                work / "generated/deeper/tool.py": "def generated_tool():\n    return 1\n",
                work / "extracted_functions/plugin-state/results/nested/rendered-py/generated_result.py":
                    "def generated_result():\n    return 1\n",
                work / "extracted_functions/legacy-py/generated.py":
                    "def generated_legacy():\n    return 1\n",
            }
            for path, content in generated.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)

            before = {path.relative_to(work) for path in work.rglob("*") if path.is_file()}
            first = load_function_units(
                str(project), str(work), excluded_root=str(work.resolve())
            )
            after_first = {path.relative_to(work) for path in work.rglob("*") if path.is_file()}
            resumed = load_function_units(
                str(project), str(work), excluded_root=str(work.resolve())
            )
            after_resumed = {path.relative_to(work) for path in work.rglob("*") if path.is_file()}

            expected = {
                ("src/alpha-py/handle.py", "handle"),
                ("src/beta-py/handle.py", "handle"),
                ("src/cycle-py/first.py", "first"),
                ("src/cycle-py/second.py", "second"),
            }
            first_ids = {
                (unit.id.rel.replace("\\", "/"), unit.id.name) for unit in first
            }
            resumed_ids = {
                (unit.id.rel.replace("\\", "/"), unit.id.name) for unit in resumed
            }
            self.assertEqual(expected, first_ids)
            self.assertEqual(first_ids, resumed_ids)
            self.assertEqual(after_first, after_resumed)
            self.assertTrue(before <= after_first)
            for path, content in generated.items():
                self.assertEqual(content, path.read_text())
            self.assertFalse(any(
                part in {"plugin-state", "results", "facts_cache", "extracted_functions"}
                for unit in first for part in Path(unit.id.rel).parts
            ))

            program = build_program_index(first)
            ordered = order_bottom_up(first)
            self.assertEqual(
                expected,
                {
                    (unit.id.rel.replace("\\", "/"), unit.id.name)
                    for unit in ordered
                },
            )
            first_id = next(unit.id for unit in first if unit.id.name == "first")
            second_id = next(unit.id for unit in first if unit.id.name == "second")
            self.assertEqual([second_id], [site.callee for site in program.calls_by_caller[first_id]])
            self.assertEqual([first_id], [site.callee for site in program.calls_by_caller[second_id]])

    def test_scan_excludes_fm_agent_work_dirs_but_not_prefix_siblings(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            work = project / "active-work"
            sibling = project / "active-work-copy"
            default_work = project / "fm_agent_authn"
            main_work = project / "fm_agent"
            prefix_sibling = project / "fm_agentx_authn"
            top_level_source_pkg = project / "fm_agent_utils"
            nested_source_pkg = project / "src/fm_agent_authn"
            for path in (
                project / "app.py",
                work / "results/nested/generated.py",
                sibling / "user.py",
                default_work / "user.py",
                main_work / "user.py",
                prefix_sibling / "user.py",
                top_level_source_pkg / "core.py",
                nested_source_pkg / "core.py",
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("def target():\n    return 1\n")

            found = scan_source_files(str(project), excluded_root=str(work.resolve()))

            self.assertEqual(
                [
                    "active-work-copy/user.py",
                    "app.py",
                    "fm_agent_utils/core.py",
                    "fm_agentx_authn/user.py",
                    "src/fm_agent_authn/core.py",
                ],
                found,
            )

    def test_driver_passes_every_plugins_absolute_active_work_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            calls = []

            def no_units(proj_dir, work_dir, excluded_root=None):
                calls.append((proj_dir, work_dir, excluded_root))
                return []

            with mock.patch.object(driver.callgraph, "load_function_units", side_effect=no_units):
                for name in registry.plugin_names():
                    manifest = registry.get_manifest(name)
                    plugin = SimpleNamespace(metadata=SimpleNamespace(name=name))
                    driver.run_plugin(
                        plugin,
                        str(project),
                        work_subdir=manifest.get("work_subdir"),
                        results_subdir=manifest.get("results_subdir", "results"),
                        verbose=False,
                    )

            self.assertEqual(len(registry.plugin_names()), len(calls))
            for name, (_, work_dir, excluded_root) in zip(registry.plugin_names(), calls):
                manifest = registry.get_manifest(name)
                expected = (project / manifest.get("work_subdir", f"fm_agent_{name}")).resolve()
                self.assertEqual(str(expected), work_dir)
                self.assertEqual(str(expected), excluded_root)
            ifc_index = list(registry.plugin_names()).index("ifc")
            self.assertTrue(calls[ifc_index][1].endswith("fm_agent_ifc"))

    def test_driver_resume_reuses_facts_without_scanning_generated_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("def original():\n    return 1\n")
            generated = project / "custom-ifc-work/results/nested/generated.py"
            generated.parent.mkdir(parents=True)
            generated.write_text("def generated():\n    return 2\n")
            metadata = SimpleNamespace(
                name="ifc", requires_top_down_context=False
            )
            plugin = SimpleNamespace(
                metadata=metadata,
                select_relevance_slice=lambda program: None,
                check=lambda facts, context, propagated: Verdict(
                    plugin_name="ifc", verdict="SAFE"
                ),
                render_result=lambda unit, facts, verdict, context: {
                    "rel": unit.id.rel, "verdict": verdict.verdict
                },
                render_summary=lambda results, counts: {
                    "total": len(results), "counts": dict(counts), "results": list(results)
                },
            )

            def facts_for(plugin, request, model, max_iter):
                return FactEnvelope(
                    plugin_name="ifc",
                    schema_version="test.v1",
                    function=request.function.id,
                    status="ok",
                    payload={"original": True},
                )

            with mock.patch.object(
                driver, "_call_llm_with_retries", side_effect=facts_for
            ) as llm:
                first = driver.run_plugin(
                    plugin,
                    str(project),
                    work_subdir="custom-ifc-work",
                    results_subdir="ifc_results",
                    verbose=False,
                )
                second = driver.run_plugin(
                    plugin,
                    str(project),
                    work_subdir="custom-ifc-work",
                    results_subdir="ifc_results",
                    verbose=False,
                )

            self.assertEqual(1, llm.call_count)
            self.assertEqual(1, first["total"])
            self.assertEqual(first, second)
            self.assertEqual("def generated():\n    return 2\n", generated.read_text())
            self.assertTrue((
                project / "custom-ifc-work/facts_cache/app-py/original.json"
            ).is_file())

    def test_driver_does_not_cache_error_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "app.py").write_text("def original():\n    return 1\n")
            metadata = SimpleNamespace(
                name="ifc", requires_top_down_context=False
            )
            plugin = SimpleNamespace(
                metadata=metadata,
                check=lambda facts, context, propagated: Verdict(
                    plugin_name="ifc", verdict="ERROR", status="error"
                ),
                render_result=lambda unit, facts, verdict, context: {
                    "rel": unit.id.rel, "verdict": verdict.verdict,
                    "status": verdict.status,
                },
                render_summary=lambda results, counts: {
                    "total": len(results), "counts": dict(counts), "results": list(results)
                },
            )

            def error_facts(plugin, request, model, max_iter):
                return FactEnvelope(
                    plugin_name="ifc",
                    schema_version="test.v1",
                    function=request.function.id,
                    status="error",
                    payload=None,
                )

            with mock.patch.object(
                driver, "_call_llm_with_retries", side_effect=error_facts
            ) as llm:
                driver.run_plugin(
                    plugin,
                    str(project),
                    work_subdir="custom-ifc-work",
                    results_subdir="ifc_results",
                    verbose=False,
                )
                driver.run_plugin(
                    plugin,
                    str(project),
                    work_subdir="custom-ifc-work",
                    results_subdir="ifc_results",
                    verbose=False,
                )

            self.assertEqual(2, llm.call_count)
            self.assertFalse((
                project / "custom-ifc-work/facts_cache/app-py/original.json"
            ).exists())


class _RecordingPlugin:
    metadata = PluginMetadata(
        name="slice-test",
        version="1.0.0",
        schema_version="slice-test.v1",
        supported_languages=("python",),
        verdicts=("SAFE",),
    )

    def __init__(self, selected=None):
        self.selected = selected
        self.selector_calls = 0
        self.selector_programs = []
        self.events = []

    def select_relevance_slice(self, program):
        self.selector_calls += 1
        self.selector_programs.append(program)
        return self.selected

    def build_abstraction_prompt(self, request):
        self.events.append(("prompt", request.function.id))
        return []

    def parse_abstraction_response(self, request, raw_response):
        return None

    def make_error_facts(self, request, error):
        raise AssertionError(error)

    def summarize_for_caller(self, facts):
        self.events.append(("summary", facts.function))
        return facts.function.rel

    def compose_calls(self, caller_facts, resolved_calls, context):
        self.events.append(("compose", caller_facts.function))
        return caller_facts

    def check(self, facts, context, propagated_contexts=()):
        self.events.append(("check", facts.function))
        return Verdict(plugin_name=self.metadata.name, verdict="SAFE")

    def render_result(self, unit, facts, verdict, context):
        self.events.append(("render", unit.id))
        return {"rel": unit.id.rel, "verdict": verdict.verdict}

    def render_summary(self, results, counts):
        self.events.append(("render_summary", tuple(row["function"] for row in results)))
        return {"total": len(results), "counts": dict(counts), "results": list(results)}


class _AggregateOutputPlugin(_RecordingPlugin):
    metadata = PluginMetadata(
        name="aggregate-test",
        version="1.0.0",
        schema_version="aggregate-test.v1",
        supported_languages=("python",),
        verdicts=("NEEDS_REVIEW", "SAFE"),
        aggregate_only=True,
    )

    def render_summary(self, results, counts):
        self.events.append(("render_summary", tuple(row["function"] for row in results)))
        return {
            "total": len(results),
            "counts": dict(counts),
            "results": list(results),
            "verdict": "NEEDS_REVIEW",
            "analysis_scope": {
                "selected_functions": len(results),
                "program_functions": len(results),
            },
        }


class AggregateOutputDriverTests(unittest.TestCase):
    def test_aggregate_only_prints_one_project_verdict_and_writes_results(self):
        # Given
        first_id = FunctionId("first.py", "first", "first", "python")
        second_id = FunctionId("second.py", "second", "second", "python")
        units = [
            FunctionUnit(first_id, "def first(): pass", "def first():"),
            FunctionUnit(second_id, "def second(): pass", "def second():"),
        ]
        program = base.ProgramIndex(
            functions={unit.id: unit for unit in units},
            calls_by_caller={},
            callers_by_callee={},
            entrypoints=(first_id, second_id),
        )
        plugin = _AggregateOutputPlugin()

        def facts_for(active_plugin, request, model, max_iter):
            return FactEnvelope(
                plugin_name=active_plugin.metadata.name,
                schema_version=active_plugin.metadata.schema_version,
                function=request.function.id,
                status="ok",
                payload={"raw": request.function.id.rel},
            )

        # When
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            output = StringIO()
            with (
                redirect_stdout(output),
                mock.patch.dict(driver.os.environ, {"FM_AGENT_STAGE3_WORKERS": "1"}),
                mock.patch.object(driver.callgraph, "load_function_units", return_value=units),
                mock.patch.object(driver.callgraph, "build_program_index", return_value=program),
                mock.patch.object(driver.callgraph, "order_bottom_up", return_value=units),
                mock.patch.object(driver, "_call_llm_with_retries", side_effect=facts_for),
            ):
                summary = driver.run_plugin(plugin, str(project), verbose=True)

            # Then
            stdout = output.getvalue()
            project_lines = [
                line for line in stdout.splitlines() if "Project verdict:" in line
            ]
            self.assertEqual(
                ["[aggregate-test] Project verdict: NEEDS_REVIEW (selected=2/program=2)"],
                project_lines,
            )
            self.assertNotRegex(stdout, r"(?m)^\s*(first|second)\.py:")
            self.assertEqual("NEEDS_REVIEW", summary["verdict"])
            self.assertTrue((project / "fm_agent_aggregate-test/results/first.json").is_file())
            self.assertTrue((project / "fm_agent_aggregate-test/results/second.json").is_file())
            self.assertTrue((project / "fm_agent_aggregate-test/results/summary.json").is_file())


class _TopDownRecordingPlugin(_RecordingPlugin):
    metadata = PluginMetadata(
        name="slice-test",
        version="1.0.0",
        schema_version="slice-test.v1",
        supported_languages=("python",),
        verdicts=("SAFE",),
        requires_top_down_context=True,
    )

    def initial_context(self, facts, context):
        self.events.append(("initial", facts.function))
        return "entry"

    def propagate_context(
        self, caller_facts, callee_facts, call_site, caller_context, context
    ):
        self.events.append(("propagate", callee_facts.function))
        return caller_context

    def merge_contexts(self, old, new):
        return tuple(dict.fromkeys((*old, *new)))


class _ContextRecordingPlugin(_RecordingPlugin):
    def __init__(self, selected=None):
        super().__init__(selected)
        self.contexts = {}
        self.callee_contexts = {}

    def _record_context(self, boundary, context):
        self.contexts[(boundary, context.function.id)] = {
            "program": tuple(context.program.functions),
            "calls_by_caller": tuple(
                (caller, tuple((site.caller, site.callee) for site in sites))
                for caller, sites in context.program.calls_by_caller.items()
            ),
            "callers_by_callee": tuple(
                (callee, tuple((site.caller, site.callee) for site in sites))
                for callee, sites in context.program.callers_by_callee.items()
            ),
            "callers": tuple((site.caller, site.callee) for site in context.callers),
            "callees": tuple((site.caller, site.callee) for site in context.callees),
        }

    def build_abstraction_prompt(self, request):
        self._record_context("prompt", request.context)
        self.callee_contexts[request.function.id] = tuple(request.callee_context)
        return super().build_abstraction_prompt(request)

    def compose_calls(self, caller_facts, resolved_calls, context):
        self._record_context("compose", context)
        return super().compose_calls(caller_facts, resolved_calls, context)

    def check(self, facts, context, propagated_contexts=()):
        self._record_context("check", context)
        return super().check(facts, context, propagated_contexts)

    def render_result(self, unit, facts, verdict, context):
        self._record_context("render", context)
        return super().render_result(unit, facts, verdict, context)


class _ComposingRecordingPlugin(_RecordingPlugin):
    def summarize_for_caller(self, facts):
        self.events.append(("summary", facts.function))
        return facts.payload["phase"]

    def compose_calls(self, caller_facts, resolved_calls, context):
        super().compose_calls(caller_facts, resolved_calls, context)
        caller_facts.payload["phase"] = "composed"
        return caller_facts


def _raw_stage3_facts(active_plugin, request):
    return FactEnvelope(
        plugin_name=active_plugin.metadata.name,
        schema_version=active_plugin.metadata.schema_version,
        function=request.function.id,
        status="ok",
        payload={"phase": "raw"},
    )


class Stage3ParallelDriverTests(unittest.TestCase):
    def setUp(self):
        self.first_id = FunctionId("first.py", "first", "first", "python")
        self.second_id = FunctionId("second.py", "second", "second", "python")
        self.units = [
            FunctionUnit(self.first_id, "def first(): pass", "def first():"),
            FunctionUnit(self.second_id, "def second(): pass", "def second():"),
        ]
        self.program = base.ProgramIndex(
            functions={unit.id: unit for unit in self.units},
            calls_by_caller={},
            callers_by_callee={},
            entrypoints=(self.first_id, self.second_id),
        )
        self.plugin = _ComposingRecordingPlugin()
        self.workers = 2

    def _run(self, project, llm):
        with (
            mock.patch.dict(
                driver.os.environ,
                {"FM_AGENT_STAGE3_WORKERS": str(self.workers)},
            ),
            mock.patch.object(
                driver.callgraph, "load_function_units", return_value=self.units
            ),
            mock.patch.object(
                driver.callgraph, "build_program_index", return_value=self.program
            ),
            mock.patch.object(
                driver.callgraph, "order_bottom_up", return_value=self.units
            ),
            mock.patch.object(driver, "_call_llm_with_retries", side_effect=llm),
        ):
            return driver.run_plugin(self.plugin, str(project), verbose=False)

    def test_independent_raw_abstractions_overlap_when_workers_gt_one(self):
        # Given
        rendezvous = threading.Barrier(2)
        overlap_proved = threading.Event()

        def slow_llm(active_plugin, request, model, max_iter):
            position = rendezvous.wait(timeout=5)
            if position == 0:
                overlap_proved.set()
            return _raw_stage3_facts(active_plugin, request)

        # When
        with tempfile.TemporaryDirectory() as tmp:
            summary = self._run(Path(tmp), slow_llm)

        # Then
        self.assertTrue(overlap_proved.is_set())
        self.assertEqual(
            ["first.py", "second.py"],
            [result["function"] for result in summary["results"]],
        )

    def test_caller_starts_after_composed_callee_layer(self):
        # Given
        middle_id = FunctionId("middle.py", "middle", "middle", "python")
        caller_id = FunctionId("caller.py", "caller", "caller", "python")
        leaf = self.units[0]
        middle = FunctionUnit(middle_id, "def middle(): first()", "def middle():")
        caller = FunctionUnit(caller_id, "def caller(): middle()", "def caller():")
        leaf_to_middle = CallSite(leaf.id, middle_id, "middle")
        middle_to_leaf = CallSite(middle_id, leaf.id, "first")
        caller_to_middle = CallSite(caller_id, middle_id, "middle")
        self.units = [leaf, middle, caller]
        self.program = base.ProgramIndex(
            functions={unit.id: unit for unit in self.units},
            calls_by_caller={
                leaf.id: (leaf_to_middle,),
                middle_id: (middle_to_leaf,),
                caller_id: (caller_to_middle,),
            },
            callers_by_callee={
                leaf.id: (middle_to_leaf,),
                middle_id: (leaf_to_middle, caller_to_middle),
            },
            entrypoints=(caller_id,),
        )
        middle_started = threading.Event()
        release_middle = threading.Event()
        caller_started = threading.Event()
        caller_context = {}
        recursive_contexts = {}

        def slow_llm(active_plugin, request, model, max_iter):
            if request.function.id in (leaf.id, middle_id):
                recursive_contexts[request.function.id] = tuple(
                    request.callee_context
                )
            if request.function.id == middle_id:
                middle_started.set()
                if not release_middle.wait(timeout=5):
                    raise AssertionError("middle abstraction was not released")
            if request.function.id == caller_id:
                self.assertIn(("compose", middle_id), self.plugin.events)
                caller_context.update(request.callee_context)
                caller_started.set()
            return _raw_stage3_facts(active_plugin, request)

        # When
        with tempfile.TemporaryDirectory() as tmp, ThreadPoolExecutor(
            max_workers=1
        ) as test_executor:
            run = test_executor.submit(self._run, Path(tmp), slow_llm)
            try:
                self.assertTrue(middle_started.wait(timeout=5))
                self.assertFalse(caller_started.is_set())
            finally:
                release_middle.set()
            summary = run.result(timeout=5)

        # Then
        self.assertTrue(caller_started.is_set())
        self.assertEqual({leaf.id: (), middle_id: ()}, recursive_contexts)
        self.assertEqual({middle_id: "composed"}, caller_context)
        self.assertEqual(3, summary["total"])

    def test_workers_one_runs_raw_abstractions_sequentially(self):
        # Given
        self.workers = 1
        first_started = threading.Event()
        release_first = threading.Event()
        second_started = threading.Event()

        def slow_llm(active_plugin, request, model, max_iter):
            if request.function.id == self.first_id:
                first_started.set()
                if not release_first.wait(timeout=5):
                    raise AssertionError("first abstraction was not released")
            if request.function.id == self.second_id:
                second_started.set()
            return _raw_stage3_facts(active_plugin, request)

        # When
        with tempfile.TemporaryDirectory() as tmp, ThreadPoolExecutor(
            max_workers=1
        ) as test_executor:
            run = test_executor.submit(self._run, Path(tmp), slow_llm)
            try:
                self.assertTrue(first_started.wait(timeout=5))
                self.assertFalse(second_started.is_set())
            finally:
                release_first.set()
            summary = run.result(timeout=5)

        # Then
        self.assertTrue(second_started.is_set())
        self.assertEqual(2, summary["total"])


class RelevanceSliceDriverTests(unittest.TestCase):
    _FINGERPRINT = "a" * 64

    def setUp(self):
        self.first_id = FunctionId("first.py", "first", "first", "python")
        self.second_id = FunctionId("second.py", "second", "second", "python")
        self.third_id = FunctionId("third.py", "third", "third", "python")
        self.units = [
            FunctionUnit(self.first_id, "def first(): pass", "def first():"),
            FunctionUnit(self.second_id, "def second(): pass", "def second():"),
            FunctionUnit(self.third_id, "def third(): pass", "def third():"),
        ]
        self.program = base.ProgramIndex(
            functions={unit.id: unit for unit in self.units},
            calls_by_caller={},
            callers_by_callee={},
            entrypoints=(self.first_id,),
        )

    def _run(self, plugin, project):
        def facts_for(active_plugin, request, model, max_iter):
            active_plugin.events.append(("llm", request.function.id))
            active_plugin.build_abstraction_prompt(request)
            event_id = (
                f"{active_plugin.metadata.name}_{request.function.id.name}_"
                f"{len(active_plugin.events)}"
            )
            driver.record_llm_exchange(
                request.trace_dir,
                event_id,
                {
                    "event_id": event_id,
                    "type": "llm_call",
                    "stage": f"{active_plugin.metadata.name}_abstraction",
                    "status": "success",
                    "metadata": {"function_id": request.function.id.rel},
                },
                [{"role": "user", "content": request.function.id.rel}],
                "response",
            )
            return FactEnvelope(
                plugin_name=active_plugin.metadata.name,
                schema_version=active_plugin.metadata.schema_version,
                function=request.function.id,
                status="ok",
                payload={"raw": request.function.id.rel},
                trace_ids=[event_id],
            )

        with (
            mock.patch.dict(
                driver.os.environ,
                {"FM_AGENT_STAGE3_WORKERS": "1"},
            ),
            mock.patch.object(driver.callgraph, "load_function_units", return_value=self.units),
            mock.patch.object(driver.callgraph, "build_program_index", return_value=self.program),
            mock.patch.object(driver.callgraph, "order_bottom_up", return_value=self.units),
            mock.patch.object(driver, "_call_llm_with_retries", side_effect=facts_for),
        ):
            return driver.run_plugin(plugin, str(project), verbose=False)

    def _trace_function_ids(self, project):
        events_path = project / "fm_agent_slice-test/trace/events.jsonl"
        if not events_path.exists():
            return []
        return [
            json.loads(line)["metadata"]["function_id"]
            for line in events_path.read_text().splitlines()
        ]

    def test_default_none_selects_all_functions_and_accepts_legacy_cache(self):
        plugin = _RecordingPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            first = self._run(plugin, project)
            checkpoint = next(
                (project / "fm_agent_slice-test/facts_cache").rglob("*.json")
            )
            legacy_payload = json.loads(checkpoint.read_text())
            plugin.events.clear()
            second = self._run(plugin, project)

        self.assertEqual(3, first["total"])
        self.assertEqual(3, second["total"])
        self.assertEqual(2, plugin.selector_calls)
        self.assertNotIn("analysis_fingerprint", legacy_payload)
        self.assertFalse(any(event[0] == "llm" for event in plugin.events))

    def test_default_none_exposes_original_full_program_to_context_boundaries(self):
        first_to_second = CallSite(
            caller=self.first_id,
            callee=self.second_id,
            callee_name="second",
        )
        self.units = [self.units[1], self.units[0], self.units[2]]
        self.program = base.ProgramIndex(
            functions={unit.id: unit for unit in self.units},
            calls_by_caller={self.first_id: (first_to_second,)},
            callers_by_callee={self.second_id: (first_to_second,)},
            entrypoints=(self.first_id,),
        )
        plugin = _ContextRecordingPlugin()

        with tempfile.TemporaryDirectory() as tmp:
            self._run(plugin, Path(tmp))

        expected_ids = tuple(self.program.functions)
        expected_call = ((self.first_id, self.second_id),)
        self.assertEqual([self.program], plugin.selector_programs)
        for boundary in ("prompt", "compose", "check", "render"):
            context = plugin.contexts[(boundary, self.first_id)]
            self.assertEqual(expected_ids, context["program"])
            self.assertEqual(expected_call, context["callees"])
        self.assertEqual((self.second_id,), plugin.callee_contexts[self.first_id])

    def test_subset_touches_only_selected_ids(self):
        self.assertTrue(hasattr(base, "RelevanceSlice"))
        selected = base.RelevanceSlice(
            (self.third_id, self.first_id), self._FINGERPRINT
        )
        plugin = _RecordingPlugin(selected)
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            summary = self._run(plugin, project)
            cache_files = {
                path.name
                for path in (
                    project / "fm_agent_slice-test/facts_cache"
                ).rglob("*.json")
            }

        self.assertEqual(1, plugin.selector_calls)
        for action in ("llm", "check", "render"):
            self.assertEqual(
                [self.first_id, self.third_id],
                [event[1] for event in plugin.events if event[0] == action],
            )
        self.assertEqual(
            ["first.py", "third.py"],
            [row["function"] for row in summary["results"]],
        )
        self.assertEqual({"first.json", "third.json"}, cache_files)

    def test_subset_contexts_expose_only_selected_functions_and_calls(self):
        first_to_second = CallSite(
            caller=self.first_id,
            callee=self.second_id,
            callee_name="second",
            order_index=0,
        )
        first_to_third = CallSite(
            caller=self.first_id,
            callee=self.third_id,
            callee_name="third",
            order_index=1,
        )
        self.units = [self.units[1], self.units[2], self.units[0]]
        self.program = base.ProgramIndex(
            functions={unit.id: unit for unit in self.units},
            calls_by_caller={self.first_id: (first_to_second, first_to_third)},
            callers_by_callee={
                self.second_id: (first_to_second,),
                self.third_id: (first_to_third,),
            },
            entrypoints=(self.first_id,),
        )
        selected = base.RelevanceSlice(
            (self.first_id, self.third_id), self._FINGERPRINT
        )
        plugin = _ContextRecordingPlugin(selected)

        with tempfile.TemporaryDirectory() as tmp:
            self._run(plugin, Path(tmp))

        expected_ids = (self.third_id, self.first_id)
        expected_calls_by_caller = (
            (self.first_id, ((self.first_id, self.third_id),)),
        )
        expected_callers_by_callee = (
            (self.third_id, ((self.first_id, self.third_id),)),
        )
        expected_callees = ((self.first_id, self.third_id),)
        self.assertEqual([self.program], plugin.selector_programs)
        for boundary in ("prompt", "compose", "check", "render"):
            context = plugin.contexts[(boundary, self.first_id)]
            self.assertEqual(expected_ids, context["program"])
            self.assertEqual(expected_calls_by_caller, context["calls_by_caller"])
            self.assertEqual(
                expected_callers_by_callee, context["callers_by_callee"]
            )
            self.assertEqual(expected_callees, context["callees"])
            self.assertEqual((), context["callers"])
        self.assertEqual((self.third_id,), plugin.callee_contexts[self.first_id])

    def test_empty_slice_writes_summary_without_function_work(self):
        self.assertTrue(hasattr(base, "RelevanceSlice"))
        plugin = _RecordingPlugin(base.RelevanceSlice((), self._FINGERPRINT))
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            with (
                mock.patch.object(driver, "_load_facts_checkpoint") as load,
                mock.patch.object(driver, "_write_facts_checkpoint") as write,
            ):
                summary = self._run(plugin, project)
            cache_files = list(
                (project / "fm_agent_slice-test/facts_cache").rglob("*.json")
            )
            result_files = list(
                (project / "fm_agent_slice-test/results").rglob("*.json")
            )

        self.assertEqual({"total": 0, "counts": {}, "results": []}, summary)
        self.assertEqual([("render_summary", ())], plugin.events)
        self.assertEqual([], cache_files)
        self.assertEqual(1, len(result_files))
        load.assert_not_called()
        write.assert_not_called()

    def test_second_empty_slice_prunes_skipped_generated_artifacts_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            sources = {
                fid.rel: project / fid.rel
                for fid in (self.first_id, self.second_id, self.third_id)
            }
            for rel, path in sources.items():
                path.write_text(f"def {Path(rel).stem}(): pass\n")
            source_hashes = {
                rel: hashlib.sha256(path.read_bytes()).hexdigest()
                for rel, path in sources.items()
            }
            first = _RecordingPlugin(
                base.RelevanceSlice((self.first_id,), self._FINGERPRINT)
            )
            self._run(first, project)
            work = project / "fm_agent_slice-test"
            first_cache = work / "facts_cache/first.json"
            first_result = work / "results/first.json"
            first_payloads = tuple((work / "trace/payloads").iterdir())
            self.assertTrue(first_cache.is_file())
            self.assertTrue(first_result.is_file())
            self.assertTrue(first_payloads)

            empty = _RecordingPlugin(base.RelevanceSlice((), "b" * 64))
            summary = self._run(empty, project)

            self.assertEqual({"total": 0, "counts": {}, "results": []}, summary)
            self.assertFalse(first_cache.exists())
            self.assertFalse(first_result.exists())
            self.assertTrue((work / "results/summary.json").is_file())
            self.assertEqual([], self._trace_function_ids(project))
            self.assertFalse(any(path.exists() for path in first_payloads))
            self.assertEqual(
                source_hashes,
                {
                    rel: hashlib.sha256(path.read_bytes()).hexdigest()
                    for rel, path in sources.items()
                },
            )

    def test_second_subset_prunes_a_and_preserves_b_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            sources = {
                fid.rel: project / fid.rel for fid in (self.first_id, self.second_id)
            }
            for rel, path in sources.items():
                path.write_text(f"def {Path(rel).stem}(): pass\n")
            source_hashes = {
                rel: hashlib.sha256(path.read_bytes()).hexdigest()
                for rel, path in sources.items()
            }
            first = _RecordingPlugin(
                base.RelevanceSlice((self.first_id,), self._FINGERPRINT)
            )
            self._run(first, project)
            work = project / "fm_agent_slice-test"
            first_payloads = tuple((work / "trace/payloads").iterdir())

            second = _RecordingPlugin(
                base.RelevanceSlice((self.second_id,), "b" * 64)
            )
            summary = self._run(second, project)

            self.assertEqual(["second.py"], [row["function"] for row in summary["results"]])
            self.assertFalse((work / "facts_cache/first.json").exists())
            self.assertFalse((work / "results/first.json").exists())
            self.assertTrue((work / "facts_cache/second.json").is_file())
            self.assertTrue((work / "results/second.json").is_file())
            self.assertTrue((work / "results/summary.json").is_file())
            self.assertEqual(["second.py"], self._trace_function_ids(project))
            self.assertFalse(any(path.exists() for path in first_payloads))
            self.assertEqual(
                source_hashes,
                {
                    rel: hashlib.sha256(path.read_bytes()).hexdigest()
                    for rel, path in sources.items()
                },
            )

    def test_fingerprint_match_hits_and_mismatch_reanalyzes(self):
        self.assertTrue(hasattr(base, "RelevanceSlice"))
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            initial = _RecordingPlugin(
                base.RelevanceSlice((self.first_id,), self._FINGERPRINT)
            )
            self._run(initial, project)
            exact = _RecordingPlugin(
                base.RelevanceSlice((self.first_id,), self._FINGERPRINT)
            )
            self._run(exact, project)
            stale = _RecordingPlugin(base.RelevanceSlice((self.first_id,), "b" * 64))
            self._run(stale, project)
            checkpoint = next(
                (project / "fm_agent_slice-test/facts_cache").rglob("*.json")
            )
            payload = json.loads(checkpoint.read_text())
            stale_payload = dict(payload)

            payload.pop("analysis_fingerprint")
            checkpoint.write_text(json.dumps(payload))
            missing = _RecordingPlugin(base.RelevanceSlice((self.first_id,), "b" * 64))
            self._run(missing, project)

            payload = json.loads(checkpoint.read_text())
            payload["analysis_fingerprint"] = "B" * 64
            checkpoint.write_text(json.dumps(payload))
            malformed = _RecordingPlugin(
                base.RelevanceSlice((self.first_id,), "b" * 64)
            )
            self._run(malformed, project)

            checkpoint.write_text("[]")
            non_object = _RecordingPlugin(
                base.RelevanceSlice((self.first_id,), "b" * 64)
            )
            self._run(non_object, project)

            checkpoint.write_text("not json")
            corrupt = _RecordingPlugin(base.RelevanceSlice((self.first_id,), "b" * 64))
            self._run(corrupt, project)
            final_payload = json.loads(checkpoint.read_text())

        self.assertFalse(any(event[0] == "llm" for event in exact.events))
        for plugin in (stale, missing, malformed, non_object, corrupt):
            self.assertEqual(
                [("llm", self.first_id)],
                [event for event in plugin.events if event[0] == "llm"],
            )
        self.assertEqual("b" * 64, stale_payload["analysis_fingerprint"])
        self.assertEqual("b" * 64, final_payload["analysis_fingerprint"])

    def test_cached_raw_facts_are_recomposed(self):
        call = CallSite(
            caller=self.first_id,
            callee=self.second_id,
            callee_name="second",
        )
        self.units = [self.second_id, self.first_id]
        self.units = [
            FunctionUnit(fid, f"def {fid.name}(): pass", f"def {fid.name}():")
            for fid in self.units
        ]
        self.program = base.ProgramIndex(
            functions={unit.id: unit for unit in self.units},
            calls_by_caller={self.first_id: (call,)},
            callers_by_callee={self.second_id: (call,)},
            entrypoints=(self.first_id,),
        )
        selected = base.RelevanceSlice(
            (self.first_id, self.second_id), self._FINGERPRINT
        )
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            first = _RecordingPlugin(selected)
            self._run(first, project)
            second = _RecordingPlugin(selected)
            self._run(second, project)

        self.assertEqual(
            [("compose", self.first_id)],
            [event for event in second.events if event[0] == "compose"],
        )
        self.assertFalse(any(event[0] == "llm" for event in second.events))

    def test_top_down_context_ignores_unselected_callees(self):
        call = CallSite(
            caller=self.first_id,
            callee=self.second_id,
            callee_name="second",
        )
        self.program = base.ProgramIndex(
            functions={unit.id: unit for unit in self.units},
            calls_by_caller={self.first_id: (call,)},
            callers_by_callee={self.second_id: (call,)},
            entrypoints=(self.first_id,),
        )
        selected = base.RelevanceSlice((self.first_id,), self._FINGERPRINT)
        plugin = _TopDownRecordingPlugin(selected)

        with tempfile.TemporaryDirectory() as tmp:
            self._run(plugin, Path(tmp))

        self.assertEqual(
            [("initial", self.first_id)],
            [event for event in plugin.events if event[0] == "initial"],
        )
        self.assertFalse(any(event[0] == "propagate" for event in plugin.events))

    def test_invalid_slice_mentions_plugin(self):
        self.assertTrue(hasattr(base, "RelevanceSlice"))
        unknown = FunctionId("unknown.py", "unknown", "unknown", "python")
        invalid = (
            SimpleNamespace(function_ids=(), fingerprint=self._FINGERPRINT),
            base.RelevanceSlice([self.first_id], self._FINGERPRINT),
            base.RelevanceSlice((self.first_id, self.first_id), self._FINGERPRINT),
            base.RelevanceSlice((unknown,), self._FINGERPRINT),
            base.RelevanceSlice(("first.py",), self._FINGERPRINT),
            base.RelevanceSlice((self.first_id,), "A" * 64),
            base.RelevanceSlice((self.first_id,), "a" * 63),
            base.RelevanceSlice((self.first_id,), None),
        )
        for selected in invalid:
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as tmp:
                plugin = _RecordingPlugin(selected)
                stale = Path(tmp) / "fm_agent_slice-test/facts_cache/first.json"
                stale.parent.mkdir(parents=True)
                stale.write_text("stale")
                with (
                    mock.patch.object(driver, "_load_facts_checkpoint") as load,
                    mock.patch.object(driver, "_write_facts_checkpoint") as write,
                    mock.patch.object(driver, "_referenced_callee_context") as context,
                    mock.patch.object(driver, "_resolved_calls") as resolved,
                    self.assertRaisesRegex(ValueError, "slice-test"),
                ):
                    self._run(plugin, Path(tmp))
                self.assertEqual([], plugin.events)
                self.assertTrue(stale.is_file())
                for spy in (load, write, context, resolved):
                    spy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
