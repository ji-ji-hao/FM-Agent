from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import ifc_viewer


class CapabilityViewerTests(unittest.TestCase):
    def test_capability_has_dedicated_overview_and_detail_routes(self) -> None:
        # Given
        viewer_html = ifc_viewer.INDEX_HTML

        # When
        capability_routes = (
            'renderCapabilityOverview();' in viewer_html,
            'renderCapabilityDetail(d,f,r);' in viewer_html,
            'id="modalbody-capability"' in viewer_html,
        )

        # Then
        self.assertEqual((True, True, True), capability_routes)

    def test_capability_run_defers_function_details_until_selected(self) -> None:
        # Given
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            workspace = project / ifc_viewer.PLUGINS["capability"]["workspace"]
            results = workspace / "results"
            extracted = workspace / "extracted_functions" / "crypto"
            trace = workspace / "trace"
            results.joinpath("crypto").mkdir(parents=True)
            extracted.mkdir(parents=True)
            trace.mkdir(parents=True)
            results.joinpath("summary.json").write_text(
                json.dumps({"plugin": "capability", "counts": {"SAFE": 1}}),
                encoding="utf-8",
            )
            results.joinpath("crypto", "check.json").write_text(
                json.dumps(
                    {
                        "function": "crypto/check.c",
                        "verdict": "SAFE",
                        "resource_flows": [{"large": "payload" * 100}],
                    }
                ),
                encoding="utf-8",
            )
            extracted.joinpath("check.c").write_text(
                "int check(void) { return 0; }\n",
                encoding="utf-8",
            )
            trace.joinpath("events.jsonl").write_text(
                json.dumps(
                    {
                        "event_id": "event-1",
                        "metadata": {"function_id": "crypto/check.c"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            # When
            run = ifc_viewer.load_run(str(project), "capability")
            detail = ifc_viewer.load_function(str(project), "capability", "crypto/check")

            # Then
            self.assertEqual(1, len(run["functions"]))
            self.assertNotIn("result", run["functions"][0])
            self.assertNotIn("source_path", run["functions"][0])
            self.assertEqual("SAFE", run["functions"][0]["verdict"])
            self.assertEqual(
                str(Path("extracted_functions") / "crypto" / "check.c"),
                detail["source_path"],
            )
            self.assertEqual(["event-1"], detail["event_ids"])
            self.assertEqual("SAFE", detail["result"]["verdict"])

    def test_frontend_requests_function_details_on_selection(self) -> None:
        self.assertIn('api("/api/function?', ifc_viewer.INDEX_HTML)
        self.assertIn("if(eid===f.event_ids[0])head.click();", ifc_viewer.INDEX_HTML)

    def test_capability_overview_omits_missing_dispatch_metadata(self) -> None:
        self.assertNotIn(
            'route.slot||route.kind||"direct"',
            ifc_viewer.INDEX_HTML,
        )
        self.assertIn("route.implementation", ifc_viewer.INDEX_HTML)


if __name__ == "__main__":
    unittest.main()
