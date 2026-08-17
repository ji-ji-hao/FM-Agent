from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.capability_contract_loader import load_contract_pack
from src.capability_contracts import StaticContractProvider, contract_facts
from src.capability_prompts import CapabilityPayload, JsonValue
from src.capability_reasoner import reason_capability
from src.plugins.base import FactEnvelope, FunctionId, FunctionUnit, ProgramIndex
from src.plugins.capability import CapabilityPlugin


def _pack(name: str, target_arg: int = 0) -> dict[str, JsonValue]:
    return {
        "schema_version": "capability-contract.v1",
        "name": name,
        "version": "1",
        "authority": "TRUSTED",
        "languages": ["c"],
        "apis": [{
            "symbol": "custom_write",
            "seed_arg": None,
            "effects": [{
                "kind": "WRITE",
                "source_arg": None,
                "target_arg": target_arg,
            }],
        }],
        "registrations": [],
        "dispatches": [],
    }


def _program() -> ProgramIndex:
    function_id = FunctionId("write-c/write.c", "write", "write", "c")
    unit = FunctionUnit(
        function_id,
        "void write(char *dst) { custom_write(dst); }",
        "void write(char *dst)",
        params=("dst",),
    )
    return ProgramIndex(
        {function_id: unit},
        {function_id: ()},
        {function_id: ()},
        (function_id,),
    )


def _contract_verdict(
    unit: FunctionUnit,
    provider: StaticContractProvider,
) -> str:
    inputs, effects = contract_facts(unit, provider)
    payload: CapabilityPayload = {
        "schema_version": "capability.v3",
        "coverage": "complete",
        "inputs": inputs,
        "effects": effects,
        "unknowns": [],
        "obligations": [],
        "resource_flows": [],
        "propagation_chain": [],
    }
    facts = FactEnvelope(
        "capability",
        "capability.v3",
        unit.id,
        "ok",
        payload,
    )
    return reason_capability(facts).verdict


class CapabilityContractLoaderTests(unittest.TestCase):
    def test_path_validator_contract_ignores_unchecked_result(self) -> None:
        # Given
        contract_path = (
            Path(__file__).parents[1]
            / "contracts"
            / "capability"
            / "postgresql-path-extraction-v1.json"
        )
        provider = StaticContractProvider((load_contract_pack(contract_path),))
        function_id = FunctionId(
            "src/bin/pg_rewind/file_ops.c",
            "open_target_file",
            "open_target_file",
            "c",
        )
        unchecked = FunctionUnit(
            function_id,
            (
                "void open_target_file(char *path) { char dstpath[1024]; "
                "path_is_safe_for_extraction(path); "
                "snprintf(dstpath, sizeof(dstpath), \"%s/%s\", root, path); "
                "open(dstpath, mode, 0600); }"
            ),
            "void open_target_file(char *path)",
            params=("path",),
        )

        # When
        _, effects = contract_facts(unchecked, provider)

        # Then
        self.assertNotIn("GRANT", [effect["kind"] for effect in effects])
        self.assertEqual("VULNERABLE", _contract_verdict(unchecked, provider))

    def test_path_validator_contract_distinguishes_fixed_source(self) -> None:
        # Given
        contract_path = (
            Path(__file__).parents[1]
            / "contracts"
            / "capability"
            / "postgresql-path-extraction-v1.json"
        )
        provider = StaticContractProvider((load_contract_pack(contract_path),))
        function_id = FunctionId(
            "src/bin/pg_rewind/file_ops.c",
            "open_target_file",
            "open_target_file",
            "c",
        )
        vulnerable = FunctionUnit(
            function_id,
            (
                "void open_target_file(char *path) { char dstpath[1024]; "
                "snprintf(dstpath, sizeof(dstpath), \"%s/%s\", root, path); "
                "open(dstpath, mode, 0600); }"
            ),
            "void open_target_file(char *path)",
            params=("path",),
        )
        fixed = FunctionUnit(
            function_id,
            (
                "void open_target_file(char *path) { "
                "if (!path_is_safe_for_extraction(path)) pg_fatal(); "
                "char dstpath[1024]; "
                "snprintf(dstpath, sizeof(dstpath), \"%s/%s\", root, path); "
                "open(dstpath, mode, 0600); }"
            ),
            "void open_target_file(char *path)",
            params=("path",),
        )
        # When
        _, vulnerable_effects = contract_facts(vulnerable, provider)
        _, fixed_effects = contract_facts(fixed, provider)

        # Then
        self.assertNotIn("GRANT", [effect["kind"] for effect in vulnerable_effects])
        self.assertIn("GRANT", [effect["kind"] for effect in fixed_effects])
        self.assertEqual("param:path", fixed_effects[0]["target"])
        self.assertEqual("VULNERABLE", _contract_verdict(vulnerable, provider))
        self.assertEqual("SAFE", _contract_verdict(fixed, provider))

    def test_path_validator_accepts_terminal_failure_forms(self) -> None:
        contract_path = (
            Path(__file__).parents[1]
            / "contracts"
            / "capability"
            / "postgresql-path-extraction-v1.json"
        )
        provider = StaticContractProvider((load_contract_pack(contract_path),))
        variants = (
            "if (!path_is_safe_for_extraction(path)) return false;",
            "if (!path_is_safe_for_extraction(path)) goto error;",
            (
                "if (!path_is_safe_for_extraction(path)) "
                "{ log_bad_path(path); return false; }"
            ),
            (
                "if (!path_is_safe_for_extraction(path)) "
                "ereport(ERROR, (errmsg(\"unsafe path\")));"
            ),
        )
        for index, guard in enumerate(variants):
            with self.subTest(guard=guard):
                unit = FunctionUnit(
                    FunctionId(f"terminal_{index}.c", "extract", "extract", "c"),
                    f"bool extract(char *path) {{ {guard} use(path); return true; }}",
                    "bool extract(char *path)",
                    params=("path",),
                )
                _, effects = contract_facts(unit, provider)
                self.assertIn("GRANT", [effect["kind"] for effect in effects])

    def test_path_validator_rejects_nonterminal_failure_log(self) -> None:
        contract_path = (
            Path(__file__).parents[1]
            / "contracts"
            / "capability"
            / "postgresql-path-extraction-v1.json"
        )
        provider = StaticContractProvider((load_contract_pack(contract_path),))
        unit = FunctionUnit(
            FunctionId("warning.c", "extract", "extract", "c"),
            (
                "bool extract(char *path) { "
                "if (!path_is_safe_for_extraction(path)) "
                "ereport(WARNING, (errmsg(\"unsafe path\"))); "
                "use(path); return true; }"
            ),
            "bool extract(char *path)",
            params=("path",),
        )

        _, effects = contract_facts(unit, provider)

        self.assertNotIn("GRANT", [effect["kind"] for effect in effects])

    def test_path_validator_rejects_conditionally_terminal_failure_branch(self) -> None:
        contract_path = (
            Path(__file__).parents[1]
            / "contracts"
            / "capability"
            / "postgresql-path-extraction-v1.json"
        )
        provider = StaticContractProvider((load_contract_pack(contract_path),))
        unit = FunctionUnit(
            FunctionId("conditional.c", "extract", "extract", "c"),
            (
                "bool extract(char *path, bool fatal) { "
                "if (!path_is_safe_for_extraction(path)) "
                "{ if (fatal) pg_fatal(\"unsafe path\"); } "
                "use(path); return true; }"
            ),
            "bool extract(char *path, bool fatal)",
            params=("path", "fatal"),
        )

        _, effects = contract_facts(unit, provider)

        self.assertNotIn("GRANT", [effect["kind"] for effect in effects])

    def test_default_provider_loads_no_contract_packs(self) -> None:
        # Given / When
        with patch.dict(os.environ, {}, clear=True):
            scope = CapabilityPlugin().analysis_scope

        # Then
        self.assertEqual("disabled", scope["contract_mode"])
        self.assertEqual([], scope["contract_packs"])

    def test_external_contract_path_controls_provider(self) -> None:
        # Given
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.json"
            raw = json.dumps(_pack("custom-c-v1"), sort_keys=True)
            path.write_text(raw, encoding="utf-8")

            # When
            with patch.dict(
                os.environ,
                {"CAPABILITY_CONTRACT_PATHS": str(path)},
            ):
                scope = CapabilityPlugin().analysis_scope

            # Then
            self.assertEqual(["custom-c-v1"], scope["contract_packs"])
            self.assertEqual(
                hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                scope["contract_pack_sources"][0]["sha256"],
            )

    def test_external_contract_content_changes_fingerprint(self) -> None:
        # Given
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.json"
            path.write_text(
                json.dumps(_pack("custom-c-v1", target_arg=0)),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"CAPABILITY_CONTRACT_PATHS": str(path)},
            ):
                first = CapabilityPlugin().select_relevance_slice(_program())
            path.write_text(
                json.dumps(_pack("custom-c-v1", target_arg=1)),
                encoding="utf-8",
            )

            # When
            with patch.dict(
                os.environ,
                {"CAPABILITY_CONTRACT_PATHS": str(path)},
            ):
                second = CapabilityPlugin().select_relevance_slice(_program())

            # Then
            self.assertNotEqual(first.fingerprint, second.fingerprint)

    def test_conflicting_external_contracts_fail_closed(self) -> None:
        # Given
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            first.write_text(
                json.dumps(_pack("first", target_arg=0)),
                encoding="utf-8",
            )
            second.write_text(
                json.dumps(_pack("second", target_arg=1)),
                encoding="utf-8",
            )

            # When / Then
            with patch.dict(
                os.environ,
                {
                    "CAPABILITY_CONTRACT_PATHS": os.pathsep.join((
                        str(first),
                        str(second),
                    )),
                },
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "conflicting API contract",
                ):
                    CapabilityPlugin()


if __name__ == "__main__":
    unittest.main()
