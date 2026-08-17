from __future__ import annotations

# noqa: SIZE_OK - focused v3 parser, composition, contract, and slicing scenarios.

import json
import os
import unittest
from unittest.mock import ANY, patch

from src.capability_prompts import CapabilityPayload, JsonValue, parse_capability_response
from src.capability_flow import (
    _Edge,
    _Hop,
    _Node,
    _candidate_assignment_edges,
    _candidate_reverse_alias_edges,
    _compose_candidate_chains,
    compose_project_chain,
)
from src.capability_contracts import (
    StaticContractProvider,
    contract_facts,
)
from src.capability_contract_loader import DEFAULT_CONTRACT_PROVIDER
from src.languages.registry import REGISTRY as LANGUAGE_FRONTENDS
from src.plugins.base import (
    AbstractionRequest,
    CallSite,
    DriverContext,
    FactEnvelope,
    FunctionId,
    FunctionUnit,
    ProgramIndex,
    ResolvedCall,
)
from src.plugins.callgraph import extract_params, signature_header, signature_line
from src.plugins.capability import CapabilityPlugin
from src.plugins import driver as plugin_driver


def _evidence(authority: str = "CONTRACT") -> dict[str, JsonValue]:
    return {"authority": authority, "lines": [1]}


def _input(
    formal: str,
    *,
    authority: str = "CONTRACT",
    write_authority: str = "DENIED",
) -> dict[str, JsonValue]:
    return {
        "formal": formal,
        "resource_id": formal,
        "reference_origin": "USER_CONTROLLED",
        "possible_backing": ["READONLY_MAPPING"],
        "write_authority": [write_authority],
        "role": "INPUT",
        "identity": "SAME",
        "evidence": _evidence(authority),
    }


def _effect(
    order: int,
    kind: str,
    source: str | None,
    target: str | None,
    *,
    authority: str = "CONTRACT",
    identity: str = "SAME",
    region: str = "OVERLAP",
) -> dict[str, JsonValue]:
    return {
        "order": order,
        "kind": kind,
        "source": source,
        "target": target,
        "identity": identity,
        "region": region,
        "guard": "FEASIBLE",
        "evidence": _evidence(authority),
    }


def _model(
    inputs: list[dict[str, JsonValue]],
    effects: list[dict[str, JsonValue]],
    *,
    coverage: str = "complete",
) -> dict[str, JsonValue]:
    return {
        "schema_version": "capability.v3",
        "coverage": coverage,
        "inputs": inputs,
        "effects": effects,
        "unknowns": [],
    }


def _tagged(payload: dict[str, JsonValue]) -> str:
    return "[CAPABILITY_JSON]" + json.dumps(payload) + "[/CAPABILITY_JSON]"


def _unit(
    name: str,
    source: str = "void f(char *dst) { dst[0] = 0; }",
    params: tuple[str, ...] = ("dst",),
    language: str = "c",
) -> FunctionUnit:
    extension = "java" if language == "java" else language
    function_id = FunctionId(
        f"{name}-{extension}/{name}.{extension}",
        name,
        name,
        language,
    )
    return FunctionUnit(function_id, source, source.splitlines()[0], params=params)


_REAL_REGISTRATION_SOURCE = "\n".join((
    "static int crypto_authenc_esn_create(struct crypto_template *tmpl,",
    "                                     struct rtattr **tb)",
    "{",
    "    struct aead_instance *inst;",
    "    int err;",
    "",
    "    inst->alg.decrypt = crypto_authenc_esn_decrypt;",
    "    inst->free = crypto_authenc_esn_free;",
    "    err = aead_register_instance(tmpl, inst);",
    "    return err;",
    "}",
    "",
))

_REAL_DISPATCH_SOURCE = "\n".join((
    "int crypto_aead_decrypt(struct aead_request *req)",
    "{",
    "    struct crypto_aead *aead = crypto_aead_reqtfm(req);",
    "",
    "    return crypto_aead_alg(aead)->decrypt(req);",
    "}",
    "",
))


def _real_c_unit(name: str, source: str) -> FunctionUnit:
    signature = signature_line(source, "c")
    params = tuple(extract_params(signature_header(source, signature), "c"))
    return _unit(name, source, params=params)


def _program(
    units: tuple[FunctionUnit, ...],
    sites: tuple[CallSite, ...] = (),
) -> ProgramIndex:
    calls = {unit.id: [] for unit in units}
    callers = {unit.id: [] for unit in units}
    for site in sites:
        calls[site.caller].append(site)
        callers[site.callee].append(site)
    return ProgramIndex(
        {unit.id: unit for unit in units},
        calls,
        callers,
        tuple(unit.id for unit in units if not callers[unit.id]),
    )


def _context(
    unit: FunctionUnit,
    program: ProgramIndex | None = None,
    calls: tuple[CallSite, ...] = (),
) -> DriverContext:
    selected = program or _program((unit,), calls)
    return DriverContext(selected, unit, True, callees=calls)


def _parse(payload: dict[str, JsonValue], line_count: int = 1) -> CapabilityPayload:
    parsed = parse_capability_response(_tagged(payload), line_count=line_count)
    if parsed is None:
        raise AssertionError("valid test payload was rejected")
    return parsed


def _facts(unit: FunctionUnit, payload: CapabilityPayload) -> FactEnvelope[CapabilityPayload]:
    return FactEnvelope("capability", "capability.v3", unit.id, "ok", payload)


def _project_chain_fixture() -> tuple[
    tuple[FunctionUnit, ...],
    ProgramIndex,
    dict[FunctionId, FactEnvelope[CapabilityPayload]],
]:
    seed = _unit("af_alg_get_rsgl", params=("msg",))
    request = _unit("_aead_recvmsg", params=("req",))
    dispatch = _unit("crypto_aead_decrypt", params=("req",))
    register = _unit("register_algorithm", params=())
    implementation = _unit("crypto_authenc_esn_decrypt", params=("req",))
    tail = _unit("crypto_authenc_esn_decrypt_tail", params=("dst",))
    units = (seed, request, dispatch, register, implementation, tail)
    program = _program(units)
    seed_payload = _parse(
        _model(
            [_input("param:msg.msg_iter")],
            [_effect(
                1,
                "FIELD",
                "param:msg.msg_iter",
                "param:rsgl.sgl.sgt.sgl",
            )],
        )
    )
    seed_payload["resource_flows"] = [{
        "from_function": seed.id.rel,
        "to_function": request.id.rel,
        "formal": "param:req.first_rsgl.sgl.sgt.sgl",
        "actual": "param:rsgl.sgl.sgt.sgl",
        "resource_id": "param:msg.msg_iter",
        "identity": "SAME",
        "effect": "FIELD",
        "evidence": _evidence(),
        "uncertainty": None,
    }]
    request_payload = _parse(
        _model(
            [],
            [
                _effect(
                    1,
                    "ALIAS",
                    "param:req.first_rsgl.sgl.sgt.sgl",
                    "local:rsgl_src",
                ),
                _effect(
                    2,
                    "ROLE_BIND",
                    "local:rsgl_src",
                    "param:req.dst",
                ),
            ],
        )
    )
    request_payload["resource_flows"] = [{
        "from_function": request.id.rel,
        "to_function": dispatch.id.rel,
        "formal": "param:req.dst",
        "actual": "param:req.dst",
        "resource_id": "param:msg.msg_iter",
        "identity": "SAME",
        "effect": "ARG",
        "evidence": _evidence(),
        "uncertainty": None,
    }]
    register_payload = _parse(
        _model(
            [],
            [_effect(
                1,
                "REGISTER",
                "resource:function.crypto_authenc_esn_decrypt",
                "global:aead_alg.decrypt",
            )],
        )
    )
    dispatch_payload = _parse(
        _model(
            [],
            [_effect(
                1,
                "DISPATCH",
                "global:aead_alg.decrypt",
                "param:req.dst",
            )],
        )
    )
    implementation_input = _input("param:req.dst")
    implementation_input["reference_origin"] = "KERNEL_CONTROLLED"
    implementation_input["write_authority"] = ["GRANTED"]
    implementation_payload = _parse(
        _model(
            [implementation_input],
            [_effect(1, "ALIAS", "param:req.dst", "local:dst")],
        )
    )
    implementation_payload["resource_flows"] = [{
        "from_function": implementation.id.rel,
        "to_function": tail.id.rel,
        "formal": "param:dst",
        "actual": "local:dst",
        "resource_id": "param:msg.msg_iter",
        "identity": "SAME",
        "effect": "ARG",
        "evidence": _evidence(),
        "uncertainty": None,
    }]
    tail_payload = _parse(
        _model(
            [],
            [_effect(1, "WRITEBACK", None, "param:dst")],
        )
    )
    facts = {
        unit.id: _facts(unit, payload)
        for unit, payload in zip(
            units,
            (
                seed_payload,
                request_payload,
                dispatch_payload,
                register_payload,
                implementation_payload,
                tail_payload,
            ),
        )
    }
    return units, program, facts


def _candidate_chain_fixture() -> tuple[
    tuple[FunctionUnit, ...],
    ProgramIndex,
    dict[FunctionId, FactEnvelope[CapabilityPayload]],
]:
    return _project_chain_fixture()


def _independent_candidate_fixture(count: int) -> tuple[
    tuple[FunctionUnit, ...],
    ProgramIndex,
    dict[FunctionId, FactEnvelope[CapabilityPayload]],
]:
    units: list[FunctionUnit] = []
    sites: list[CallSite] = []
    facts: dict[FunctionId, FactEnvelope[CapabilityPayload]] = {}
    for index in range(count):
        suffix = f"{index:03d}"
        seed = _unit(f"chain_{suffix}_seed", params=("src",))
        obligation = _unit(f"chain_{suffix}_obligation", params=("req",))
        dispatch = _unit(f"chain_{suffix}_dispatch", params=("req",))
        register = _unit(f"chain_{suffix}_register", params=())
        implementation = _unit(f"chain_{suffix}_implementation", params=("req",))
        writeback = _unit(f"chain_{suffix}_writeback", params=("dst",))
        chain_units = (
            seed,
            obligation,
            dispatch,
            register,
            implementation,
            writeback,
        )
        units.extend(chain_units)
        sites.extend((
            CallSite(
                seed.id,
                obligation.id,
                obligation.id.base_name,
                1,
                {"param:req": f"seed_bridge_{suffix}"},
            ),
            CallSite(
                obligation.id,
                dispatch.id,
                dispatch.id.base_name,
                2,
                {"param:req": f"req.output_{suffix}"},
            ),
            CallSite(
                implementation.id,
                writeback.id,
                writeback.id.base_name,
                3,
                {"param:dst": f"implementation_{suffix}"},
            ),
        ))
        payloads = (
            _parse(_model(
                [_input("param:src")],
                [_effect(
                    1,
                    "FIELD",
                    "param:src",
                    f"local:seed_bridge_{suffix}",
                )],
            )),
            _parse(_model(
                [],
                [_effect(
                    1,
                    "ROLE_BIND",
                    "param:req",
                    f"param:req.output_{suffix}",
                )],
            )),
            _parse(_model(
                [_input("param:req")],
                [_effect(
                    1,
                    "DISPATCH",
                    f"global:slot_{suffix}",
                    "param:req",
                )],
            )),
            _parse(_model(
                [],
                [_effect(
                    1,
                    "REGISTER",
                    f"resource:function.{implementation.id.base_name}",
                    f"global:slot_{suffix}",
                )],
            )),
            _parse(_model(
                [_input("param:req")],
                [_effect(
                    1,
                    "ALIAS",
                    "param:req",
                    f"local:implementation_{suffix}",
                )],
            )),
            _parse(_model(
                [],
                [_effect(
                    1,
                    "WRITEBACK",
                    None,
                    "param:dst",
                )],
            )),
        )
        facts.update({
            unit.id: _facts(unit, payload)
            for unit, payload in zip(chain_units, payloads)
        })
    all_units = tuple(units)
    return all_units, _program(all_units, tuple(sites)), facts


def _branching_candidate_fixture() -> tuple[
    tuple[FunctionUnit, ...],
    ProgramIndex,
    dict[FunctionId, FactEnvelope[CapabilityPayload]],
]:
    seed = _unit("branch_seed", params=("src",))
    obligation_a = _unit("branch_obligation_a", params=("req",))
    obligation_b = _unit("branch_obligation_b", params=("req",))
    dispatch = _unit("branch_dispatch", params=("req",))
    register = _unit("branch_register", params=())
    implementation = _unit("branch_implementation", params=("req",))
    writeback = _unit("branch_writeback", params=("dst",))
    units = (
        seed,
        obligation_a,
        obligation_b,
        dispatch,
        register,
        implementation,
        writeback,
    )
    sites = (
        CallSite(
            seed.id,
            obligation_a.id,
            obligation_a.id.base_name,
            1,
            {"param:req": "branch_bridge"},
        ),
        CallSite(
            seed.id,
            obligation_b.id,
            obligation_b.id.base_name,
            2,
            {"param:req": "branch_bridge"},
        ),
        CallSite(
            obligation_a.id,
            dispatch.id,
            dispatch.id.base_name,
            3,
            {"param:req": "req.output_a"},
        ),
        CallSite(
            obligation_b.id,
            dispatch.id,
            dispatch.id.base_name,
            4,
            {"param:req": "req.output_b"},
        ),
        CallSite(
            implementation.id,
            writeback.id,
            writeback.id.base_name,
            5,
            {"param:dst": "branch_implementation"},
        ),
    )
    payloads = (
        _parse(_model(
            [_input("param:src")],
            [_effect(1, "FIELD", "param:src", "local:branch_bridge")],
        )),
        _parse(_model(
            [],
            [_effect(
                1,
                "ROLE_BIND",
                "param:req",
                "param:req.output_a",
            )],
        )),
        _parse(_model(
            [],
            [_effect(
                1,
                "ROLE_BIND",
                "param:req",
                "param:req.output_b",
            )],
        )),
        _parse(_model(
            [_input("param:req")],
            [_effect(
                1,
                "DISPATCH",
                "global:branch_slot",
                "param:req",
            )],
        )),
        _parse(_model(
            [],
            [_effect(
                1,
                "REGISTER",
                "resource:function.branch_implementation",
                "global:branch_slot",
            )],
        )),
        _parse(_model(
            [_input("param:req")],
            [_effect(
                1,
                "ALIAS",
                "param:req",
                "local:branch_implementation",
            )],
        )),
        _parse(_model(
            [],
            [_effect(
                1,
                "WRITEBACK",
                None,
                "param:dst",
            )],
        )),
    )
    facts = {
        unit.id: _facts(unit, payload)
        for unit, payload in zip(units, payloads)
    }
    return units, _program(units, sites), facts


def _direct_candidate_fixture() -> tuple[
    tuple[FunctionUnit, ...],
    ProgramIndex,
    dict[FunctionId, FactEnvelope[CapabilityPayload]],
]:
    seed = _unit("direct_seed", params=("src",))
    obligation = _unit("direct_obligation", params=("req",))
    implementation = _unit("direct_implementation", params=("req",))
    writeback = _unit("direct_writeback", params=("dst",))
    units = (seed, obligation, implementation, writeback)
    sites = (
        CallSite(
            seed.id,
            obligation.id,
            obligation.id.base_name,
            1,
            {"param:req": "direct_bridge"},
        ),
        CallSite(
            obligation.id,
            implementation.id,
            implementation.id.base_name,
            2,
            {"param:req": "req.direct_output"},
        ),
        CallSite(
            implementation.id,
            writeback.id,
            writeback.id.base_name,
            3,
            {"param:dst": "req"},
        ),
    )
    payloads = (
        _parse(_model(
            [_input("param:src")],
            [_effect(1, "FIELD", "param:src", "local:direct_bridge")],
        )),
        _parse(_model(
            [],
            [_effect(
                1,
                "ROLE_BIND",
                "param:req",
                "param:req.direct_output",
            )],
        )),
        _parse(_model([_input("param:req")], [])),
        _parse(_model(
            [],
            [_effect(
                1,
                "WRITEBACK",
                None,
                "param:dst",
            )],
        )),
    )
    facts = {
        unit.id: _facts(unit, payload)
        for unit, payload in zip(units, payloads)
    }
    return units, _program(units, sites), facts


def _render_project_summary(
    units: tuple[FunctionUnit, ...],
    program: ProgramIndex,
    facts: dict[FunctionId, FactEnvelope[CapabilityPayload]],
) -> dict[str, JsonValue]:
    plugin = CapabilityPlugin()
    plugin.select_relevance_slice(program)
    rendered: list[dict[str, JsonValue]] = []
    counts: dict[str, int] = {}
    for unit in units:
        context = _context(unit, program)
        verdict = plugin.check(facts[unit.id], context)
        counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1
        rendered.append(plugin.render_result(unit, facts[unit.id], verdict, context))
    return plugin.render_summary(rendered, counts)


class CapabilityParserTests(unittest.TestCase):
    def test_relevant_unsupported_syntax_fails_closed_without_hiding_project_chain(self) -> None:
        # Given
        plugin = CapabilityPlugin(contract_provider=StaticContractProvider(()))
        unit = _unit(
            "macro_write",
            "void macro_write(char *dst) { WRITE_TO(dst); dst[0] = 0; }",
        )
        raw = _tagged(_model(
            [_input("param:dst")],
            [
                _effect(1, "REQUIRE_WRITE", "param:dst", "param:dst"),
                _effect(2, "WRITEBACK", None, "param:dst"),
            ],
        ))
        request = AbstractionRequest(unit, _context(unit))

        # When
        facts = plugin.parse_abstraction_response(request, raw)
        assert facts is not None
        local = plugin.check(facts, _context(unit))
        project = compose_project_chain({unit.id: facts}, _program((unit,)))

        # Then
        self.assertEqual("NEEDS_REVIEW", local.verdict)
        self.assertEqual("VULNERABLE", project["verdict"])
        self.assertIn("uppercase_macro", facts.payload["unknowns"][0])
        self.assertEqual("scanner-unsupported-syntax", facts.diagnostics[0].message)
        self.assertTrue(facts.diagnostics[0].data["resource_flow_relevant"])
        self.assertEqual(1, plugin.analysis_scope["unsupported_syntax_functions"])
        self.assertEqual(
            ["uppercase_macro"],
            plugin.analysis_scope["unsupported_syntax_kinds"],
        )

    def test_irrelevant_unsupported_syntax_is_diagnostic_only(self) -> None:
        # Given
        plugin = CapabilityPlugin(contract_provider=StaticContractProvider(()))
        unit = _unit(
            "macro_only",
            "void macro_only(void) { TRACE_ONLY(); }",
            (),
        )
        request = AbstractionRequest(unit, _context(unit))

        # When
        facts = plugin.parse_abstraction_response(
            request,
            _tagged(_model([], [])),
        )

        # Then
        assert facts is not None
        self.assertEqual([], facts.payload["unknowns"])
        self.assertEqual("scanner-unsupported-syntax", facts.diagnostics[0].message)
        self.assertFalse(facts.diagnostics[0].data["resource_flow_relevant"])

    def test_already_valid_v3_payload_preserves_semantic_facts(self) -> None:
        payload = _model(
            [_input("param:req.src")],
            [
                _effect(1, "FIELD", "param:req.src", "local:src"),
                _effect(2, "WRITE", None, "param:req.dst"),
                _effect(3, "DISPATCH", "global:slot", "param:req.dst"),
            ],
        )

        parsed = _parse(payload)

        self.assertEqual("capability.v3", parsed["schema_version"])
        self.assertEqual("complete", parsed["coverage"])
        self.assertEqual(["FIELD", "WRITE", "DISPATCH"], [
            effect["kind"] for effect in parsed["effects"]
        ])
        self.assertEqual([], parsed["unknowns"])
        self.assertEqual("param:req.src", parsed["inputs"][0]["resource_id"])

    def test_valid_facts_survive_observed_null_return_shape(self) -> None:
        payload = _model(
            [_input("param:msg.msg_iter")],
            [
                _effect(1, "FIELD", "param:msg.msg_iter", "param:sg"),
                _effect(2, "RETURN", None, "null"),
            ],
        )

        parsed = _parse(payload)

        self.assertEqual(["FIELD"], [effect["kind"] for effect in parsed["effects"]])
        self.assertEqual(["malformed optional RETURN effect at index 2"], parsed["unknowns"])

    def test_outer_schema_and_required_effects_remain_strict(self) -> None:
        payload = _model([], [_effect(1, "OVERWRITE", None, "param:dst")])

        parsed = parse_capability_response(_tagged(payload), line_count=1)

        self.assertIsNone(parsed)

    def test_same_region_alias_normalizes_to_overlap(self) -> None:
        # Given
        effect = _effect(1, "FIELD", "param:src", "local:dst")
        effect["region"] = "SAME"

        # When
        parsed = parse_capability_response(
            _tagged(_model([_input("param:src")], [effect])),
            line_count=1,
        )

        # Then
        self.assertIsNotNone(parsed)
        if parsed is None:
            return
        self.assertEqual("OVERLAP", parsed["effects"][0]["region"])

    def test_always_guard_alias_normalizes_to_feasible(self) -> None:
        effect = _effect(1, "WRITE", None, "param:dst")
        effect["guard"] = "ALWAYS"

        parsed = parse_capability_response(
            _tagged(_model([_input("param:dst")], [effect])),
            line_count=1,
        )

        self.assertIsNotNone(parsed)
        if parsed is None:
            return
        self.assertEqual("FEASIBLE", parsed["effects"][0]["guard"])

    def test_call_guard_normalizes_to_unknown_without_retry(self) -> None:
        effect = _effect(1, "WRITE", None, "param:dst")
        effect["guard"] = "CALL"

        parsed = parse_capability_response(
            _tagged(_model([_input("param:dst")], [effect])),
            line_count=1,
        )

        self.assertIsNotNone(parsed)
        if parsed is None:
            return
        self.assertEqual("UNKNOWN", parsed["effects"][0]["guard"])

    def test_observed_effect_aliases_salvage_facts_without_granting_write(self) -> None:
        registration = _effect(
            1,
            "REGISTER",
            "resource:function.impl",
            "global:slot",
            authority="CALL",
            identity="OTHER",
            region="EXACT",
        )
        registration.update({
            "write_authority": ["GRANTED"],
            "possible_backing": ["WRITABLE_PRIVATE"],
            "callee_info": {"name": "impl"},
        })
        flow = _effect(2, "FLOW", "local:src", "local:dst", authority="CALL")
        argument = _effect(
            3,
            "ARG",
            "param:req.src",
            "param:req.dst",
            authority="CALL",
        )
        interleave = _effect(
            4,
            "INTERLEAVE",
            "param:req.dst",
            "param:req.dst.field",
            authority="CONTRACT",
        )
        read = _effect(5, "READ", "param:req.src", "local:observed", authority="CALL")
        write = _effect(6, "WRITE", None, "param:req.dst", authority="CALL")
        write.update({
            "write_authority": ["GRANTED"],
            "possible_backing": ["WRITABLE_PRIVATE"],
            "callee_info": {"callee": "write"},
        })
        dispatch = _effect(
            7,
            "DISPATCH",
            "global:slot",
            "param:req.dst",
            authority="CALL",
        )

        parsed = parse_capability_response(
            _tagged(_model([_input("param:req.src")], [
                registration,
                flow,
                argument,
                interleave,
                read,
                write,
                dispatch,
            ])),
            line_count=1,
        )

        self.assertIsNotNone(parsed)
        if parsed is None:
            return
        self.assertEqual(
            ["REGISTER", "ALIAS", "ALIAS", "FIELD", "WRITE", "DISPATCH"],
            [effect["kind"] for effect in parsed["effects"]],
        )
        self.assertEqual([], parsed["unknowns"])
        self.assertEqual(["DENIED"], parsed["inputs"][0]["write_authority"])
        self.assertEqual("UNKNOWN", parsed["effects"][0]["identity"])
        self.assertEqual("OVERLAP", parsed["effects"][0]["region"])
        self.assertEqual("SOURCE", parsed["effects"][1]["evidence"]["authority"])
        self.assertEqual("param:req.src", parsed["effects"][2]["source"])
        self.assertEqual("param:req.dst", parsed["effects"][2]["target"])

    def test_unknown_effect_kind_remains_strict_after_known_read_drop(self) -> None:
        payload = _model(
            [],
            [
                _effect(1, "READ", "param:src", "local:read"),
                _effect(2, "MODEL_INVENTED", "param:src", "param:dst"),
            ],
        )

        parsed = parse_capability_response(_tagged(payload), line_count=1)

        self.assertIsNone(parsed)

    def test_declared_param_canonicalizes_typed_prefix_effect_resources(self) -> None:
        payload = _model(
            [_input("param:areq")],
            [
                _effect(
                    1,
                    "FIELD",
                    "areq:af_alg_async_req.rsgl_list",
                    "areq:af_alg_async_req.rsgl_list.sgl",
                ),
                _effect(
                    2,
                    "WRITE",
                    None,
                    "areq:af_alg_async_req.rsgl_list",
                ),
            ],
        )

        parsed = parse_capability_response(_tagged(payload), line_count=1)

        self.assertIsNotNone(parsed)
        if parsed is None:
            return
        self.assertEqual(
            "param:areq.rsgl_list",
            parsed["effects"][0]["source"],
        )
        self.assertEqual(
            "param:areq.rsgl_list.sgl",
            parsed["effects"][0]["target"],
        )
        self.assertEqual("param:areq.rsgl_list", parsed["effects"][1]["target"])

    def test_declared_param_canonicalizes_arrow_typed_prefix_effect_resources(self) -> None:
        payload = _model(
            [_input("param:areq")],
            [
                _effect(
                    1,
                    "FIELD",
                    "areq:af_alg_async_req.rsgl_list->sgl.sgt",
                    "areq:af_alg_async_req.rsgl_list->sgl.sgt.tail",
                ),
                _effect(
                    2,
                    "WRITE",
                    None,
                    "areq:af_alg_async_req.rsgl_list->sgl.sgt",
                ),
            ],
        )

        parsed = parse_capability_response(_tagged(payload), line_count=1)

        self.assertIsNotNone(parsed)
        if parsed is None:
            return
        self.assertEqual(
            "param:areq.rsgl_list.sgl.sgt",
            parsed["effects"][0]["source"],
        )
        self.assertEqual(
            "param:areq.rsgl_list.sgl.sgt.tail",
            parsed["effects"][0]["target"],
        )
        self.assertEqual(
            "param:areq.rsgl_list.sgl.sgt",
            parsed["effects"][1]["target"],
        )

    def test_declared_param_canonicalizes_nested_colon_resource(self) -> None:
        payload = _model(
            [_input("param:callback")],
            [
                _effect(
                    1,
                    "FIELD",
                    "param:callback",
                    "param:callback.arg:path",
                ),
            ],
        )

        parsed = parse_capability_response(_tagged(payload), line_count=1)

        self.assertIsNotNone(parsed)
        if parsed is None:
            return
        self.assertEqual(
            "param:callback.arg.path",
            parsed["effects"][0]["target"],
        )

    def test_arrow_typed_prefix_controls_remain_strict(self) -> None:
        controls = (
            "cmsg:struct_cmsg.foo->bar",
            "areq:af_alg_async_req.rsgl_list->->sgl",
            "areq:af_alg_async_req.rsgl_list->sgl(0)",
            "areq:af_alg_async_req.rsgl_list->sgl[0]",
            "areq:af_alg_async_req.rsgl_list->sgl+tail",
        )
        for resource in controls:
            payload = _model(
                [_input("param:areq")],
                [_effect(1, "FIELD", resource, "local:dst")],
            )
            with self.subTest(resource=resource):
                self.assertIsNone(
                    parse_capability_response(_tagged(payload), line_count=1),
                )

    def test_unmatched_typed_prefix_remains_rejected(self) -> None:
        payload = _model(
            [_input("param:areq")],
            [_effect(1, "FIELD", "cmsg:struct_cmsg.foo", "local:dst")],
        )

        parsed = parse_capability_response(_tagged(payload), line_count=1)

        self.assertIsNone(parsed)

        read_payload = _model(
            [_input("param:areq")],
            [_effect(1, "READ", "cmsg:struct_cmsg.foo", "local:dst")],
        )
        self.assertIsNone(
            parse_capability_response(_tagged(read_payload), line_count=1),
        )

    def test_valid_local_inputs_are_ignored_after_full_validation(self) -> None:
        payload = _model(
            [_input("param:areq"), _input("local:ctx"), _input("local:tfm")],
            [
                _effect(1, "FIELD", "param:areq", "local:ctx"),
                _effect(2, "WRITE", None, "param:areq"),
            ],
        )

        parsed = parse_capability_response(_tagged(payload), line_count=1)

        self.assertIsNotNone(parsed)
        if parsed is None:
            return
        self.assertEqual(["param:areq"], [item["formal"] for item in parsed["inputs"]])
        self.assertEqual([], parsed["unknowns"])

    def test_malformed_local_input_remains_rejected(self) -> None:
        malformed = _input("local:ctx")
        malformed["possible_backing"] = ["NOT_A_BACKING"]
        payload = _model([_input("param:areq"), malformed], [])

        parsed = parse_capability_response(_tagged(payload), line_count=1)

        self.assertIsNone(parsed)

    def test_fenced_markdown_around_tagged_response_remains_rejected(self) -> None:
        payload = _tagged(_model([_input("param:areq")], []))

        parsed = parse_capability_response(f"```json\n{payload}\n```", line_count=1)

        self.assertIsNone(parsed)


class CapabilityRequestPolicyTests(unittest.TestCase):
    def test_capability_requests_non_thinking_llm_calls(self) -> None:
        # Given
        unit = _unit("direct_fact", params=())
        plugin = CapabilityPlugin(StaticContractProvider(()))
        request = AbstractionRequest(unit, _context(unit))
        response = _tagged(_model([], []))

        # When
        with patch.object(
            plugin_driver,
            "_retry_create",
            return_value=(response, {}),
        ) as query:
            plugin_driver._call_llm_with_retries(
                plugin,
                request,
                "deepseek-v4-pro",
                1,
            )

        # Then
        query.assert_called_once_with(
            ANY,
            "deepseek-v4-pro",
            ANY,
            disable_thinking=True,
        )

    def test_capability_supplies_its_own_retry_correction(self) -> None:
        unit = _unit("direct_fact", params=())
        plugin = CapabilityPlugin(StaticContractProvider(()))
        request = AbstractionRequest(unit, _context(unit))
        response = _tagged(_model([], []))

        with (
            patch.object(
                plugin_driver,
                "_retry_create",
                side_effect=[("invalid", {}), (response, {})],
            ) as query,
            patch.object(
                plugin,
                "format_correction_message",
                return_value="capability-specific-correction",
            ) as correction,
        ):
            plugin_driver._call_llm_with_retries(
                plugin,
                request,
                "deepseek-v4-pro",
                2,
            )

        correction.assert_called_once_with(request, "invalid")
        second_messages = query.call_args_list[1].args[2]
        self.assertEqual(
            "capability-specific-correction",
            second_messages[-1]["content"],
        )


class CapabilityReasonerTests(unittest.TestCase):
    def test_write_effect_does_not_imply_write_authority(self) -> None:
        unit = _unit("write_only")
        payload = _parse(
            _model(
                [_input("param:dst", write_authority="UNKNOWN")],
                [
                    _effect(1, "REQUIRE_WRITE", "param:dst", "param:dst"),
                    _effect(2, "WRITE", None, "param:dst"),
                ],
            )
        )

        verdict = CapabilityPlugin().check(_facts(unit, payload), _context(unit))

        self.assertEqual(["UNKNOWN"], payload["inputs"][0]["write_authority"])
        self.assertEqual("NEEDS_REVIEW", verdict.verdict)

    def test_copyfail_identity_obligation_and_writeback_is_vulnerable(self) -> None:
        plugin = CapabilityPlugin()
        unit = _unit("copyfail")
        payload = _parse(
            _model(
                [_input("param:msg.msg_iter")],
                [
                    _effect(1, "FIELD", "param:msg.msg_iter", "param:req.src"),
                    _effect(2, "ROLE_BIND", "param:req.src", "param:req.dst"),
                    _effect(3, "WRITEBACK", None, "param:req.dst"),
                ],
            )
        )

        facts = _facts(unit, payload)
        context = _context(unit)
        verdict = plugin.check(facts, context)
        rendered = plugin.render_result(unit, facts, verdict, context)
        summary = plugin.render_summary(
            (rendered, rendered),
            {"VULNERABLE": 2},
        )

        self.assertEqual("VULNERABLE", verdict.verdict)
        self.assertEqual(
            ["SEED", "FIELD", "REQUIRE_WRITE", "WRITEBACK"],
            [step["kind"] for step in verdict.data["path"]],
        )
        self.assertEqual(
            [step["kind"] for step in verdict.data["path"]],
            [step["kind"] for step in summary["findings"][0]["path"]],
        )
        self.assertEqual(4, len(summary["findings"][0]["path"]))

    def test_fresh_deep_copy_to_distinct_destination_is_safe(self) -> None:
        unit = _unit("patched")
        payload = _parse(
            _model(
                [_input("param:src")],
                [
                    _effect(
                        1,
                        "DEEP_COPY",
                        "param:src",
                        "param:dst",
                        identity="FRESH",
                        region="DISJOINT",
                    ),
                    _effect(
                        2,
                        "ROLE_BIND",
                        "param:src",
                        "param:dst",
                        identity="FRESH",
                        region="DISJOINT",
                    ),
                    _effect(3, "WRITE", None, "param:dst"),
                ],
            )
        )

        verdict = CapabilityPlugin().check(_facts(unit, payload), _context(unit))

        self.assertEqual("SAFE", verdict.verdict)
        self.assertEqual("DEEP_COPY", verdict.data["path"][-1]["kind"])

    def test_model_only_path_needs_review(self) -> None:
        unit = _unit("model_only")
        payload = _parse(
            _model(
                [_input("param:src", authority="MODEL")],
                [
                    _effect(1, "ROLE_BIND", "param:src", "param:src", authority="MODEL"),
                    _effect(2, "WRITE", None, "param:src", authority="MODEL"),
                ],
            )
        )

        verdict = CapabilityPlugin().check(_facts(unit, payload), _context(unit))

        self.assertEqual("NEEDS_REVIEW", verdict.verdict)
        self.assertIn("trusted", verdict.data["missing_premise"])

    def test_empty_model_without_body_or_contract_proof_needs_review(self) -> None:
        unit = _unit("opaque", "void opaque(void) { hidden(); }", ())
        payload = _parse(_model([], []))

        verdict = CapabilityPlugin().check(_facts(unit, payload), _context(unit))

        self.assertEqual("NEEDS_REVIEW", verdict.verdict)
        self.assertIn("body or contract", verdict.data["missing_premise"])

    def test_java_read_only_buffer_uses_the_same_resource_policy(self) -> None:
        unit = _unit(
            "writeReadOnly",
            "void writeReadOnly(ByteBuffer source) { source.put((byte) 1); }",
            ("source",),
            "java",
        )
        payload = _parse(
            _model(
                [_input("param:source")],
                [
                    _effect(
                        1,
                        "REQUIRE_WRITE",
                        "param:source",
                        "param:source",
                        authority="EXPLICIT",
                    ),
                    _effect(
                        2,
                        "WRITE",
                        None,
                        "param:source",
                        authority="SOURCE",
                    ),
                ],
            )
        )

        verdict = CapabilityPlugin().check(_facts(unit, payload), _context(unit))

        self.assertEqual("VULNERABLE", verdict.verdict)

    def test_normalized_c_source_facts_form_trusted_project_chain(self) -> None:
        # Given
        unit = _unit(
            "normalized_c",
            "void normalized_c(char *dst) { dst[0] = 0; }",
            ("dst",),
        )
        plugin = CapabilityPlugin(StaticContractProvider(()))
        request = AbstractionRequest(unit, _context(unit))
        raw = _tagged(_model(
            [_input("param:dst", authority="SOURCE")],
            [
                _effect(
                    1,
                    "REQUIRE_WRITE",
                    "param:dst",
                    "param:dst",
                    authority="SOURCE",
                ),
                _effect(
                    2,
                    "WRITEBACK",
                    None,
                    "param:dst",
                    authority="SOURCE",
                ),
            ],
        ))

        # When
        facts = plugin.parse_abstraction_response(request, raw)

        # Then
        self.assertIsNotNone(facts)
        if facts is None:
            return
        chain = compose_project_chain(
            {unit.id: facts},
            _program((unit,)),
        )
        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(
            ["SEED", "REQUIRE_WRITE", "WRITEBACK"],
            [step["kind"] for step in chain["path"]],
        )

    def test_prior_trusted_grant_cuts_project_writeback_chain(self) -> None:
        unit = _unit("checked_write", params=("path",))
        payload = _parse(_model(
            [_input("param:path", authority="CONTRACT")],
            [
                _effect(1, "GRANT", "param:path", "param:path", authority="CONTRACT"),
                _effect(2, "REQUIRE_WRITE", "param:path", "param:path", authority="CONTRACT"),
                _effect(3, "WRITEBACK", None, "param:path", authority="CONTRACT"),
            ],
        ))

        facts = _facts(unit, payload)
        chain = compose_project_chain({facts.function: facts}, _program((unit,)))

        self.assertEqual("SAFE", chain["verdict"])
        self.assertEqual([], chain["path"])

    def test_late_trusted_grant_does_not_cut_prior_writeback_chain(self) -> None:
        unit = _unit("late_checked_write", params=("path",))
        payload = _parse(_model(
            [_input("param:path", authority="CONTRACT")],
            [
                _effect(1, "REQUIRE_WRITE", "param:path", "param:path", authority="CONTRACT"),
                _effect(2, "WRITEBACK", None, "param:path", authority="CONTRACT"),
                _effect(3, "GRANT", "param:path", "param:path", authority="CONTRACT"),
            ],
        ))

        facts = _facts(unit, payload)
        chain = compose_project_chain({facts.function: facts}, _program((unit,)))

        self.assertEqual("VULNERABLE", chain["verdict"])

    def test_plain_write_does_not_overwrite_trusted_writeback_sink(self) -> None:
        unit = _unit("write_after_writeback", params=("path",))
        payload = _parse(_model(
            [_input("param:path", authority="CONTRACT")],
            [
                _effect(1, "REQUIRE_WRITE", "param:path", "param:path"),
                _effect(2, "WRITEBACK", None, "param:path"),
                _effect(
                    3,
                    "WRITE",
                    "param:path",
                    "param:path",
                    authority="SOURCE",
                    identity="UNKNOWN",
                    region="UNKNOWN",
                ),
            ],
        ))

        facts = _facts(unit, payload)
        chain = compose_project_chain({facts.function: facts}, _program((unit,)))

        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(1, chain["strict_path_count"])

    def test_multiple_trusted_writebacks_on_one_node_are_all_preserved(self) -> None:
        unit = _unit("multiple_writebacks", params=("path",))
        first = _effect(2, "WRITEBACK", None, "param:path")
        second = _effect(3, "WRITEBACK", None, "param:path")
        first["evidence"] = {"authority": "CONTRACT", "lines": [1]}
        second["evidence"] = {"authority": "EXPLICIT", "lines": [1]}
        payload = _parse(_model(
            [_input("param:path", authority="CONTRACT")],
            [
                _effect(1, "REQUIRE_WRITE", "param:path", "param:path"),
                first,
                second,
            ],
        ))

        facts = _facts(unit, payload)
        chain = compose_project_chain({facts.function: facts}, _program((unit,)))

        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(2, chain["strict_path_count"])
        self.assertEqual(2, len(chain["strict_paths"]))

    def test_untrusted_or_nonidentical_writeback_cannot_close_strict_chain(self) -> None:
        unit = _unit("invalid_writebacks", params=("path",))
        payload = _parse(_model(
            [_input("param:path", authority="CONTRACT")],
            [
                _effect(1, "REQUIRE_WRITE", "param:path", "param:path"),
                _effect(
                    2,
                    "WRITEBACK",
                    None,
                    "param:path",
                    identity="FRESH",
                    region="DISJOINT",
                ),
                _effect(
                    3,
                    "WRITEBACK",
                    None,
                    "param:path",
                    authority="MODEL",
                ),
            ],
        ))

        facts = _facts(unit, payload)
        chain = compose_project_chain({facts.function: facts}, _program((unit,)))

        self.assertNotEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(0, chain["strict_path_count"])

    def test_source_fact_with_mixed_kernel_authority_is_not_a_strict_seed(self) -> None:
        # Given
        unit = _unit(
            "kernel_owned_folio",
            "void kernel_owned_folio(struct folio *folio) { zero(folio); }",
            ("folio",),
        )
        input_fact = _input("param:folio", authority="SOURCE")
        input_fact["possible_backing"] = [
            "WRITABLE_PRIVATE",
            "READONLY_MAPPING",
            "KERNEL_PRIVATE",
        ]
        input_fact["write_authority"] = ["GRANTED", "DENIED"]
        payload = _parse(_model(
            [input_fact],
            [
                _effect(
                    1,
                    "REQUIRE_WRITE",
                    "param:folio",
                    "param:folio",
                    authority="SOURCE",
                ),
                _effect(
                    2,
                    "WRITEBACK",
                    None,
                    "param:folio",
                    authority="SOURCE",
                ),
            ],
        ))
        facts = _facts(unit, payload)

        # When
        local = CapabilityPlugin().check(facts, _context(unit))
        chain = compose_project_chain({unit.id: facts}, _program((unit,)))

        # Then
        self.assertEqual("NEEDS_REVIEW", local.verdict)
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertNotEqual("strict_identity_path", chain["reason"])


class CapabilityMultilanguageTests(unittest.TestCase):
    def test_supported_languages_match_registered_frontends(self) -> None:
        # Given
        expected = (
            "python",
            "go",
            "c",
            "cpp",
            "java",
            "rust",
            "javascript",
            "typescript",
            "erlang",
        )

        # When
        advertised = tuple(CapabilityPlugin().metadata.supported_languages)

        # Then
        self.assertEqual(expected, tuple(LANGUAGE_FRONTENDS))
        self.assertEqual(expected, advertised)

    def test_normalized_source_facts_compose_identically_for_each_frontend(
        self,
    ) -> None:
        # Given
        sources = {
            "python": "def mutate(dst): return dst",
            "go": "func mutate(dst []byte) { dst[0] = 0 }",
            "c": "void mutate(char *dst) { dst[0] = 0; }",
            "cpp": "void mutate(char *dst) { dst[0] = 0; }",
            "java": "void mutate(byte[] dst) { dst[0] = 0; }",
            "rust": "fn mutate(dst: &mut [u8]) { dst[0] = 0; }",
            "javascript": "function mutate(dst) { dst[0] = 0; }",
            "typescript": "function mutate(dst: Uint8Array) { dst[0] = 0; }",
            "erlang": "mutate(Dst) -> Dst.",
        }
        raw = _tagged(_model(
            [_input("param:dst", authority="SOURCE")],
            [
                _effect(
                    1,
                    "REQUIRE_WRITE",
                    "param:dst",
                    "param:dst",
                    authority="SOURCE",
                ),
                _effect(
                    2,
                    "WRITEBACK",
                    None,
                    "param:dst",
                    authority="SOURCE",
                ),
            ],
        ))
        serialized_chains: list[str] = []

        # When
        for language, source in sources.items():
            with self.subTest(language=language):
                function_id = FunctionId(
                    "normalized/shared",
                    "mutate",
                    "mutate",
                    language,
                )
                unit = FunctionUnit(
                    function_id,
                    source,
                    source,
                    params=("dst",),
                )
                plugin = CapabilityPlugin(StaticContractProvider(()))
                facts = plugin.parse_abstraction_response(
                    AbstractionRequest(unit, _context(unit)),
                    raw,
                )
                self.assertIsNotNone(facts)
                if facts is None:
                    continue
                chain = compose_project_chain(
                    {unit.id: facts},
                    _program((unit,)),
                )
                serialized_chains.append(json.dumps(
                    chain,
                    sort_keys=True,
                    separators=(",", ":"),
                ))

        # Then
        self.assertEqual(tuple(sources), tuple(LANGUAGE_FRONTENDS))
        self.assertEqual(1, len(set(serialized_chains)))
        chain = json.loads(serialized_chains[0])
        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(
            ["SEED", "REQUIRE_WRITE", "WRITEBACK"],
            [step["kind"] for step in chain["path"]],
        )

    def test_model_only_normalized_chain_remains_untrusted(self) -> None:
        # Given
        unit = _unit(
            "model_only_rust",
            "fn mutate(dst: &mut [u8]) { dst[0] = 0; }",
            ("dst",),
            "rust",
        )
        plugin = CapabilityPlugin(StaticContractProvider(()))
        raw = _tagged(_model(
            [_input("param:dst", authority="MODEL")],
            [
                _effect(
                    1,
                    "REQUIRE_WRITE",
                    "param:dst",
                    "param:dst",
                    authority="MODEL",
                ),
                _effect(
                    2,
                    "WRITEBACK",
                    None,
                    "param:dst",
                    authority="MODEL",
                ),
            ],
        ))

        # When
        facts = plugin.parse_abstraction_response(
            AbstractionRequest(unit, _context(unit)),
            raw,
        )

        # Then
        self.assertIsNotNone(facts)
        if facts is None:
            return
        chain = compose_project_chain(
            {unit.id: facts},
            _program((unit,)),
        )
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertNotIn(chain["verdict"], {"VULNERABLE", "ERROR"})

    def test_missing_adapter_format_exhaustion_is_partial_review(self) -> None:
        # Given
        unit = _unit(
            "format_exhausted_erlang",
            "format_exhausted(Dst) -> Dst.",
            ("dst",),
            "erlang",
        )
        plugin = CapabilityPlugin()
        request = AbstractionRequest(unit, _context(unit))

        # When
        with patch("src.capability_contracts.scan_source") as scanner:
            facts = plugin.make_format_exhausted_facts(
                request,
                "invalid structured response",
                ("trace-1",),
            )
        verdict = plugin.check(facts, _context(unit))
        chain = compose_project_chain(
            {unit.id: facts},
            _program((unit,)),
        )

        # Then
        scanner.assert_not_called()
        self.assertEqual("partial", facts.status)
        self.assertEqual("NEEDS_REVIEW", verdict.verdict)
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertNotIn("ERROR", {verdict.verdict, chain["verdict"]})

    def test_linux_contract_scanner_is_not_invoked_for_python(self) -> None:
        # Given
        unit = _unit(
            "python_contract_lookalike",
            "def f(msg, dst): extract_iter_to_sg(msg, 4, dst, 1, 0)",
            ("msg", "dst"),
            "python",
        )

        # When
        with patch("src.capability_contracts.scan_source") as scanner:
            facts = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        # Then
        scanner.assert_not_called()
        self.assertEqual(([], []), facts)


class CapabilityCompositionTests(unittest.TestCase):
    def test_candidate_builder_requires_resource_continuity_and_keeps_unique_dispatch(
        self,
    ) -> None:
        # A uniquely registered dispatch with continuous ARG mappings is retained.
        units, program, facts = _independent_candidate_fixture(1)
        retained = _compose_candidate_chains(facts, program)
        self.assertEqual(1, len(retained.findings))

        # An unrelated implementation resource cannot reach the WRITEBACK.
        implementation = next(
            unit for unit in units
            if unit.id.name == "chain_000_implementation"
        )
        writeback = next(
            unit for unit in units
            if unit.id.name == "chain_000_writeback"
        )
        broken_sites = tuple(
            CallSite(
                site.caller,
                site.callee,
                site.callee_name,
                site.order_index,
                ({"param:dst": "unrelated_resource"}
                 if site.caller == implementation.id and site.callee == writeback.id
                 else site.arg_bindings),
                site.span,
            )
            for sites in program.calls_by_caller.values()
            for site in sites
        )
        broken = _compose_candidate_chains(
            facts,
            _program(units, broken_sites),
        )
        self.assertEqual(0, len(broken.findings))

    def test_trusted_lifecycle_slot_connects_separate_entrypoints(self) -> None:
        # Given
        publisher = _unit("publish", params=("source",))
        subscriber = _unit("consume", params=("target",))
        program = _program((publisher, subscriber))
        publisher_payload = _parse(_model(
            [_input("param:source")],
            [_effect(
                1,
                "FIELD",
                "param:source",
                "global:lifecycle_shared_buffer",
            )],
        ))
        subscriber_payload = _parse(_model(
            [],
            [
                _effect(
                    1,
                    "FIELD",
                    "global:lifecycle_shared_buffer",
                    "param:target",
                ),
                _effect(2, "REQUIRE_WRITE", "param:target", "param:target"),
                _effect(3, "WRITEBACK", None, "param:target"),
            ],
        ))
        facts = {
            publisher.id: _facts(publisher, publisher_payload),
            subscriber.id: _facts(subscriber, subscriber_payload),
        }

        # When
        result = compose_project_chain(facts, program)

        # Then
        self.assertEqual("VULNERABLE", result["verdict"])
        self.assertIn(
            "LIFECYCLE",
            [step["kind"] for step in result["propagation_chain"]],
        )

    def test_lifecycle_path_crosses_wrapper_without_declared_inputs(self) -> None:
        # Given
        publisher = _unit("z_publish", params=("source",))
        entry = _unit("entry", params=("item",))
        wrapper = _unit("wrapper", params=("item",))
        sink = _unit("sink", params=("item",))
        sites = (
            CallSite(
                entry.id,
                wrapper.id,
                wrapper.id.name,
                order_index=1,
                arg_bindings={"param:item": "item"},
            ),
            CallSite(
                wrapper.id,
                sink.id,
                sink.id.name,
                order_index=2,
                arg_bindings={"param:item": "item"},
            ),
        )
        program = _program((publisher, entry, wrapper, sink), sites)
        entry_payload = _parse(_model(
            [],
            [
                _effect(
                    1,
                    "FIELD",
                    "global:lifecycle_shared_item",
                    "param:item",
                ),
                _effect(2, "ARG", "param:item", "param:item"),
            ],
        ))
        entry_payload["effects"][1]["kind"] = "ARG"
        facts = {
            publisher.id: _facts(publisher, _parse(_model(
                [_input("param:source")],
                [_effect(
                    1,
                    "FIELD",
                    "param:source",
                    "global:lifecycle_shared_item",
                )],
            ))),
            entry.id: _facts(entry, entry_payload),
            wrapper.id: _facts(wrapper, _parse(_model([], []))),
            sink.id: _facts(sink, _parse(_model(
                [_input("param:item")],
                [
                    _effect(1, "REQUIRE_WRITE", "param:item", "param:item"),
                    _effect(2, "WRITEBACK", None, "param:item"),
                ],
            ))),
        }

        # When
        result = compose_project_chain(facts, program)

        # Then
        self.assertEqual("VULNERABLE", result["verdict"])
        self.assertIn(
            "LIFECYCLE",
            [step["kind"] for step in result["propagation_chain"]],
        )

    def test_project_summary_keeps_chains_once_without_raw_diagnostics(self) -> None:
        # Given
        units, program, facts = _candidate_chain_fixture()

        # When
        summary = _render_project_summary(units, program, facts)

        # Then
        self.assertEqual(1, summary["candidate_path_count"])
        self.assertEqual(1, len(summary["findings"]))
        self.assertTrue(summary["findings"][0]["path"])
        self.assertTrue(all(
            set(step) == {"kind", "function", "from", "to"}
            for step in summary["findings"][0]["path"]
        ))
        self.assertTrue({
            "path",
            "candidate_path",
            "candidate_paths",
            "propagation_chain",
            "function_evidence",
            "resource_flows",
        }.isdisjoint(summary))

    def test_candidate_contract_flow_suppresses_broad_model_seeds(self) -> None:
        # Given
        units, base_program, facts = _candidate_chain_fixture()
        seed = next(unit for unit in units if unit.id.name == "af_alg_get_rsgl")
        request = next(unit for unit in units if unit.id.name == "_aead_recvmsg")
        broad_msg = _input("param:msg")
        broad_sock = _input("param:sock")
        facts[seed.id].payload["inputs"].extend((broad_msg, broad_sock))
        facts[seed.id].payload["resource_flows"] = [{
            "from_function": seed.id.rel,
            "to_function": request.id.rel,
            "formal": "param:req",
            "actual": "param:msg.msg_iter",
            "resource_id": "param:msg.msg_iter",
            "identity": "SAME",
            "effect": "ARG",
            "evidence": _evidence("CONTRACT"),
            "uncertainty": None,
        }]
        functions = dict(base_program.functions)
        functions[seed.id] = FunctionUnit(
            seed.id,
            seed.source,
            seed.signature_line,
            params=("msg", "sock"),
        )
        program = ProgramIndex(
            functions,
            base_program.calls_by_caller,
            base_program.callers_by_callee,
            base_program.entrypoints,
        )

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(1, chain["candidate_path_count"])
        self.assertEqual(
            {"param:msg.msg_iter"},
            {
                finding["signature"]["seed_resource"]
                for finding in chain["candidate_findings"]
            },
        )

    def test_candidate_chains_preserve_distinct_obligation_branches_to_one_dispatcher(
        self,
    ) -> None:
        # Given
        _, program, facts = _branching_candidate_fixture()

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(2, chain["candidate_path_count"])
        self.assertEqual(
            {
                (
                    finding["signature"]["obligation_function"],
                    finding["signature"]["obligation_resource"],
                )
                for finding in chain["candidate_findings"]
            },
            {
                (
                    "branch_obligation_a-c/branch_obligation_a.c",
                    "param:req.output_a",
                ),
                (
                    "branch_obligation_b-c/branch_obligation_b.c",
                    "param:req.output_b",
                ),
            },
        )

    def test_candidate_chain_uses_source_backed_direct_route_without_registration(
        self,
    ) -> None:
        # Given
        _, program, facts = _direct_candidate_fixture()

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(1, chain["candidate_path_count"])
        finding = chain["candidate_findings"][0]
        self.assertEqual("DIRECT", finding["signature"]["route"]["kind"])
        self.assertEqual(
            "direct_implementation-c/direct_implementation.c",
            finding["signature"]["route"]["implementation"],
        )
        self.assertIsNone(finding["signature"]["route"]["slot"])
        self.assertTrue(finding["signature"]["route"]["direct_identity"])
        kinds = [step["kind"] for step in finding["path"]]
        self.assertIn("DIRECT", kinds)
        self.assertNotIn("REGISTER", kinds)
        self.assertNotIn("DISPATCH", kinds)
        self.assertEqual(finding["path"], chain["candidate_path"])

    def test_candidate_direct_route_ignores_unselected_alternate_callee(
        self,
    ) -> None:
        # Given
        units, base_program, facts = _direct_candidate_fixture()
        by_name = {unit.id.name: unit for unit in units}
        obligation = by_name["direct_obligation"]
        alternate = _unit("crypto_aead_encrypt", params=("req",))
        sites = tuple(
            site
            for caller_sites in base_program.calls_by_caller.values()
            for site in caller_sites
        )
        program = _program(
            (*units, alternate),
            (
                *sites,
                CallSite(
                    obligation.id,
                    alternate.id,
                    alternate.id.base_name,
                    0,
                    {"param:req": "alternate_request"},
                ),
            ),
        )
        self.assertIn(alternate.id, program.functions)
        self.assertNotIn(alternate.id, facts)

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(1, chain["candidate_path_count"])
        finding = chain["candidate_findings"][0]
        self.assertEqual(
            "direct_implementation-c/direct_implementation.c",
            finding["signature"]["route"]["implementation"],
        )
        self.assertNotIn(alternate.id.rel, json.dumps(chain, sort_keys=True))

    def test_candidate_route_prefers_longer_all_selected_path(
        self,
    ) -> None:
        # Given
        units, base_program, facts = _direct_candidate_fixture()
        by_name = {unit.id.name: unit for unit in units}
        seed = by_name["direct_seed"]
        obligation = by_name["direct_obligation"]
        selected_a = _unit("selected_bridge_a", params=("req",))
        selected_b = _unit("selected_bridge_b", params=("req",))
        unselected = _unit("unselected_shortcut", params=("req",))
        facts[selected_a.id] = _facts(
            selected_a,
            _parse(_model([], [
                _effect(1, "ALIAS", "param:req.a", "local:selected_a"),
            ])),
        )
        facts[selected_b.id] = _facts(
            selected_b,
            _parse(_model([], [
                _effect(1, "ALIAS", "param:req.b", "local:selected_b"),
            ])),
        )
        downstream_sites = tuple(
            site
            for caller_sites in base_program.calls_by_caller.values()
            for site in caller_sites
            if site.caller != seed.id
        )
        program = _program(
            (*units, selected_a, selected_b, unselected),
            (
                CallSite(
                    seed.id,
                    unselected.id,
                    unselected.id.base_name,
                    1,
                    {"param:req": "short_path"},
                ),
                CallSite(
                    unselected.id,
                    obligation.id,
                    obligation.id.base_name,
                    2,
                    {"param:req": "short_path"},
                ),
                CallSite(
                    seed.id,
                    selected_a.id,
                    selected_a.id.base_name,
                    3,
                    {"param:req": "selected_path"},
                ),
                CallSite(
                    selected_a.id,
                    selected_b.id,
                    selected_b.id.base_name,
                    4,
                    {"param:req": "selected_path"},
                ),
                CallSite(
                    selected_b.id,
                    obligation.id,
                    obligation.id.base_name,
                    5,
                    {"param:req": "selected_path"},
                ),
                *downstream_sites,
            ),
        )
        self.assertNotIn(unselected.id, facts)

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual("VULNERABLE", chain["verdict"])
        rendered = json.dumps(chain["candidate_findings"], sort_keys=True)
        self.assertIn(selected_a.id.rel, rendered)
        self.assertIn(selected_b.id.rel, rendered)
        self.assertNotIn(unselected.id.rel, rendered)

    def test_strict_multi_chain_summary_preserves_each_dispatch_route(self) -> None:
        # Given
        units, program, facts = _independent_candidate_fixture(2)

        # When
        chain = compose_project_chain(facts, program)
        summary = _render_project_summary(units, program, facts)

        # Then
        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(2, chain["strict_path_count"])
        self.assertEqual(0, chain["candidate_path_count"])
        self.assertEqual(2, len(summary["strict_findings"]))
        routes = [
            finding["signature"]["route"]
            for finding in summary["strict_findings"]
        ]
        self.assertEqual(
            ["global:slot_000", "global:slot_001"],
            [route["slot"] for route in routes],
        )
        self.assertEqual(
            [
                "chain_000_implementation-c/chain_000_implementation.c",
                "chain_001_implementation-c/chain_001_implementation.c",
            ],
            [route["implementation"] for route in routes],
        )

    def test_candidate_chains_collapse_alias_variants_of_one_signature(self) -> None:
        # Given
        _, program, facts = _independent_candidate_fixture(1)
        obligation = next(
            function
            for function in facts
            if function.name == "chain_000_obligation"
        )
        facts[obligation].payload["effects"] = [
            _effect(
                1,
                "ALIAS",
                "param:req.input_000",
                "local:short_variant",
            ),
            _effect(
                2,
                "ROLE_BIND",
                "local:short_variant",
                "param:req.output_000",
            ),
            _effect(
                3,
                "ALIAS",
                "local:short_variant",
                "local:long_variant",
            ),
            _effect(
                4,
                "ROLE_BIND",
                "local:long_variant",
                "param:req.output_000",
            ),
        ]

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual(1, chain["candidate_path_count"])
        self.assertFalse(chain["candidate_paths_truncated"])
        self.assertNotIn(
            "local:long_variant",
            [step["target"] for step in chain["candidate_paths"][0]],
        )

    def test_candidate_reverse_alias_requires_contract_write_anchor(self) -> None:
        unit = _unit("reverse_alias_anchor", params=("value",))
        payload = _parse(_model(
            [_input("param:value")],
            [_effect(1, "WRITEBACK", "local:anchored", "local:anchored")],
        ))
        facts = {unit.id: _facts(unit, payload)}

        def alias(source: str, target: str) -> _Edge:
            evidence = _evidence("CONTRACT")
            return _Edge(
                _Node(unit.id, source),
                _Node(unit.id, target),
                (_Hop(
                    "ALIAS",
                    unit.id,
                    unit.id,
                    source,
                    target,
                    evidence,
                ),),
            )

        reversed_edges = _candidate_reverse_alias_edges(
            (
                alias("param:value", "local:anchored"),
                alias("param:value", "local:noise"),
            ),
            facts,
        )

        self.assertEqual(1, len(reversed_edges))
        self.assertEqual("local:anchored", reversed_edges[0].source.resource)
        self.assertEqual("param:value", reversed_edges[0].target.resource)

    def test_candidate_alias_accepts_contract_field_descendant_anchor(self) -> None:
        unit = _unit(
            "field_descendant_anchor",
            "void f(void *areq) { rsgl = &areq->first_rsgl; }",
            ("areq",),
        )
        payload = _parse(_model(
            [_input("param:areq")],
            [_effect(
                1,
                "FIELD",
                "param:msg.msg_iter",
                "local:rsgl.sgl.sgt",
            )],
        ))
        facts = {unit.id: _facts(unit, payload)}

        assignments = _candidate_assignment_edges(facts, _program((unit,)))
        reversed_edges = _candidate_reverse_alias_edges(assignments, facts)

        self.assertEqual(1, len(assignments))
        self.assertEqual("param:areq.first_rsgl", assignments[0].source.resource)
        self.assertEqual("local:rsgl", assignments[0].target.resource)
        self.assertEqual(1, len(reversed_edges))
        self.assertEqual("local:rsgl", reversed_edges[0].source.resource)
        self.assertEqual(
            "param:areq.first_rsgl",
            reversed_edges[0].target.resource,
        )

    def test_candidate_chain_order_is_stable_when_fact_map_is_shuffled(self) -> None:
        # Given
        _, program, facts = _independent_candidate_fixture(3)
        shuffled = dict(reversed(tuple(facts.items())))

        # When
        forward = compose_project_chain(facts, program)
        reversed_result = compose_project_chain(shuffled, program)

        # Then
        self.assertEqual(
            forward["candidate_findings"],
            reversed_result["candidate_findings"],
        )
        self.assertEqual(
            forward["candidate_paths"],
            reversed_result["candidate_paths"],
        )

    def test_candidate_chains_cap_one_hundred_distinct_signatures(self) -> None:
        # Given
        _, program, facts = _independent_candidate_fixture(101)

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual(100, chain["candidate_path_count"])
        self.assertEqual(100, len(chain["candidate_paths"]))
        self.assertEqual(100, len(chain["candidate_findings"]))
        self.assertTrue(chain["candidate_paths_truncated"])

    def test_candidate_chain_without_writeback_is_not_counted(self) -> None:
        # Given
        _, program, facts = _independent_candidate_fixture(2)
        missing_writeback = next(
            function
            for function in facts
            if function.name == "chain_001_writeback"
        )
        facts[missing_writeback].payload["effects"] = []

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual(1, chain["candidate_path_count"])
        self.assertFalse(chain["candidate_paths_truncated"])
        self.assertNotIn(
            "chain_001_writeback",
            json.dumps(chain["candidate_findings"], sort_keys=True),
        )

    def test_candidate_chain_model_only_writeback_is_not_counted(self) -> None:
        # Given
        _, program, facts = _independent_candidate_fixture(1)
        writeback = next(
            function
            for function in facts
            if function.name == "chain_000_writeback"
        )
        facts[writeback].payload["effects"][0]["evidence"] = _evidence("MODEL")

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertEqual(0, chain["candidate_path_count"])
        self.assertEqual([], chain["candidate_paths"])
        self.assertFalse(chain["candidate_paths_truncated"])

    def test_candidate_chain_links_nonidentical_trusted_resources(self) -> None:
        # Given
        units, program, facts = _candidate_chain_fixture()

        # When
        chain = compose_project_chain(facts, program)
        plugin = CapabilityPlugin()
        plugin.select_relevance_slice(program)
        rendered: list[dict[str, JsonValue]] = []
        counts: dict[str, int] = {}
        for unit in units:
            context = _context(unit, program)
            verdict = plugin.check(facts[unit.id], context)
            counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1
            rendered.append(
                plugin.render_result(unit, facts[unit.id], verdict, context)
            )
        summary = plugin.render_summary(rendered, counts)

        # Then
        candidate = chain["candidate_path"]
        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual("candidate_source_backed", chain["reason"])
        self.assertEqual("candidate_source_backed", chain["confidence"])
        self.assertEqual(candidate, chain["path"])
        self.assertEqual([candidate], chain["candidate_paths"])
        self.assertEqual(1, chain["candidate_path_count"])
        self.assertFalse(chain["candidate_paths_truncated"])
        self.assertEqual(1, len(chain["candidate_findings"]))
        self.assertEqual(1, len(summary["findings"]))
        self.assertEqual(
            chain["candidate_findings"][0]["chain_id"],
            summary["findings"][0]["chain_id"],
        )
        self.assertEqual(
            [step["kind"] for step in candidate],
            [step["kind"] for step in summary["findings"][0]["path"]],
        )
        self.assertEqual(
            [
                "SEED",
                "FIELD",
                "ARG",
                "ALIAS",
                "REQUIRE_WRITE",
                "ARG",
                "REGISTER",
                "DISPATCH",
                "ALIAS",
                "ARG",
                "WRITEBACK",
            ],
            [step["kind"] for step in candidate],
        )
        self.assertTrue(all(
            step["confidence"] == "candidate"
            and step["function_rel"]
            and step["from"]
            and step["to"]
            and step["evidence"]["authority"] != "MODEL"
            for step in candidate
        ))

    def test_candidate_chain_missing_register_or_writeback_stays_review(self) -> None:
        # Given
        units, program, missing_register = _candidate_chain_fixture()
        register = next(
            unit for unit in units if unit.id.name == "register_algorithm"
        )
        missing_register[register.id].payload["effects"] = []
        _, _, missing_writeback = _candidate_chain_fixture()
        tail = next(
            unit
            for unit in units
            if unit.id.name == "crypto_authenc_esn_decrypt_tail"
        )
        missing_writeback[tail.id].payload["effects"] = []

        # When
        register_chain = compose_project_chain(missing_register, program)
        writeback_chain = compose_project_chain(missing_writeback, program)

        # Then
        self.assertEqual("NEEDS_REVIEW", register_chain["verdict"])
        self.assertIn("REGISTER", register_chain["missing_premise"] or "")
        self.assertEqual("NEEDS_REVIEW", writeback_chain["verdict"])
        self.assertIn("WRITEBACK", writeback_chain["missing_premise"] or "")

    def test_candidate_chain_ignores_model_only_milestone(self) -> None:
        # Given
        units, program, facts = _candidate_chain_fixture()
        request = next(unit for unit in units if unit.id.name == "_aead_recvmsg")
        obligation = next(
            effect
            for effect in facts[request.id].payload["effects"]
            if effect["kind"] == "ROLE_BIND"
        )
        obligation["evidence"] = _evidence("MODEL")

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertIn("REQUIRE_WRITE", chain["missing_premise"] or "")
        self.assertNotIn(
            "REQUIRE_WRITE",
            [step["kind"] for step in chain["candidate_path"]],
        )

    def test_candidate_chain_ignores_ambiguous_registration(self) -> None:
        # Given
        units, program, facts = _candidate_chain_fixture()
        register = next(
            unit for unit in units if unit.id.name == "register_algorithm"
        )
        original = facts[register.id].payload["effects"][0]
        facts[register.id].payload["effects"].append({
            **original,
            "order": 2,
        })

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertIn("REGISTER", chain["missing_premise"] or "")
        self.assertNotIn("REGISTER", [
            step["kind"] for step in chain["candidate_path"]
        ])

    def test_project_chain_local_input_cannot_seed_plain_write(self) -> None:
        unit = _unit("local_seed", params=("dst",))
        payload = _parse(
            _model(
                [],
                [
                    _effect(1, "REQUIRE_WRITE", "local:dst", "local:dst"),
                    _effect(2, "WRITE", None, "local:dst"),
                ],
            )
        )
        local_input = _input("param:dst")
        local_input["formal"] = "local:dst"
        local_input["resource_id"] = "local:dst"
        payload["inputs"] = [local_input]

        chain = compose_project_chain(
            {unit.id: _facts(unit, payload)},
            _program((unit,)),
        )

        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertEqual([], chain["path"])
        self.assertIsNone(chain["missing_premise"])

    def test_project_chain_param_seed_plain_write_needs_writeback(self) -> None:
        unit = _unit("param_write", params=("dst",))
        payload = _parse(
            _model(
                [_input("param:dst")],
                [
                    _effect(1, "REQUIRE_WRITE", "param:dst", "param:dst"),
                    _effect(2, "WRITE", None, "param:dst"),
                ],
            )
        )

        chain = compose_project_chain(
            {unit.id: _facts(unit, payload)},
            _program((unit,)),
        )

        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertEqual(["SEED", "REQUIRE_WRITE"], [
            step["kind"] for step in chain["path"]
        ])
        self.assertIn("WRITEBACK", chain["missing_premise"] or "")

    def test_project_chain_param_seed_writeback_remains_vulnerable(self) -> None:
        unit = _unit("param_writeback", params=("dst",))
        payload = _parse(
            _model(
                [_input("param:dst")],
                [
                    _effect(1, "REQUIRE_WRITE", "param:dst", "param:dst"),
                    _effect(2, "WRITEBACK", None, "param:dst"),
                ],
            )
        )

        chain = compose_project_chain(
            {unit.id: _facts(unit, payload)},
            _program((unit,)),
        )

        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(
            ["SEED", "REQUIRE_WRITE", "WRITEBACK"],
            [step["kind"] for step in chain["path"]],
        )

    def test_non_entry_helper_parameter_cannot_start_complete_chain(self) -> None:
        # Given
        entry = _unit("entry", params=("path",))
        helper = _unit("helper", params=("path",))
        site = CallSite(
            entry.id,
            helper.id,
            helper.id.name,
            arg_bindings={"path": "param:path"},
        )
        program = _program((entry, helper), (site,))
        helper_payload = _parse(
            _model(
                [_input("param:path")],
                [
                    _effect(1, "REQUIRE_WRITE", "param:path", "param:path"),
                    _effect(2, "WRITEBACK", None, "param:path"),
                ],
            )
        )
        entry_payload = _parse(_model([], []))

        # When
        chain = compose_project_chain(
            {
                entry.id: _facts(entry, entry_payload),
                helper.id: _facts(helper, helper_payload),
            },
            program,
        )

        # Then
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertEqual([], chain["path"])

    def test_source_only_origin_claim_cannot_start_complete_chain(self) -> None:
        # Given
        unit = _unit("entry", params=("path",))
        payload = _parse(
            _model(
                [_input("param:path", authority="SOURCE")],
                [
                    _effect(1, "REQUIRE_WRITE", "param:path", "param:path"),
                    _effect(2, "WRITEBACK", None, "param:path"),
                ],
            )
        )

        # When
        chain = compose_project_chain(
            {unit.id: _facts(unit, payload)},
            _program((unit,)),
        )

        # Then
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertEqual([], chain["path"])

    def test_project_chain_local_labeled_node_propagates_but_cannot_seed(self) -> None:
        unit = _unit("local_propagation", params=("src", "dst"))
        payload = _parse(
            _model(
                [_input("param:src")],
                [
                    _effect(1, "FIELD", "param:src", "local:dst"),
                    _effect(2, "REQUIRE_WRITE", "local:dst", "local:dst"),
                    _effect(3, "WRITEBACK", None, "local:dst"),
                ],
            )
        )
        local_input = _input("param:dst")
        local_input["formal"] = "local:dst"
        local_input["resource_id"] = "local:dst"
        payload["inputs"].append(local_input)
        facts = {unit.id: _facts(unit, payload)}
        program = _program((unit,))

        chain = compose_project_chain(facts, program)

        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual(
            ["SEED", "FIELD", "REQUIRE_WRITE", "WRITEBACK"],
            [step["kind"] for step in chain["path"]],
        )

        payload["inputs"] = [local_input]
        local_only = compose_project_chain(facts, program)

        self.assertEqual("NEEDS_REVIEW", local_only["verdict"])
        self.assertEqual([], local_only["path"])

    def test_project_chain_links_arg_field_register_dispatch_and_writeback(self) -> None:
        units, program, facts = _project_chain_fixture()

        chain = compose_project_chain(facts, program)
        plugin = CapabilityPlugin()
        plugin.select_relevance_slice(program)
        rendered: list[dict[str, JsonValue]] = []
        counts: dict[str, int] = {}
        for unit in units:
            context = _context(unit, program)
            verdict = plugin.check(facts[unit.id], context)
            counts[verdict.verdict] = counts.get(verdict.verdict, 0) + 1
            rendered.append(
                plugin.render_result(unit, facts[unit.id], verdict, context)
            )
        summary = plugin.render_summary(rendered, counts)

        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertEqual("VULNERABLE", summary["verdict"])
        self.assertEqual(
            [step["kind"] for step in chain["path"]],
            [step["kind"] for step in summary["findings"][0]["path"]],
        )
        self.assertEqual(
            [
                "SEED",
                "FIELD",
                "FIELD",
                "ALIAS",
                "REQUIRE_WRITE",
                "ARG",
                "REGISTER",
                "DISPATCH",
                "ALIAS",
                "ARG",
                "WRITEBACK",
            ],
            [step["kind"] for step in chain["path"]],
        )
        self.assertEqual(
            len(chain["path"]),
            len({json.dumps(step, sort_keys=True) for step in chain["path"]}),
        )
        self.assertIsNone(chain["missing_premise"])

    def test_dispatch_without_declared_input_binds_unique_actual_formal(self) -> None:
        # Given
        units, program, facts = _project_chain_fixture()
        implementation = next(
            unit
            for unit in units
            if unit.id.name == "crypto_authenc_esn_decrypt"
        )
        facts[implementation.id].payload["inputs"] = []
        alias = next(
            effect
            for effect in facts[implementation.id].payload["effects"]
            if effect["kind"] == "ALIAS"
        )
        alias["source"] = "param:req"

        # When
        chain = compose_project_chain(facts, program)

        # Then
        self.assertEqual("VULNERABLE", chain["verdict"])
        dispatch = next(step for step in chain["path"] if step["kind"] == "DISPATCH")
        self.assertEqual("param:req", dispatch["target"])

    def test_dispatch_ignores_bogus_declared_input_and_binds_unique_actual_formal(self) -> None:
        # Given
        units, program, facts = _project_chain_fixture()
        implementation = next(
            unit
            for unit in units
            if unit.id.name == "crypto_authenc_esn_decrypt"
        )
        facts[implementation.id].payload["inputs"] = [_input("param:src")]

        # When
        chain = compose_project_chain(facts, program)

        # Then
        dispatch = next(step for step in chain["path"] if step["kind"] == "DISPATCH")
        self.assertEqual("param:req", dispatch["target"])

    def test_dispatch_preserves_valid_declared_formal(self) -> None:
        # Given
        units, program, facts = _project_chain_fixture()
        implementation = next(
            unit
            for unit in units
            if unit.id.name == "crypto_authenc_esn_decrypt"
        )
        facts[implementation.id].payload["inputs"] = [_input("param:req")]

        # When
        chain = compose_project_chain(facts, program)

        # Then
        dispatch = next(step for step in chain["path"] if step["kind"] == "DISPATCH")
        self.assertEqual("param:req", dispatch["target"])

    def test_dispatch_without_declared_input_rejects_multiple_actual_formals(self) -> None:
        # Given
        units, program, facts = _project_chain_fixture()
        implementation = next(
            unit
            for unit in units
            if unit.id.name == "crypto_authenc_esn_decrypt"
        )
        facts[implementation.id].payload["inputs"] = []
        alias = next(
            effect
            for effect in facts[implementation.id].payload["effects"]
            if effect["kind"] == "ALIAS"
        )
        alias["source"] = "param:req"
        functions = dict(program.functions)
        functions[implementation.id] = FunctionUnit(
            implementation.id,
            implementation.source,
            implementation.signature_line,
            params=("req", "context"),
        )
        multi_formal_program = ProgramIndex(
            functions,
            program.calls_by_caller,
            program.callers_by_callee,
            program.entrypoints,
        )

        # When
        chain = compose_project_chain(facts, multi_formal_program)

        # Then
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertNotIn("DISPATCH", [step["kind"] for step in chain["path"]])

    def test_dispatch_ignores_bogus_declared_input_with_multiple_actual_formals(self) -> None:
        # Given
        units, program, facts = _project_chain_fixture()
        implementation = next(
            unit
            for unit in units
            if unit.id.name == "crypto_authenc_esn_decrypt"
        )
        facts[implementation.id].payload["inputs"] = [_input("param:src")]
        functions = dict(program.functions)
        functions[implementation.id] = FunctionUnit(
            implementation.id,
            implementation.source,
            implementation.signature_line,
            params=("req", "context"),
        )
        multi_formal_program = ProgramIndex(
            functions,
            program.calls_by_caller,
            program.callers_by_callee,
            program.entrypoints,
        )

        # When
        chain = compose_project_chain(facts, multi_formal_program)

        # Then
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertNotIn("DISPATCH", [step["kind"] for step in chain["path"]])

    def test_project_chain_keeps_trusted_path_with_partial_intermediate_unknown(self) -> None:
        units, program, facts = _project_chain_fixture()
        request = next(unit for unit in units if unit.id.name == "_aead_recvmsg")
        tail = next(
            unit
            for unit in units
            if unit.id.name == "crypto_authenc_esn_decrypt_tail"
        )
        facts[request.id].status = "partial"
        facts[request.id].payload["coverage"] = "partial"
        facts[request.id].payload["unknowns"].append("unrelated parser uncertainty")
        facts[tail.id].payload["unknowns"].append("unrelated tail uncertainty")

        chain = compose_project_chain(facts, program)

        self.assertEqual("VULNERABLE", chain["verdict"])
        self.assertTrue(chain["path"])
        self.assertEqual(
            [
                "SEED",
                "FIELD",
                "FIELD",
                "ALIAS",
                "REQUIRE_WRITE",
                "ARG",
                "REGISTER",
                "DISPATCH",
                "ALIAS",
                "ARG",
                "WRITEBACK",
            ],
            [step["kind"] for step in chain["path"]],
        )

    def test_project_chain_missing_required_hop_is_needs_review_not_safe(self) -> None:
        units, program, facts = _project_chain_fixture()
        request = next(unit for unit in units if unit.id.name == "_aead_recvmsg")
        request_payload = facts[request.id].payload
        request_payload["effects"] = [
            effect
            for effect in request_payload["effects"]
            if effect["kind"] != "ROLE_BIND"
        ]

        chain = compose_project_chain(facts, program)

        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertNotEqual("SAFE", chain["verdict"])
        self.assertTrue(chain["path"])
        self.assertIsNotNone(chain["missing_premise"])

    def test_project_chain_unknown_facts_alone_cannot_create_path(self) -> None:
        unit = _unit("unknown_only")
        payload = _parse(_model([], []))
        payload["unknowns"].append("unrelated unknown fact")
        facts = {unit.id: _facts(unit, payload)}

        chain = compose_project_chain(facts, _program((unit,)))

        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertEqual([], chain["path"])

    def test_project_chain_partial_safe_cut_remains_needs_review(self) -> None:
        unit = _unit("partial_safe")
        payload = _parse(
            _model(
                [_input("param:src")],
                [
                    _effect(
                        1,
                        "DEEP_COPY",
                        "param:src",
                        "param:dst",
                        identity="FRESH",
                        region="DISJOINT",
                    ),
                ],
            )
        )
        payload["coverage"] = "partial"
        payload["unknowns"].append("unrelated safe-path uncertainty")
        facts = {unit.id: _facts(unit, payload)}

        chain = compose_project_chain(facts, _program((unit,)))

        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertNotEqual("SAFE", chain["verdict"])

    def test_project_chain_error_envelope_remains_review_and_local_check_is_error(self) -> None:
        units, program, facts = _project_chain_fixture()
        request = next(unit for unit in units if unit.id.name == "_aead_recvmsg")
        facts[request.id].status = "error"

        chain = compose_project_chain(facts, program)
        local = CapabilityPlugin().check(facts[request.id], _context(request, program))

        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertEqual("ERROR", local.verdict)

    def test_field_actuals_keep_one_stable_identity_and_deduplicate_paths(self) -> None:
        plugin = CapabilityPlugin()
        caller = _unit(
            "caller",
            "void caller(struct msg *msg, struct req *req) { forward(msg, req); }",
            ("msg", "req"),
        )
        callee = _unit("forward", params=("src", "dst"))
        caller_payload = _parse(_model([_input("param:msg.msg_iter")], []))
        callee_payload = _parse(
            _model(
                [_input("param:src.page")],
                [_effect(1, "FIELD", "param:src.page", "param:dst.tail")],
            )
        )
        site = CallSite(
            caller.id,
            callee.id,
            "forward",
            order_index=2,
            arg_bindings={
                "param:src": "msg->msg_iter",
                "param:dst": "&req->dst",
            },
        )
        program = _program((caller, callee), (site,))
        context = _context(caller, program, (site,))
        resolved = ResolvedCall(site, _facts(callee, callee_payload))

        composed = plugin.compose_calls(
            _facts(caller, caller_payload),
            (resolved, resolved),
            context,
        )

        inherited = next(
            item for item in composed.payload["inputs"]
            if item["formal"] == "param:msg.msg_iter.page"
        )
        self.assertEqual("param:msg.msg_iter.page", inherited["resource_id"])
        transferred = next(
            effect for effect in composed.payload["effects"]
            if effect["target"] == "param:req.dst.tail"
        )
        self.assertEqual("param:msg.msg_iter.page", transferred["source"])
        self.assertEqual(3, len(composed.payload["resource_flows"]))
        self.assertEqual(
            len(composed.payload["resource_flows"]),
            len({
                json.dumps(flow, sort_keys=True)
                for flow in composed.payload["resource_flows"]
            }),
        )
        self.assertEqual(
            len(composed.payload["propagation_chain"]),
            len(set(composed.payload["propagation_chain"])),
        )

    def test_source_callback_assignment_with_bridge_emits_trusted_registration(self) -> None:
        source = "\n".join((
            "void bind(struct instance *inst, struct template *tmpl) {",
            "  inst->alg.decrypt = chosen_decrypt_callback;",
            "  aead_register_instance(tmpl, inst);",
            "}",
        ))
        unit = _unit("bind", source, ("inst", "tmpl"))

        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        registrations = [
            effect for effect in effects if effect["kind"] == "REGISTER"
        ]
        self.assertEqual(1, len(registrations))
        self.assertEqual(
            (
                "resource:function.chosen_decrypt_callback",
                "global:aead_alg.decrypt",
                "SAME",
                "OVERLAP",
                "CONTRACT",
            ),
            (
                registrations[0]["source"],
                registrations[0]["target"],
                registrations[0]["identity"],
                registrations[0]["region"],
                registrations[0]["evidence"]["authority"],
            ),
        )
        self.assertTrue(registrations[0]["evidence"]["lines"])

    def test_real_authencesn_create_source_emits_trusted_registration(self) -> None:
        unit = _real_c_unit(
            "crypto_authenc_esn_create",
            _REAL_REGISTRATION_SOURCE,
        )

        self.assertEqual(("tmpl", "tb"), tuple(unit.params))
        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        registrations = [
            effect for effect in effects if effect["kind"] == "REGISTER"
        ]
        self.assertEqual(1, len(registrations))
        self.assertEqual(
            "resource:function.crypto_authenc_esn_decrypt",
            registrations[0]["source"],
        )
        self.assertEqual(
            "global:aead_alg.decrypt",
            registrations[0]["target"],
        )
        self.assertEqual("CONTRACT", registrations[0]["evidence"]["authority"])

    def test_real_crypto_aead_decrypt_source_emits_trusted_dispatch(self) -> None:
        unit = _real_c_unit("crypto_aead_decrypt", _REAL_DISPATCH_SOURCE)

        self.assertEqual(("req",), tuple(unit.params))
        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        dispatches = [
            effect for effect in effects if effect["kind"] == "DISPATCH"
        ]
        self.assertEqual(1, len(dispatches))
        self.assertEqual(
            "global:aead_alg.decrypt",
            dispatches[0]["source"],
        )
        self.assertEqual("param:req", dispatches[0]["target"])
        self.assertEqual("CONTRACT", dispatches[0]["evidence"]["authority"])

    def test_callback_assignment_without_bridge_emits_no_registration(self) -> None:
        source = (
            "void bind(struct instance *inst) "
            "{ inst->alg.decrypt = chosen_decrypt_callback; }"
        )
        unit = _unit("bind_without_bridge", source, ("inst",))

        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual(
            [],
            [effect for effect in effects if effect["kind"] == "REGISTER"],
        )

    def test_registration_bridge_without_assignment_emits_no_registration(self) -> None:
        source = (
            "void bind(struct instance *inst, struct template *tmpl) "
            "{ aead_register_instance(tmpl, inst); }"
        )
        unit = _unit("bridge_without_assignment", source, ("inst", "tmpl"))

        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual(
            [],
            [effect for effect in effects if effect["kind"] == "REGISTER"],
        )

    def test_callback_assignment_to_wrong_slot_emits_no_registration(self) -> None:
        source = "\n".join((
            "void bind(struct instance *inst, struct template *tmpl) {",
            "  inst->alg.encrypt = chosen_decrypt_callback;",
            "  aead_register_instance(tmpl, inst);",
            "}",
        ))
        unit = _unit("wrong_registration_slot", source, ("inst", "tmpl"))

        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual(
            [],
            [effect for effect in effects if effect["kind"] == "REGISTER"],
        )

    def test_callback_assignment_on_wrong_object_emits_no_registration(self) -> None:
        source = "\n".join((
            "void bind(struct instance *inst, struct instance *other, struct template *tmpl) {",
            "  inst->alg.decrypt = chosen_decrypt_callback;",
            "  aead_register_instance(tmpl, other);",
            "}",
        ))
        unit = _unit(
            "wrong_registration_object",
            source,
            ("inst", "other", "tmpl"),
        )

        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual(
            [],
            [effect for effect in effects if effect["kind"] == "REGISTER"],
        )

    def test_source_indirect_member_call_emits_trusted_dispatch(self) -> None:
        source = "\n".join((
            "int run(struct request *req, struct aead *aead) {",
            "  return crypto_aead_alg(aead)->decrypt(req);",
            "}",
        ))
        unit = _unit("run", source, ("req", "aead"))

        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        dispatches = [
            effect for effect in effects if effect["kind"] == "DISPATCH"
        ]
        self.assertEqual(1, len(dispatches))
        self.assertEqual(
            (
                "global:aead_alg.decrypt",
                "param:req",
                "SAME",
                "OVERLAP",
                "CONTRACT",
            ),
            (
                dispatches[0]["source"],
                dispatches[0]["target"],
                dispatches[0]["identity"],
                dispatches[0]["region"],
                dispatches[0]["evidence"]["authority"],
            ),
        )
        self.assertTrue(dispatches[0]["evidence"]["lines"])

    def test_direct_callback_named_call_emits_no_dispatch(self) -> None:
        source = "int run(struct request *req) { return decrypt(req); }"
        unit = _unit("direct_run", source, ("req",))

        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual(
            [],
            [effect for effect in effects if effect["kind"] == "DISPATCH"],
        )

    def test_wrong_accessor_indirect_call_emits_no_dispatch(self) -> None:
        source = (
            "int run(struct request *req, struct aead *aead) "
            "{ return other_alg(aead)->decrypt(req); }"
        )
        unit = _unit("wrong_dispatch_accessor", source, ("req", "aead"))

        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual(
            [],
            [effect for effect in effects if effect["kind"] == "DISPATCH"],
        )

    def test_aead_contract_requires_distinct_destination_write_obligation(self) -> None:
        source = "void f(struct req *req, struct buf *src, struct buf *dst) { aead_request_set_crypt(req, src, dst, 4, 0); }"
        unit = _unit("aead_distinct", source, ("req", "src", "dst"))

        _, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual(
            [
                ("FIELD", "param:src", "param:req.src"),
                ("FIELD", "param:dst", "param:req.dst"),
            ],
            [
                (effect["kind"], effect["source"], effect["target"])
                for effect in effects
                if effect["kind"] == "FIELD"
            ],
        )
        obligations = [
            effect for effect in effects if effect["kind"] == "REQUIRE_WRITE"
        ]
        self.assertEqual(1, len(obligations))
        obligation = obligations[0]
        self.assertEqual("param:dst", obligation["source"])
        self.assertEqual("param:dst", obligation["target"])
        self.assertEqual("SAME", obligation["identity"])
        self.assertEqual("OVERLAP", obligation["region"])
        self.assertEqual("CONTRACT", obligation["evidence"]["authority"])
        self.assertEqual([], [effect for effect in effects if effect["kind"] == "GRANT"])

        destination_field = next(
            effect
            for effect in effects
            if effect["kind"] == "FIELD" and effect["source"] == "param:dst"
        )
        self.assertEqual("param:req.dst", destination_field["target"])
        self.assertEqual("SAME", destination_field["identity"])
        self.assertEqual("OVERLAP", destination_field["region"])

    def test_aead_destination_field_joins_seeded_actual_to_request_destination(self) -> None:
        unit = _unit("aead_destination_join", params=("dst", "req"))
        payload = _parse(
            _model(
                [_input("param:dst")],
                [
                    _effect(1, "FIELD", "param:dst", "local:sgl"),
                    _effect(2, "FIELD", "local:sgl", "local:aead_req.dst"),
                    _effect(3, "REQUIRE_WRITE", "local:sgl", "local:sgl"),
                ],
            )
        )

        chain = compose_project_chain(
            {unit.id: _facts(unit, payload)},
            _program((unit,)),
        )

        self.assertEqual(
            ["SEED", "FIELD", "REQUIRE_WRITE", "FIELD"],
            [step["kind"] for step in chain["path"]],
        )
        self.assertEqual("local:aead_req.dst", chain["path"][-1]["target"])
        self.assertEqual("NEEDS_REVIEW", chain["verdict"])

    def test_destination_obligation_without_seed_flow_cannot_create_vulnerable_chain(self) -> None:
        unit = _unit("aead_no_flow", params=("seed", "dst"))
        payload = _parse(
            _model(
                [_input("param:seed")],
                [
                    _effect(1, "REQUIRE_WRITE", "param:dst", "param:dst"),
                    _effect(2, "WRITE", None, "param:dst"),
                ],
            )
        )

        chain = compose_project_chain(
            {unit.id: _facts(unit, payload)},
            _program((unit,)),
        )

        self.assertEqual("NEEDS_REVIEW", chain["verdict"])
        self.assertNotIn(
            "REQUIRE_WRITE",
            [step["kind"] for step in chain["path"]],
        )

    def test_contract_pack_builds_trusted_generic_source_obligation_and_sink(self) -> None:
        plugin = CapabilityPlugin(DEFAULT_CONTRACT_PROVIDER)
        source = "\n".join(
            (
                "void transform(struct msg *msg, struct request *req, struct sg *buf) {",
                "  extract_iter_to_sg(&msg->msg_iter, 4, buf, 1, 0);",
                "  aead_request_set_crypt(req, buf, buf, 4, 0);",
                "  scatterwalk_map_and_copy(tmp, buf, 0, 4, 1);",
                "}",
            )
        )
        unit = _unit("transform", source, ("msg", "req", "buf"))
        context = _context(unit)
        request = AbstractionRequest(unit, context)
        raw = _tagged(_model([], []))

        facts = plugin.parse_abstraction_response(request, raw)

        self.assertIsNotNone(facts)
        verdict = plugin.check(facts, context)
        caller_summary = json.loads(plugin.summarize_for_caller(facts))
        self.assertEqual("VULNERABLE", verdict.verdict)
        self.assertEqual(
            ["GRANTED", "DENIED"],
            facts.payload["inputs"][0]["write_authority"],
        )
        self.assertIn("REQUIRE_WRITE", [item["kind"] for item in facts.payload["effects"]])
        self.assertEqual("USER_CONTROLLED", caller_summary["inputs"][0]["reference_origin"])
        self.assertTrue(caller_summary["obligations"])

    def test_real_extract_iter_contract_seeds_formal_iterator_and_field_flow(self) -> None:
        source = "\n".join((
            "int af_alg_get_rsgl(struct sock *sk, struct msg *msg, int flags,",
            "                     struct aead_request *areq, unsigned int maxsize,",
            "                     unsigned int *outlen)",
            "{",
            "    extract_iter_to_sg(&msg->msg_iter, seglen, &rsgl->sgl.sgt, flags);",
            "}",
        ))
        unit = _unit(
            "af_alg_get_rsgl_contract",
            source,
            ("sk", "msg", "flags", "areq", "maxsize", "outlen"),
        )

        inputs, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual(1, len(inputs))
        self.assertEqual(
            {
                "formal": "param:msg.msg_iter",
                "resource_id": "param:msg.msg_iter",
                "reference_origin": "USER_CONTROLLED",
                "possible_backing": [
                    "WRITABLE_PRIVATE",
                    "READONLY_MAPPING",
                    "PROTECTED_SHARED",
                ],
                "write_authority": ["GRANTED", "DENIED"],
                "role": "INPUT",
                "identity": "SAME",
                "evidence": {"authority": "CONTRACT", "lines": [5]},
            },
            inputs[0],
        )
        self.assertEqual(
            [
                (
                    "FIELD",
                    "param:msg.msg_iter",
                    "local:rsgl.sgl.sgt",
                    "SAME",
                ),
            ],
            [
                (effect["kind"], effect["source"], effect["target"], effect["identity"])
                for effect in effects
            ],
        )

    def test_contract_seed_rejects_non_formal_local_iterator(self) -> None:
        source = (
            "void local_iterator(struct msg *msg) { "
            "struct iter *it; "
            "extract_iter_to_sg(it, seglen, &msg->dst, flags); }"
        )
        unit = _unit("local_iterator", source, ("msg",))

        inputs, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual([], inputs)
        self.assertEqual(
            [("FIELD", "local:it", "param:msg.dst")],
            [(effect["kind"], effect["source"], effect["target"]) for effect in effects],
        )

    def test_unknown_api_and_ordinary_copy_emit_no_contract_seed(self) -> None:
        source = (
            "void ordinary_copy(struct msg *msg) { "
            "ordinary_copy(&msg->msg_iter, dst); "
            "unknown_extract(&msg->msg_iter, dst); }"
        )
        unit = _unit("ordinary_copy", source, ("msg",))

        inputs, effects = contract_facts(unit, DEFAULT_CONTRACT_PROVIDER)

        self.assertEqual([], inputs)
        self.assertEqual([], effects)


class CapabilityRelevanceSliceTests(unittest.TestCase):
    def test_contract_pack_selector_disables_all_packs(self) -> None:
        # Given
        unit = _unit(
            "seed_user_input",
            "void seed_user_input(void *user_input) { user_input; }",
            ("user_input",),
        )

        # When
        with patch.dict(
            os.environ,
            {"CAPABILITY_CONTRACT_PACKS": "none"},
        ):
            plugin = CapabilityPlugin()
            plugin.select_relevance_slice(_program((unit,)))

        # Then
        self.assertEqual("disabled", plugin.analysis_scope["contract_mode"])
        self.assertEqual([], plugin.analysis_scope["contract_packs"])

    def test_contract_pack_selector_enables_linux_pack(self) -> None:
        # Given
        unit = _unit(
            "seed_user_input",
            "void seed_user_input(void *user_input) { user_input; }",
            ("user_input",),
        )

        # When
        with patch.dict(
            os.environ,
            {
                "CAPABILITY_CONTRACT_PACKS": "linux",
                "CAPABILITY_DISABLE_CONTRACTS": "1",
            },
        ):
            plugin = CapabilityPlugin()
            plugin.select_relevance_slice(_program((unit,)))

        # Then
        self.assertEqual("enabled", plugin.analysis_scope["contract_mode"])
        self.assertEqual(
            ["linux-resource-v1"],
            plugin.analysis_scope["contract_packs"],
        )

    def test_contract_pack_selector_rejects_unavailable_pack(self) -> None:
        # Given / When / Then
        with patch.dict(
            os.environ,
            {"CAPABILITY_CONTRACT_PACKS": "c"},
        ):
            with self.assertRaisesRegex(
                ValueError,
                "available contract packs: auto, linux, none",
            ):
                CapabilityPlugin()

    def test_environment_disables_contract_dispatch_closure(self) -> None:
        # Given
        seed = _unit(
            "seed_user_input",
            "void seed_user_input(void *user_input) { user_input; }",
            ("user_input",),
        )
        dispatcher = _real_c_unit("crypto_aead_decrypt", _REAL_DISPATCH_SOURCE)
        registrar = _real_c_unit(
            "crypto_authenc_esn_create",
            _REAL_REGISTRATION_SOURCE,
        )
        implementation = _real_c_unit(
            "crypto_authenc_esn_decrypt",
            "\n".join((
                "int crypto_authenc_esn_decrypt(struct aead_request *req)",
                "{",
                "    return write(req);",
                "}",
            )),
        )
        site = CallSite(seed.id, dispatcher.id, dispatcher.id.name, order_index=1)
        program = _program((seed, dispatcher, registrar, implementation), (site,))

        # When
        with patch.dict(
            os.environ,
            {
                "CAPABILITY_DISABLE_CONTRACTS": "1",
                "CAPABILITY_MAX_FUNCTIONS": "2",
            },
        ):
            plugin = CapabilityPlugin()
            selected = plugin.select_relevance_slice(program)

        # Then
        self.assertEqual({seed.id, dispatcher.id}, set(selected.function_ids))
        self.assertEqual("disabled", plugin.analysis_scope["contract_mode"])

    def test_contract_mode_changes_analysis_fingerprint(self) -> None:
        # Given
        unit = _unit(
            "seed_user_input",
            "void seed_user_input(void *user_input) { user_input; }",
            ("user_input",),
        )
        program = _program((unit,))

        # When
        enabled = CapabilityPlugin(DEFAULT_CONTRACT_PROVIDER)
        enabled_slice = enabled.select_relevance_slice(program)
        with patch.dict(
            os.environ,
            {"CAPABILITY_DISABLE_CONTRACTS": "1"},
        ):
            disabled = CapabilityPlugin()
            disabled_slice = disabled.select_relevance_slice(program)

        # Then
        self.assertEqual(enabled_slice.function_ids, disabled_slice.function_ids)
        self.assertNotEqual(
            enabled_slice.fingerprint,
            disabled_slice.fingerprint,
        )

    def test_abstraction_protocol_change_invalidates_analysis_fingerprint(self) -> None:
        # Given
        unit = _unit(
            "seed_user_input",
            "void seed_user_input(void *user_input) { user_input; }",
            ("user_input",),
        )
        program = _program((unit,))
        plugin = CapabilityPlugin(DEFAULT_CONTRACT_PROVIDER)

        # When
        with patch(
            "src.plugins.capability._ABSTRACTION_PROTOCOL_VERSION",
            "capability-prompt-a",
            create=True,
        ):
            first = plugin.select_relevance_slice(program)
        with patch(
            "src.plugins.capability._ABSTRACTION_PROTOCOL_VERSION",
            "capability-prompt-b",
            create=True,
        ):
            second = plugin.select_relevance_slice(program)

        # Then
        self.assertNotEqual(
            first.fingerprint,
            second.fingerprint,
            "Capability prompt protocol changes reused a stale analysis fingerprint",
        )

    def test_dispatch_slice_closes_over_exact_source_registration(self) -> None:
        # Given
        seed = _unit(
            "seed_user_input",
            "void seed_user_input(void *user_input) { user_input; }",
            ("user_input",),
        )
        dispatcher = _real_c_unit("crypto_aead_decrypt", _REAL_DISPATCH_SOURCE)
        registrar = _real_c_unit(
            "crypto_authenc_esn_create",
            _REAL_REGISTRATION_SOURCE,
        )
        implementation = _real_c_unit(
            "crypto_authenc_esn_decrypt",
            "\n".join((
                "int crypto_authenc_esn_decrypt(struct aead_request *req)",
                "{",
                "    return write(req);",
                "}",
            )),
        )
        site = CallSite(seed.id, dispatcher.id, dispatcher.id.name, order_index=1)
        program = _program((seed, dispatcher, registrar, implementation), (site,))
        plugin = CapabilityPlugin(DEFAULT_CONTRACT_PROVIDER)

        # When
        with patch.dict(os.environ, {"CAPABILITY_MAX_FUNCTIONS": "2"}):
            selected = plugin.select_relevance_slice(program)

        # Then
        self.assertEqual(
            {seed.id, dispatcher.id, registrar.id, implementation.id},
            set(selected.function_ids),
        )
        self.assertEqual(4, plugin.analysis_scope["selected_functions"])
        self.assertEqual(0, plugin.analysis_scope["skipped_functions"])

    def test_dispatch_slice_enumerates_ambiguous_registered_implementations(self) -> None:
        # Given
        seed = _unit(
            "seed_user_input",
            "void seed_user_input(void *user_input) { user_input; }",
            ("user_input",),
        )
        dispatcher = _real_c_unit("crypto_aead_decrypt", _REAL_DISPATCH_SOURCE)
        registrar = _real_c_unit(
            "crypto_authenc_esn_create",
            _REAL_REGISTRATION_SOURCE,
        )
        implementation_a = _unit(
            "crypto_authenc_esn_decrypt_a",
            "int crypto_authenc_esn_decrypt(void *req) { return write(req); }",
            ("req",),
        )
        implementation_a = FunctionUnit(
            FunctionId(
                implementation_a.id.rel,
                implementation_a.id.name,
                "crypto_authenc_esn_decrypt",
                implementation_a.id.language,
            ),
            implementation_a.source,
            implementation_a.signature_line,
            params=implementation_a.params,
        )
        implementation_b = _unit(
            "crypto_authenc_esn_decrypt_b",
            "int crypto_authenc_esn_decrypt(void *req) { return write(req); }",
            ("req",),
        )
        implementation_b = FunctionUnit(
            FunctionId(
                implementation_b.id.rel,
                implementation_b.id.name,
                "crypto_authenc_esn_decrypt",
                implementation_b.id.language,
            ),
            implementation_b.source,
            implementation_b.signature_line,
            params=implementation_b.params,
        )
        site = CallSite(seed.id, dispatcher.id, dispatcher.id.name, order_index=1)
        program = _program(
            (seed, dispatcher, registrar, implementation_a, implementation_b),
            (site,),
        )

        # When
        with patch.dict(os.environ, {"CAPABILITY_MAX_FUNCTIONS": "2"}):
            selected = CapabilityPlugin(
                DEFAULT_CONTRACT_PROVIDER,
            ).select_relevance_slice(program)

        # Then
        self.assertEqual(
            {
                seed.id,
                dispatcher.id,
                registrar.id,
                implementation_a.id,
                implementation_b.id,
            },
            set(selected.function_ids),
        )

    def test_dispatch_slice_prefers_static_implementation_in_registrar_unit(self) -> None:
        seed = _unit(
            "seed_user_input",
            "void seed_user_input(void *user_input) { user_input; }",
            ("user_input",),
        )
        dispatcher = _real_c_unit("crypto_aead_decrypt", _REAL_DISPATCH_SOURCE)
        registrar = _real_c_unit(
            "crypto_authenc_esn_create",
            _REAL_REGISTRATION_SOURCE,
        )
        local = _unit(
            "crypto_authenc_esn_decrypt_local",
            "static int crypto_authenc_esn_decrypt(void *req) { return write(req); }",
            ("req",),
        )
        remote = _unit(
            "crypto_authenc_esn_decrypt_remote",
            "static int crypto_authenc_esn_decrypt(void *req) { return write(req); }",
            ("req",),
        )

        def located(unit: FunctionUnit, rel: str) -> FunctionUnit:
            return FunctionUnit(
                FunctionId(unit.id.rel, unit.id.name, "crypto_authenc_esn_decrypt", unit.id.language),
                unit.source,
                unit.signature_line,
                params=unit.params,
                original_rel=rel,
            )

        registrar = FunctionUnit(
            registrar.id,
            registrar.source,
            registrar.signature_line,
            params=registrar.params,
            original_rel="crypto/authencesn.c",
        )
        local = located(local, "crypto/authencesn.c")
        remote = located(remote, "crypto/other.c")
        site = CallSite(seed.id, dispatcher.id, dispatcher.id.name, order_index=1)
        program = _program((seed, dispatcher, registrar, local, remote), (site,))

        with patch.dict(os.environ, {"CAPABILITY_MAX_FUNCTIONS": "2"}):
            selected = CapabilityPlugin(
                DEFAULT_CONTRACT_PROVIDER,
            ).select_relevance_slice(program)

        self.assertIn(local.id, selected.function_ids)
        self.assertNotIn(remote.id, selected.function_ids)

    def test_noise_slice_retains_copyfail_resource_chain(self) -> None:
        names = (
            "af_alg_sendmsg",
            "af_alg_get_rsgl",
            "_aead_recvmsg",
            "crypto_aead_decrypt",
            "crypto_authenc_esn_decrypt",
            "memcpy_to_scatterwalk",
        )
        critical = tuple(
            _unit(
                name,
                f"void {name}(void *resource) {{ resource->field = write(resource); }}",
            )
            for name in names
        )
        noise = tuple(
            _unit(f"noise_{index:03d}", "void noise(void *value) { value; }")
            for index in range(80)
        )
        sites = tuple(
            CallSite(left.id, right.id, right.id.name, order_index=index)
            for index, (left, right) in enumerate(zip(critical, critical[1:]))
        )
        plugin = CapabilityPlugin()
        program = _program(critical + noise, sites)

        selected = plugin.select_relevance_slice(program)

        self.assertTrue({unit.id for unit in critical} <= set(selected.function_ids))
        self.assertLessEqual(len(selected.function_ids), 2000)
        self.assertEqual(2000, plugin.analysis_scope["cap"])
        self.assertEqual(
            selected.function_ids,
            plugin.select_relevance_slice(program).function_ids,
        )

    def test_complete_small_program_keeps_every_function(self) -> None:
        units = tuple(_unit(f"small_{index}", "void small(void) { 0; }", ()) for index in range(3))
        plugin = CapabilityPlugin()

        selected = plugin.select_relevance_slice(_program(units))

        self.assertEqual(tuple(unit.id for unit in units), selected.function_ids)


if __name__ == "__main__":
    unittest.main()
