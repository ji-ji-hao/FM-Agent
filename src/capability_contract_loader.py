from __future__ import annotations

# noqa: SIZE_OK - focused boundary parser for one capability-contract schema.

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from src.capability_contracts import (
    ApiContract,
    ContractPack,
    DispatchContract,
    EffectContract,
    RegistrationContract,
    StaticContractProvider,
)


_SCHEMA: Final = "capability-contract.v1"
_EFFECT_KINDS: Final = frozenset({
    "ALIAS", "ARG", "FIELD", "GRANT", "REQUIRE_WRITE", "RETURN", "ROLE_BIND",
    "WRITE", "WRITEBACK",
})
_RESULT_CONDITIONS: Final = frozenset({"FALSY", "TRUTHY"})
DEFAULT_CONTRACT_DIR: Final = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "capability"
)
DEFAULT_CONTRACT_PATH: Final = DEFAULT_CONTRACT_DIR / "linux-resource-v1.json"
ContractDefinition = ApiContract | RegistrationContract | DispatchContract
_CONSTANT_RESOURCE_RE: Final = re.compile(
    r"(?:global|resource):[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){0,16}"
)


class ContractPackLoadError(ValueError):
    def __init__(self, source: str, reason: str) -> None:
        self.source = source
        self.reason = reason
        super().__init__(f"invalid capability contract pack {source!r}: {reason}")


def _object(value: Any, source: str, allowed: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ContractPackLoadError(source, "expected a JSON object")
    unknown = set(value) - allowed
    if unknown:
        raise ContractPackLoadError(
            source,
            f"unknown fields: {', '.join(sorted(unknown))}",
        )
    return value


def _required(data: Mapping[str, Any], key: str, source: str) -> Any:
    if key not in data:
        raise ContractPackLoadError(source, f"missing field {key!r}")
    return data[key]


def _string(value: Any, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractPackLoadError(source, "expected a non-empty string")
    return value


def _integer(value: Any, source: str, *, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if type(value) is not int or value < 0:
        raise ContractPackLoadError(source, "expected a non-negative integer")
    return value


def _items(value: Any, source: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise ContractPackLoadError(source, "expected a JSON array")
    return value


def _constant_resource(value: Any, source: str) -> str | None:
    if value is None:
        return None
    resource = _string(value, source)
    if _CONSTANT_RESOURCE_RE.fullmatch(resource) is None:
        raise ContractPackLoadError(
            source,
            "expected a global: or resource: capability identifier",
        )
    return resource


def _effect(value: Any, source: str) -> EffectContract:
    fields = {
        "kind", "source_arg", "target_arg", "source_suffix", "target_suffix",
        "identity", "region", "when_arg", "when_value", "target_return",
        "source_resource", "target_resource", "when_result",
        "failure_terminates_with",
    }
    data = _object(value, source, fields)
    kind = _string(_required(data, "kind", source), f"{source}.kind")
    if kind not in _EFFECT_KINDS:
        raise ContractPackLoadError(source, f"unsupported effect kind {kind!r}")
    target_return = data.get("target_return", False)
    if not isinstance(target_return, bool):
        raise ContractPackLoadError(f"{source}.target_return", "expected boolean")
    when_value = data.get("when_value")
    if when_value is not None:
        when_value = _string(when_value, f"{source}.when_value")
    when_result = data.get("when_result")
    if when_result is not None:
        when_result = _string(when_result, f"{source}.when_result")
        if when_result not in _RESULT_CONDITIONS:
            raise ContractPackLoadError(
                f"{source}.when_result",
                f"expected one of {', '.join(sorted(_RESULT_CONDITIONS))}",
            )
    failure_terminates_with = data.get("failure_terminates_with")
    if failure_terminates_with is not None:
        failure_terminates_with = _string(
            failure_terminates_with,
            f"{source}.failure_terminates_with",
        )
    if (when_result is None) != (failure_terminates_with is None):
        raise ContractPackLoadError(
            source,
            "when_result and failure_terminates_with must be provided together",
        )
    if when_result is not None and kind != "GRANT":
        raise ContractPackLoadError(
            source,
            "result conditions are only valid for GRANT effects",
        )
    source_arg = _integer(
        _required(data, "source_arg", source),
        f"{source}.source_arg",
        optional=True,
    )
    target_arg = _integer(
        _required(data, "target_arg", source),
        f"{source}.target_arg",
        optional=True,
    )
    source_resource = _constant_resource(
        data.get("source_resource"),
        f"{source}.source_resource",
    )
    target_resource = _constant_resource(
        data.get("target_resource"),
        f"{source}.target_resource",
    )
    if source_arg is not None and source_resource is not None:
        raise ContractPackLoadError(
            source,
            "source_arg and source_resource are mutually exclusive",
        )
    if sum((
        target_arg is not None,
        target_return,
        target_resource is not None,
    )) > 1:
        raise ContractPackLoadError(
            source,
            "target_arg, target_return, and target_resource are mutually exclusive",
        )
    return EffectContract(
        kind=kind,
        source_arg=source_arg,
        target_arg=target_arg,
        source_suffix=_string(data.get("source_suffix", ""), f"{source}.source_suffix")
        if data.get("source_suffix", "") else "",
        target_suffix=_string(data.get("target_suffix", ""), f"{source}.target_suffix")
        if data.get("target_suffix", "") else "",
        identity=_string(data.get("identity", "SAME"), f"{source}.identity"),
        region=_string(data.get("region", "OVERLAP"), f"{source}.region"),
        when_arg=_integer(
            data.get("when_arg"),
            f"{source}.when_arg",
            optional=True,
        ),
        when_value=when_value,
        target_return=target_return,
        source_resource=source_resource,
        target_resource=target_resource,
        when_result=when_result,
        failure_terminates_with=failure_terminates_with,
    )


def _api(value: Any, source: str) -> ApiContract:
    data = _object(
        value,
        source,
        {"symbol", "seed_arg", "seed_requires_formal", "effects"},
    )
    seed_requires_formal = data.get("seed_requires_formal", True)
    if not isinstance(seed_requires_formal, bool):
        raise ContractPackLoadError(
            f"{source}.seed_requires_formal",
            "expected boolean",
        )
    effects = _items(_required(data, "effects", source), f"{source}.effects")
    return ApiContract(
        symbol=_string(_required(data, "symbol", source), f"{source}.symbol"),
        seed_arg=_integer(
            _required(data, "seed_arg", source),
            f"{source}.seed_arg",
            optional=True,
        ),
        effects=tuple(
            _effect(item, f"{source}.effects[{index}]")
            for index, item in enumerate(effects)
        ),
        seed_requires_formal=seed_requires_formal,
    )


def _registration(value: Any, source: str) -> RegistrationContract:
    keys = {
        "bridge_symbol", "bridge_object_arg", "assignment_slot", "canonical_slot",
    }
    data = _object(value, source, keys)
    return RegistrationContract(
        _string(_required(data, "bridge_symbol", source), f"{source}.bridge_symbol"),
        _integer(
            _required(data, "bridge_object_arg", source),
            f"{source}.bridge_object_arg",
        ),
        _string(_required(data, "assignment_slot", source), f"{source}.assignment_slot"),
        _string(_required(data, "canonical_slot", source), f"{source}.canonical_slot"),
    )


def _dispatch(value: Any, source: str) -> DispatchContract:
    keys = {"accessor_symbol", "member", "target_arg", "canonical_slot"}
    data = _object(value, source, keys)
    return DispatchContract(
        _string(_required(data, "accessor_symbol", source), f"{source}.accessor_symbol"),
        _string(_required(data, "member", source), f"{source}.member"),
        _integer(_required(data, "target_arg", source), f"{source}.target_arg"),
        _string(_required(data, "canonical_slot", source), f"{source}.canonical_slot"),
    )


def load_contract_pack(path: str | Path) -> ContractPack:
    contract_path = Path(path).expanduser().resolve()
    source = str(contract_path)
    try:
        raw = contract_path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractPackLoadError(source, str(error)) from error
    fields = {
        "schema_version", "name", "version", "authority", "languages",
        "apis", "registrations", "dispatches",
    }
    data = _object(payload, source, fields)
    schema = _string(_required(data, "schema_version", source), f"{source}.schema_version")
    if schema != _SCHEMA:
        raise ContractPackLoadError(source, f"unsupported schema {schema!r}")
    authority = _string(_required(data, "authority", source), f"{source}.authority")
    if authority != "TRUSTED":
        raise ContractPackLoadError(source, "authority must be 'TRUSTED'")
    languages = _items(_required(data, "languages", source), f"{source}.languages")
    apis = _items(_required(data, "apis", source), f"{source}.apis")
    registrations = _items(data.get("registrations", []), f"{source}.registrations")
    dispatches = _items(data.get("dispatches", []), f"{source}.dispatches")
    return ContractPack(
        name=_string(_required(data, "name", source), f"{source}.name"),
        languages=tuple(_string(item, f"{source}.languages") for item in languages),
        contracts=tuple(_api(item, f"{source}.apis[{i}]") for i, item in enumerate(apis)),
        version=_string(_required(data, "version", source), f"{source}.version"),
        authority=authority,
        source_path=source,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        registrations=tuple(
            _registration(item, f"{source}.registrations[{i}]")
            for i, item in enumerate(registrations)
        ),
        dispatches=tuple(
            _dispatch(item, f"{source}.dispatches[{i}]")
            for i, item in enumerate(dispatches)
        ),
    )


def _reject_conflicts(packs: Sequence[ContractPack]) -> None:
    seen: dict[tuple[str, str, str], ContractDefinition] = {}
    groups = (
        ("API", "contracts", lambda item: item.symbol),
        ("registration", "registrations", lambda item: f"{item.bridge_symbol}:{item.assignment_slot}"),
        ("dispatch", "dispatches", lambda item: f"{item.accessor_symbol}:{item.member}"),
    )
    for pack in packs:
        for label, field, key_of in groups:
            for language in pack.languages:
                for item in getattr(pack, field):
                    key = (label, language, key_of(item))
                    previous = seen.setdefault(key, item)
                    if previous != item:
                        raise ContractPackLoadError(
                            pack.source_path or pack.name,
                            f"conflicting {label} contract for {language}:{key[2]}",
                        )


def load_contract_provider(paths: Sequence[str | Path]) -> StaticContractProvider:
    packs = tuple(load_contract_pack(path) for path in paths)
    _reject_conflicts(packs)
    return StaticContractProvider(packs)


def _bundled_contract_paths() -> tuple[Path, ...]:
    return tuple(sorted(DEFAULT_CONTRACT_DIR.glob("*.json"), key=lambda path: path.name))


LINUX_CONTRACT_PROVIDER: Final = load_contract_provider((DEFAULT_CONTRACT_PATH,))
DEFAULT_CONTRACT_PROVIDER: Final = load_contract_provider(_bundled_contract_paths())
NO_CONTRACT_PROVIDER: Final = StaticContractProvider(())


def configured_contract_provider() -> StaticContractProvider:
    selected_paths = os.environ.get("CAPABILITY_CONTRACT_PATHS")
    if selected_paths is not None:
        if selected_paths.strip().lower() == "none":
            return NO_CONTRACT_PROVIDER
        paths = tuple(path for path in selected_paths.split(os.pathsep) if path.strip())
        if not paths:
            raise ContractPackLoadError("CAPABILITY_CONTRACT_PATHS", "no paths selected")
        return load_contract_provider(paths)
    selection = os.environ.get("CAPABILITY_CONTRACT_PACKS", "").strip().lower()
    if selection:
        if selection == "none":
            return NO_CONTRACT_PROVIDER
        if selection not in {"auto", "linux"}:
            raise ContractPackLoadError(
                "CAPABILITY_CONTRACT_PACKS",
                f"unknown selection {selection!r}; "
                "available contract packs: auto, linux, none",
            )
        if selection == "linux":
            return LINUX_CONTRACT_PROVIDER
        return DEFAULT_CONTRACT_PROVIDER
    if os.environ.get("CAPABILITY_DISABLE_CONTRACTS", "").strip() == "1":
        return NO_CONTRACT_PROVIDER
    return NO_CONTRACT_PROVIDER
