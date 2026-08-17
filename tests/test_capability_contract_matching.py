import unittest

from src.capability_contracts import (
    ContractPack,
    DispatchContract,
    StaticContractProvider,
    contract_facts,
)
from src.plugins.base import FunctionId, FunctionUnit
from src.plugins.capability import _profile


def _unit(source: str, params: tuple[str, ...] = ()) -> FunctionUnit:
    return FunctionUnit(
        FunctionId("test.c", "f", "f", "c"),
        source,
        "int f(void)",
        params=params,
    )


class CapabilityContractMatchingTests(unittest.TestCase):
    def test_profile_matches_exact_lexical_contract_symbols_only(self) -> None:
        symbols = frozenset({"target_api"})

        exact = _profile(_unit("int f(void) { target_api(); }"), symbols)
        substring = _profile(
            _unit(
                'int f(void) { my_target_api(); use("target_api()"); '
                "/* target_api(); */ }"
            ),
            symbols,
        )

        self.assertEqual(8, exact[1])
        self.assertEqual(0, substring[1])

    def test_dispatch_matches_accessor_and_accessor_derived_receiver(self) -> None:
        provider = StaticContractProvider((ContractPack(
            "dispatch-test",
            ("c",),
            (),
            dispatches=(DispatchContract(
                "crypto_aead_alg",
                "decrypt",
                0,
                "global:aead_alg.decrypt",
            ),),
        ),))
        immediate = _unit(
            "int f(void *tfm, void *req) { "
            "return crypto_aead_alg(tfm)->decrypt(req); }",
            ("tfm", "req"),
        )
        derived = _unit(
            "int f(void *tfm, void *req) { "
            "struct crypto_aead_alg *alg = crypto_aead_alg(tfm); "
            "return alg->decrypt(req); }",
            ("tfm", "req"),
        )

        for unit in (immediate, derived):
            with self.subTest(source=unit.source):
                _, effects = contract_facts(unit, provider)
                dispatches = [effect for effect in effects if effect["kind"] == "DISPATCH"]
                self.assertEqual(1, len(dispatches))
                self.assertEqual("param:req", dispatches[0]["target"])

    def test_dispatch_ignores_pointer_checks_and_unrelated_receivers(self) -> None:
        provider = StaticContractProvider((ContractPack(
            "dispatch-test",
            ("c",),
            (),
            dispatches=(DispatchContract(
                "crypto_aead_alg",
                "decrypt",
                0,
                "global:aead_alg.decrypt",
            ),),
        ),))
        unit = _unit(
            "int f(void *other, void *req) { "
            "if (other->decrypt) return other->decrypt(req); return 0; }",
            ("other", "req"),
        )

        _, effects = contract_facts(unit, provider)

        self.assertNotIn("DISPATCH", [effect["kind"] for effect in effects])


if __name__ == "__main__":
    unittest.main()
