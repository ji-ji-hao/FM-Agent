import unittest

from src.capability_scanner import scan_source


class CapabilityScannerTests(unittest.TestCase):
    def test_indirect_calls_expose_receiver_member_and_accessor(self) -> None:
        scanned = scan_source(
            "int f(void *alg, void *tfm, void *req) { "
            "alg->decrypt(req); crypto_aead_alg(tfm)->decrypt(req); "
            "if (alg->decrypt) return 1; return 0; }"
        )

        dispatches = [call for call in scanned.calls if call.member == "decrypt"]

        self.assertEqual(2, len(dispatches))
        self.assertEqual("alg", dispatches[0].receiver)
        self.assertIsNone(dispatches[0].accessor)
        self.assertEqual("crypto_aead_alg(tfm)", dispatches[1].receiver)
        self.assertEqual("crypto_aead_alg", dispatches[1].accessor)
        self.assertTrue(all(call.is_indirect for call in dispatches))

    def test_unsupported_syntax_reports_specific_kinds(self) -> None:
        scanned = scan_source(
            "#define WRAP(x) (x)\n"
            "int f(int x) { asm(\"nop\"); MACRO(x); return ({ x; }); }"
        )

        self.assertTrue(scanned.has_unsupported_syntax)
        self.assertEqual(
            (
                "preprocessor",
                "inline_asm",
                "uppercase_macro",
                "gnu_statement_expression",
            ),
            scanned.unsupported_syntax_kinds,
        )

    def test_typedef_structs_resolve_field_receiver_types_and_callbacks(self) -> None:
        scanned = scan_source(
            "typedef struct { int slot; } anon_ops_t; "
            "typedef struct named_ops { int slot; } named_ops_t; "
            "typedef struct forward_ops forward_ops_t; "
            "void f(anon_ops_t *anon, named_ops_t *named, forward_ops_t *forward) { "
            "anon->slot = anon_handler; named->slot = named_handler; "
            "forward->slot = forward_handler; }"
        )

        receiver_types = {
            store.receiver: store.receiver_type
            for store in scanned.field_stores
        }
        self.assertEqual("struct anon_ops_t", receiver_types["anon"])
        self.assertEqual("struct named_ops", receiver_types["named"])
        self.assertEqual("struct forward_ops", receiver_types["forward"])
        self.assertEqual(
            frozenset({"anon_handler", "named_handler", "forward_handler"}),
            scanned.callback_symbols,
        )
        self.assertIn("anon_ops_t", scanned.identifier_symbols)


if __name__ == "__main__":
    unittest.main()
