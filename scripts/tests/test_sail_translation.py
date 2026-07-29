"""Checked Sail-AST translation receipts, and the drift they must refuse.

The fixtures under `fixtures/sail_translation/` are reconstructions, not
captured generated Sail output; see the README in that directory. These tests
are therefore evidence about the receipt machinery, not about the pinned Sail
model.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts.riscv_refinement_lib import sail_translation as translation
from scripts.riscv_refinement_lib.sail_translation import SailTranslationError

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sail_translation"
NAMES = ("execute_UTYPE", "execute_ITYPE")

# Copied verbatim from sail.py::_validate_semantic_shapes. Duplicated rather
# than imported so that this test pins the fixtures independently of that
# module's current contents.
PINNED_PHRASES = {
    "execute_UTYPE": (
        "sign_extend (m := 32) (imm +++ 0x000#12)",
        "| .LUI => (pure off)",
        "(wX_bits rd",
        "(pure RETIRE_SUCCESS)",
    ),
    "execute_ITYPE": (
        "sign_extend (m := 32) imm",
        "| .ADDI => (pure ((← (rX_bits rs1)) + immext))",
        "(wX_bits rd",
        "(pure RETIRE_SUCCESS)",
    ),
}


def definitions() -> dict[str, str]:
    return translation.load_definitions(FIXTURES, NAMES)


def mutate(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(f"mutation anchor {old!r} is not unique")
    return text.replace(old, new)


class FixtureShapeTest(unittest.TestCase):
    def test_fixtures_carry_the_strings_sail_py_pins(self) -> None:
        sources = definitions()
        for name, phrases in PINNED_PHRASES.items():
            for phrase in phrases:
                self.assertIn(phrase, sources[name], f"{name} lost {phrase!r}")

    def test_fixture_directory_declares_its_provenance(self) -> None:
        readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
        self.assertIn("NOT captured generated output", readme)


class TranslationTest(unittest.TestCase):
    def test_utype_normalizes_to_lui_and_auipc_effects(self) -> None:
        entry = translation.translate("execute_UTYPE", definitions()["execute_UTYPE"])
        self.assertEqual(entry["selector_binder"], "op")
        self.assertEqual(sorted(entry["selectors"]), ["AUIPC", "LUI"])
        lui = entry["selectors"]["LUI"]
        self.assertEqual(
            lui["register_write"],
            {"target": "rd", "value": "(sign_extend (m := 32) (imm +++ 0x000#12))"},
        )
        self.assertEqual(lui["next_pc"], translation.SEQUENTIAL_NEXT_PC)
        self.assertEqual(lui["retirement"], "RETIRE_SUCCESS")
        self.assertIsNone(lui["memory_read"])
        self.assertIsNone(lui["memory_write"])
        self.assertEqual(lui["register_reads"], [])
        self.assertFalse(lui["reads_program_counter"])
        self.assertTrue(entry["selectors"]["AUIPC"]["reads_program_counter"])

    def test_itype_normalizes_every_iop_alternative(self) -> None:
        entry = translation.translate("execute_ITYPE", definitions()["execute_ITYPE"])
        self.assertEqual(
            sorted(entry["selectors"]),
            ["ADDI", "ANDI", "ORI", "SLTI", "SLTIU", "XORI"],
        )
        addi = entry["selectors"]["ADDI"]
        self.assertEqual(
            addi["register_write"],
            {
                "target": "rd",
                "value": "((← (rX_bits rs1)) + (sign_extend (m := 32) imm))",
            },
        )
        self.assertEqual(addi["register_reads"], ["rs1"])
        self.assertEqual(addi["retirement"], "RETIRE_SUCCESS")
        for selector, effect in entry["selectors"].items():
            self.assertEqual(
                effect["next_pc"], translation.SEQUENTIAL_NEXT_PC, selector
            )
            self.assertIsNone(effect["memory_write"], selector)
            self.assertEqual(effect["register_write"]["target"], "rd", selector)

    def test_declared_binders_and_rules_are_recorded(self) -> None:
        entry = translation.translate("execute_UTYPE", definitions()["execute_UTYPE"])
        self.assertEqual(
            entry["binders"],
            [
                {"names": ["imm"], "type": "(BitVec 20)"},
                {"names": ["rd"], "type": "regidx"},
                {"names": ["op"], "type": "uop"},
            ],
        )
        self.assertEqual(entry["result_type"], "(SailM Retired)")
        for rule in entry["applied_rules"]:
            self.assertIn(rule, translation.NORMALIZATION_RULES)

    def test_alternative_indentation_does_not_change_the_ast(self) -> None:
        source = definitions()["execute_UTYPE"]
        indented = source.replace("\n    | .", "\n      | .")
        self.assertNotEqual(indented, source)
        self.assertEqual(
            translation.ast_json(translation.parse_definition(source)),
            translation.ast_json(translation.parse_definition(indented)),
        )

    def test_a_definition_name_mismatch_is_refused(self) -> None:
        with self.assertRaises(SailTranslationError):
            translation.translate("execute_ITYPE", definitions()["execute_UTYPE"])


class ReceiptTest(unittest.TestCase):
    def test_receipt_is_stable_and_self_digesting(self) -> None:
        first = translation.build_receipt(definitions())
        second = translation.build_receipt(definitions())
        self.assertEqual(first, second)
        self.assertEqual(
            first["canonical_digest"],
            translation.content_digest(first),
        )
        self.assertEqual(first["schema_version"], translation.SCHEMA_VERSION)
        self.assertEqual(sorted(first["definitions"]), sorted(NAMES))

    def test_receipt_carries_its_own_claim_boundary(self) -> None:
        receipt = translation.build_receipt(definitions())
        self.assertEqual(receipt["claim"], translation.RECEIPT_CLAIM)
        self.assertIn("not a proof about the pinned", receipt["claim"])
        self.assertIn("re-derived", receipt["claim"])

    def test_verify_accepts_the_matching_pair(self) -> None:
        sources = definitions()
        receipt = translation.build_receipt(sources)
        self.assertEqual(translation.verify_receipt(receipt, sources), receipt)

    def test_receipt_records_the_source_digest_of_each_definition(self) -> None:
        import hashlib

        sources = definitions()
        receipt = translation.build_receipt(sources)
        for name, text in sources.items():
            self.assertEqual(
                receipt["definitions"][name]["source_sha256"],
                hashlib.sha256(text.encode("utf-8")).hexdigest(),
            )


class FailClosedTest(unittest.TestCase):
    def test_unknown_syntax_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "| .LUI => (pure off)",
            "| .LUI => if (is_zero rd) then (pure off) else (pure off)",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.parse_definition(source)
        self.assertIn("unsupported keyword 'if'", str(caught.exception))

    def test_an_unlexable_token_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "| .LUI => (pure off)",
            "| .LUI => (pure off@[3])",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.parse_definition(source)
        self.assertIn("unsupported syntax", str(caught.exception))

    def test_a_dropped_match_alternative_breaks_the_receipt(self) -> None:
        sources = definitions()
        receipt = translation.build_receipt(sources)
        sources["execute_ITYPE"] = mutate(
            sources["execute_ITYPE"],
            "    | .XORI => (pure ((← (rX_bits rs1)) ^^^ immext))\n",
            "",
        )
        self.assertNotIn(
            "XORI",
            translation.translate(
                "execute_ITYPE", sources["execute_ITYPE"]
            )["selectors"],
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.verify_receipt(receipt, sources)
        self.assertIn("drifted", str(caught.exception))

    def test_a_changed_value_expression_breaks_the_receipt(self) -> None:
        sources = definitions()
        receipt = translation.build_receipt(sources)
        sources["execute_UTYPE"] = mutate(
            sources["execute_UTYPE"],
            "(imm +++ 0x000#12)",
            "(imm +++ 0x001#12)",
        )
        rederived = translation.translate("execute_UTYPE", sources["execute_UTYPE"])
        self.assertEqual(
            rederived["selectors"]["LUI"]["register_write"]["value"],
            "(sign_extend (m := 32) (imm +++ 0x001#12))",
        )
        with self.assertRaises(SailTranslationError):
            translation.verify_receipt(receipt, sources)

    def test_a_changed_write_target_breaks_the_receipt(self) -> None:
        sources = definitions()
        receipt = translation.build_receipt(sources)
        sources["execute_ITYPE"] = mutate(
            sources["execute_ITYPE"],
            "(wX_bits rd result)",
            "(wX_bits rs1 result)",
        )
        rederived = translation.translate("execute_ITYPE", sources["execute_ITYPE"])
        self.assertEqual(
            rederived["selectors"]["ADDI"]["register_write"]["target"],
            "rs1",
        )
        with self.assertRaises(SailTranslationError):
            translation.verify_receipt(receipt, sources)

    def test_a_tampered_receipt_digest_is_refused(self) -> None:
        sources = definitions()
        receipt = translation.build_receipt(sources)
        receipt["definitions"]["execute_UTYPE"]["selectors"]["LUI"][
            "register_write"
        ]["target"] = "rs1"
        with self.assertRaises(SailTranslationError) as caught:
            translation.verify_receipt(receipt, sources)
        self.assertIn("digest does not cover", str(caught.exception))

    def test_a_resigned_but_wrong_receipt_is_still_refused(self) -> None:
        sources = definitions()
        receipt = translation.build_receipt(sources)
        receipt["definitions"]["execute_UTYPE"]["selectors"]["LUI"][
            "register_write"
        ]["target"] = "rs1"
        receipt["canonical_digest"] = translation.content_digest(receipt)
        with self.assertRaises(SailTranslationError) as caught:
            translation.verify_receipt(receipt, sources)
        self.assertIn("register_write.target", str(caught.exception))

    def test_a_missing_canonical_digest_is_refused(self) -> None:
        sources = definitions()
        receipt = translation.build_receipt(sources)
        receipt.pop("canonical_digest")
        with self.assertRaises(SailTranslationError):
            translation.verify_receipt(receipt, sources)

    def test_an_unknown_value_function_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "(pure off)",
            "(pure (undocumented_helper off))",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.translate("execute_UTYPE", source)
        self.assertIn("undocumented_helper", str(caught.exception))

    def test_an_unknown_effect_function_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "  (wX_bits rd ret)\n",
            "  (wX_bits rd ret)\n  (undocumented_effect rd)\n",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.translate("execute_UTYPE", source)
        self.assertIn("undocumented_effect", str(caught.exception))

    def test_a_missing_retirement_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "  (pure RETIRE_SUCCESS)\n",
            "",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.translate("execute_UTYPE", source)
        self.assertIn("retirement", str(caught.exception))

    def test_a_wildcard_alternative_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "| .AUIPC =>",
            "| _ =>",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.parse_definition(source)
        self.assertIn("single-constructor", str(caught.exception))

    def test_a_duplicate_alternative_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "| .AUIPC =>",
            "| .LUI =>",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.parse_definition(source)
        self.assertIn("duplicate", str(caught.exception))

    def test_ambiguous_operator_precedence_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_ITYPE"],
            "(pure ((← (rX_bits rs1)) + immext))",
            "(pure ((← (rX_bits rs1)) + immext * immext))",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.parse_definition(source)
        self.assertIn("mixed operators", str(caught.exception))

    def test_an_unbound_identifier_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "| .LUI => (pure off)",
            "| .LUI => (pure ghost)",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.translate("execute_UTYPE", source)
        self.assertIn("ghost", str(caught.exception))

    def test_a_non_monadic_definition_is_refused(self) -> None:
        with self.assertRaises(SailTranslationError):
            translation.parse_definition(
                "def execute_NOP : Retired := RETIRE_SUCCESS\n"
            )

    def test_a_slice_with_a_second_declaration_is_refused(self) -> None:
        source = definitions()["execute_UTYPE"] + "def execute_OTHER : T := do\n  x\n"
        with self.assertRaises(SailTranslationError) as caught:
            translation.parse_definition(source)
        self.assertIn("more than one top-level declaration", str(caught.exception))

    def test_an_effect_before_the_selector_match_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "  let ret : (BitVec 32) ← do\n",
            "  (wX_bits rd off)\n  let ret : (BitVec 32) ← do\n",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.translate("execute_UTYPE", source)
        self.assertIn("selector match must precede", str(caught.exception))

    def test_a_second_register_write_is_refused(self) -> None:
        source = mutate(
            definitions()["execute_UTYPE"],
            "  (wX_bits rd ret)\n",
            "  (wX_bits rd ret)\n  (wX_bits rd ret)\n",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.translate("execute_UTYPE", source)
        self.assertIn("more than one register write", str(caught.exception))

    def test_an_empty_receipt_is_refused(self) -> None:
        with self.assertRaises(SailTranslationError):
            translation.build_receipt({})


# A hand-written probe of the memory and jump effect slots. It is deliberately
# NOT a fixture file: no generated backend text for a load is available here, so
# this string makes no provenance claim at all. It exists only to keep the
# memory/next-pc branches of the normalizer under test.
SYNTHETIC_LOAD = """\
def execute_PROBE (imm : (BitVec 12)) (rs1 : regidx) (rd : regidx) (op : pop) : SailM Retired := do
  let offset : (BitVec 32) := (sign_extend (m := 32) imm)
  let value : (BitVec 32) ← do
    match op with
    | .PROBE_LOAD => (pure (sign_extend (m := 32) (mem_read ((← (rX_bits rs1)) + offset))))
  (wX_bits rd value)
  (mem_write_value ((← (rX_bits rs1)) + offset) value)
  (set_next_pc ((← (get_arch_pc ())) + offset))
  (pure RETIRE_SUCCESS)
"""


class EffectSlotProbeTest(unittest.TestCase):
    def test_memory_and_jump_slots_are_extracted(self) -> None:
        entry = translation.translate("execute_PROBE", SYNTHETIC_LOAD)
        effect = entry["selectors"]["PROBE_LOAD"]
        self.assertEqual(
            effect["memory_read"],
            "((← (rX_bits rs1)) + (sign_extend (m := 32) imm))",
        )
        self.assertIsNotNone(effect["memory_write"])
        self.assertIn("mem_write_value", effect["memory_write"])
        self.assertNotEqual(effect["next_pc"], translation.SEQUENTIAL_NEXT_PC)
        self.assertTrue(effect["reads_program_counter"])
        self.assertEqual(effect["register_reads"], ["rs1"])
        self.assertNotIn(
            "next-pc-sequential-unless-set",
            entry["applied_rules"],
        )

    def test_a_second_next_pc_effect_is_refused(self) -> None:
        source = mutate(
            SYNTHETIC_LOAD,
            "  (pure RETIRE_SUCCESS)",
            "  (set_next_pc ((← (get_arch_pc ())) + offset))\n  (pure RETIRE_SUCCESS)",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.translate("execute_PROBE", source)
        self.assertIn("more than one next-pc", str(caught.exception))

    def test_a_second_memory_write_is_refused(self) -> None:
        source = mutate(
            SYNTHETIC_LOAD,
            "  (set_next_pc",
            "  (mem_write_value ((← (rX_bits rs1)) + offset) value)\n  (set_next_pc",
        )
        with self.assertRaises(SailTranslationError) as caught:
            translation.translate("execute_PROBE", source)
        self.assertIn("more than one memory write", str(caught.exception))

    def test_an_unknown_retirement_is_refused(self) -> None:
        source = mutate(SYNTHETIC_LOAD, "RETIRE_SUCCESS", "RETIRE_MAYBE")
        with self.assertRaises(SailTranslationError) as caught:
            translation.translate("execute_PROBE", source)
        self.assertIn("RETIRE_MAYBE", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
