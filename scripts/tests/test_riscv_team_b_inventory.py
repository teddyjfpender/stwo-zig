"""Tests for the Team B mutation-control evidence inventory.

The inventory exists because promotion-by-hand went wrong twice: once by
citing a vacuous control and once by promoting on a false hypothesis. These
tests pin the distinctions that caught both: UNCONDITIONAL vs CONDITIONAL
corollaries, in-file soundness proofs, and guard-derived opcode credit.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

from scripts import riscv_team_b_inventory as inventory_tool

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "inventory"


def build() -> inventory_tool.Inventory:
    return inventory_tool.build_inventory(FIXTURES)


def control_named(inventory, definition):
    for control in inventory.controls:
        if control.definition == definition:
            return control
    raise AssertionError(f"control {definition} not found in inventory")


class MutationControlScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = build()
        cls.summary = inventory_tool.opcode_summary(cls.inventory)

    # -- fixture 1: the unconditional control -----------------------------

    def test_unconditional_control_is_fully_reported(self):
        control = control_named(self.inventory, "divReleasedComparison")
        self.assertEqual(
            control.control_name, "div-released-comparison-witness"
        )
        self.assertEqual(control.weakened, "DivHoldsWithoutScanTotal")
        self.assertEqual(control.conclusion, "DivuRetiresQuotient")
        self.assertEqual(control.file, "UnconditionalControl.lean")
        source = (FIXTURES / "UnconditionalControl.lean").read_text()
        expected_line = next(
            index
            for index, line in enumerate(source.splitlines(), start=1)
            if line.startswith("def divReleasedComparison")
        )
        self.assertEqual(control.line, expected_line)

    def test_unconditional_classification(self):
        control = control_named(self.inventory, "divReleasedComparison")
        self.assertEqual(control.status, "unconditional")
        self.assertEqual(len(control.corollaries), 1)
        corollary = control.corollaries[0]
        self.assertEqual(corollary.name, "div_scan_total_is_load_bearing")
        self.assertEqual(corollary.classification, "unconditional")
        self.assertEqual(corollary.hypotheses, [])
        self.assertEqual(corollary.sound_term, "divu_conclusion_sound")

    def test_unconditional_control_has_in_file_soundness(self):
        control = control_named(self.inventory, "divReleasedComparison")
        self.assertTrue(control.soundness_in_file)
        self.assertIn("divu_conclusion_sound", control.soundness_theorems)
        self.assertEqual(control.original, "DivHolds")

    def test_guard_derived_opcode_credit_is_selector_exact(self):
        control = control_named(self.inventory, "divReleasedComparison")
        self.assertTrue(control.guarded)
        self.assertEqual(control.certifies, ["divu"])
        self.assertNotIn("div", control.certifies)
        self.assertNotIn("rem", control.certifies)

    # -- fixture 2: the conditional control -------------------------------

    def test_conditional_control_is_flagged_even_with_unused_soundness(self):
        control = control_named(self.inventory, "mulFreeLowLimb")
        self.assertEqual(control.status, "conditional")
        corollary = control.corollaries[0]
        self.assertEqual(corollary.classification, "conditional")
        self.assertEqual(corollary.sound_term, "sound")
        self.assertTrue(
            any("sound" in hypothesis for hypothesis in corollary.hypotheses)
        )
        # The in-file soundness lemma exists but the corollary ignores it:
        # the control must still be reported as conditional.
        self.assertTrue(control.soundness_in_file)
        self.assertIn("mul_conclusion_sound", control.soundness_theorems)
        self.assertTrue(
            any("CONDITIONAL" in flag for flag in control.flags)
        )

    def test_unguarded_conclusion_is_flagged(self):
        control = control_named(self.inventory, "mulFreeLowLimb")
        self.assertFalse(control.guarded)
        self.assertEqual(control.certifies, ["mul"])
        self.assertTrue(
            any("no selector guard" in flag for flag in control.flags)
        )

    # -- fixture 3: conditional with no soundness proof -------------------

    def test_control_without_soundness_proof(self):
        control = control_named(self.inventory, "lhWrongHighHalf")
        self.assertEqual(control.status, "conditional")
        self.assertFalse(control.soundness_in_file)
        self.assertEqual(control.soundness_theorems, [])
        self.assertEqual(control.certifies, ["lh"])
        self.assertTrue(control.guarded)

    # -- fixture 4: a file with no controls -------------------------------

    def test_file_without_controls_contributes_no_controls(self):
        files = {control.file for control in self.inventory.controls}
        self.assertNotIn("NoControls.lean", files)

    def test_commented_out_controls_are_ignored(self):
        names = {control.control_name for control in self.inventory.controls}
        self.assertNotIn("decoy-in-block-comment", names)
        self.assertNotIn("decoy-in-line-comment", names)
        self.assertEqual(len(self.inventory.controls), 3)

    # -- the summary table -------------------------------------------------

    def test_summary_promotes_only_the_unconditional_opcode(self):
        divu = self.summary["divu"]
        self.assertEqual(divu["refinement_theorem"], "divu_refines")
        self.assertEqual(divu["tuple_theorem"], "divu_refines")
        self.assertTrue(divu["tuple_via_refinement"])
        self.assertEqual(divu["non_vacuity_theorems"], ["divu_exists"])
        self.assertEqual(divu["mutation_status"], "unconditional")
        self.assertTrue(divu["promotion_ready"])
        self.assertFalse(divu["needs_review"])

    def test_summary_holds_back_conditional_only_opcodes(self):
        mul = self.summary["mul"]
        self.assertEqual(mul["mutation_status"], "conditional-only")
        self.assertFalse(mul["promotion_ready"])
        self.assertTrue(mul["needs_review"])

        lh = self.summary["lh"]
        self.assertEqual(lh["mutation_status"], "conditional-only")
        self.assertFalse(lh["promotion_ready"])

    def test_summary_requires_a_mutation_control(self):
        sll = self.summary["sll"]
        self.assertEqual(sll["refinement_theorem"], "sll_refines")
        self.assertEqual(sll["non_vacuity_theorems"], ["sll_exists"])
        self.assertEqual(sll["mutation_status"], "none")
        self.assertFalse(sll["promotion_ready"])

    def test_summary_covers_all_twenty_two_team_b_opcodes(self):
        self.assertEqual(
            sorted(self.summary), sorted(inventory_tool.TEAM_B_OPCODES)
        )
        self.assertEqual(len(self.summary), 22)
        untouched = self.summary["remu"]
        self.assertIsNone(untouched["refinement_theorem"])
        self.assertEqual(untouched["mutation_status"], "none")
        self.assertFalse(untouched["promotion_ready"])

    # -- review flags ------------------------------------------------------

    def test_every_conditional_corollary_is_flagged_for_review(self):
        conditional_definitions = {"mulFreeLowLimb", "lhWrongHighHalf"}
        for definition in conditional_definitions:
            self.assertTrue(
                any(
                    definition in flag and "CONDITIONAL" in flag
                    for flag in self.inventory.flags
                ),
                f"no review flag for conditional control {definition}",
            )

    # -- rendering ---------------------------------------------------------

    def test_json_rendering_round_trips(self):
        payload = json.loads(inventory_tool.render_json(self.inventory))
        self.assertEqual(len(payload["controls"]), 3)
        self.assertTrue(payload["opcodes"]["divu"]["promotion_ready"])
        self.assertFalse(payload["opcodes"]["mul"]["promotion_ready"])
        self.assertIn("flags", payload)

    def test_text_rendering_names_the_evidence(self):
        text = inventory_tool.render_text(self.inventory)
        self.assertIn("div-released-comparison-witness", text)
        self.assertIn("UNCONDITIONAL", text)
        self.assertIn("CONDITIONAL", text)
        self.assertIn("| divu |", text)
        self.assertIn("Review flags", text)

    def test_text_rendering_headlines_the_conditional_count(self):
        text = inventory_tool.render_text(self.inventory)
        self.assertIn("CONDITIONAL corollaries requiring review: 2", text)
        self.assertIn("`mulFreeLowLimb`", text)
        self.assertIn("`lhWrongHighHalf`", text)


class ParserUnitTest(unittest.TestCase):
    def test_strip_comments_removes_block_and_line_comments(self):
        text = (
            "def real : Nat := 1\n"
            "/- def fake : MutationControl A B where\n"
            "  name := \"gone\" -/\n"
            "-- def fake2 : MutationControl A B where\n"
            "def alsoReal : Nat := 2\n"
        )
        stripped = inventory_tool.strip_comments(text)
        self.assertIn("def real", stripped)
        self.assertIn("def alsoReal", stripped)
        self.assertNotIn("fake", stripped)
        self.assertNotIn("gone", stripped)
        # Line structure survives so line numbers stay valid.
        self.assertEqual(stripped.count("\n"), text.count("\n"))

    def test_strip_comments_keeps_string_contents(self):
        text = 'def x : String := "a -- not a comment"\n'
        self.assertEqual(inventory_tool.strip_comments(text), text)

    def test_conditional_detection_uses_top_level_binders(self):
        declarations = None
        for path in FIXTURES.glob("ConditionalControl.lean"):
            declarations = inventory_tool.parse_declarations(path, FIXTURES)
        assert declarations is not None
        by_name = {decl.name: decl for decl in declarations}
        conditional = by_name["mul_product_limb0_is_load_bearing"]
        self.assertEqual(len(conditional.binders), 1)
        self.assertIn("MulHolds row", conditional.binders[0])
        unconditional = by_name["mul_conclusion_sound"]
        self.assertEqual(
            unconditional.goal.split()[0], "MulComputesProduct"
        )

    def test_selector_enum_guard_maps_to_a_single_opcode(self):
        declaration = inventory_tool.Declaration(
            kind="def",
            name="MulhsuRetiresHighWord",
            qualified="RiscvRefinement.Opcodes.MulhsuRetiresHighWord",
            file="Synthetic.lean",
            line=1,
            binders=["row : MulhRow"],
            goal="Prop",
            body=(
                "row.selector = MulhSelector.mulhsu →\n"
                "    row.rdNext.word = architecturalValue row.rd high"
            ),
        )
        info = inventory_tool.conclusion_opcodes(declaration)
        self.assertTrue(info.guarded)
        self.assertEqual(info.opcodes, ["mulhsu"])
        self.assertEqual(info.unknown_guards, [])

    def test_qualified_names_track_namespaces(self):
        declarations = inventory_tool.parse_declarations(
            FIXTURES / "UnconditionalControl.lean", FIXTURES
        )
        by_name = {decl.name: decl for decl in declarations}
        self.assertEqual(
            by_name["div_scan_total_is_load_bearing"].qualified,
            "RiscvRefinement.Opcodes.div_scan_total_is_load_bearing",
        )


class CliTest(unittest.TestCase):
    def _run(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = inventory_tool.main(argv)
        return code, stdout.getvalue()

    def test_json_flag_and_output_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            code, printed = self._run(
                [
                    "--lean-root",
                    str(FIXTURES),
                    "--json",
                    "--output",
                    str(output),
                    "--skip-manifest-check",
                ]
            )
            self.assertEqual(code, 0)
            payload = json.loads(printed)
            self.assertEqual(payload, json.loads(output.read_text()))

    def test_missing_root_fails_closed(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code, _ = self._run(
                ["--lean-root", "/nonexistent/lean/tree",
                 "--skip-manifest-check"]
            )
        self.assertEqual(code, 2)
        self.assertIn("not a directory", stderr.getvalue())

    def test_tool_never_writes_the_certificate_index(self):
        """The inventory produces evidence; it must not be able to promote.

        The certificate index is owned by another gate. Two guarantees: the
        module's only filesystem write is the explicit ``--output`` report,
        and a full CLI run leaves the committed index byte-identical.
        """

        source = Path(inventory_tool.__file__).read_text(encoding="utf-8")
        self.assertEqual(source.count(".write_text("), 1)
        self.assertIn("args.output.write_text(", source)
        self.assertNotIn("json.dump(", source.replace("json.dumps(", ""))

        index = (
            inventory_tool.REPOSITORY_ROOT
            / "formal/riscv-refinement/team-b-coverage.json"
        )
        before = index.read_bytes() if index.exists() else None
        code, _ = self._run(
            ["--lean-root", str(FIXTURES), "--skip-manifest-check"]
        )
        self.assertEqual(code, 0)
        if before is not None:
            self.assertEqual(index.read_bytes(), before)

    def test_embedded_opcode_table_matches_production_manifest(self):
        manifest = (
            inventory_tool.REPOSITORY_ROOT
            / "src/frontends/riscv/opcode_manifest.zig"
        )
        if not manifest.exists():
            self.skipTest("production manifest not in this tree slice")
        inventory = build()
        inventory_tool.verify_manifest(inventory, manifest)
        self.assertIn("matches", inventory.manifest_note)


if __name__ == "__main__":
    unittest.main()
