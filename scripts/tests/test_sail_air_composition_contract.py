"""Fail-closed structural contract for the scoped Sail/AIR theorem."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = ROOT / "soundness" / "SAIL_AIR_COMPOSITION.md"
REFINEMENT_DOCUMENT = ROOT / "soundness" / "UNIVERSAL_AIR_SAIL_REFINEMENT.md"
REFINEMENT_STATUS = ROOT / "soundness" / "RISCV_FRONTEND_VERIFICATION_STATUS.md"
FORMAL_README = ROOT / "formal" / "riscv-refinement" / "README.md"
FORMAL_EVIDENCE = ROOT / "conformance" / "riscv" / "formal-corpus-evidence.json"
CLAIMS = ROOT / "src" / "frontends" / "riscv" / "air" / "transcript" / "claims.zig"
OPCODE_MANIFEST = ROOT / "src" / "frontends" / "riscv" / "opcode_manifest.zig"


class SailAirCompositionContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = DOCUMENT.read_text(encoding="utf-8")
        cls.refinement_document = REFINEMENT_DOCUMENT.read_text(encoding="utf-8")
        cls.refinement_status = REFINEMENT_STATUS.read_text(encoding="utf-8")
        cls.formal_readme = FORMAL_README.read_text(encoding="utf-8")

    def test_refinement_status_surfaces_agree_on_the_bounded_claim(self) -> None:
        for source in (
            self.refinement_document,
            self.refinement_status,
            self.formal_readme,
        ):
            with self.subTest(source=source[:40]):
                self.assertIn("46/46", source)
                self.assertIn("94", source)
                self.assertIn("constructive_row_local_execution = true", source)
                self.assertIn("FV-3", source)
                self.assertIn("FV-4", source)
                self.assertIn("FV-5", source)
                self.assertIn("whole_frontend_verified = false", source)
                self.assertIn("proof_system_soundness = false", source)
                self.assertIn("receipt-bound", source)
                self.assertIn("receipt", source)
                self.assertIn("regenerat", source)

    def test_all_five_cross_row_lemmas_are_explicit_and_unique(self) -> None:
        headings = re.findall(r"^### (CR-[1-5]) — ", self.document, re.MULTILINE)
        self.assertEqual([f"CR-{index}" for index in range(1, 6)], headings)

    def test_theorem_is_conditional_and_refuses_the_universal_overclaim(self) -> None:
        required = (
            "conditional research theorem",
            "premise 1 and premise 5 universally",
            "machine-checked statement “AIR satisfaction universally refines pinned",
            "remains open",
            "The Python checker is not a verifier",
            "Row-local uniqueness is not row-local correctness",
            "accepted-production-AIR → generated-Sail",
            "reviewed-predicate → AIR direction",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_crypto_and_external_nonclaims_remain_visible(self) -> None:
        required = (
            "randomized LogUp",
            "field-to-integer coefficient lift",
            "collision resistance",
            "PCS commitment binding",
            "FRI/list-decoding",
            "Fiat–Shamir",
            "independent second verifier",
            "reviewed security-bit accounting",
            "Legacy Stark-V layout comparisons are not a premise",
            "archived CP-11 receipt reader is fail-closed",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_strict_access_order_and_clock_indirection_are_load_bearing(self) -> None:
        required = (
            "strict per-access clocks",
            "zero gap",
            "2^{20}-1",
            "A(c,i)=4(c-1)+i+1",
            "B &= 2^{26}",
            "68{,}157{,}438",
            "max\\_bridges}(0,2^{26}-1) &= 64",
            "current_access_clock - previous_clock - 1",
            "G = 2^{20}",
            "scripts/riscv_state_chain_recurrence.py",
            "same-clock alias counterexample",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_documented_formal_corpus_counts_match_bound_evidence(self) -> None:
        evidence = json.loads(FORMAL_EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual("equivalent", evidence["result"])
        inventory = (
            f"{evidence['programs']} programs, "
            f"{evidence['retirements']:,} retirements, and "
            f"{evidence['negative_decode_and_trap_cases']} negative dispositions"
        )
        self.assertIn(inventory, self.document)

    def test_28_claim_inventory_matches_production_enum(self) -> None:
        source = CLAIMS.read_text(encoding="utf-8")
        enum_body = source.split("pub const Component = enum(u8) {", 1)[1].split("};", 1)[0]
        components = [
            line.strip().removesuffix(",")
            for line in enum_body.splitlines()
            if line.strip() and not line.lstrip().startswith("//")
        ]
        self.assertEqual(28, len(components))
        self.assertEqual("auipc", components[0])
        self.assertEqual("range_check_m31", components[-1])
        self.assertIn("exactly 28 component slots", self.document)
        self.assertIn("17 opcode families", self.document)
        self.assertIn("six preprocessed lookup tables", self.document)

    def test_merkle_all_source_lift_is_bound_without_overclaiming(self) -> None:
        self.assertIn("2\\,n_{\\mathrm{node}}<p", self.document)
        self.assertIn(
            "2\\,n_{\\mathrm{node}}+n_{\\mathrm{program}}",
            self.document,
        )
        self.assertIn("+\\sum n_{\\mathrm{memory}}+3 < p", self.document)
        self.assertIn("**all-source** field-to-integer coefficient lift", self.document)
        self.assertIn(
            "do not themselves establish exact tuple balance",
            self.document,
        )

    def test_poseidon_reproduction_uses_the_required_subcommand(self) -> None:
        self.assertIn(
            "python3 -m scripts.riscv_poseidon_table_uniqueness check",
            self.document,
        )

    def test_universal_refinement_plan_preserves_scope_and_binding_gates(self) -> None:
        required = (
            "bridge receipts bind the current row-local FV-1/FV-2 source",
            "AIR IR v2 is delivered for all 17 families and 46 selectors",
            "generated fetch/decode/execute step",
            "typed AST and a canonical receipt records their normalized selector",
            "one exact manifest-wide accepted-production-AIR theorem inventory",
            "The eventual FV-4 trace theorem closes SA-1 premise 5.",
            "does **not** by itself prove",
            "**Publication binding:**",
            "must not claim a universal theorem about the shipped AIR until level 2 is",
            "The final CI result is a Lean kernel check.",
            "Hand-transcribing 46 instruction functions",
            "# Complete live row-local publication gate",
            "Every opcode needs a machine-checked existence theorem",
            "independent proof-system validation",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.refinement_document)

        self.assertIn(
            "[`UNIVERSAL_AIR_SAIL_REFINEMENT.md`](UNIVERSAL_AIR_SAIL_REFINEMENT.md)",
            self.document,
        )

    def test_universal_refinement_closure_gates_are_normative_and_current(self) -> None:
        gates = re.findall(
            r"^#### (FV-[1-5]) — ",
            self.refinement_document,
            re.MULTILINE,
        )
        self.assertEqual([f"FV-{index}" for index in range(1, 6)], gates)

        required = (
            "and regenerated receipts satisfy the row-local obligations",
            "neutral 46-opcode",
            "one exact manifest-wide accepted-production-AIR theorem inventory",
            "The historical graded 46/46 index is only an input",
            "Current status: 46/46 receipt-bound constructive row-local publication",
            "exactly 94 receipt records",
            "constructive_row_local_execution = true",
            "A theorem whose strongest chain is only “reviewed semantic predicate → AIR",
            "`composeU32` is therefore non-injective",
            "`ALIASING_BASE = 0x7FFFFFFB`",
            "CR-1 through",
            "`normalized_retirements.proved = 46`",
            "`publication_level.proved = 46`",
            "`full_generated_sail_step = true`",
            "`whole_frontend_verified = true`",
            "`proof_system_soundness` remains false",
            "### 15.2 Operational adoption audit",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.refinement_document)

        self.assertIn(
            "they are not semantic\n> categories, publication grades, or current ownership boundaries",
            self.refinement_document,
        )

    def test_universal_refinement_plan_covers_exactly_46_opcodes(self) -> None:
        table_rows = re.findall(
            r"^\| `[^`]+` \| ([^|]+) \| (\d+) \|",
            self.refinement_document,
            re.MULTILINE,
        )
        family_counts = [int(count) for _, count in table_rows]
        self.assertEqual(17, len(family_counts))
        self.assertEqual(46, sum(family_counts))
        self.assertIn("| **Total** |  | **46** |", self.refinement_document)

        documented_opcodes = {
            opcode.strip()
            for opcode_cell, _ in table_rows
            for opcode in opcode_cell.split(",")
        }
        manifest = OPCODE_MANIFEST.read_text(encoding="utf-8")
        enum_body = manifest.split("pub const Opcode = enum(u8) {", 1)[1].split(
            "pub inline fn protocolId",
            1,
        )[0]
        manifest_opcodes = {
            (quoted or plain).upper()
            for quoted, plain in re.findall(
                r'^\s*(?:@"([^"]+)"|([a-z][a-z0-9_]*))\s*=\s*\d+,',
                enum_body,
                re.MULTILINE,
            )
        }
        self.assertEqual(manifest_opcodes, documented_opcodes)

        work_packages = re.findall(
            r"^### (UR-\d{2}) — ",
            self.refinement_document,
            re.MULTILINE,
        )
        self.assertEqual([f"UR-{index:02d}" for index in range(8)], work_packages)

    def test_universal_refinement_document_links_resolve(self) -> None:
        targets = re.findall(r"\]\(([^)#]+)(?:#[^)]+)?\)", self.refinement_document)
        self.assertGreaterEqual(len(targets), 2)
        missing = sorted(
            {
                target
                for target in targets
                if not (REFINEMENT_DOCUMENT.parent / target).resolve().exists()
            }
        )
        self.assertEqual([], missing)

    def test_every_linked_in_repo_evidence_path_exists(self) -> None:
        targets = re.findall(r"\]\(\.\./([^)#]+)", self.document)
        self.assertGreaterEqual(len(targets), 20)
        missing = sorted(
            {
                target
                for target in targets
                if not (ROOT / target).exists()
            }
        )
        self.assertEqual([], missing)


if __name__ == "__main__":
    unittest.main()
