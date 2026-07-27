"""Fail-closed structural contract for the scoped Sail/AIR theorem."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = ROOT / "soundness" / "SAIL_AIR_COMPOSITION.md"
FORMAL_EVIDENCE = ROOT / "conformance" / "riscv" / "formal-corpus-evidence.json"
CLAIMS = ROOT / "src" / "frontends" / "riscv" / "air" / "transcript" / "claims.zig"


class SailAirCompositionContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = DOCUMENT.read_text(encoding="utf-8")

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
