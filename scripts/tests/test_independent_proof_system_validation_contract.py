"""Structural contract for the independent proof-system validation scope."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = ROOT / "soundness" / "INDEPENDENT_PROOF_SYSTEM_VALIDATION.md"
ROADMAP = ROOT / "soundness" / "ROADMAP.md"
README = ROOT / "README.md"


class IndependentProofSystemValidationContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = DOCUMENT.read_text(encoding="utf-8")
        cls.roadmap = ROADMAP.read_text(encoding="utf-8")
        cls.readme = README.read_text(encoding="utf-8")

    def test_status_and_primary_deliverables_are_explicit(self) -> None:
        required = (
            "**Status:** engineering design; implementation not started.",
            "**Primary result:**",
            "**Adversarial result:**",
            "**Review result:**",
            "Commands and paths labelled",
            "do not exist at the date of this document",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_scope_targets_the_production_riscv_wire(self) -> None:
        required = (
            'artifact_kind = "stwo_riscv_proof"',
            "schema is version `4`",
            "`riscv_proof_json_wire_v4`",
            "lowercase-hex **Postcard** bytes",
            "original ELF",
            "externally supplied expected-statement digest",
            "`STWOPRW1`",
            "would not satisfy this plan",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_independence_is_measurable_and_forbids_shared_verifiers(self) -> None:
        required = (
            "I0",
            "I1",
            "I2",
            "I3",
            "The release target is I2.",
            "declare an empty local `[workspace]`",
            "use no Git dependency",
            "use no path dependency",
            "import no Zig-generated source",
            "import no Stwo, Stwo-Cairo, constraint-framework",
            "contain no proving code",
            "no source file copied from",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_complete_verification_layers_are_in_scope(self) -> None:
        required = (
            "strict JSON",
            "Postcard preflight",
            "M31, CM31, and QM31",
            "Fiat–Shamir transcript",
            "all twelve relation-challenge pairs",
            "all 17 opcode families",
            "all six fixed lookup tables",
            "public LogUp compensation",
            "OODS",
            "Lifted Merkle",
            "FRI verification",
            "final-degree bound",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_all_requested_mutation_families_have_executable_contracts(self) -> None:
        headings = (
            "### 7.3 Bit-flip corpus",
            "### 7.4 Truncation corpus",
            "### 7.5 Splice corpus",
            "### 7.6 Wrong-statement corpus",
        )
        for heading in headings:
            with self.subTest(heading=heading):
                self.assertIn(heading, self.document)

        required = (
            "flips every bit",
            "truncated at every byte offset",
            "spliced at every structural boundary",
            "external expected-statement digest",
            "Both verifiers must reject every negative case.",
            "A no-op mutation, an unexecuted case, or an accepted negative",
            "Sensitivity controls",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_external_review_cannot_presuppose_the_security_answer(self) -> None:
        required = (
            "FRI proximity soundness",
            "Query dependence",
            "Randomized LogUp",
            "Merkle binding",
            "Fiat–Shamir",
            "Parameter composition",
            "Multi-target use",
            "The review must not assume the desired 96-bit answer.",
            "proof-security-ledger-v1.json",
            "critical/high unresolved: release blocked",
            "re-review before promotion",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_work_packages_are_complete_and_ordered(self) -> None:
        proof_packages = re.findall(
            r"^### (PV-\d{2}) — ",
            self.document,
            re.MULTILINE,
        )
        security_packages = re.findall(
            r"^### (SR-\d{2}) — ",
            self.document,
            re.MULTILINE,
        )
        self.assertEqual([f"PV-{index:02d}" for index in range(7)], proof_packages)
        self.assertEqual([f"SR-{index:02d}" for index in range(3)], security_packages)
        self.assertEqual(10, self.document.count("Exit gate:"))

    def test_planning_range_and_estimate_reset_gate_are_honest(self) -> None:
        self.assertIn("**Internal total**", self.document)
        self.assertIn("**35–57**", self.document)
        self.assertIn("roughly 5–8 months with two core engineers", self.document)
        self.assertIn("4–8 review weeks", self.document)
        self.assertIn("PV-03 is the", self.document)
        self.assertIn("estimate-reset gate", self.document)

    def test_definition_of_done_preserves_nonclaims(self) -> None:
        required = (
            "Definition of done",
            "source-isolated verifier",
            "both verifier receipts are mandatory release evidence",
            "security accounting remains under external review",
            "under its stated computational and random-oracle assumptions",
            "must still not shorten that claim to an unconditional proof",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_primary_review_literature_is_explicit(self) -> None:
        required = (
            "## 16. Primary review references",
            "theorem hypotheses",
            "Fast Reed-Solomon Interactive Oracle Proofs of Proximity",
            "DEEP-FRI",
            "Circle STARKs",
            "Fiat-Shamir Security of FRI and Related SNARKs",
            "Multivariate lookups based on logarithmic derivatives",
            "From List-Decodability to Proximity Gaps",
            "https://drops.dagstuhl.de/",
            "https://eprint.iacr.org/",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.document)

    def test_roadmap_links_to_the_scope_without_closing_open_items(self) -> None:
        link = (
            "[`INDEPENDENT_PROOF_SYSTEM_VALIDATION.md`]"
            "(INDEPENDENT_PROOF_SYSTEM_VALIDATION.md)"
        )
        self.assertGreaterEqual(self.roadmap.count(link), 2)
        self.assertIn(
            "- [ ] Add a second independently implemented verifier",
            self.roadmap,
        )
        self.assertIn(
            "- [ ] Obtain independent review of the FRI/list-decoding",
            self.roadmap,
        )

    def test_root_readme_describes_current_artifact_and_required_elf(self) -> None:
        self.assertIn("emits a bounded schema-v4 artifact", self.readme)
        self.assertNotIn("emits a bounded schema-v3 artifact", self.readme)
        verify_example = self.readme.split("zig-out/bin/stwo-zig verify \\", 1)[1]
        verify_example = verify_example.split("```", 1)[0]
        self.assertIn("--artifact riscv-proof.json", verify_example)
        self.assertIn("--elf vectors/riscv_elfs/branch_fib.elf", verify_example)
        self.assertIn("--expect-statement-digest", verify_example)

    def test_document_links_resolve(self) -> None:
        targets = re.findall(r"\]\(([^)#]+)(?:#[^)]+)?\)", self.document)
        self.assertGreaterEqual(len(targets), 2)
        missing = sorted(
            {
                target
                for target in targets
                if "://" not in target
                if not (DOCUMENT.parent / target).resolve().exists()
            }
        )
        self.assertEqual([], missing)


if __name__ == "__main__":
    unittest.main()
