from __future__ import annotations

import json
import unittest
from unittest import mock

from scripts import riscv_refinement_publication as publication
from scripts.riscv_refinement_lib import air_program_contract
from scripts.riscv_refinement_lib.model import (
    Paths,
    RefinementError,
    repository_root,
)


class PublicationEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.paths = Paths(repository_root())

    def receipt(self) -> dict[str, object]:
        selectors = [
            mnemonic.upper()
            for _, mnemonic, _ in air_program_contract.OPCODES
        ]
        required = {
            publication.FULL_STEP_THEOREM,
            publication.CROSS_PROJECT_CONTRACT_THEOREM,
            *publication.NORMALIZED_THEOREMS.values(),
            *publication.COMPOSITION_THEOREMS.values(),
        }
        return {
            "claim_boundary": {
                "input_bound_selectors": selectors,
                "normalized_retirement_selectors": selectors,
                "fetch_interrupt_trap_and_step_loop_framing": True,
                "publication_binding": True,
            },
            "selector_source_digests": [
                {
                    "selector": selector,
                    "sha256": f"{index + 1:064x}",
                }
                for index, selector in enumerate(selectors)
            ],
            "theorem_axioms": {
                theorem: [] for theorem in sorted(required)
            },
        }

    def local_axioms(self) -> dict[str, list[str]]:
        result = {
            theorem: []
            for theorem in publication.LOCAL_UNIVERSAL_THEOREMS
        }
        coverage = json.loads(
            publication.riscv_opcode_coverage.INDEX_PATH.read_text(
                encoding="utf-8"
            )
        )
        for certificate in coverage["certificates"]:
            for field in (
                "tuple_theorem",
                "non_vacuity_theorem",
                "mutation_theorem",
            ):
                result[certificate[field]] = []
        return result

    def test_exact_publication_evidence(self) -> None:
        coverage = json.loads(
            publication.riscv_opcode_coverage.INDEX_PATH.read_text(
                encoding="utf-8"
            )
        )
        with mock.patch.object(
            publication.riscv_opcode_coverage,
            "build_index",
            return_value=coverage,
        ):
            evidence = publication.build_publication_evidence(
                self.paths,
                self.receipt(),
                self.local_axioms(),
            )
        self.assertEqual(
            evidence["normalized_retirements"],
            {"proved": 46, "total": 46},
        )
        self.assertEqual(
            evidence["publication_level"],
            {"proved": 46, "total": 46},
        )
        self.assertTrue(evidence["full_generated_sail_step"])
        entries = evidence["entries"]
        self.assertEqual(len(entries), 46)
        self.assertEqual(
            [entry["manifest_id"] for entry in entries],
            list(range(46)),
        )
        self.assertEqual(
            len(
                {
                    entry["accepted_air_refinement_theorem"]
                    for entry in entries
                }
            ),
            46,
        )

    def test_current_carried_receipt_is_not_publication_evidence(self) -> None:
        receipt = json.loads(
            (
                self.paths.formal
                / "generated/sail/generated-monad-bridge-receipt-v1.json"
            ).read_text(encoding="utf-8")
        )
        with self.assertRaisesRegex(
            RefinementError,
            "does not establish FV-1/FV-2",
        ):
            publication.build_publication_evidence(
                self.paths,
                receipt,
                self.local_axioms(),
            )

    def test_missing_composition_theorem_is_rejected(self) -> None:
        receipt = self.receipt()
        theorem = publication.COMPOSITION_THEOREMS["mul"]
        del receipt["theorem_axioms"][theorem]
        with self.assertRaisesRegex(
            RefinementError,
            "missing a valid record",
        ):
            publication.build_publication_evidence(
                self.paths,
                receipt,
                self.local_axioms(),
            )

    def test_incomplete_selector_source_inventory_is_rejected(self) -> None:
        receipt = self.receipt()
        del receipt["selector_source_digests"][44]
        with self.assertRaisesRegex(
            RefinementError,
            "exact 46-entry manifest order",
        ):
            publication.build_publication_evidence(
                self.paths,
                receipt,
                self.local_axioms(),
            )

    def test_false_full_step_claim_is_rejected(self) -> None:
        receipt = self.receipt()
        receipt["claim_boundary"][
            "fetch_interrupt_trap_and_step_loop_framing"
        ] = False
        with self.assertRaisesRegex(
            RefinementError,
            "does not establish FV-1/FV-2",
        ):
            publication.build_publication_evidence(
                self.paths,
                receipt,
                self.local_axioms(),
            )

    def test_unapproved_axiom_is_rejected(self) -> None:
        receipt = self.receipt()
        theorem = publication.NORMALIZED_THEOREMS["lw"]
        receipt["theorem_axioms"][theorem] = ["Bad.escape"]
        with self.assertRaisesRegex(
            RefinementError,
            "uses unapproved axioms",
        ):
            publication.build_publication_evidence(
                self.paths,
                receipt,
                self.local_axioms(),
            )

    def test_missing_local_universal_theorem_is_rejected(self) -> None:
        local = self.local_axioms()
        del local[publication.ADMISSION_DECODE_THEOREM]
        with self.assertRaisesRegex(
            RefinementError,
            "missing a valid record",
        ):
            publication.build_publication_evidence(
                self.paths,
                self.receipt(),
                local,
            )


if __name__ == "__main__":
    unittest.main()
