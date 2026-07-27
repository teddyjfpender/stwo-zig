"""Forensic contract tests for archived Stark-V AIR-comparison receipts."""

from __future__ import annotations

import time
import unittest
from pathlib import Path
from unittest import mock

from scripts.riscv_release_gate_lib.contract import (
    ARCHIVED_RECEIPT_ERROR,
    BOUNDARIES,
    PARITY_BOUNDARIES,
    receipt_errors,
)
from scripts.tests.riscv_release_receipt_fixture import (
    TEST_COMMIT as COMMIT,
    air_divergence,
    bind_case_digests,
    superseded_receipt,
    valid_receipt,
)


class ArchivedBoundaryTests(unittest.TestCase):
    """Old receipts stay parseable but can never authorize a release."""

    PATHS = ["/components/auipc/stream", "/components/jalr/relations/range_check_8_8"]

    def errors(self, receipt: dict[str, object], *, authorize: list[str] | None) -> list[str]:
        shapes = dict(air_divergence.AUTHORIZED_SHAPES)
        if authorize is not None:
            for name in air_divergence.SUPERSEDED_BOUNDARIES:
                shapes[name] = frozenset({air_divergence.shape_digest(authorize)})
        with mock.patch.dict(air_divergence.AUTHORIZED_SHAPES, shapes, clear=True):
            return receipt_errors(
                receipt, COMMIT, now=receipt["created_at_unix"], vector_names=("alu",)
            )

    def test_only_the_air_comparison_boundaries_are_demoted(self) -> None:
        self.assertEqual(
            {"per_family_witness_rows", "relation_tuples", "relation_sums"},
            set(air_divergence.SUPERSEDED_BOUNDARIES),
        )
        self.assertEqual(
            set(BOUNDARIES),
            set(PARITY_BOUNDARIES) | set(air_divergence.SUPERSEDED_BOUNDARIES),
        )
        self.assertEqual((), tuple(
            name for name in PARITY_BOUNDARIES
            if name in air_divergence.SUPERSEDED_BOUNDARIES
        ))
        for name in air_divergence.SUPERSEDED_BOUNDARIES.values():
            self.assertTrue(name.strip(), "every demoted boundary states its reason")
        self.assertEqual(
            set(air_divergence.SUPERSEDED_BOUNDARIES),
            set(air_divergence.AUTHORIZED_SHAPES),
            "a demoted boundary without a shape slot could never be authorized",
        )

    def test_old_shape_parser_accepts_known_structure_but_not_release(self) -> None:
        for boundary in air_divergence.SUPERSEDED_BOUNDARIES:
            with self.subTest(boundary=boundary):
                receipt = superseded_receipt(int(time.time()), boundary, self.PATHS)
                self.assertEqual(
                    [ARCHIVED_RECEIPT_ERROR],
                    self.errors(receipt, authorize=self.PATHS),
                )

                regressed = superseded_receipt(
                    int(time.time()), boundary, [*self.PATHS, "/components/div/stream"]
                )
                errors = self.errors(regressed, authorize=self.PATHS)
                self.assertTrue(
                    any(
                        "unauthorized archived divergence shape" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_unpinned_divergence_fails_closed_with_a_named_remediation(self) -> None:
        """AUTHORIZED_SHAPES is empty in the repository: nothing is pre-approved."""
        for boundary in air_divergence.SUPERSEDED_BOUNDARIES:
            self.assertEqual(frozenset(), air_divergence.AUTHORIZED_SHAPES[boundary])
        receipt = superseded_receipt(int(time.time()), "relation_tuples", self.PATHS)
        errors = self.errors(receipt, authorize=None)
        self.assertTrue(any(
            "unauthorized archived divergence shape" in error
            and "no new shape may be authorized" in error
            and "use the Sail release gate instead" in error
            for error in errors
        ), errors)

    def test_shape_digest_does_not_bind_a_relabelled_path_set(self) -> None:
        receipt = superseded_receipt(int(time.time()), "relation_sums", self.PATHS)
        receipt["boundaries"]["relation_sums"]["divergence_paths"] = [
            "/components/lui/stream"
        ]
        bind_case_digests(receipt)
        errors = self.errors(receipt, authorize=self.PATHS)
        self.assertIn(
            "boundary relation_sums divergence shape digest does not bind its paths",
            errors,
        )

    def test_a_parity_boundary_cannot_borrow_the_superseded_status(self) -> None:
        receipt = valid_receipt(int(time.time()))
        receipt["boundaries"]["execution"].update({
            "status": air_divergence.SUPERSEDED_STATUS,
            "superseded_by": air_divergence.LEDGER_REFERENCE,
            "divergence_paths": self.PATHS,
            "divergence_shape_sha256": air_divergence.shape_digest(self.PATHS),
            "lineage": {"agree": True, "comparison": "lineage"},
        })
        bind_case_digests(receipt)
        self.assertIn(
            "boundary execution claims supersession outside the demoted "
            "AIR-comparison set",
            self.errors(receipt, authorize=self.PATHS),
        )

    def test_case_divergence_must_stay_inside_the_boundary_declaration(self) -> None:
        receipt = superseded_receipt(int(time.time()), "relation_tuples", self.PATHS)
        boundary = receipt["boundaries"]["relation_tuples"]
        boundary["corpus"][0]["divergence_paths"] = [
            *self.PATHS, "/components/memory/stream",
        ]
        bind_case_digests(receipt)
        errors = self.errors(receipt, authorize=self.PATHS)
        self.assertIn(
            "boundary case relation_tuples/alu diverges at unauthorized path "
            "/components/memory/stream",
            errors,
        )

    def test_declaration_may_not_pre_authorize_an_unobserved_path(self) -> None:
        receipt = superseded_receipt(int(time.time()), "relation_sums", self.PATHS)
        boundary = receipt["boundaries"]["relation_sums"]
        boundary["corpus"][0]["divergence_paths"] = [self.PATHS[0]]
        boundary["nonempty_public_input"]["divergence_paths"] = [self.PATHS[0]]
        bind_case_digests(receipt)
        self.assertIn(
            "boundary relation_sums divergence declaration is not exactly the union "
            "of the divergence paths its cases report",
            self.errors(receipt, authorize=self.PATHS),
        )

    def test_layout_lineage_agreement_is_still_mandatory(self) -> None:
        receipt = superseded_receipt(int(time.time()), "per_family_witness_rows", self.PATHS)
        receipt["boundaries"]["per_family_witness_rows"]["lineage"]["agree"] = False
        bind_case_digests(receipt)
        self.assertIn(
            "boundary per_family_witness_rows does not attest legacy "
            "layout-lineage agreement",
            self.errors(receipt, authorize=self.PATHS),
        )

    def test_a_demoted_boundary_that_agrees_may_not_claim_a_divergence(self) -> None:
        receipt = superseded_receipt(int(time.time()), "relation_tuples", self.PATHS)
        receipt["boundaries"]["relation_tuples"]["corpus"][0]["agree"] = True
        bind_case_digests(receipt)
        errors = self.errors(receipt, authorize=self.PATHS)
        self.assertIn(
            "boundary case relation_tuples/alu attests agreement yet still declares "
            "a divergence",
            errors,
        )

    def test_a_demoted_boundary_still_needs_comparable_evidence(self) -> None:
        receipt = superseded_receipt(int(time.time()), "relation_tuples", self.PATHS)
        receipt["boundaries"]["relation_tuples"]["corpus"][0]["evidence_error"] = "boom"
        bind_case_digests(receipt)
        errors = self.errors(receipt, authorize=self.PATHS)
        self.assertTrue(
            any("produced no comparable evidence" in error for error in errors), errors
        )

    def test_producer_and_contract_agree_on_the_status_spelling(self) -> None:
        """The producer package may not import this one, so bind the two spellings."""
        producer = (
            Path(__file__).resolve().parents[2]
            / "scripts/riscv_release_oracle_lib/superseded_air.py"
        ).read_text(encoding="utf-8")
        self.assertIn(f'DIVERGENCE_STATUS = "{air_divergence.SUPERSEDED_STATUS}"', producer)
        self.assertIn(f'LEDGER_REFERENCE = "{air_divergence.LEDGER_REFERENCE}"', producer)

if __name__ == "__main__":
    unittest.main()
