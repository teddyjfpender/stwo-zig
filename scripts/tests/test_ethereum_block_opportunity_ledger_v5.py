from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_opportunity_ledger_v5 as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


class OpportunityLedgerV5Tests(unittest.TestCase):
    def fixture(self) -> dict:
        inputs = {
            name: {
                "path": f"/private/tmp/{name}", "bytes": 1,
                "sha256": str(index) * 64,
            }
            for index, name in enumerate((
                "prior_ledger_v4", "word_sponge_execution_evidence",
                "word_sponge_bulk_projection_evidence",
                "ecrecover_execution_evidence",
                "ecrecover_bulk_projection_evidence",
                "ecrecover_pc_census_evidence",
            ), start=1)
        }
        return protocol.seal({
            "schema": subject.SCHEMA,
            "status": subject.STATUS,
            "inputs": inputs,
            "retained_prior_scopes": {},
            "word_sponge_execution": {},
            "word_sponge_bulk_projection": {},
            "ecrecover_success_execution": {},
            "ecrecover_bulk_projection": {},
            "ecrecover_pc_census": {},
            "scope_separation": {
                "cross_candidate_combination": None,
                "independent_gain_multiplication_used": False,
                "synthesized_post_bulk_journal": None,
            },
            "claims": {
                "full_program_semantic_equivalence": None,
                "full_block_air_complete": None,
                "full_block_proof_complete": None,
                "fresh_full_block_verification": None,
                "measured_proving_end_to_end_wall_ns": None,
                "production_promotion_eligible": False,
            },
        })

    def test_resealed_combination_and_promotion_mutations_reject(self) -> None:
        value = self.fixture()
        with (
            mock.patch.object(subject, "_validate_identity"),
            mock.patch.object(subject, "build", return_value=value),
        ):
            self.assertIs(subject.validate(value), value)
            changed = copy.deepcopy(value)
            changed["scope_separation"]["independent_gain_multiplication_used"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.OpportunityLedgerV5Error):
                subject.validate(changed)

            changed = copy.deepcopy(value)
            changed["claims"]["production_promotion_eligible"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.OpportunityLedgerV5Error):
                subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
