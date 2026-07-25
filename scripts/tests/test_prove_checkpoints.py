#!/usr/bin/env python3
"""Unit tests for bidirectional prove checkpoint normalization."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import prove_checkpoints


def artifact_for(proof_wire: dict[str, object]) -> dict[str, object]:
    encoded = json.dumps(proof_wire, separators=(",", ":")).encode("utf-8")
    return {"proof_bytes_hex": encoded.hex()}


class CanonicalProofWireTests(unittest.TestCase):
    def test_normalizes_only_backward_compatible_config_defaults(self) -> None:
        rust_wire = {
            "config": {
                "pow_bits": 0,
                "fri_config": {
                    "log_blowup_factor": 1,
                    "log_last_layer_degree_bound": 0,
                    "n_queries": 3,
                },
            },
            "commitments": [[1, 2, 3]],
        }
        zig_wire = {
            "config": {
                "pow_bits": 0,
                "fri_config": {
                    "log_blowup_factor": 1,
                    "log_last_layer_degree_bound": 0,
                    "n_queries": 3,
                    "fold_step": 1,
                },
                "lifting_log_size": None,
            },
            "commitments": [[1, 2, 3]],
        }

        self.assertEqual(
            prove_checkpoints.canonical_proof_wire(artifact_for(rust_wire)),
            prove_checkpoints.canonical_proof_wire(artifact_for(zig_wire)),
        )

    def test_preserves_non_default_semantic_differences(self) -> None:
        left = artifact_for(
            {"config": {"fri_config": {"fold_step": 1}}, "commitments": [[1]]}
        )
        right = artifact_for(
            {"config": {"fri_config": {"fold_step": 2}}, "commitments": [[1]]}
        )

        self.assertNotEqual(
            prove_checkpoints.canonical_proof_wire(left),
            prove_checkpoints.canonical_proof_wire(right),
        )


class GeneratedArtifactLifecycleTests(unittest.TestCase):
    def test_retires_only_the_prior_generated_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            generated = root / "proof.json"
            sibling = root / "receipt.json"
            generated.write_text("stale", encoding="utf-8")
            sibling.write_text("preserve", encoding="utf-8")

            prove_checkpoints.prepare_generated_artifact(generated)
            prove_checkpoints.prepare_generated_artifact(generated)

            self.assertFalse(generated.exists())
            self.assertEqual(sibling.read_text(encoding="utf-8"), "preserve")

    def test_exact_blake_statement_mutation_changes_logup_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "proof.json"
            mutated = root / "mutated.json"
            source.write_text(
                json.dumps(
                    {
                        "blake_statement": {
                            "stmt0": {"log_size": 4},
                            "stmt1": {
                                "scheduler_claimed_sum": [1, 2, 3, 4],
                                "round_claimed_sums": [],
                                "xor_claimed_sums": [],
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )

            prove_checkpoints.tamper_statement(source, mutated, "blake")

            statement = json.loads(mutated.read_text(encoding="utf-8"))[
                "blake_statement"
            ]
            self.assertEqual(statement["stmt0"]["log_size"], 4)
            self.assertEqual(
                statement["stmt1"]["scheduler_claimed_sum"],
                [2, 2, 3, 4],
            )


if __name__ == "__main__":
    unittest.main()
