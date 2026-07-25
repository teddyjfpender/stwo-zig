#!/usr/bin/env python3
"""Schema and independence tests for Native interchange mutations."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scripts.e2e_interop_lib.mutations import (
    ACTIVE_MUTATIONS,
    M31_MODULUS,
    PLONK_LOGUP_ORACLE_MUTATIONS,
    SUPPORTED_EXAMPLES,
    coverage_manifest,
    mutate_artifact,
    plonk_logup_oracle_coverage_manifest,
    mutations_for_example,
)


def proof_wire() -> dict[str, Any]:
    digest = list(range(32))
    return {
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
        "commitments": [digest, digest, digest, digest],
        "sampled_values": [[[[1, 2, 3, 4]]]],
        "decommitments": [{"hash_witness": [digest]}],
        "queried_values": [[[1]]],
        "proof_of_work": 7,
        "fri_proof": {
            "first_layer": {
                "fri_witness": [[5, 6, 7, 8]],
                "decommitment": {"hash_witness": [digest]},
                "commitment": digest,
            },
            "inner_layers": [],
            "last_layer_poly": [[9, 10, 11, 12]],
        },
    }


def artifact(example: str) -> dict[str, Any]:
    statements = {
        "blake_statement": None,
        "plonk_statement": None,
        "plonk_logup_statement": None,
        "poseidon_statement": None,
        "state_machine_statement": None,
        "wide_fibonacci_statement": None,
        "xor_statement": None,
    }
    values = {
        "blake": (
            "blake_statement",
            {
                "stmt0": {"log_size": 8},
                "stmt1": {
                    "scheduler_claimed_sum": [1, 2, 3, 4],
                    "round_claimed_sums": [[1, 2, 3, 4], [5, 6, 7, 8]],
                    "xor_claimed_sums": [[1, 2, 3, 4]] * 5,
                },
            },
        ),
        "plonk": ("plonk_statement", {"log_n_rows": 8}),
        "plonk_logup": (
            "plonk_logup_statement",
            {"log_n_rows": 8, "claimed_sum": [1, 2, 3, 4]},
        ),
        "poseidon": ("poseidon_statement", {"log_n_instances": 8}),
        "state_machine": (
            "state_machine_statement",
            {
                "public_input": [[1, 2], [3, 4]],
                "stmt0": {"n": 1, "m": 2},
                "stmt1": {
                    "x_axis_claimed_sum": [1, 2, 3, 4],
                    "y_axis_claimed_sum": [5, 6, 7, 8],
                },
            },
        ),
        "wide_fibonacci": (
            "wide_fibonacci_statement",
            {"log_n_rows": 8, "sequence_len": 16},
        ),
        "xor": (
            "xor_statement",
            {
                "log_size": 8,
                "log_step": 2,
                "offset": 1,
                "claimed_sum": [0, 0, 0, 0],
            },
        ),
    }
    statement_name, statement = values[example]
    statements[statement_name] = statement
    wire = json.dumps(proof_wire(), separators=(",", ":")).encode("utf-8")
    return {
        "schema_version": 1,
        "upstream_commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
        "exchange_mode": "proof_exchange_json_wire_v1",
        "generator": "rust",
        "example": example,
        "prove_mode": "prove",
        "pcs_config": {
            "pow_bits": 0,
            "fri_config": {
                "log_blowup_factor": 1,
                "log_last_layer_degree_bound": 0,
                "n_queries": 3,
                "fold_step": 1,
            },
            "lifting_log_size": None,
        },
        **statements,
        "proof_bytes_hex": wire.hex(),
    }


def semantic_artifact(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["proof"] = json.loads(bytes.fromhex(result.pop("proof_bytes_hex")))
    return result


def differing_leaves(left: Any, right: Any, path: str = "") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict):
        if set(left) != set(right):
            return [path]
        differences: list[str] = []
        for key in sorted(left):
            child = f"{path}.{key}" if path else key
            differences.extend(differing_leaves(left[key], right[key], child))
        return differences
    if isinstance(left, list):
        if len(left) != len(right):
            return [path]
        differences = []
        for index, (lhs, rhs) in enumerate(zip(left, right)):
            differences.extend(differing_leaves(lhs, rhs, f"{path}[{index}]"))
        return differences
    return [] if left == right else [path]


class InteropMutationTests(unittest.TestCase):
    def test_every_mutation_changes_exactly_one_semantic_leaf_for_every_example(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for example in SUPPORTED_EXAMPLES:
                source = root / f"{example}.json"
                original = artifact(example)
                source.write_text(json.dumps(original), encoding="utf-8")
                digests: set[str] = set()
                applicable = mutations_for_example(example)
                for spec in applicable:
                    with self.subTest(example=example, mutation=spec.mutation_id):
                        destination = root / f"{example}-{spec.mutation_id}.json"
                        mutate_artifact(source, destination, spec, example=example)
                        mutated = json.loads(destination.read_text(encoding="utf-8"))
                        differences = differing_leaves(
                            semantic_artifact(original), semantic_artifact(mutated)
                        )
                        self.assertEqual(len(differences), 1, differences)
                        digests.add(destination.read_bytes().hex())
                self.assertEqual(len(digests), len(applicable))
                self.assertEqual(json.loads(source.read_text(encoding="utf-8")), original)

    def test_plonk_logup_oracle_mutations_are_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plonk_logup.json"
            original = artifact("plonk_logup")
            source.write_text(json.dumps(original), encoding="utf-8")
            for spec in PLONK_LOGUP_ORACLE_MUTATIONS:
                with self.subTest(mutation=spec.mutation_id):
                    destination = root / f"{spec.mutation_id}.json"
                    mutate_artifact(source, destination, spec, example="plonk_logup")
                    mutated = json.loads(destination.read_text(encoding="utf-8"))
                    differences = differing_leaves(
                        semantic_artifact(original), semantic_artifact(mutated)
                    )
                    self.assertEqual(len(differences), 1, differences)

    def test_mutations_remain_canonical_field_values(self) -> None:
        self.assertGreater(M31_MODULUS, 0)
        ids = [spec.mutation_id for spec in ACTIVE_MUTATIONS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("pow_nonce", ids)
        self.assertIn("proof_pcs_config", ids)
        self.assertIn("outer_fold_step", ids)
        self.assertIn("outer_lifting_log_size", ids)
        self.assertIn("transcript_bound_sampled_value", ids)
        self.assertIn("xor_commitment_count_missing", ids)
        self.assertIn("xor_commitment_count_extra", ids)
        self.assertIn("state_machine_stmt0_n", ids)
        self.assertIn("state_machine_stmt0_m", ids)
        self.assertIn("state_machine_x_axis_claimed_sum", ids)
        self.assertIn("state_machine_y_axis_claimed_sum", ids)
        self.assertIn("state_machine_commitment_count_missing", ids)
        self.assertIn("state_machine_commitment_count_extra", ids)

    def test_coverage_names_all_required_and_not_applicable_surfaces(self) -> None:
        coverage = coverage_manifest(list(SUPPORTED_EXAMPLES))
        self.assertEqual(
            coverage["required_cases"],
            sum(
                len(mutations_for_example(example)) * 2
                for example in SUPPORTED_EXAMPLES
            ),
        )
        self.assertEqual(
            {entry["mutation_id"] for entry in coverage["applicable"]},
            {spec.mutation_id for spec in ACTIVE_MUTATIONS},
        )
        not_applicable = coverage["not_applicable"]
        self.assertEqual(len(not_applicable), 1)
        self.assertEqual(not_applicable[0]["mutation_id"], "serialized_transcript_challenge")
        self.assertIn("no Fiat-Shamir transcript state", not_applicable[0]["reason"])

        exact = plonk_logup_oracle_coverage_manifest()
        self.assertEqual(
            exact["required_cases"], len(PLONK_LOGUP_ORACLE_MUTATIONS)
        )
        self.assertEqual(
            {entry["mutation_id"] for entry in exact["applicable"]},
            {spec.mutation_id for spec in PLONK_LOGUP_ORACLE_MUTATIONS},
        )


if __name__ == "__main__":
    unittest.main()
