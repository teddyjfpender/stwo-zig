from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch" / "benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_evm_swap_workload_evidence as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def symbol(index: int) -> str:
    return (
        f"{subject.SWAP_PREFIX}{index}, "
        "revm_interpreter::interpreter::EthInterpreter>"
    )


def source_row(
    index: int,
    *,
    rows_per_call: int = 137,
    integer_closure: bool = True,
) -> dict:
    calls = index
    missing = 1 if index == 1 else 0
    rows = calls * rows_per_call + (0 if integer_closure else 1)
    return {
        "category": "stack",
        "observed_cross_symbol_entries": calls,
        "observed_rows": rows,
        "observed_self_symbol_edges": rows - calls - missing,
        "opcode_group": "swap",
        "rows_without_observed_incoming_edge": missing,
        "symbol": symbol(index),
    }


def census(
    *,
    nonuniform_index: int | None = None,
    noninteger_index: int | None = None,
) -> dict:
    rows = []
    for index in subject.SWAP_INDICES:
        rows.append(source_row(
            index,
            rows_per_call=138 if index == nonuniform_index else 137,
            integer_closure=index != noninteger_index,
        ))
    rows.append({
        "category": "arithmetic",
        "observed_cross_symbol_entries": 1,
        "observed_rows": 5,
        "observed_self_symbol_edges": 4,
        "opcode_group": "add",
        "rows_without_observed_incoming_edge": 0,
        "symbol": "revm_interpreter::instructions::arithmetic::add",
    })
    return {"symbols": rows}


class EvmSwapWorkloadEvidenceTests(unittest.TestCase):
    def test_exact_swap_membership_counts_rows_and_uniform_closure(self) -> None:
        workload = subject.derive_swap(census())
        self.assertEqual(
            [row["swap_index"] for row in workload["members"]],
            list(range(1, 17)),
        )
        self.assertEqual(
            [row["observed_call_count"] for row in workload["members"]],
            list(range(1, 17)),
        )
        totals = workload["totals"]
        self.assertEqual(totals["total_observed_call_count"], 136)
        self.assertEqual(totals["total_observed_rows"], 18_632)
        self.assertEqual(totals["uniform_rows_per_call"], 137)
        self.assertTrue(totals["all_members_exact_integer_closure"])
        self.assertTrue(totals["aggregate_integer_closure"])
        self.assertEqual(totals["total_rows_without_observed_incoming_edge"], 1)

    def test_uniform_claim_is_null_on_nonuniform_or_noninteger_member(self) -> None:
        nonuniform = subject.derive_swap(census(nonuniform_index=8))["totals"]
        self.assertTrue(nonuniform["all_members_exact_integer_closure"])
        self.assertFalse(nonuniform["aggregate_integer_closure"])
        self.assertIsNone(nonuniform["uniform_rows_per_call"])

        noninteger = subject.derive_swap(census(noninteger_index=8))["totals"]
        self.assertFalse(noninteger["all_members_exact_integer_closure"])
        self.assertFalse(noninteger["aggregate_integer_closure"])
        self.assertIsNone(noninteger["uniform_rows_per_call"])

    def test_missing_duplicate_or_malformed_swap_member_rejects(self) -> None:
        missing = census()
        missing["symbols"] = [
            row for row in missing["symbols"]
            if row.get("symbol") != symbol(16)
        ]
        with self.assertRaises(subject.EvmSwapWorkloadEvidenceError):
            subject.derive_swap(missing)

        duplicate = census()
        duplicate["symbols"].append(copy.deepcopy(source_row(1)))
        with self.assertRaises(subject.EvmSwapWorkloadEvidenceError):
            subject.derive_swap(duplicate)

        malformed = census()
        malformed["symbols"][0]["symbol"] = (
            f"{subject.SWAP_PREFIX}01, "
            "revm_interpreter::interpreter::EthInterpreter>"
        )
        with self.assertRaises(subject.EvmSwapWorkloadEvidenceError):
            subject.derive_swap(malformed)

    def fixture(self) -> dict:
        identity = {
            "bytes": 1,
            "path": "/private/tmp/source",
            "sha256": "1" * 64,
        }
        return protocol.seal({
            "candidate_boundary": subject._candidate_boundary(),
            "no_extrapolation": True,
            "performance_claim_eligible": False,
            "production": False,
            "sample": {"complete_execution": True, "no_extrapolation": True},
            "schema": subject.SCHEMA,
            "status": subject.STATUS,
            "upstream": {
                "census_v7": copy.deepcopy(identity),
                "census_v7_content_sha256": "2" * 64,
                "census_v7_inputs": {"pc": copy.deepcopy(identity)},
                "matrix_v8": copy.deepcopy(identity),
                "matrix_v8_content_sha256": "3" * 64,
                "matrix_v8_inputs": {"census": copy.deepcopy(identity)},
                "nm_symbol_map": copy.deepcopy(identity),
                "pc_observation": copy.deepcopy(identity),
            },
            "v8_stack_family": {
                "candidate_id": "stack-transform-v1",
                "production_active": False,
            },
            "workload": subject.derive_swap(census()),
        })

    def test_resealed_workload_candidate_boolean_and_seal_mutations_reject(self) -> None:
        original = self.fixture()
        mutations = (
            lambda value: value["workload"]["totals"].__setitem__(
                "uniform_rows_per_call", 138,
            ),
            lambda value: value["workload"]["members"][0].__setitem__(
                "observed_call_count", True,
            ),
            lambda value: value["workload"]["members"][0].__setitem__(
                "symbol", symbol(2),
            ),
            lambda value: value["candidate_boundary"].__setitem__(
                "candidate_air_geometry", {},
            ),
            lambda value: value.__setitem__("production", 0),
            lambda value: value.__setitem__("performance_claim_eligible", 0),
            lambda value: value["upstream"].__setitem__(
                "census_v7_content_sha256", "4" * 64,
            ),
        )
        with (
            mock.patch.object(subject, "_validate_identity", side_effect=lambda value, _: value),
            mock.patch.object(subject, "build", return_value=original),
        ):
            self.assertIs(subject.validate(original), original)
            for mutate in mutations:
                changed = copy.deepcopy(original)
                mutate(changed)
                changed["content_sha256"] = protocol.content_sha256(changed)
                with self.assertRaises(subject.EvmSwapWorkloadEvidenceError):
                    subject.validate(changed)

    def test_unsealed_content_mutation_rejects(self) -> None:
        original = self.fixture()
        original["workload"]["totals"]["total_observed_rows"] += 1
        with self.assertRaises(subject.EvmSwapWorkloadEvidenceError):
            subject.validate(original)


if __name__ == "__main__":
    unittest.main()
