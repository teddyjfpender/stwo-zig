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

import ethereum_block_analyze_legacy_opportunity as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def observation() -> dict:
    calls = [
        {
            "bitmap_bytes": 2,
            "eof_immediate_padding": 0,
            "jumpdest_count": 1,
            "length": 9,
            "opcode_positions": [0, 2, 8],
            "push_count": 1,
            "push_overflow": 0,
            "scan_iterations": 3,
            "total_padding": 0,
            "witness_code_index": 2,
        },
        {
            "bitmap_bytes": 2,
            "eof_immediate_padding": 1,
            "jumpdest_count": 0,
            "length": 16,
            "opcode_positions": [0, 1, 5, 7],
            "push_count": 2,
            "push_overflow": 2,
            "scan_iterations": 4,
            "total_padding": 3,
            "witness_code_index": 8,
        },
    ]
    return {
        "aggregate": {
            "bitmap_bytes_sum": 4,
            "call_count": 2,
            "eof_immediate_padding_sum": 1,
            "jumpdest_count_sum": 1,
            "length_sum": 25,
            "opcode_positions_sum": 23,
            "push_count_sum": 3,
            "push_overflow_sum": 2,
            "scan_iterations_sum": 7,
            "source_bytes_chain_sha256": "a" * 64,
            "total_padding_sum": 3,
        },
        "calls": calls,
        "function_authority": {"symbol_rows": 274},
        "witness_code_inventory": {
            "accessed_legacy_code_count": 2,
            "code_count": 7,
            "eip7702_delegation_code_count": 4,
            "empty_code_count": 1,
            "legacy_bytes": 25,
            "legacy_code_count": 2,
            "routing_policy": (
                "legacy=>analyze_legacy;empty-or-0xef01=>Bytecode::new_raw"
            ),
            "total_bytes": 117,
            "unobserved_fallback_code_count": 5,
        },
    }


class AnalyzeLegacyOpportunityTests(unittest.TestCase):
    def test_exact_metrics_histograms_and_call_closure(self) -> None:
        summary = subject.summarize(observation())
        self.assertEqual(summary["call_authority"]["call_count"], 2)
        self.assertEqual(summary["call_authority"]["opcode_position_count"], 7)
        self.assertEqual(summary["call_authority"]["opcode_position_index_sum"], 23)
        self.assertEqual(summary["metrics"]["input_length_bytes"]["sum"], 25)
        self.assertEqual(
            summary["metrics"]["input_length_bytes"]["histogram"],
            [
                {"call_count": 1, "value": 9},
                {"call_count": 1, "value": 16},
            ],
        )
        self.assertEqual(summary["metrics"]["total_padding"]["maximum"], 3)
        self.assertEqual(summary["function_rows"]["observed_symbol_rows"], 274)

    def test_call_aggregate_code_and_position_mutations_reject(self) -> None:
        changed = observation()
        changed["aggregate"]["scan_iterations_sum"] += 1
        with self.assertRaises(subject.AnalyzeLegacyOpportunityError):
            subject.summarize(changed)
        changed = observation()
        changed["calls"][1]["witness_code_index"] = 2
        with self.assertRaises(subject.AnalyzeLegacyOpportunityError):
            subject.summarize(changed)
        changed = observation()
        changed["calls"][1]["opcode_positions"].append(12)
        with self.assertRaises(subject.AnalyzeLegacyOpportunityError):
            subject.summarize(changed)

    @staticmethod
    def fixture() -> dict:
        identity = {
            "bytes": 1,
            "path": "/private/tmp/source",
            "sha256": "1" * 64,
        }
        return protocol.seal({
            "claim_boundary": subject._claim_boundary(),
            "exact_observation": subject.summarize(observation()),
            "inputs": {
                "authorities": {
                    name: copy.deepcopy(identity)
                    for name in subject.IDENTITY_FIELDS
                },
                "semantic_observation": copy.deepcopy(identity),
                "semantic_observation_content_sha256": "2" * 64,
            },
            "production": False,
            "sample": {
                "clock_frame": "leaf_local",
                "execution_profile": "rv32im-zkvm-ethereum-v1",
                "first_global_cycle": 0,
                "first_segment_index": 0,
                "no_extrapolation": True,
                "retired_instructions": 100,
                "sampled_cycles": 100,
                "segment_count": 1,
            },
            "schema": subject.SCHEMA,
            "status": subject.STATUS,
        })

    def test_resealed_histogram_boundary_bool_and_identity_mutations_reject(self) -> None:
        original = self.fixture()
        mutations = (
            lambda value: value.__setitem__("production", 0),
            lambda value: value["claim_boundary"].__setitem__(
                "candidate_air_columns", 0,
            ),
            lambda value: value["sample"].__setitem__("no_extrapolation", 1),
            lambda value: value["exact_observation"]["metrics"][
                "input_length_bytes"
            ]["histogram"][0].__setitem__("call_count", True),
            lambda value: value["exact_observation"]["metrics"][
                "input_length_bytes"
            ]["histogram"].reverse(),
            lambda value: value["exact_observation"]["call_authority"].__setitem__(
                "opcode_position_count", 8,
            ),
            lambda value: value["inputs"].__setitem__(
                "semantic_observation_content_sha256", "3" * 64,
            ),
        )
        with (
            mock.patch.object(
                subject, "_validate_identity", side_effect=lambda value, _: value,
            ),
            mock.patch.object(subject, "build", return_value=original),
        ):
            self.assertIs(subject.validate(original), original)
            for mutate in mutations:
                changed = copy.deepcopy(original)
                mutate(changed)
                changed["content_sha256"] = protocol.content_sha256(changed)
                with self.assertRaises(subject.AnalyzeLegacyOpportunityError):
                    subject.validate(changed)

    def test_unsealed_mutation_rejects(self) -> None:
        value = self.fixture()
        value["exact_observation"]["metrics"]["bitmap_bytes"]["sum"] += 1
        with self.assertRaises(subject.AnalyzeLegacyOpportunityError):
            subject.validate(value)


if __name__ == "__main__":
    unittest.main()
