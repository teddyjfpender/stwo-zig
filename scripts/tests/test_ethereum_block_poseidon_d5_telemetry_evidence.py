from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_poseidon_d5_telemetry_evidence as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def measurement(prove_ns: int, proof_bytes: int) -> dict:
    return {
        "prove_ns": prove_ns,
        "verify_ns": 10_000_000,
        "proof_bytes": proof_bytes,
    }


def telemetry(arm: str, retained: int, recomputed: int) -> dict:
    return {
        "schema": subject.TELEMETRY_SCHEMA,
        "arm": arm,
        "prepare_ns": 42,
        "layout_ns": 2,
        "source_stage_ns": 3,
        "twiddle_ns": 5,
        "retained_extension_ns": 7,
        "recomputed_extension_ns": 11,
        "finalize_ns": 14,
        "row_evaluation_ns": 100,
        "source_columns": 249,
        "borrowed_columns": 0,
        "retained_columns": retained,
        "recomputed_columns": recomputed,
        "evaluated_rows": 1 << 18,
    }


class PoseidonD5TelemetryEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.stderr = self.root / "stderr-time.log"
        self.stdout = self.root / "stdout.log"
        self.stdout.write_bytes(b"")
        self.records = [
            {
                "schema": subject.AB_SCHEMA,
                "production": False,
                "log_size": 16,
                "call_count": 1 << 16,
                "engine_workers": 4,
                "legacy_main_columns": 445,
                "degree5_main_columns": 239,
                "legacy_never": [
                    measurement(400, 31_170), measurement(410, 31_170),
                ],
                "degree5_never": [
                    measurement(350, 25_360), measurement(360, 25_360),
                ],
                "legacy_always": measurement(80, 31_170),
                "degree5_always": measurement(170, 25_360),
            },
            telemetry("degree5_never_a", 0, 249),
            telemetry("degree5_never_b", 0, 249),
            telemetry("degree5_always", 249, 0),
        ]
        self.write_stream()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_stream(self) -> None:
        records = "\n".join(json.dumps(
            value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
        ) for value in self.records)
        self.stderr.write_text(
            subject.PREFIX + records + "\n"
            "real 1.00\nuser 2.00\nsys 0.25\n"
            " 100 maximum resident set size\n"
            " 0 swaps\n"
            " 120 peak memory footprint\n",
            encoding="ascii",
        )

    def test_replays_and_ranks_stage_only(self) -> None:
        value = subject.build(self.stderr, self.stdout)
        self.assertEqual(value["stage_ranking"]["best_measured_arm"],
                         "legacy_always")
        self.assertTrue(value["stage_ranking"][
            "degree5_never_faster_than_legacy_never"
        ])
        self.assertTrue(value["stage_ranking"][
            "degree5_retained_regresses_vs_legacy_retained"
        ])
        self.assertEqual(value["process_measurement"]["wall_ns"],
                         1_000_000_000)
        boundary = value["claim_boundary"]
        self.assertIsNone(boundary["executable_custody"])
        self.assertIsNone(boundary["proof_correctness"])
        self.assertIsNone(boundary["fresh_proof_verification"])
        self.assertIsNone(boundary["measured_end_to_end_wall_ns"])
        self.assertFalse(boundary["performance_claim_eligible"])

    def test_bool_as_int_and_phase_mutations_reject(self) -> None:
        self.records[0]["production"] = 0
        self.write_stream()
        with self.assertRaises(subject.PoseidonD5TelemetryEvidenceError):
            subject.build(self.stderr, self.stdout)

    def test_winner_is_derived_when_degree5_retained_is_faster(self) -> None:
        self.records[0]["degree5_always"]["prove_ns"] = 70
        self.write_stream()
        value = subject.build(self.stderr, self.stdout)
        self.assertEqual(value["stage_ranking"]["best_measured_arm"],
                         "degree5_always")
        self.assertFalse(value["stage_ranking"][
            "degree5_retained_regresses_vs_legacy_retained"
        ])

        self.records[0]["production"] = False
        self.records[1]["prepare_ns"] += 1
        self.write_stream()
        with self.assertRaises(subject.PoseidonD5TelemetryEvidenceError):
            subject.build(self.stderr, self.stdout)

    def test_resealed_promotion_mutation_fails_replay(self) -> None:
        value = subject.build(self.stderr, self.stdout)
        with mock.patch.object(subject, "build", return_value=value):
            self.assertIs(subject.validate(value), value)
            changed = copy.deepcopy(value)
            changed["claim_boundary"]["performance_claim_eligible"] = 0
            changed["content_sha256"] = protocol.content_sha256(changed)
            with self.assertRaises(subject.PoseidonD5TelemetryEvidenceError):
                subject.validate(changed)


if __name__ == "__main__":
    unittest.main()
