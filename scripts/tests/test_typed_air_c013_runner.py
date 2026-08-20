from __future__ import annotations

import datetime as dt
import json
import unittest
from pathlib import Path

from scripts.typed_air_c013_capture_lib.child_report import (
    CALIBRATION_SCHEMA,
    RESOURCE_SCOPE,
    SECURE_PCS,
)
from scripts.typed_air_c013_capture_lib.model import SCHEDULE_SHA256
from scripts.typed_air_c013_capture_lib.runner import ProcessResult, run_attempt


class AttemptRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = {
            "source": {"commit": "1" * 40, "tree": "2" * 40},
            "artifacts": {
                "calibration_child": {
                    "path": "/capture/calibration-child",
                    "sha256": "10" * 32,
                },
                "calibration_elf": {
                    "path": "/capture/calibration.elf",
                    "sha256": "11" * 32,
                },
            },
        }
        empty = "e3" * 32
        self.attempt = {
            "global_ordinal": 0,
            "kind": "calibration",
            "phase": "calibration",
            "arm": "a",
            "sample_index": 0,
            "input_bytes": 0,
            "output_bytes": 0,
            "input_sha256": empty,
            "output_sha256": empty,
            "executable_id": "calibration_child",
            "elf_id": "calibration_elf",
        }

    def _report(self) -> bytes:
        report = {
            "schema": CALIBRATION_SCHEMA,
            "status": "verified",
            "label": "a",
            "security": "secure",
            "phase": "calibration",
            "workload": "multi_shard_addi",
            "schedule_sha256": SCHEDULE_SHA256,
            "sample_index": 0,
            "max_steps": 262_144,
            "input_bytes": 0,
            "output_bytes": 0,
            "input_sha256": self.attempt["input_sha256"],
            "output_sha256": self.attempt["output_sha256"],
            "elf_sha256": "11" * 32,
            "executable_sha256": "10" * 32,
            "proof_sha256": "12" * 32,
            "implementation_commit": "1" * 40,
            "implementation_tree": "2" * 40,
            "implementation_dirty": False,
            "dirty_content_sha256": None,
            "pcs": SECURE_PCS,
            "metrics": {
                "execution_steps": 1,
                "execution_ns": 2,
                "proving_ns": 3,
                "proof_encoding_ns": 4,
                "verification_ns": 5,
                "verified_request_ns": 10,
                "proof_wire_bytes": 6,
                "preprocessed_cells": 7,
                "main_cells": 8,
                "interaction_cells": 9,
            },
            "resources": {
                "scope": RESOURCE_SCOPE,
                "source": "darwin_proc_pid_rusage_v6",
                "lifetime_peak_physical_footprint_bytes": 10,
                "process_cpu_ns": 11,
                "energy_nj": 12,
                "instructions": 13,
                "cycles": 14,
                "unavailable_reason": None,
            },
        }
        return json.dumps(report, separators=(",", ":")).encode() + b"\n"

    def test_verified_child_becomes_one_authenticated_attempt_record(self) -> None:
        monotonic = iter((100, 175))
        result = run_attempt(
            repository=Path("/capture"),
            plan=self.plan,
            attempt=self.attempt,
            timeout_seconds=1,
            child_runner=lambda *_: ProcessResult(0, self._report(), b""),
            monotonic=lambda: next(monotonic),
            utc_clock=lambda: dt.datetime(2026, 8, 11, tzinfo=dt.timezone.utc),
        )
        record, stdout, stderr, report = result
        self.assertEqual(record["status"], "verified")
        self.assertEqual(record["launcher_elapsed_ns"], 75)
        self.assertIsNone(record["failure_code"])
        self.assertEqual(report["proof_sha256"], "12" * 32)
        self.assertTrue(stdout.endswith(b"\n"))
        self.assertEqual(stderr, b"")

    def test_stderr_is_retained_as_failure_never_silently_accepted(self) -> None:
        monotonic = iter((10, 20))
        record, stdout, stderr, report = run_attempt(
            repository=Path("/capture"),
            plan=self.plan,
            attempt=self.attempt,
            timeout_seconds=1,
            child_runner=lambda *_: ProcessResult(0, self._report(), b"warning"),
            monotonic=lambda: next(monotonic),
            utc_clock=lambda: dt.datetime(2026, 8, 11, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["failure_code"], "child-stderr")
        self.assertIsNone(report)
        self.assertEqual(stderr, b"warning")
        self.assertTrue(stdout)


if __name__ == "__main__":
    unittest.main()
