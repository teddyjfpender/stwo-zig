from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path

from scripts.typed_air_r006_capture_lib.codec import (
    canonical_bytes,
    content_digest,
    sha256_bytes,
)
from scripts.typed_air_r006_capture_lib.controller import (
    FileInventory,
    Journal,
    ProcessResult,
    _validate_record,
    run_attempt,
)
from scripts.typed_air_r006_capture_lib.model import CaptureError
from scripts.tests.test_typed_air_r006_capture import R006Fixture


class ControllerSmokeTests(R006Fixture):
    def test_one_fresh_profiled_attempt_runs_independent_verifier_and_journals(self) -> None:
        attempt = self.plan["attempts"][80]
        proof = b"deterministic-proof"
        calls: list[tuple[str, ...]] = []

        def runner(command, cwd, timeout, environment):
            del timeout
            calls.append(tuple(command))
            self.assertEqual(environment["STWO_ZIG_WORKERS"], str(attempt["worker_count"]))
            self.assertEqual(
                environment["STWO_ZIG_MERKLE_WORKERS"],
                str(attempt["worker_count"]),
            )
            self.assertNotIn("STWO_ZIG_POW_WORKERS", environment)
            if command[1] == "bench":
                proof_path = Path(cwd) / command[command.index("--proof-out") + 1]
                proof_path.write_bytes(proof)
                return ProcessResult(0, self.report(self.plan, attempt, proof), b"", 123)
            self.assertEqual(command[1], "verify")
            return ProcessResult(0, self.verifier_receipt(self.plan), b"", 45)

        clock_values = iter(range(100, 1000, 100))
        bundle = self.scratch / "one-attempt-bundle"
        journal = Journal(bundle, self.plan, canonical_bytes(self.plan))
        record = run_attempt(
            journal=journal,
            plan=self.plan,
            attempt=attempt,
            timeout_seconds=10,
            child_runner=runner,
            monotonic=lambda: next(clock_values),
            utc_clock=lambda: dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc),
        )
        sealed = journal.append(record)
        identity = journal.close()
        self.assertEqual(record["status"], "verified")
        self.assertEqual(record["process_cpu_ns"], 123)
        self.assertEqual(record["independent_verification"]["process_cpu_ns"], 45)
        self.assertEqual(len(calls), 2)
        self.assertIn("--profiled", calls[0])
        self.assertEqual(identity["records"], 2)
        self.assertTrue((bundle / attempt["proof_path"]).is_file())
        replayed = _validate_record(
            sealed,
            plan=self.plan,
            attempt=attempt,
            inventory=FileInventory(bundle),
        )
        self.assertEqual(replayed, record["identity"])

        changed = copy.deepcopy(sealed)
        changed["streams"]["report"]["path"] = attempt["stderr_path"]
        with self.assertRaisesRegex(CaptureError, "stream path"):
            _validate_record(
                changed,
                plan=self.plan,
                attempt=attempt,
                inventory=FileInventory(bundle),
            )

        receipt_path = bundle / attempt["verify_stdout_path"]
        receipt = json.loads(receipt_path.read_bytes())
        receipt["transcript_state_blake2s"] = "a" * 64
        mutated_raw = json.dumps(receipt, separators=(",", ":")).encode() + b"\n"
        receipt_path.write_bytes(mutated_raw)
        changed = copy.deepcopy(sealed)
        changed["independent_verification"]["stdout"] = {
            "path": attempt["verify_stdout_path"],
            "bytes": len(mutated_raw),
            "sha256": sha256_bytes(mutated_raw),
        }
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "transcript_state_blake2s"):
            _validate_record(
                changed,
                plan=self.plan,
                attempt=attempt,
                inventory=FileInventory(bundle),
            )

    def test_verifier_stderr_remains_forbidden_with_a_valid_receipt(self) -> None:
        attempt = self.plan["attempts"][80]
        proof = b"deterministic-proof"

        def runner(command, cwd, timeout, environment):
            del timeout, environment
            if command[1] == "bench":
                proof_path = Path(cwd) / command[command.index("--proof-out") + 1]
                proof_path.write_bytes(proof)
                return ProcessResult(0, self.report(self.plan, attempt, proof), b"", 123)
            return ProcessResult(
                0,
                self.verifier_receipt(self.plan),
                b"unexpected diagnostic",
                45,
            )

        clock_values = iter(range(100, 1000, 100))
        journal = Journal(
            self.scratch / "verifier-stderr-bundle",
            self.plan,
            canonical_bytes(self.plan),
        )
        record = run_attempt(
            journal=journal,
            plan=self.plan,
            attempt=attempt,
            timeout_seconds=10,
            child_runner=runner,
            monotonic=lambda: next(clock_values),
            utc_clock=lambda: dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc),
        )
        journal.append(record)
        journal.close()
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["failure_code"], "verifier-output")
        self.assertEqual(record["independent_verification"]["status"], "failed")
