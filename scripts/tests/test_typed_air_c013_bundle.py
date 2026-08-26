from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.typed_air_c013_capture_lib import bundle as bundle_module
from scripts.typed_air_c013_capture_lib import schedule
from scripts.typed_air_c013_capture_lib.bundle import validate_bundle
from scripts.typed_air_c013_capture_lib.child_report import (
    BACKGROUND,
    CALIBRATION_SCHEMA,
    POSEIDON_SCHEMA,
    RESOURCE_SCOPE,
    SECURE_PCS,
    command_for_attempt,
)
from scripts.typed_air_c013_capture_lib.codec import (
    canonical_bytes,
    content_digest,
    sha256_bytes,
)
from scripts.typed_air_c013_capture_lib.model import (
    CORPUS_DIGESTS,
    CaptureError,
    SCHEDULE_SHA256,
)
from scripts.typed_air_c013_capture_lib.statistics import (
    calibration_gate,
    evaluate_calibration,
)


EMPTY_SHA256 = sha256_bytes(b"")
NOW = "2026-08-11T00:00:00Z"


def _identity(path: str, raw: bytes) -> dict[str, object]:
    return {"path": path, "bytes": len(raw), "sha256": sha256_bytes(raw)}


def _seal(value: dict[str, object]) -> dict[str, object]:
    value["content_sha256"] = content_digest(value)
    return value


class BundleFixture:
    def __init__(self, root: Path, destination: Path):
        self.repository = root
        self.path = destination
        self.path.mkdir()
        (self.path / "attempts").mkdir()
        self.attempts = self._attempts()
        self.plan = self._plan()
        (self.path / "plan.json").write_bytes(canonical_bytes(self.plan))
        self.reports = [self._report(item) for item in self.attempts]
        self.records = [self._header()]
        for attempt, report in zip(
            self.attempts[:80], self.reports[:80], strict=True
        ):
            self.records.append(self._attempt_record(attempt, report))
        calibration = evaluate_calibration(
            self.repository,
            self.plan,
            list(zip(self.attempts[:80], self.reports[:80], strict=True)),
        )
        (self.path / "calibration.json").write_bytes(canonical_bytes(calibration))
        self.records.append(
            {
                "schema": "stwo.typed-air.c013-aa-admission-record.v1",
                "verdict": "PASS",
                "artifact": {},
            }
        )
        self.records.append(self._attempt_record(self.attempts[80], self.reports[80]))
        self.bundle = {
            "schema": "stwo.typed-air.c013-capture-bundle.v1",
            "status": "CAPTURE_COMPLETE_AWAITING_RECEIPT_VALIDATION",
            "session_id": self.plan["session_id"],
            "plan_sha256": self.plan["content_sha256"],
            "started_at_utc": NOW,
            "completed_at_utc": NOW,
            "planned_attempts": 81,
            "recorded_attempts": 81,
            "verified_attempts": 81,
            "failed_attempts": 0,
            "journal": {},
            "calibration": {},
            "cpu_reduction": None,
            "performance_verdict": None,
        }
        self.persist()

    @staticmethod
    def _attempts() -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for item in schedule.all_attempts()[:80]:
            result.append(
                {
                    "global_ordinal": item.global_ordinal,
                    "kind": "calibration",
                    "sample_index": item.sample_index,
                    "phase": item.phase,
                    "arm": item.arm,
                    "round": item.round,
                    "input_bytes": 0,
                    "output_bytes": 0,
                    "input_sha256": EMPTY_SHA256,
                    "output_sha256": EMPTY_SHA256,
                    "executable_id": "calibration_child",
                    "elf_id": "calibration_elf",
                }
            )
        item = schedule.all_attempts()[80]
        assert item.calls is not None and item.shape is not None
        input_sha, output_sha = CORPUS_DIGESTS[item.calls]
        result.append(
            {
                "global_ordinal": 80,
                "kind": "m6",
                "sample_index": item.sample_index,
                "phase": item.phase,
                "arm": item.arm,
                "round": item.round,
                "shape": item.shape,
                "calls": item.calls,
                "input_bytes": 4 + item.calls * 64,
                "output_bytes": item.calls * 64,
                "input_sha256": input_sha,
                "output_sha256": output_sha,
                "executable_id": "poseidon2_proof_child",
                "elf_id": f"{item.shape}_{item.arm}_elf",
            }
        )
        return result

    def _plan(self) -> dict[str, object]:
        m6_elf = self.attempts[80]["elf_id"]
        plan = {
            "session_id": "bundle-validator-fixture",
            "source": {"commit": "1" * 40, "tree": "2" * 40},
            "artifacts": {
                "calibration_child": {
                    "path": "/fixture/calibration-child",
                    "sha256": "10" * 32,
                },
                "calibration_elf": {
                    "path": "/fixture/calibration.elf",
                    "sha256": "11" * 32,
                },
                "poseidon2_proof_child": {
                    "path": "/fixture/poseidon-child",
                    "sha256": "20" * 32,
                },
                m6_elf: {
                    "path": "/fixture/poseidon.elf",
                    "sha256": "21" * 32,
                },
            },
            "calibration_gate": calibration_gate(self.repository),
            "attempts": self.attempts,
        }
        _seal(plan)
        return plan

    @staticmethod
    def _metrics() -> dict[str, int]:
        return {
            "execution_steps": 131_078,
            "execution_ns": 100,
            "proving_ns": 200,
            "proof_encoding_ns": 25,
            "verification_ns": 50,
            "verified_request_ns": 350,
            "proof_wire_bytes": 60_000,
            "preprocessed_cells": 100,
            "main_cells": 200,
            "interaction_cells": 300,
        }

    @staticmethod
    def _resources() -> dict[str, object]:
        return {
            "scope": RESOURCE_SCOPE,
            "source": "darwin_proc_pid_rusage_v6",
            "lifetime_peak_physical_footprint_bytes": 1_000_000,
            "process_cpu_ns": 1_000,
            "energy_nj": 2_000,
            "instructions": 3_000,
            "cycles": 4_000,
            "unavailable_reason": None,
        }

    def _report(self, attempt: dict[str, object]) -> dict[str, object]:
        common = {
            "status": "verified",
            "security": "secure",
            "phase": attempt["phase"],
            "schedule_sha256": SCHEDULE_SHA256,
            "sample_index": attempt["sample_index"],
            "input_bytes": attempt["input_bytes"],
            "output_bytes": attempt["output_bytes"],
            "input_sha256": attempt["input_sha256"],
            "output_sha256": attempt["output_sha256"],
            "elf_sha256": self.plan["artifacts"][attempt["elf_id"]]["sha256"],
            "executable_sha256": self.plan["artifacts"][attempt["executable_id"]]["sha256"],
            "proof_sha256": "30" * 32,
            "implementation_commit": "1" * 40,
            "implementation_tree": "2" * 40,
            "implementation_dirty": False,
            "dirty_content_sha256": None,
            "pcs": dict(SECURE_PCS),
            "metrics": self._metrics(),
            "resources": self._resources(),
        }
        if attempt["kind"] == "calibration":
            return {
                "schema": CALIBRATION_SCHEMA,
                "label": attempt["arm"],
                "workload": "multi_shard_addi",
                "max_steps": 262_144,
                **common,
            }
        calls = attempt["calls"]
        shape = attempt["shape"]
        return {
            "schema": POSEIDON_SCHEMA,
            "arm": attempt["arm"],
            "shape": shape,
            "background_permutations_per_call": BACKGROUND[shape],
            "calls": calls,
            "extension_calls": calls if attempt["arm"] == "precompile" else 0,
            "max_steps": 100_000 + calls * (BACKGROUND[shape] + 1) * 100_000,
            **common,
        }

    def _header(self) -> dict[str, object]:
        return {
            "schema": "stwo.typed-air.c013-attempt-journal-header.v1",
            "session_id": self.plan["session_id"],
            "plan_sha256": self.plan["content_sha256"],
            "schedule_sha256": SCHEDULE_SHA256,
            "planned_attempts": len(self.attempts),
        }

    def _attempt_record(
        self, attempt: dict[str, object], report: dict[str, object]
    ) -> dict[str, object]:
        ordinal = attempt["global_ordinal"]
        stdout = canonical_bytes(report)
        stderr = b""
        stdout_path = f"attempts/{ordinal:04d}.stdout.json"
        stderr_path = f"attempts/{ordinal:04d}.stderr.bin"
        (self.path / stdout_path).write_bytes(stdout)
        (self.path / stderr_path).write_bytes(stderr)
        command = command_for_attempt(self.plan, attempt)
        return {
            "schema": "stwo.typed-air.c013-attempt-result.v1",
            "global_ordinal": ordinal,
            "kind": attempt["kind"],
            "sample_index": attempt["sample_index"],
            "status": "verified",
            "failure_code": None,
            "started_at_utc": NOW,
            "completed_at_utc": NOW,
            "launcher_elapsed_ns": 1,
            "child_exit_code": 0,
            "command_sha256": sha256_bytes(canonical_bytes(list(command))),
            "report_sha256": sha256_bytes(stdout),
            "streams": {
                "stdout": _identity(stdout_path, stdout),
                "stderr": _identity(stderr_path, stderr),
            },
        }

    def persist(self) -> None:
        calibration_raw = (self.path / "calibration.json").read_bytes()
        calibration = json.loads(calibration_raw)
        calibration_identity = _identity("calibration.json", calibration_raw)
        admission = next(
            item
            for item in self.records
            if item["schema"] == "stwo.typed-air.c013-aa-admission-record.v1"
        )
        admission["artifact"] = calibration_identity
        admission["verdict"] = calibration["verdict"]
        for record in self.records:
            _seal(record)
        journal_raw = b"".join(canonical_bytes(item) for item in self.records)
        (self.path / "journal.ndjson").write_bytes(journal_raw)
        self.bundle["journal"] = {
            **_identity("journal.ndjson", journal_raw),
            "records": len(self.records),
        }
        self.bundle["calibration"] = {
            **calibration_identity,
            "verdict": calibration["verdict"],
        }
        _seal(self.bundle)
        (self.path / "bundle.json").write_bytes(canonical_bytes(self.bundle))

    def validation(self):
        return mock.patch.object(
            bundle_module,
            "validate_plan",
            side_effect=lambda value, **_: value,
        )


class BundleValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(__file__).resolve().parents[2]
        self.fixture = BundleFixture(
            self.repository, Path(self.temporary.name) / "bundle"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self):
        with self.fixture.validation():
            return validate_bundle(self.repository, self.fixture.path)

    def test_complete_cpu_bundle_is_authenticated_but_never_promoted(self) -> None:
        result = self.validate()
        self.assertEqual(
            result.capture_status,
            "CAPTURE_COMPLETE_AWAITING_RECEIPT_VALIDATION",
        )
        self.assertEqual(result.recorded_attempts, 81)
        self.assertEqual(result.calibration_verdict, "PASS")
        self.assertIsNone(result.cpu_reduction_verdict)
        self.assertIsNone(result.m6_verdict)
        self.assertFalse(result.normative_receipt)
        self.assertEqual(
            result.remaining_gaps,
            bundle_module.NORMATIVE_RECEIPT_GAPS,
        )

    def test_authenticated_cpu_reduction_is_lane_local_not_m6_promotion(
        self,
    ) -> None:
        reduction = {
            "schema": "stwo.typed-air.c013-cpu-reduction.v1",
            "verdict": "PASS",
        }
        _seal(reduction)
        raw = canonical_bytes(reduction)
        (self.fixture.path / "cpu-reduction.json").write_bytes(raw)
        self.fixture.bundle["cpu_reduction"] = {
            **_identity("cpu-reduction.json", raw),
            "verdict": "PASS",
        }
        self.fixture.persist()
        with (
            self.fixture.validation(),
            mock.patch.object(bundle_module.schedule, "GLOBAL_ATTEMPTS", 81),
            mock.patch.object(
                bundle_module,
                "evaluate_m6_cpu",
                return_value=reduction,
            ),
        ):
            result = validate_bundle(self.repository, self.fixture.path)
        self.assertEqual(result.cpu_reduction_verdict, "PASS")
        self.assertIsNone(result.m6_verdict)
        self.assertFalse(result.normative_receipt)
        self.assertNotIn(
            "cpu-m6-exact-gate-and-statistical-reduction",
            result.remaining_gaps,
        )
        self.assertIn(
            "metal-hybrid-capture-residency-fallback-and-gpu-timing-evidence",
            result.remaining_gaps,
        )

    def test_path_traversal_rejects_even_after_all_digests_are_resealed(self) -> None:
        self.fixture.records[1]["streams"]["stdout"]["path"] = "../escape.json"
        self.fixture.persist()
        with self.assertRaisesRegex(CaptureError, "normalized bundle-relative"):
            self.validate()

    def test_reordered_deleted_and_duplicate_attempts_reject(self) -> None:
        for mutation, message in (
            (
                lambda records: records.__setitem__(
                    slice(1, 3), [records[2], records[1]]
                ),
                "global_ordinal",
            ),
            (lambda records: records.pop(10), "global_ordinal|admission"),
            (
                lambda records: records.insert(2, copy.deepcopy(records[1])),
                "global_ordinal|duplicate",
            ),
        ):
            with self.subTest(message=message):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = BundleFixture(
                        self.repository, Path(temporary) / "bundle"
                    )
                    mutation(fixture.records)
                    fixture.persist()
                    with fixture.validation(), self.assertRaisesRegex(CaptureError, message):
                        validate_bundle(self.repository, fixture.path)

    def test_stream_digest_drift_rejects(self) -> None:
        stdout = self.fixture.path / "attempts/0000.stdout.json"
        stdout.write_bytes(stdout.read_bytes() + b"drift")
        with self.assertRaisesRegex(CaptureError, "byte count or SHA-256"):
            self.validate()

    def test_invalid_child_report_rejects_after_consistent_rehash(self) -> None:
        record = self.fixture.records[1]
        path = self.fixture.path / record["streams"]["stdout"]["path"]
        report = json.loads(path.read_bytes())
        report["proof_sha256"] = "invalid"
        raw = canonical_bytes(report)
        path.write_bytes(raw)
        record["streams"]["stdout"] = _identity(
            record["streams"]["stdout"]["path"], raw
        )
        record["report_sha256"] = sha256_bytes(raw)
        self.fixture.persist()
        with self.assertRaisesRegex(CaptureError, "proof digest"):
            self.validate()

    def test_calibration_drift_rejects_after_consistent_rehash(self) -> None:
        path = self.fixture.path / "calibration.json"
        calibration = json.loads(path.read_bytes())
        calibration["metrics"]["proving_ns"]["ci_width"] = 0.0001
        path.write_bytes(canonical_bytes(calibration))
        self.fixture.persist()
        with self.assertRaisesRegex(CaptureError, "independent recomputation"):
            self.validate()

    def test_incomplete_bundle_is_classified_without_receipt_claim(self) -> None:
        record = self.fixture.records.pop()
        for stream in record["streams"].values():
            (self.fixture.path / stream["path"]).unlink()
        self.fixture.bundle.update(
            status="INCOMPLETE",
            recorded_attempts=80,
            verified_attempts=80,
        )
        self.fixture.persist()
        result = self.validate()
        self.assertEqual(result.capture_status, "INCOMPLETE")
        self.assertIn(
            "complete-frozen-cpu-attempt-schedule-in-a-new-session",
            result.remaining_gaps,
        )
        self.assertIsNone(result.m6_verdict)

    def test_complete_bundle_with_failed_child_remains_non_promotable(self) -> None:
        record = self.fixture.records[-1]
        stdout_path = self.fixture.path / record["streams"]["stdout"]["path"]
        stdout_path.write_bytes(b"")
        record["streams"]["stdout"] = _identity(
            record["streams"]["stdout"]["path"], b""
        )
        record.update(
            status="failed",
            failure_code="child-nonzero-exit",
            child_exit_code=1,
            report_sha256=None,
        )
        self.fixture.bundle.update(
            status="CAPTURE_COMPLETE_WITH_FAILURES",
            verified_attempts=80,
            failed_attempts=1,
        )
        self.fixture.persist()
        result = self.validate()
        self.assertEqual(result.capture_status, "CAPTURE_COMPLETE_WITH_FAILURES")
        self.assertEqual(result.failed_attempts, 1)
        self.assertIn(
            "failure-free-frozen-cpu-capture-in-a-new-session",
            result.remaining_gaps,
        )
        self.assertIsNone(result.m6_verdict)

    def test_duplicate_keys_noncanonical_plan_and_nan_journal_reject(self) -> None:
        bundle_path = self.fixture.path / "bundle.json"
        raw = bundle_path.read_bytes()
        bundle_path.write_bytes(raw.replace(b"{", b'{"schema":"duplicate",', 1))
        with self.assertRaisesRegex(CaptureError, "duplicate JSON key"):
            self.validate()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = BundleFixture(self.repository, Path(temporary) / "bundle")
            plan_path = fixture.path / "plan.json"
            plan_path.write_bytes(plan_path.read_bytes().replace(b":", b": ", 1))
            with fixture.validation(), self.assertRaisesRegex(CaptureError, "not canonical JSON"):
                validate_bundle(self.repository, fixture.path)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = BundleFixture(self.repository, Path(temporary) / "bundle")
            journal = fixture.path / "journal.ndjson"
            journal_raw = journal.read_bytes().replace(
                b'"launcher_elapsed_ns":1',
                b'"launcher_elapsed_ns":NaN',
                1,
            )
            journal.write_bytes(journal_raw)
            fixture.bundle["journal"] = {
                **_identity("journal.ndjson", journal_raw),
                "records": len(fixture.records),
            }
            _seal(fixture.bundle)
            (fixture.path / "bundle.json").write_bytes(canonical_bytes(fixture.bundle))
            with fixture.validation(), self.assertRaisesRegex(CaptureError, "non-standard JSON"):
                validate_bundle(self.repository, fixture.path)


if __name__ == "__main__":
    unittest.main()
