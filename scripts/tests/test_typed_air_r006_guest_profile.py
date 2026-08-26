from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import struct
from pathlib import Path

from scripts.typed_air_r006_capture_lib.codec import canonical_bytes, content_digest, sha256_bytes
from scripts.typed_air_r006_capture_lib.controller import (
    FileInventory,
    Journal,
    ProcessResult,
    _validate_record,
    proof_command,
    run_attempt,
    verify_command,
)
from scripts.typed_air_r006_capture_lib.model import CaptureError
from scripts.typed_air_r006_capture_lib.model import GENERATED_WORKLOAD_PARAMETERS
from scripts.typed_air_r006_capture_lib.receipt import validate_receipt
from scripts.typed_air_r006_capture_lib.report import validate_report
from scripts.tests.test_typed_air_r006_capture import R006Fixture
from scripts.tests.typed_air_r006_guest_fixture import (
    guest_artifact,
    guest_verifier_receipt,
)


class GuestProfileTests(R006Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.attempt = next(
            attempt
            for attempt in self.plan["attempts"]
            if attempt["workload_id"] == "balanced_core_and_poseidon2"
        )
        self.artifact = guest_artifact()
        self.artifact_path = self.scratch / self.attempt["proof_path"]
        self.artifact_path.parent.mkdir(exist_ok=True)
        self.artifact_path.write_bytes(self.artifact)
        self.raw_report = self.report(
            self.plan,
            self.attempt,
            self.artifact,
        )

    def validate_report(self, raw: bytes | None = None) -> tuple[dict, dict]:
        return validate_report(
            self.raw_report if raw is None else raw,
            plan=self.plan,
            attempt=self.attempt,
            proof_path=self.artifact_path,
        )

    def test_v4_report_binds_guest_profile_and_stwgpf01_artifact(self) -> None:
        identity, metrics = self.validate_report()
        self.assertEqual(identity["artifact_kind"], "stwo_riscv_guest_poseidon2_proof")
        self.assertEqual(identity["artifact_schema_version"], 1)
        self.assertEqual(identity["profile_identity"], "rv32im-zkvm-poseidon2-v1")
        self.assertEqual(
            identity["guest_calls"],
            GENERATED_WORKLOAD_PARAMETERS["balanced_core_and_poseidon2"]["calls"],
        )
        self.assertEqual(identity["proof_bytes"], len(self.artifact))
        self.assertEqual(metrics["work_disclosure"]["source_mask"], 0x3F)

    def test_commands_preserve_base_argv_and_bind_guest_input(self) -> None:
        for workload_id in (
            "balanced_core_and_poseidon2",
            "poseidon2_dominant",
        ):
            with self.subTest(workload_id=workload_id):
                attempt = next(
                    item
                    for item in self.plan["attempts"]
                    if item["workload_id"] == workload_id
                )
                workload = next(
                    item for item in self.plan["workloads"] if item["id"] == workload_id
                )
                proof = proof_command(self.plan, attempt)
                verify = verify_command(self.plan, attempt, "4" * 64)
                self.assertEqual(proof[1], "bench")
                self.assertEqual(
                    proof[proof.index("--input") + 1], workload["input"]["path"]
                )
                self.assertEqual(verify[1], "verify")
                self.assertEqual(
                    verify[verify.index("--input") + 1], workload["input"]["path"]
                )

        base = self.plan["attempts"][0]
        self.assertNotIn("--input", proof_command(self.plan, base))
        self.assertNotIn("--input", verify_command(self.plan, base, "4" * 64))

    def test_guest_report_rejects_base_profile_and_unknown_generator(self) -> None:
        changed = json.loads(self.raw_report)
        changed["verified_request_attempts"][0]["task_profile"]["example"] = (
            "sail_rv32im_zkvm_v1"
        )
        raw = json.dumps(changed, separators=(",", ":")).encode() + b"\n"
        with self.assertRaisesRegex(CaptureError, "task profile identity"):
            self.validate_report(raw)

        plan = copy.deepcopy(self.plan)
        workload = next(
            item for item in plan["workloads"] if item["id"] == self.attempt["workload_id"]
        )
        workload["generator"]["generator"] = "unreviewed-profile"
        with self.assertRaisesRegex(CaptureError, "execution profile changed"):
            validate_report(
                self.raw_report,
                plan=plan,
                attempt=self.attempt,
                proof_path=self.artifact_path,
            )

    def test_guest_artifact_header_mutations_fail_closed(self) -> None:
        mutations = (
            (0, b"X", "magic"),
            (8, struct.pack("<H", 2), "format version"),
            (10, struct.pack("<H", 79), "header length"),
            (12, struct.pack("<I", 1), "flags"),
            (16, struct.pack("<Q", len(self.artifact) + 1), "declared length"),
            (24, struct.pack("<H", 2), "encoding"),
            (26, struct.pack("<H", 2), "hasher"),
            (64, struct.pack("<I", 277), "section framing"),
        )
        baseline = json.loads(self.raw_report)
        for offset, replacement, pattern in mutations:
            with self.subTest(offset=offset):
                artifact = bytearray(self.artifact)
                artifact[offset : offset + len(replacement)] = replacement
                self.artifact_path.write_bytes(artifact)
                report = copy.deepcopy(baseline)
                report["artifact_sha256"] = hashlib.sha256(artifact).hexdigest()
                raw = json.dumps(report, separators=(",", ":")).encode() + b"\n"
                with self.assertRaisesRegex(CaptureError, pattern):
                    self.validate_report(raw)
        self.artifact_path.write_bytes(self.artifact)

    def test_guest_receipt_is_canonical_and_cross_bound_to_v4_identity(self) -> None:
        identity, _ = self.validate_report()
        raw = guest_verifier_receipt(self.plan, self.artifact)
        receipt = validate_receipt(
            raw,
            plan=self.plan,
            attempt=self.attempt,
            identity=identity,
        )
        self.assertEqual(receipt["artifact_bytes"], len(self.artifact))
        self.assertEqual(receipt["artifact_sha256"], identity["proof_sha256"])

        mutations = {
            "schema": "riscv_verify_v1",
            "status": "rejected",
            "artifact_kind": "stwo_riscv_proof",
            "artifact_schema_version": 4,
            "artifact_magic": "STWGPF02",
            "profile_identity": "sail_rv32im_zkvm_v1",
            "profile_version": 2,
            "profile_manifest_sha256": "a" * 64,
            "release_status": "parity_gated",
            "security_policy": "functional",
            "statement_sha256": "b" * 64,
            "artifact_bytes": len(self.artifact) + 1,
            "artifact_sha256": "c" * 64,
            "transcript_state_blake2s": "d" * 64,
            "implementation_commit": "e" * 40,
            "implementation_dirty": True,
            "executable_sha256": "f" * 64,
        }
        baseline = json.loads(raw)
        for name, value in mutations.items():
            with self.subTest(name=name):
                changed = dict(baseline)
                changed[name] = value
                encoded = json.dumps(changed, separators=(",", ":")).encode() + b"\n"
                with self.assertRaisesRegex(CaptureError, f"{name} identity changed"):
                    validate_receipt(
                        encoded,
                        plan=self.plan,
                        attempt=self.attempt,
                        identity=identity,
                    )
        with self.assertRaisesRegex(CaptureError, "guest verifier receipt"):
            validate_receipt(
                self.verifier_receipt(self.plan),
                plan=self.plan,
                attempt=self.attempt,
                identity=identity,
            )

    def test_guest_receipt_shape_line_and_canonical_encoding_are_closed(self) -> None:
        identity, _ = self.validate_report()
        raw = guest_verifier_receipt(self.plan, self.artifact)
        receipt = json.loads(raw)

        receipt["extra"] = 1
        extra = json.dumps(receipt, separators=(",", ":")).encode() + b"\n"
        with self.assertRaisesRegex(CaptureError, "fields drifted"):
            validate_receipt(
                extra,
                plan=self.plan,
                attempt=self.attempt,
                identity=identity,
            )
        receipt.pop("extra")
        receipt.pop("profile_identity")
        missing = json.dumps(receipt, separators=(",", ":")).encode() + b"\n"
        with self.assertRaisesRegex(CaptureError, "fields drifted"):
            validate_receipt(
                missing,
                plan=self.plan,
                attempt=self.attempt,
                identity=identity,
            )
        with self.assertRaisesRegex(CaptureError, "one bounded JSON line"):
            validate_receipt(
                raw + raw,
                plan=self.plan,
                attempt=self.attempt,
                identity=identity,
            )
        noncanonical = json.dumps(json.loads(raw)).encode() + b"\n"
        with self.assertRaisesRegex(CaptureError, "canonical production JSON"):
            validate_receipt(
                noncanonical,
                plan=self.plan,
                attempt=self.attempt,
                identity=identity,
            )

    def test_live_and_replay_paths_require_guest_receipt_and_artifact(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(command, cwd, timeout, environment):
            del timeout, environment
            calls.append(tuple(command))
            if command[1] == "bench":
                target = Path(cwd) / command[command.index("--proof-out") + 1]
                target.write_bytes(self.artifact)
                return ProcessResult(
                    0,
                    self.report(self.plan, self.attempt, self.artifact),
                    b"",
                    123,
                )
            return ProcessResult(
                0,
                guest_verifier_receipt(self.plan, self.artifact),
                b"",
                45,
            )

        clock_values = iter(range(100, 1000, 100))
        bundle = self.scratch / "guest-attempt-bundle"
        journal = Journal(bundle, self.plan, canonical_bytes(self.plan))
        record = run_attempt(
            journal=journal,
            plan=self.plan,
            attempt=self.attempt,
            timeout_seconds=10,
            child_runner=runner,
            monotonic=lambda: next(clock_values),
            utc_clock=lambda: dt.datetime(2026, 8, 21, tzinfo=dt.timezone.utc),
        )
        sealed = journal.append(record)
        journal.close()
        self.assertEqual(record["status"], "verified")
        self.assertIn("--input", calls[1])
        replayed = _validate_record(
            sealed,
            plan=self.plan,
            attempt=self.attempt,
            inventory=FileInventory(bundle),
        )
        self.assertEqual(replayed, record["identity"])

        receipt_path = bundle / self.attempt["verify_stdout_path"]
        receipt = json.loads(receipt_path.read_bytes())
        receipt["artifact_sha256"] = "0" * 64
        mutated = json.dumps(receipt, separators=(",", ":")).encode() + b"\n"
        receipt_path.write_bytes(mutated)
        changed = copy.deepcopy(sealed)
        changed["independent_verification"]["stdout"] = {
            "path": self.attempt["verify_stdout_path"],
            "bytes": len(mutated),
            "sha256": sha256_bytes(mutated),
        }
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "artifact_sha256 identity changed"):
            _validate_record(
                changed,
                plan=self.plan,
                attempt=self.attempt,
                inventory=FileInventory(bundle),
            )
