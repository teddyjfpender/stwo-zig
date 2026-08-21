from __future__ import annotations

import hashlib
import json

from scripts.typed_air_r006_capture_lib.base_artifact import (
    verifier_payload_identity,
)
from scripts.typed_air_r006_capture_lib.codec import canonical_bytes
from scripts.typed_air_r006_capture_lib.model import CaptureError
from scripts.typed_air_r006_capture_lib.verifier_receipt import (
    MAX_RECEIPT_BYTES,
    validate_verifier_receipt,
)
from scripts.tests.test_typed_air_r006_capture import R006Fixture


class VerifierReceiptTests(R006Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.proof_payload = b"verified-pcs-proof"
        self.proof_artifact = self.base_artifact(self.proof_payload)
        self.identity = {
            "statement_sha256": "4" * 64,
            "transcript_state_blake2s": "5" * 64,
            "proof_bytes": len(self.proof_artifact),
            "proof_sha256": hashlib.sha256(self.proof_artifact).hexdigest(),
            "verifier_proof_bytes": len(self.proof_payload),
            "verifier_proof_sha256": hashlib.sha256(
                self.proof_payload
            ).hexdigest(),
        }

    def validate(self, raw: bytes) -> dict[str, object]:
        return validate_verifier_receipt(
            raw,
            plan=self.plan,
            identity=self.identity,
        )

    def mutate(self, name: str, value: object) -> bytes:
        receipt = json.loads(self.verifier_receipt(self.plan))
        receipt[name] = value
        return json.dumps(receipt, separators=(",", ":")).encode("ascii") + b"\n"

    def test_production_receipt_is_accepted(self) -> None:
        receipt = self.validate(self.verifier_receipt(self.plan))
        self.assertEqual(receipt["schema"], "riscv_verify_v1")
        self.assertEqual(receipt["security_policy"], "secure")
        self.assertGreater(receipt["proof_bytes"], 0)
        self.assertNotEqual(self.identity["proof_bytes"], receipt["proof_bytes"])

    def test_every_fixed_identity_is_cross_bound(self) -> None:
        mutations = {
            "schema": "riscv_verify_v2",
            "status": "rejected",
            "artifact_kind": "other_proof",
            "artifact_schema_version": 5,
            "release_status": "not_release_gated",
            "security_policy": "functional",
            "statement_sha256": "a" * 64,
            "transcript_state_blake2s": "b" * 64,
            "implementation_commit": "c" * 40,
            "implementation_dirty": True,
            "executable_sha256": "d" * 64,
        }
        for name, value in mutations.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                CaptureError, f"{name} identity changed"
            ):
                self.validate(self.mutate(name, value))

    def test_proof_disclosure_is_positive_bounded_and_digest_typed(self) -> None:
        for value in (0, -1, True, 1 << 64):
            with self.subTest(proof_bytes=value), self.assertRaisesRegex(
                CaptureError, "proof byte count"
            ):
                self.validate(self.mutate("proof_bytes", value))
        for value in (None, "f" * 63, "F" * 64):
            with self.subTest(proof_sha256=value), self.assertRaisesRegex(
                CaptureError, "proof digest"
            ):
                self.validate(self.mutate("proof_sha256", value))

    def test_proof_disclosure_is_cross_bound_to_the_decoded_payload(self) -> None:
        with self.assertRaisesRegex(CaptureError, "proof_bytes identity changed"):
            self.validate(
                self.mutate(
                    "proof_bytes", self.identity["verifier_proof_bytes"] + 1
                )
            )
        with self.assertRaisesRegex(CaptureError, "proof_sha256 identity changed"):
            self.validate(self.mutate("proof_sha256", "e" * 64))

        artifact_receipt = self.verifier_receipt(
            self.plan, proof_payload=self.proof_artifact
        )
        with self.assertRaisesRegex(CaptureError, "proof_bytes identity changed"):
            self.validate(artifact_receipt)

    def test_base_artifact_backend_is_bound_to_the_planned_lane(self) -> None:
        artifact = self.base_artifact(self.proof_payload, backend="metal")
        path = self.scratch / "wrong-backend.proof.json"
        path.write_bytes(artifact)
        with self.assertRaisesRegex(CaptureError, "backend changed"):
            verifier_payload_identity(
                path,
                artifact_bytes=len(artifact),
                artifact_sha256=hashlib.sha256(artifact).hexdigest(),
                expected_backend="cpu",
            )

    def test_receipt_shape_line_and_production_encoding_are_closed(self) -> None:
        receipt = json.loads(self.verifier_receipt(self.plan))
        receipt["extra"] = 1
        unknown = json.dumps(receipt, separators=(",", ":")).encode() + b"\n"
        with self.assertRaisesRegex(CaptureError, "fields drifted"):
            self.validate(unknown)

        receipt.pop("extra")
        receipt.pop("status")
        missing = json.dumps(receipt, separators=(",", ":")).encode() + b"\n"
        with self.assertRaisesRegex(CaptureError, "fields drifted"):
            self.validate(missing)

        raw = self.verifier_receipt(self.plan)
        duplicate = raw.replace(
            b'{"schema":',
            b'{"schema":"riscv_verify_v1","schema":',
            1,
        )
        with self.assertRaisesRegex(CaptureError, "duplicate JSON key"):
            self.validate(duplicate)
        with self.assertRaisesRegex(CaptureError, "one bounded JSON line"):
            self.validate(raw + raw)
        with self.assertRaisesRegex(CaptureError, "one bounded JSON line"):
            self.validate(raw.rstrip(b"\n"))
        with self.assertRaisesRegex(CaptureError, "one bounded JSON line"):
            self.validate(b"{" + b" " * MAX_RECEIPT_BYTES + b"}\n")
        with self.assertRaisesRegex(CaptureError, "canonical production JSON"):
            self.validate(canonical_bytes(json.loads(raw)))
