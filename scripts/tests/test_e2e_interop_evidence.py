#!/usr/bin/env python3
"""Tests for immutable Native interop artifacts and receipts."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.interop.e2e_interop_lib import evidence
from scripts.interop.e2e_interop_lib.evidence import (
    EvidenceError,
    archive_receipt,
    register_artifact,
)


def write_artifact(path: Path, *, proof: bytes = b'{"proof_of_work":0}') -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "example": "xor",
                "proof_bytes_hex": proof.hex(),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def report(artifact_path: Path, artifact_sha256: str) -> dict:
    return {
        "status": "ok",
        "schema_version": 1,
        "exchange_mode": "proof_exchange_json_wire_v1",
        "upstream_commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
        "summary": {"cases_passed": 1},
        "mutation_coverage": {"required_cases": 0},
        "cases": [{"artifact": str(artifact_path), "artifact_sha256": artifact_sha256}],
        "failure": None,
        "steps": [
            {
                "name": "xor_rust_to_zig_verify",
                "command": ["verifier", "--artifact", str(artifact_path)],
                "cwd": ".",
                "expect_failure": False,
                "return_code": 0,
                "status": "ok",
                "artifact_sha256": artifact_sha256,
                "stdout_sha256": "0" * 64,
                "stderr_sha256": "0" * 64,
            }
        ],
    }


class InteropEvidenceTests(unittest.TestCase):
    def test_archive_rejects_accepted_receipt_from_dirty_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "proof.json"
            write_artifact(artifact)
            record = register_artifact(
                artifact,
                example="xor",
                direction="rust_to_zig",
                role="accepted_proof",
            )
            with self.assertRaisesRegex(EvidenceError, "clean repository"):
                archive_receipt(
                    archive_dir=root / "archive",
                    report=report(artifact, record["artifact_sha256"]),
                    artifact_records=[record],
                    provenance={"repository": {"clean": False}},
                    path_replacements={},
                )

    def test_archive_preserves_exact_bytes_and_is_path_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "archive"
            first_dir = root / "first"
            second_dir = root / "second"
            first_dir.mkdir()
            second_dir.mkdir()
            first = first_dir / "proof.json"
            second = second_dir / "proof.json"
            write_artifact(first)
            second.write_bytes(first.read_bytes())

            receipts = []
            for artifact in (first, second):
                record = register_artifact(
                    artifact,
                    example="xor",
                    direction="rust_to_zig",
                    role="accepted_proof",
                )
                result = archive_receipt(
                    archive_dir=archive,
                    report=report(artifact, record["artifact_sha256"]),
                    artifact_records=[record],
                    provenance={"repository": {"clean": True}, "oracle": "pinned"},
                    path_replacements={str(artifact.parent.resolve()): "$ARTIFACT_DIR"},
                )
                receipts.append(result)
                archived = archive / "objects/sha256" / record["artifact_sha256"][:2]
                object_path = archived / f"{record['artifact_sha256']}.json"
                self.assertEqual(object_path.read_bytes(), artifact.read_bytes())
                receipt = json.loads((archive / result["receipt_path"]).read_text())
                self.assertNotIn("stdout_sha256", receipt["commands"][0])
                self.assertNotIn("stderr_sha256", receipt["commands"][0])
            self.assertEqual(receipts[0]["receipt_sha256"], receipts[1]["receipt_sha256"])
            self.assertEqual(receipts[0]["receipt_path"], receipts[1]["receipt_path"])

    def test_archive_rejects_artifact_changed_after_registration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "proof.json"
            write_artifact(artifact)
            record = register_artifact(
                artifact,
                example="xor",
                direction="rust_to_zig",
                role="accepted_proof",
            )
            write_artifact(artifact, proof=b'{"proof_of_work":1}')
            with self.assertRaisesRegex(EvidenceError, "changed after verification"):
                archive_receipt(
                    archive_dir=root / "archive",
                    report=report(artifact, record["artifact_sha256"]),
                    artifact_records=[record],
                    provenance={"repository": {"clean": True}},
                    path_replacements={},
                )

    def test_archive_rejects_content_address_collision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "proof.json"
            write_artifact(artifact)
            record = register_artifact(
                artifact,
                example="xor",
                direction="rust_to_zig",
                role="accepted_proof",
            )
            collision = (
                root
                / "archive/objects/sha256"
                / record["artifact_sha256"][:2]
                / f"{record['artifact_sha256']}.json"
            )
            collision.parent.mkdir(parents=True)
            collision.write_bytes(b"collision")
            with self.assertRaisesRegex(EvidenceError, "collision"):
                archive_receipt(
                    archive_dir=root / "archive",
                    report=report(artifact, record["artifact_sha256"]),
                    artifact_records=[record],
                    provenance={"repository": {"clean": True}},
                    path_replacements={},
                )

    def test_archive_enforces_per_run_size_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "proof.json"
            write_artifact(artifact)
            record = register_artifact(
                artifact,
                example="xor",
                direction="rust_to_zig",
                role="accepted_proof",
            )
            with mock.patch.object(evidence, "MAX_ARCHIVED_RUN_BYTES", 1):
                with self.assertRaisesRegex(EvidenceError, "per-run archive bound"):
                    archive_receipt(
                        archive_dir=root / "archive",
                        report=report(artifact, record["artifact_sha256"]),
                        artifact_records=[record],
                        provenance={"repository": {"clean": True}},
                        path_replacements={},
                    )


if __name__ == "__main__":
    unittest.main()
