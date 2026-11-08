from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.architecture.architecture_ci_artifact import ArtifactError, extract, select


NAME = "build-architecture-linux-" + "1" * 40 + "-123-2"
DIGEST = "sha256:" + "2" * 64


def metadata(**updates: object) -> dict[str, object]:
    artifact = {
        "id": 42,
        "name": NAME,
        "digest": DIGEST,
        "expired": False,
        "workflow_run": {"id": 123},
    }
    artifact.update(updates)
    return {"artifacts": [artifact]}


class ArchitectureCiArtifactTest(unittest.TestCase):
    def test_selects_one_live_same_run_exact_digest(self) -> None:
        self.assertEqual(
            {"artifact_id": 42, "digest": DIGEST, "name": NAME},
            select(metadata(), NAME, "123", DIGEST),
        )

    def test_rejects_duplicate_expired_cross_run_and_digest_substitution(self) -> None:
        for value in (
            {"artifacts": metadata()["artifacts"] * 2},
            metadata(expired=True),
            metadata(workflow_run={"id": 124}),
        ):
            with self.assertRaisesRegex(ArtifactError, "exactly one live same-run"):
                select(value, NAME, "123", DIGEST)
        with self.assertRaisesRegex(ArtifactError, "differs from producer"):
            select(metadata(digest="sha256:" + "3" * 64), NAME, "123", DIGEST)

    def test_extracts_only_exact_single_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "receipt.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("123.json", b'{"schema":"fixture"}\n')
            digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
            output = root / "linux.json"
            receipt_digest = extract(archive, output, "123.json", digest)
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), receipt_digest)
            with self.assertRaisesRegex(ArtifactError, "replace"):
                extract(archive, output, "123.json", digest)

    def test_rejects_archive_digest_extra_member_and_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "receipt.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("123.json", b"{}")
                bundle.writestr("../substitute.json", b"{}")
            digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ArtifactError, "exactly the canonical"):
                extract(archive, root / "out.json", "123.json", digest)
            with self.assertRaisesRegex(ArtifactError, "digest mismatch"):
                extract(archive, root / "out.json", "123.json", "sha256:" + "4" * 64)


if __name__ == "__main__":
    unittest.main()
