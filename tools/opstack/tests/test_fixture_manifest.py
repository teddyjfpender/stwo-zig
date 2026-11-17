"""Committed OP fixtures and golden vectors match the hashes their manifests pin."""

import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests/fixtures/opstack"
UNPINNED = {"MANIFEST.json", ".gitignore"}


def identity(path):
    data = path.read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()


class FixtureManifest(unittest.TestCase):
    def test_every_committed_fixture_is_pinned_exactly(self):
        manifest = json.loads((FIXTURES / "MANIFEST.json").read_text())
        rows = {row["path"]: row for row in manifest["files"]}
        on_disk = {
            str(p.relative_to(FIXTURES))
            for p in FIXTURES.rglob("*")
            if p.is_file() and p.name not in UNPINNED
        }
        fetched = {row["path"] for row in manifest["fetched"]}
        self.assertEqual(sorted(on_disk - fetched), sorted(rows))
        for path, row in rows.items():
            with self.subTest(path=path):
                self.assertEqual(identity(FIXTURES / path), (row["bytes"], row["sha256"]))

    def test_golden_vectors_match_the_vectors_manifest(self):
        manifest = json.loads((ROOT / "vectors/MANIFEST.json").read_text())
        rows = [r for r in manifest["files"] if r.get("group") == "vectors/opstack"]
        self.assertEqual(len(rows), manifest["groups"]["vectors/opstack"]["files"])
        listed = sorted(r["path"] for r in rows)
        present = sorted(
            str(p.relative_to(ROOT)) for p in (ROOT / "vectors/opstack").iterdir() if p.is_file()
        )
        self.assertEqual(present, listed)
        for row in rows:
            with self.subTest(path=row["path"]):
                self.assertEqual(identity(ROOT / row["path"]), (row["bytes"], row["sha256"]))


if __name__ == "__main__":
    unittest.main()
