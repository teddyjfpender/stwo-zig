"""Mutation checks for the live vector inventory, independent of oracle replay."""
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.repo.upstream_pins_lib import vector_ownership as V


class VectorOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        contract = self.root / "src/waist/core/package.contract.json"
        contract.parent.mkdir(parents=True)
        contract.write_text(json.dumps({"owner": "protocol-core"}))
        asset = self.root / "vectors/waist/fields.json"
        asset.parent.mkdir(parents=True)
        asset.write_bytes(b'{"field":31}\n')
        self.manifest = {
            "schema": "stwo-zig-vectors-manifest-v1",
            "groups": {"vectors/waist": {"files": 1, "consumers": [],
                                         "owner": "protocol-core", "kind": "golden_fixture"}},
            "files": [{"path": "vectors/waist/fields.json", "group": "vectors/waist",
                       "bytes": asset.stat().st_size,
                       "sha256": hashlib.sha256(asset.read_bytes()).hexdigest()}],
        }
        self.persist()

    def persist(self):
        (self.root / "vectors/MANIFEST.json").write_text(json.dumps(self.manifest))

    def test_declared_owner_and_exact_bytes_pass(self):
        self.assertEqual([], V.check(self.root))

    def test_corrupt_or_unlisted_assets_are_rejected(self):
        (self.root / "vectors/waist/fields.json").write_bytes(b"corruption")
        self.assertIn("identity drift", "\n".join(V.check(self.root)))
        (self.root / "vectors/waist/extra.json").write_bytes(b"{}")
        self.assertIn("unlisted vector", "\n".join(V.check(self.root)))

    def test_missing_duplicate_escaped_and_unowned_entries_are_rejected(self):
        original = json.loads(json.dumps(self.manifest))
        for mutation, expected in (("missing", "missing vector"), ("duplicate", "duplicate vector"),
                                   ("escaped", "invalid vector path"), ("owner", "undeclared owner"),
                                   ("count", "group count"), ("group", "unknown group")):
            with self.subTest(mutation=mutation):
                self.manifest = json.loads(json.dumps(original))
                if mutation == "missing":
                    self.manifest["files"][0]["path"] = "vectors/waist/missing.json"
                elif mutation == "duplicate":
                    self.manifest["files"].append(self.manifest["files"][0].copy())
                elif mutation == "escaped":
                    self.manifest["files"][0]["path"] = "vectors/../../outside.json"
                elif mutation == "owner":
                    self.manifest["groups"]["vectors/waist"]["owner"] = "nobody"
                elif mutation == "count":
                    self.manifest["groups"]["vectors/waist"]["files"] = 3
                else:
                    self.manifest["files"][0]["group"] = "vectors/absent"
                self.persist()
                self.assertIn(expected, "\n".join(V.check(self.root)))

    def test_symlinks_cannot_escape_inventory_root(self):
        target = self.root / "vectors/waist/fields.json"
        target.unlink()
        target.symlink_to(self.root.parent / "outside.json")
        self.assertIn("invalid vector path", "\n".join(V.check(self.root)))
