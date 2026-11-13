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


class ArtifactOwnerTransferTests(unittest.TestCase):
    def test_non_oracle_assets_keep_original_bytes_under_actual_owner_namespaces(self):
        from scripts.repo.upstream_pins_lib import circuit_recursion
        root = Path(__file__).resolve().parents[2]
        manifest = json.loads((root / V.MANIFEST).read_text())
        indexed = {row["path"]: row for row in manifest["files"]}
        assets = [
            ("vectors/metal/circuit/circuit_air_composition_bounded.metallib", 367765,
             "bbcfb8879ae76b0c9cb771cd70fe335abaa9ee319cbf30491d161b2dc2090473", "cairo-metal-integration"),
            ("vectors/metal/circuit/circuit_air_composition_bounded.provenance.json", 1519,
             "f7cfb28b988526c059580f4eae78e1db4ae9eff8760ff3b86b12f7603d2cc36f", "cairo-metal-integration"),
            ("vectors/recursion/registries/production.json", 4028,
             "a2503220947f161185a4f5160fd5953db92f6aec0055367830ebc8a65187eabf", "circuit-recursion"),
        ]
        for path, length, digest, owner in assets:
            with self.subTest(path=path):
                data = (root / path).read_bytes()
                self.assertEqual((length, digest), (len(data), hashlib.sha256(data).hexdigest()))
                self.assertEqual((length, digest), (indexed[path]["bytes"], indexed[path]["sha256"]))
                self.assertEqual(owner, manifest["groups"][indexed[path]["group"]]["owner"])
                self.assertNotIn(path, circuit_recursion.MANAGED)
                self.assertFalse(path.startswith(circuit_recursion.VECTORS + "/"))
        # Historical generation authority is retained byte-for-byte, not restamped.
        historical = json.loads((root / assets[1][0]).read_text())
        self.assertEqual("vectors/circuit/official/circuit_air_composition_bounded.metallib",
                         historical["artifact"]["path"])
