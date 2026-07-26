from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import orchestrator


class OrchestratorTests(unittest.TestCase):
    def test_closure_hash_binds_paths_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "b").mkdir()
            (root / "b/value").write_bytes(b"two")
            (root / "a").write_bytes(b"one")
            first = orchestrator.closure_sha256(root)
            (root / "target").mkdir()
            (root / "target/cache").write_bytes(b"ephemeral")
            self.assertEqual(first, orchestrator.closure_sha256(root))
            (root / "a").write_bytes(b"changed")
            self.assertNotEqual(first, orchestrator.closure_sha256(root))

    def test_module_patch_requires_exact_official_source(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "mod.rs"
            path.write_text("pub mod unexpected;\n")
            with self.assertRaisesRegex(RuntimeError, "module hash"):
                orchestrator.patch_module_registry(path)

    def test_build_identity_binds_entire_compiler_closure(self) -> None:
        identity = orchestrator._build_identity()
        self.assertEqual(64, len(identity))
        int(identity, 16)
        self.assertEqual(
            orchestrator._build_identity_timestamp(),
            1_600_000_000
            + int.from_bytes(bytes.fromhex(identity)[:4], "little") % 300_000_000,
        )

    def test_publish_is_atomic_and_never_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "artifact.bin"
            orchestrator.publish_new(path, b"first")
            with self.assertRaises(FileExistsError):
                orchestrator.publish_new(path, b"second")
            self.assertEqual(path.read_bytes(), b"first")

    def test_checked_in_bundle_matches_compiler_contract(self) -> None:
        vector = (
            Path(__file__).resolve().parents[3]
            / "vectors/cairo/official/witness_programs_v1.bin"
        )
        data = vector.read_bytes()
        programs, instructions = orchestrator.inspect_bundle(data)
        self.assertEqual(programs, 61)
        self.assertEqual(instructions, 146_487)
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            orchestrator.EXPECTED_BUNDLE_SHA256,
        )


if __name__ == "__main__":
    unittest.main()
