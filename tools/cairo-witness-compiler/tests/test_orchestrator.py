from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_export_overlay_preserves_modules_and_non_registry_sources(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            staged = Path(raw)
            root = staged / "crates/prover/src"
            (root / "witness").mkdir(parents=True)
            lib = root / "lib.rs"
            registry = root / "witness/mod.rs"
            lib.write_text(
                "#![feature(portable_simd)]\npub use stwo;\n"
                "pub mod prover;\npub mod witness;\n"
            )
            registry.write_text(
                "pub mod components;\nmod jit_flat_macros;\npub mod recording_export;\n"
            )
            sentinel = root / "witness/retained_test.rs"
            sentinel.write_bytes(b"#[test] fn retained() {}\n")
            originals = {p: p.read_bytes() for p in (lib, registry)}
            with patch.multiple(
                orchestrator,
                OFFICIAL_LIB_SHA256=hashlib.sha256(originals[lib]).hexdigest(),
                INSTALLED_WITNESS_MOD_SHA256=hashlib.sha256(originals[registry]).hexdigest(),
            ):
                orchestrator._isolate_recording_export(staged)
            for path, original in originals.items():
                self.assertEqual(
                    original.replace(b"pub mod ", b"mod "),
                    path.read_bytes().replace(b"pub mod ", b"mod ").replace(
                        b"pub(crate) mod ", b"mod "
                    ),
                )
            self.assertIn("pub mod witness;\n", lib.read_text())
            self.assertNotIn("pub mod prover;\n", lib.read_text())
            self.assertEqual(
                registry.read_text().splitlines(),
                ["pub(crate) mod components;", "mod jit_flat_macros;", "pub mod recording_export;"],
            )
            self.assertEqual(sentinel.read_bytes(), b"#[test] fn retained() {}\n")

    def test_export_overlay_rejects_either_registry_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            staged = Path(raw)
            root = staged / "crates/prover/src"
            (root / "witness").mkdir(parents=True)
            lib, registry = root / "lib.rs", root / "witness/mod.rs"
            lib.write_bytes(b"pub mod witness;\n")
            registry.write_bytes(b"pub mod unexpected;\n")
            originals = {p: p.read_bytes() for p in (lib, registry)}
            for lib_hash in ("wrong", hashlib.sha256(originals[lib]).hexdigest()):
                with patch.object(orchestrator, "OFFICIAL_LIB_SHA256", lib_hash):
                    with self.assertRaisesRegex(RuntimeError, "registry hash mismatch"):
                        orchestrator._isolate_recording_export(staged)
                self.assertEqual(originals, {p: p.read_bytes() for p in originals})

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
        self.assertEqual(programs, 64)
        self.assertEqual(instructions, 157_733)
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            orchestrator.EXPECTED_BUNDLE_SHA256,
        )


if __name__ == "__main__":
    unittest.main()
