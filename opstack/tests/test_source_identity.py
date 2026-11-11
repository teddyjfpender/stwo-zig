"""A build cannot qualify a guest while compiler inputs change underneath it."""

import tempfile
import unittest
from pathlib import Path

from opstack.source_identity import compile_sources, require_unchanged


class SourceIdentity(unittest.TestCase):
    def test_mantle_inputs_are_isolated_and_shared_runtime_is_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "opstack/mantle/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("Mantle executor")
            linker = root / "opstack/kona/guest/linker.ld"
            linker.parent.mkdir(parents=True)
            linker.write_text("shared ABI")
            before = compile_sources(root, "opstack/mantle")
            self.assertIn("opstack/mantle/src/lib.rs", before)
            self.assertNotIn("opstack/mantle/src/lib.rs", compile_sources(root))
            linker.write_text("changed ABI")
            with self.assertRaisesRegex(ValueError, "linker.ld"):
                require_unchanged(before, compile_sources(root, "opstack/mantle"))

    def test_shared_patch_changes_and_new_inputs_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            patch = (
                root
                / "guests/ethereum/rv64/vendor/revm-bytecode/src/legacy.rs"
            )
            patch.parent.mkdir(parents=True)
            patch.write_text("before")
            first = compile_sources(root)
            require_unchanged(first, compile_sources(root))
            patch.write_text("after")
            with self.assertRaisesRegex(ValueError, "legacy.rs"):
                require_unchanged(first, compile_sources(root))
            second = compile_sources(root)
            (patch.parent / "new.rs").write_text("new input")
            with self.assertRaisesRegex(ValueError, "new.rs"):
                require_unchanged(second, compile_sources(root))
            baseline = compile_sources(root)
            shared = (
                root
                / "guests/ethereum/rv64/src/keccak_service.rs"
            )
            shared.parent.mkdir(parents=True)
            shared.write_text("service wrapper")
            with self.assertRaisesRegex(ValueError, "keccak_service.rs"):
                require_unchanged(baseline, compile_sources(root))
            baseline = compile_sources(root)
            shared_core = root / "src/waist/core/fields/m31.zig"
            shared_core.parent.mkdir(parents=True)
            shared_core.write_text("runner dependency")
            with self.assertRaisesRegex(ValueError, "m31.zig"):
                require_unchanged(baseline, compile_sources(root))

    def test_embedded_binary_constants_are_compiler_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            constants = root / "opstack/kona/src/blob_roots/montgomery.bin"
            constants.parent.mkdir(parents=True)
            constants.write_bytes(bytes(32))
            baseline = compile_sources(root)
            self.assertEqual(baseline[str(constants.relative_to(root))]["bytes"], 32)
            constants.write_bytes(bytes(31) + b"\x01")
            with self.assertRaisesRegex(ValueError, "montgomery.bin"):
                require_unchanged(baseline, compile_sources(root))
