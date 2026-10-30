import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts import v7_runpod_bundle as bundle


class BundleTests(unittest.TestCase):
    def test_state_identity_is_not_file_hash(self):
        registers = [0] * 32
        raw = b'B7WIN001' + struct.pack('<33IQII', 4, *registers, 1, 16, 7)
        expected = hashlib.sha256(b'stwo-v7-real-window-state-v1' + struct.pack('<36Q', 4, *registers, 1, 16, 7)).hexdigest()
        self.assertEqual(expected, bundle.snapshot_identity(raw))
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), expected)
        with self.assertRaises(ValueError):
            bundle.snapshot_identity(raw + b'\x00')

    def test_state_rejects_duplicate_or_unaligned_addresses(self):
        prefix = b'B7WIN001' + struct.pack('<33IQ', 0, *([0] * 32), 2)
        for addresses in ((16, 16), (17, 20), (20, 16)):
            with self.assertRaises(ValueError):
                bundle.snapshot_identity(prefix + struct.pack('<IIII', addresses[0], 1, addresses[1], 2))

    def test_export_rejects_external_and_symlink_paths(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'real.zig').write_text('source')
            (root / 'link.zig').symlink_to(root / 'real.zig')
            with patch.object(bundle, 'ROOT', root):
                self.assertEqual(root / 'real.zig', bundle.checked(Path('real.zig')))
                for path in (Path('../real.zig'), root / 'real.zig', Path('link.zig')):
                    with self.assertRaises(ValueError):
                        bundle.checked(path)

    def test_source_selection_excludes_caches_and_host_binaries(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for path in ('src/a.zig', 'src/.zig-cache/cache.zig', 'scripts/__pycache__/a.py', 'src/key.pem', 'src/a.o', 'build_support/ok.zig'):
                file = root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('source')
            with patch.object(bundle, 'ROOT', root):
                selected = set(bundle.source_paths())
            self.assertIn(Path('src/a.zig'), selected)
            self.assertIn(Path('build_support/ok.zig'), selected)
            self.assertFalse(any('cache' in str(path) or path.suffix in ('.pem', '.o') for path in selected))


if __name__ == '__main__':
    unittest.main()
