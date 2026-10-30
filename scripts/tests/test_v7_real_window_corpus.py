import hashlib
import gzip
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("v7_real_window_corpus", Path(__file__).parents[1] / "v7_real_window_corpus.py")
CORPUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORPUS)


class CorpusImportTests(unittest.TestCase):
    def test_publishes_only_exact_checked_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payloads = {"guest.elf": b"test-elf", "input.bin": b"test-input", "expected-output.bin": bytes(43)}
            pins = {name: (hashlib.sha256(data).hexdigest(), len(data)) for name, data in payloads.items()}
            sources = {name: root / (name + ".source") for name in pins}
            for name, path in sources.items():
                path.write_bytes(payloads[name])
            with patch.dict(CORPUS.PINS, pins, clear=True):
                CORPUS.import_artifacts(root / "admitted", sources)
                CORPUS.validate_bundle(root / "admitted")
                for name, expected in payloads.items():
                    self.assertEqual(expected, (root / "admitted" / name).read_bytes())
                with self.assertRaises(ValueError):
                    CORPUS.import_artifacts(root / "admitted", sources)
                sources["input.bin"].write_bytes(b"tampered")
                with self.assertRaises(ValueError):
                    CORPUS.import_artifacts(root / "rejected", sources)
                self.assertFalse((root / "rejected").exists())

    def test_oversize_or_wrong_pin_rejected_before_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "guest.elf").write_bytes(b"not the pinned source")
            with self.assertRaises(ValueError):
                CORPUS.capture(root, root / "output", "startup", None)
            self.assertFalse((root / "output").exists())

    def test_reload_requires_external_admission_before_snapshot_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "report.json").write_bytes(b"{}")
            with patch.object(CORPUS, "validate_bundle"), patch.object(CORPUS, "snapshot_bytes") as snapshots:
                with self.assertRaisesRegex(ValueError, "independently selected"):
                    CORPUS.verify(root, root, root, "0" * 64, None)
                snapshots.assert_not_called()

    def test_compressed_capsule_is_read_without_modifying_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = b"B7WIN001" + bytes(140)
            (root / "incoming.b7win.gz").write_bytes(gzip.compress(expected))
            self.assertEqual(expected, CORPUS.snapshot_bytes(root, "incoming.b7win"))
            self.assertFalse((root / "incoming.b7win").exists())


if __name__ == "__main__":
    unittest.main()
