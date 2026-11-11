"""Bounded fixture integrity only; default tests do not execute RV64/STARK/native."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('unpack_fixture',Path(__file__).parents[1]/'capture_host/unpack_fixture.py')
U=importlib.util.module_from_spec(spec);spec.loader.exec_module(U)

class RetainedFixture(unittest.TestCase):
    def test_canonical_recent_input_bounded_integrity(self):
        path=Path(__file__).parent/'fixtures/transition-159321794/manifest.json'
        raw,m=U.decode(path)
        self.assertEqual(len(raw),13882081)
        self.assertEqual(m['uncompressed_sha256'],'9ee0a1f7b425d90c12d705212502dc135773af8d60f63c494a83500214c14031')
        self.assertFalse(m['guest_executed']);self.assertFalse(m['proof_verified'])

    def test_manifest_size_refuses_before_decompression(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'manifest.json'
            m={'schema':'op-retained-anchored-mainnet-fixture-v1','file':'input.opd.gz','compressed_bytes':U.MAX+1,'uncompressed_bytes':1}
            path.write_text(json.dumps(m))
            with self.assertRaisesRegex(ValueError,'size cap'):U.decode(path)
