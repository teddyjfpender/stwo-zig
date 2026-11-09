import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('recover_storage_sibling',Path(__file__).parents[1]/'capture_host/recover_storage_sibling.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
C=R.C

class StorageSibling(unittest.TestCase):
    def test_exact_authenticated_path_and_unknown_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            kv=Path(directory);target=C.keccak(b'actual missing node');branch=[b'']*17;branch[11]=target
            raw=C.rlp(branch);root=C.keccak(raw);name=(bytes([2])+root[1:]).hex();(kv/name[:4]).mkdir();(kv/name[:4]/(name[4:]+'.txt')).write_text(raw.hex())
            self.assertEqual(R.missing_path(kv,root,target),'b')
            with self.assertRaisesRegex(ValueError,'reachable'):R.missing_path(kv,root,C.keccak(b'foreign'))
            (kv/name[:4]/(name[4:]+'.txt')).write_text(C.rlp([b'']*17).hex())
            with self.assertRaisesRegex(ValueError,'hash'):R.missing_path(kv,root,target)

    def test_slot_search_is_genuine_keccak_and_bounded(self):
        slot,n=R.find_slot('b3',seconds=1,limit=4096)
        self.assertTrue(C.keccak(slot).hex().startswith('b3'));self.assertEqual(int.from_bytes(slot,'big')+1,n)
        for prefix in('g','1234567'):
            with self.assertRaises(ValueError):R.find_slot(prefix)
        with self.assertRaises(ValueError):R.find_slot('',seconds=61)
        with self.assertRaisesRegex(ValueError,'exhausted'):R.find_slot('ffffff',seconds=1,limit=1)
