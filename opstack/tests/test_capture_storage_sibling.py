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
        for prefix in('g','12345678'):
            with self.assertRaises(ValueError):R.find_slot(prefix)
        with self.assertRaises(ValueError):R.find_slot('',seconds=61)
        with self.assertRaisesRegex(ValueError,'exhausted'):R.find_slot('ffffff',seconds=1,limit=1)

    def test_helper_advice_is_rehashed(self):
        with tempfile.TemporaryDirectory() as directory:
            helper=Path(directory)/'search';helper.write_text('#!/bin/sh\necho \'{"candidate":0,"attempts":1}\'\n');helper.chmod(0o700)
            actual=C.keccak(bytes(32)).hex()[:2]
            self.assertEqual(R.helper_slot(helper,actual,1),(bytes(32),1))
            wrong='ff'if actual!='ff'else'00'
            with self.assertRaisesRegex(ValueError,'Keccak'):R.helper_slot(helper,wrong,1)
            helper.write_text('#!/bin/sh\necho \'{"candidate":268435456,"attempts":268435457}\'\n')
            with self.assertRaisesRegex(ValueError,'bounds'):R.helper_slot(helper,actual,1)

    def test_on_demand_requires_exact_node_and_bounded_failure_ledger(self):
        import sys,time,types,zlib
        sys.path.insert(0,str(Path(__file__).parents[1]))
        from capture_host.storage_repair import Repair
        adapter=R.A.Adapter('https://example.invalid')
        target=C.keccak(b'wanted')
        adapter.storage_repair=lambda key:{C.keccak(b'other'):b'other'}
        with self.assertRaisesRegex(ValueError,'omitted'):adapter.dispatch('debug_dbGet',['0x'+target.hex()])
        self.assertFalse(adapter.records)
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);header=base/'header';helper=base/'helper';helper.write_bytes(b'unused')
            header.write_bytes(C.rlp([b'']*15))
            stub=types.SimpleNamespace(deadline=time.monotonic()+1,code_proofs={})
            repair=Repair(stub,base,header,helper,base/'repairs',limit=1)
            with self.assertRaisesRegex(ValueError,'known storage owner'):repair(target)
            self.assertTrue((base/'repairs/1/failure.json').exists())
            with self.assertRaisesRegex(ValueError,'count'):repair(C.keccak(b'second'))
            with self.assertRaisesRegex(ValueError,'count cap'):Repair(stub,base,header,helper,base/'r',limit=9)

    def test_repair_import_isolated_from_test_search_path(self):
        import subprocess,sys
        source=str(Path(__file__).resolve().parents[1])
        result=subprocess.run([sys.executable,'-I','-c',f'import sys;sys.path.insert(0,{source!r});from capture_host.storage_repair import Repair'],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr.decode())

    def test_offset_bounds_and_disjoint_window_ledger(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            helper=Path(directory)/'search';helper.write_text('#!/bin/sh\necho \'{"candidate":0,"attempts":1}\'\n');helper.chmod(0o700)
            for offset in(-1,1<<64):
                with self.assertRaisesRegex(ValueError,'offset'):R.helper_slot(helper,'b3',1,offset)
            with self.assertRaisesRegex(ValueError,'advice bounds'):R.helper_slot(helper,'b3',1,1<<28)
            with patch.object(R,'helper_slot',side_effect=[R.SearchExhausted(1<<28),(bytes(32),7)])as mock:
                _,_,ledger=R.helper_windows(helper,'b3',5,start=1<<28,windows=2)
                self.assertEqual(ledger['exhausted_intervals'],[[1<<28,2<<28]])
                self.assertEqual(ledger['selected_interval'],[2<<28,3<<28])
                self.assertEqual(ledger['cumulative_hashes'],(1<<28)+7)
                self.assertEqual([x.args[3]for x in mock.call_args_list],[1<<28,2<<28])
            with self.assertRaisesRegex(ValueError,'disjoint'):R.helper_windows(helper,'b3',5,windows=5)
