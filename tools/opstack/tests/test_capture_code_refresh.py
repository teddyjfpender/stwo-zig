"""Evict only authenticated reachable account leaves; never guessed state."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]));sys.path.insert(0,str(Path(__file__).parents[1]/'capture_host'))
import transition_capture as C
import transition_rpc_adapter as A
import cache_refresh as R


class RefreshTests(unittest.TestCase):
    def test_membership_and_verified_code_preimage_control_eviction(self):
        code1=b'known bytecode';code2=b'missing bytecode';hash1=C.keccak(code1);hash2=C.keccak(code2)
        account=lambda code:C.rlp([b'',b'\x01',C.keccak(C.rlp(b'')),code])
        root,records=A.trie_root([(C.keccak(b'a'*20),account(hash1)),(C.keccak(b'b'*20),account(hash2))])
        # A valid-looking but unreachable leaf must not enter the sweep.
        foreign=C.rlp([b'\x20'+C.keccak(b'c'*20),account(C.keccak(b'unreachable'))]);records[C.keccak(foreign)]=foreign
        records[hash1]=code1
        with tempfile.TemporaryDirectory()as directory:
            kv=Path(directory)
            for digest,value in records.items():
                name=(bytes([2])+digest[1:]).hex();folder=kv/name[:4];folder.mkdir(exist_ok=True);(folder/(name[4:]+'.txt')).write_text(value.hex())
            report=R.missing_code_leaves(kv,root)
            self.assertEqual(report['verified_account_leaves'],2)
            self.assertEqual(len(report['evictions']),1)
            self.assertEqual(report['evictions'][0]['code_hash'],hash2.hex())
            self.assertEqual(R.missing_code_leaves(kv,root,[hash2])['evictions'],[])
            name=(bytes([2])+root[1:]).hex();(kv/name[:4]/(name[4:]+'.txt')).write_text('00')
            with self.assertRaisesRegex(ValueError,'hash'):R.missing_code_leaves(kv,root)


if __name__=='__main__':unittest.main()
