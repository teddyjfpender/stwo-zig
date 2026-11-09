"""Independent trie vectors, typed receipt authority and failure bounds."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import zlib
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import transition_capture as C
import transition_rpc_adapter as A


class AdapterTests(unittest.TestCase):
    def test_ethereum_independent_trie_vectors(self):
        fixture = json.loads((Path(__file__).parent / 'fixtures/ethereum-trie-vectors.json').read_text())
        def binary(s):
            return bytes.fromhex(s[2:]) if s.startswith('0x') else s.encode()
        for name, vector in fixture['vectors'].items():
            values = {}
            for key, value in vector['in']:
                if value is None or value == '':
                    values.pop(binary(key), None)
                else:
                    values[binary(key)] = binary(value)
            root, _ = A.trie_root(list(values.items()))
            self.assertEqual('0x' + root.hex(), vector['root'], name)
        self.assertEqual(A.trie_root([])[0].hex(), '56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421')

    def receipt(self, kind='0x0'):
        return {'type':kind, 'status':'0x1','cumulativeGasUsed':'0x5208','logsBloom':'0x'+'00'*256,'logs':[]}

    def test_receipt_independent_explicit_encoding_and_deposit_tail(self):
        # Manually specified RLP, including the long list/bloom prefixes.
        expected = bytes.fromhex('f9010801825208b90100') + bytes(256) + b'\xc0'
        self.assertEqual(A.receipt_rlp(self.receipt()), expected)
        self.assertEqual(A.receipt_rlp(self.receipt('0x2')), b'\x02'+expected)
        deposit = self.receipt('0x7e'); deposit['depositNonce']='0x0'; deposit['depositReceiptVersion']='0x1'
        self.assertEqual(A.receipt_rlp(deposit), b'\x7e'+bytes.fromhex('f9010a01825208b90100')+bytes(256)+b'\xc0\x80\x01')
        deposit['depositNonce']=None
        with self.assertRaises(ValueError): A.receipt_rlp(deposit)
        bad=self.receipt(); bad['depositNonce']='0x0'
        with self.assertRaises(ValueError): A.receipt_rlp(bad)
        for key,value in [('status','0x2'),('type','0x7f'),('cumulativeGasUsed','0x01')]:
            bad=self.receipt();bad[key]=value
            with self.assertRaises(ValueError): A.receipt_rlp(bad)

    def test_trie_duplicates_budget_and_failure_atomic_records(self):
        with self.assertRaisesRegex(ValueError,'duplicate'): A.trie_root([(b'k',b'a'),(b'k',b'b')])
        adapter=A.Adapter('https://example.invalid',record_limit=4)
        raw=b'good';adapter.retain({C.keccak(raw):raw})
        before=dict(adapter.records)
        with self.assertRaisesRegex(ValueError,'budget'): adapter.retain({C.keccak(b'next'):b'next'})
        self.assertEqual(adapter.records,before)
        with self.assertRaisesRegex(ValueError,'unauthenticated'): adapter.retain({bytes(32):b'bad'})
        self.assertEqual(adapter.records,before)
        for method in ('debug_dbGet','debug_executePayload','eth_sendRawTransaction','eth_call'):
            with self.assertRaisesRegex(ValueError,'unsupported'): adapter.dispatch(method,[])

    def test_real_header_and_unknown_hash_guard(self):
        block=json.loads((Path(__file__).parent/'fixtures/transition-159257842-headers.json').read_text())[0]
        adapter=A.Adapter('https://example.invalid')
        with patch.object(C,'rpc',return_value=block):
            self.assertEqual(adapter.dispatch('debug_getRawHeader',[block['hash']]),'0x'+C.header_rlp(block).hex())
        with patch.object(C,'rpc',return_value=block):
            with self.assertRaisesRegex(ValueError,'requested'): adapter.block('0x'+'11'*32)
        with self.assertRaises(ValueError): adapter.dispatch('debug_getRawHeader',[])

    def test_real_receipt_fixture_root_and_coherent_mutations(self):
        fixture_path=Path(__file__).parent/'fixtures/transition-anchor-receipts.json.zlib'
        f=json.loads(zlib.decompress(fixture_path.read_bytes()));raw,records=A.ordered_receipts(f['block'],f['receipts'])
        self.assertEqual(len(raw),len(f['receipts']))
        self.assertTrue(all(C.keccak(value)==key for key,value in records.items()))
        for mutation in ('status','order','missing','block'):
            bad=copy.deepcopy(f['receipts'])
            if mutation=='status':bad[0]['status']='0x0' if bad[0]['status']=='0x1' else '0x1'
            elif mutation=='order':bad[0],bad[1]=bad[1],bad[0]
            elif mutation=='missing':bad.pop()
            else:bad[0]['blockHash']='0x'+'22'*32
            with self.assertRaises(ValueError): A.ordered_receipts(f['block'],bad)


if __name__=='__main__':unittest.main()
