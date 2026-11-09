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
        for method in ('debug_executePayload','eth_sendRawTransaction','eth_call'):
            with self.assertRaisesRegex(ValueError,'unsupported'): adapter.dispatch(method,[])
        with self.assertRaisesRegex(ValueError,'unknown'): adapter.dispatch('debug_dbGet',['0x'+'11'*32])

    def test_real_storage_presence_absence_code_provenance_and_mutations(self):
        f=json.loads(zlib.decompress((Path(__file__).parent/'fixtures/recent-storage-code.json.zlib').read_bytes()))
        address=f['proof']['address'];slots=[A.storage_slot(x) for x in ('0x0','0x1','0x2')]
        records,code=A.verified_proof(f['block'],address,slots,f['proof'])
        self.assertEqual(code,C.keccak(C.unhex(f['code'])))
        self.assertEqual([x['value']for x in f['proof']['storageProof']],['0x0','0x8ab2','0x0'])
        self.assertTrue(records)
        for mutation in ('value','slot','address','node','codehash'):
            bad=copy.deepcopy(f['proof'])
            if mutation=='value':bad['storageProof'][0]['value']='0x1'
            elif mutation=='slot':bad['storageProof'][0]['key']='0x7'
            elif mutation=='address':bad['address']='0x'+'11'*20
            elif mutation=='codehash':bad['codeHash']='0x'+'22'*32
            else:bad['storageProof'][0]['proof'][-1]+='00'
            with self.assertRaises(ValueError):A.verified_proof(f['block'],address,slots,bad)
        adapter=A.Adapter('https://example.invalid')
        with patch.object(C,'rpc',side_effect=[f['block'],f['proof'],f['code']]) as rpc:
            adapter.dispatch('eth_getProof',[address,['0x0','0x1','0x2'],{'blockHash':f['block']['hash'],'requireCanonical':True}])
            got=adapter.dispatch('debug_dbGet',['0x63'+code.hex()])
        self.assertEqual(got,f['code'])
        self.assertEqual(rpc.call_args_list[-1].args[1],'eth_getCode')
        with patch.object(C,'rpc') as rpc:
            self.assertEqual(adapter.dispatch('debug_dbGet',['0x'+code.hex()]),f['code'])
            with self.assertRaisesRegex(ValueError,'unknown'):adapter.dispatch('debug_dbGet',['0x'+'55'*32])
            rpc.assert_not_called()
        corrupt=A.Adapter('https://example.invalid')
        with patch.object(C,'rpc',side_effect=[f['block'],f['proof'],'0x00']):
            corrupt.dispatch('eth_getProof',[address,['0x0','0x1','0x2'],f['block']['hash']])
            before=dict(corrupt.records)
            with self.assertRaisesRegex(ValueError,'code hash'):corrupt.dispatch('debug_dbGet',['0x'+code.hex()])
            self.assertEqual(corrupt.records,before)

    def test_absence_is_opt_in_and_root_authenticated(self):
        root=C.keccak(C.rlp(b''))
        self.assertIsNone(C.verify_trie_value(root,bytes(32),[],allow_absence=True))
        with self.assertRaises(ValueError):C.verify_trie_value(root,bytes(32),[])
        leaf=C.rlp([b'\x20'+bytes(32),b'value'])
        self.assertIsNone(C.verify_trie_value(C.keccak(leaf),bytes([1])*32,[leaf.hex()],allow_absence=True))
        with self.assertRaises(ValueError):C.verify_trie_value(bytes(32),bytes([1])*32,[leaf.hex()],allow_absence=True)
        adapter=A.Adapter('https://example.invalid')
        with patch.object(C,'rpc') as rpc:
            with self.assertRaisesRegex(ValueError,'duplicate'):adapter.dispatch('eth_getProof',['0x'+'00'*20,['0x0','0x'+'00'*32],'latest'])
            rpc.assert_not_called()

    def test_durable_code_provenance_reverified_without_new_account_query(self):
        import tempfile
        f=json.loads(zlib.decompress((Path(__file__).parent/'fixtures/recent-storage-code.json.zlib').read_bytes()))
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);original=A.Adapter('https://example.invalid')
            with patch.object(C,'rpc',side_effect=[f['block'],f['proof']]):
                original.dispatch('eth_getProof',[f['proof']['address'],['0x0','0x1','0x2'],f['block']['hash']])
            original.export(root/'old');advice=root/'old/code-provenance.json'
            resumed=A.Adapter('https://example.invalid',code_provenance=[advice],provenance_block=f['block']['hash'])
            with patch.object(C,'rpc',return_value=f['code'])as rpc:
                self.assertEqual(resumed.dispatch('debug_dbGet',['0x63'+f['proof']['codeHash'][2:]]),f['code'])
            self.assertEqual(rpc.call_args.args[1],'eth_getCode')
            with self.assertRaisesRegex(ValueError,'expected block'):
                A.Adapter('https://example.invalid',code_provenance=[advice],provenance_block='0x'+'44'*32)
            data=json.loads(advice.read_bytes());key=next(iter(data['entries']))
            data['entries'][key]['address']='0x'+'55'*20
            bad=root/'bad.json';bad.write_text(json.dumps(data))
            empty=A.Adapter('https://example.invalid')
            with self.assertRaises(ValueError):empty.load_provenance(bad,f['block']['hash'])
            self.assertEqual(empty.code_accounts,{})
            data=json.loads(advice.read_bytes());entry=data['entries'].pop(key);entry['account']['codeHash']='0x'+'66'*32;data['entries']['66'*32]=entry
            bad.write_text(json.dumps(data))
            with self.assertRaises(ValueError):empty.load_provenance(bad,f['block']['hash'])
            self.assertEqual(empty.code_accounts,{})

    def test_failure_ledger_is_finite_and_redacts_unrecognized_data(self):
        adapter=A.Adapter('https://example.invalid');adapter.method_counts['eth_getProof']=1
        request={'method':'eth_getProof','params':['0x'+'11'*20,['0x0'],{'blockHash':'0x'+'22'*32,'requireCanonical':True}]}
        row=adapter.record_failure(request,C.RpcFailure('rpc_error',429,-32005))
        self.assertEqual(row['upstream']['http_status'],429)
        self.assertEqual(row['proof_request']['slots'],['0x'+'00'*32])
        row=adapter.record_failure({'method':'secret-url','params':['TOKEN=EXAMPLE']},ValueError('TOKEN=EXAMPLE'))
        self.assertNotIn('EXAMPLE',json.dumps(row));self.assertNotIn('secret-url',json.dumps(row))
        for _ in range(100):adapter.record_failure(request,ValueError('storage proof slot mismatch'))
        self.assertEqual(len(adapter.failures),64);self.assertEqual(adapter.failure_count,102)

    def test_readahead_authenticates_parent_chain_and_reuses_hash_cache(self):
        head,parent=json.loads((Path(__file__).parent/'fixtures/transition-159257842-headers.json').read_text())
        adapter=A.Adapter('https://example.invalid',header_window=2)
        with patch.object(C,'rpc',side_effect=[head,parent]) as rpc:
            self.assertEqual(adapter.block(head['hash'])['hash'],head['hash'])
            self.assertEqual(adapter.block(parent['hash'])['hash'],parent['hash'])
            self.assertEqual(rpc.call_count,2)
        self.assertEqual(adapter.prefetched_headers,1)
        fork=copy.deepcopy(parent);fork['gasUsed']='0x0'
        fields=C.decode_rlp(C.header_rlp(parent));fields[10]=b''
        fork['hash']='0x'+C.keccak(C.rlp(fields)).hex()
        C.header_rlp(fork)  # Internally valid header on a different ancestry.
        adapter=A.Adapter('https://example.invalid',header_window=2)
        with patch.object(C,'rpc',side_effect=[head,fork]):adapter.block(head['hash'])
        self.assertNotIn(fork['hash'],adapter.headers)
        self.assertEqual(adapter.prefetched_headers,0)
        for window in (0,33):
            with self.assertRaises(ValueError):A.Adapter('https://example.invalid',header_window=window)

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
