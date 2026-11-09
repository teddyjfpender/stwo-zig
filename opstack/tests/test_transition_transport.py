"""Authenticated full-body cache and coherent producer tamper controls."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib
sys.path.insert(0,str(Path(__file__).parents[1]))
import transition_capture as C
import transition_transactions as T
import transition_transport_cache as K
import transition_rpc_adapter as A
F=Path(__file__).parent/'fixtures'


class TransportTests(unittest.TestCase):
    def l1(self):return json.loads(zlib.decompress((F/'transition-anchor-transactions.json.zlib').read_bytes()))
    def receipts(self):return json.loads(zlib.decompress((F/'transition-anchor-receipts.json.zlib').read_bytes()))['receipts']
    def test_actual_full_transaction_tries_and_mutations(self):
        for name,count in [('transition-anchor-transactions.json.zlib',185),('recent-transactions.json.zlib',102)]:
            block=json.loads(zlib.decompress((F/name).read_bytes()))
            self.assertTrue(T.verify_block(block));self.assertEqual(len(block['transactions']),count)
            bad=copy.deepcopy(block);bad['transactions'][0]['value']='0x1'
            with self.assertRaises(ValueError):T.verify_block(bad)
            bad=copy.deepcopy(block);bad['transactions'][0],bad['transactions'][1]=bad['transactions'][1],bad['transactions'][0]
            with self.assertRaises(ValueError):T.verify_block(bad)
        block=self.l1();bad=copy.deepcopy(block);index=next(i for i,t in enumerate(bad['transactions'])if t['type']=='0x0')
        tx=bad['transactions'][index];fields=C.decode_rlp(T.encoded(tx));fields[4]=b'\x01'
        tx['value']='0x1';tx['hash']='0x'+C.keccak(C.rlp(fields)).hex()
        with self.assertRaisesRegex(ValueError,'trie root'):T.verify_block(bad)
        tx=copy.deepcopy(block['transactions'][0]);tx['type']='0x7f'
        with self.assertRaisesRegex(ValueError,'unsupported'):T.encoded(tx)

    def test_actual_l1_info_origin_is_transaction_and_domain_bound(self):
        block=json.loads(zlib.decompress((F/'recent-transactions.json.zlib').read_bytes()))
        origin=T.l1_origin(block)
        self.assertEqual(origin['number'],26378577)
        self.assertEqual(origin['hash'],'0xa318027d823bee7ebe41f143d57c441bc6c461ca5c7af237871b7ae023b152a1')
        self.assertEqual(origin['sequence_number'],1)
        block['transactions'][0]['sourceHash']='0x'+'11'*32
        with self.assertRaises(ValueError):T.l1_origin(block)

    def make_cache(self,root,payload):
        key=payload['block']['hash'][2:];raw=json.dumps(payload).encode();(root/(key+'.json')).write_bytes(raw)
        index={'schema':'op-l1-transport-cache-v1','claim_sha256':'11'*32,'blocks':{key:{'number':26367973,'bytes':len(raw),'sha256':C.sha(raw)}},'bytes':len(raw)}
        (root/'cache.json').write_text(json.dumps(index));return key,index
    def test_cache_source_claim_and_coherent_payload_forgery(self):
        payload={'block':self.l1(),'receipts':self.receipts()}
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);key,index=self.make_cache(root,payload)
            cache=K.Cache(root,'11'*32);self.assertEqual(len(cache.load('0x'+key)['receipts']),185)
            with self.assertRaisesRegex(ValueError,'claim'):K.Cache(root,'22'*32)
            adapter=A.Adapter('https://example.invalid',transport_cache=root,cache_claim='11'*32)
            with patch.object(C,'rpc',side_effect=AssertionError('cache made network request')):
                self.assertEqual(adapter.dispatch('eth_getBlockByHash',['0x'+key,True])['hash'],'0x'+key)
                self.assertTrue(adapter.dispatch('debug_getRawHeader',['0x'+key]))
                self.assertEqual(len(adapter.dispatch('debug_getRawReceipts',['0x'+key])),185)
            payload['receipts'][0]['status']='0x0'
            self.make_cache(root,payload) # Producer coherently changes bytes+manifest SHA.
            with self.assertRaisesRegex(ValueError,'trie root'):K.Cache(root,'11'*32).load('0x'+key)
    def test_header_ancestry_direct_lookup_ignores_blob_namespace(self):
        head,parent=json.loads((F/'transition-159257842-headers.json').read_bytes())
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory)
            for block in(head,parent):
                raw=C.header_rlp(block);name=(bytes([2])+C.keccak(raw)[1:]).hex();p=root/name[:4];p.mkdir(exist_ok=True);(p/(name[4:]+'.txt')).write_text(raw.hex())
            # Irrelevant malformed blob namespace is never read as a header.
            (root/'0500').mkdir();(root/'0500'/'blob.txt').write_text('not a header')
            rows=K.ancestry(root,head['hash'],2);self.assertEqual([x[0]for x in rows],[159257842,159257841])
            name=(bytes([2])+C.unhex(head['hash'],32)[1:]).hex();(root/name[:4]/(name[4:]+'.txt')).write_text('00')
            with self.assertRaisesRegex(ValueError,'Keccak'):K.ancestry(root,head['hash'],2)


if __name__=='__main__':unittest.main()
