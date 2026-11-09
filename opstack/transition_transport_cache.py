#!/usr/bin/env python3
"""Bounded immutable L1 body/receipt precollection from authenticated ancestry."""
import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import json
from pathlib import Path
import re
import time

import transition_capture as C
import transition_transactions as T

MAX_FILE=32<<20
MAX_CACHE=256<<20


def claim_id(candidate):
    return C.sha(json.dumps(candidate,sort_keys=True,separators=(',',':')).encode())


def verify_payload(payload,expected):
    from transition_rpc_adapter import ordered_receipts
    if set(payload)!={'block','receipts'}:raise ValueError('cache payload fields')
    block=payload['block']
    if C.unhex(block['hash'],32)!=C.unhex(expected,32):raise ValueError('cache expected hash mismatch')
    records=T.verify_block(block)
    flat=dict(block);flat['transactions']=[tx['hash']for tx in block['transactions']]
    _,receipts=ordered_receipts(flat,payload['receipts'])
    records.update(receipts)
    encoded=C.header_rlp(block);records[C.keccak(encoded)]=encoded
    return records


class Cache:
    def __init__(self,path,expected_claim):
        C.unhex(expected_claim,32)
        self.path=Path(path)
        self.index=C.read_json(self.path/'cache.json',1<<20)
        if self.index['schema']!='op-l1-transport-cache-v1' or self.index['claim_sha256']!=expected_claim:
            raise ValueError('transport cache claim mismatch')
        entries=self.index['blocks']
        if not isinstance(entries,dict)or len(entries)>512:raise ValueError('transport cache count cap')
        total=0
        for key,row in entries.items():
            if not re.fullmatch('[0-9a-f]{64}',key) or not isinstance(row['bytes'],int)or not 0<row['bytes']<=MAX_FILE:
                raise ValueError('transport cache entry bound')
            C.unhex(row['sha256'],32);total+=row['bytes']
        if total>MAX_CACHE or total!=self.index['bytes']:raise ValueError('transport cache byte cap')

    def load(self,digest):
        key=C.unhex(digest,32).hex()
        if key not in self.index['blocks']:return None
        expected=self.index['blocks'][key];file=self.path/(key+'.json')
        if file.is_symlink()or file.stat().st_size!=expected['bytes']:raise ValueError('transport cache file bound')
        raw=file.read_bytes()
        if C.sha(raw)!=expected['sha256']:raise ValueError('transport cache byte integrity')
        payload=json.loads(raw);verify_payload(payload,'0x'+key)
        return payload


def ancestry(kv,anchor,maximum):
    key=C.unhex(anchor,32);out=[]
    for _ in range(maximum):
        masked=(bytes([2])+key[1:]).hex();directory=kv/masked[:4];file=directory/(masked[4:]+'.txt')
        if not file.exists():break
        if directory.is_symlink()or file.is_symlink()or file.stat().st_size>8192:raise ValueError('header KV bound')
        raw=C.unhex(file.read_text())
        if C.keccak(raw)!=key:raise ValueError('anchored header Keccak mismatch')
        node=C.decode_rlp(raw)
        if not isinstance(node,list)or len(node)<15 or len(node[6])!=256:raise ValueError('invalid anchored header')
        number=int.from_bytes(node[8],'big')
        if out and number+1!=out[-1][0]:raise ValueError('anchored header number mismatch')
        out.append((number,'0x'+key.hex()));key=node[0]
    if not out:raise ValueError('anchor not present in authenticated KV')
    return out


def prefetch(rpc,kv,candidate,output,seconds=180,workers=8,count=128):
    if not 1<=seconds<=180 or not 1<=workers<=8 or not 1<=count<=512:raise ValueError('prefetch limits')
    C.endpoint_label(rpc)
    v=C.read_json(candidate/'capture.json',1<<20)['candidate']
    headers=ancestry(kv,v['l1-anchor']['hash'],count)
    output.mkdir(parents=True,exist_ok=False)
    started=time.monotonic();deadline=started+seconds
    index={'schema':'op-l1-transport-cache-v1','claim_sha256':claim_id(v),'anchor':v['l1-anchor'],
           'blocks':{},'bytes':0,'complete_witness':False,'derivation_accepted':False,'proof_verified':False}
    errors=[]
    def fetch(item):
        number,digest=item
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError('prefetch deadline')
        block=C.rpc(rpc,'eth_getBlockByHash',[digest,True],cap=16<<20,timeout=min(12,remaining))
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError('prefetch deadline')
        receipts=C.rpc(rpc,'eth_getBlockReceipts',[hex(number)],cap=16<<20,timeout=min(12,remaining))
        payload={'block':block,'receipts':receipts};verify_payload(payload,digest)
        raw=(json.dumps(payload,separators=(',',':'))+'\n').encode()
        if len(raw)>MAX_FILE:raise ValueError('cache payload byte cap')
        return number,digest,raw
    pending={};iterator=iter(headers)
    with ThreadPoolExecutor(max_workers=workers)as pool:
        def fill():
            while len(pending)<workers and time.monotonic()<deadline:
                item=next(iterator,None)
                if item is None:break
                pending[pool.submit(fetch,item)]=item
        fill()
        while pending:
            done,_=wait(pending,timeout=.25,return_when=FIRST_COMPLETED)
            for future in done:
                item=pending.pop(future)
                try:
                    number,digest,raw=future.result()
                    if index['bytes']+len(raw)>MAX_CACHE:raise ValueError('transport cache total budget')
                    key=C.unhex(digest,32).hex();C.write_new(output/(key+'.json'),raw)
                    index['blocks'][key]={'number':number,'bytes':len(raw),'sha256':C.sha(raw)};index['bytes']+=len(raw)
                except(C.RpcFailure,ValueError,KeyError,TypeError,OSError)as error:
                    errors.append({'number':item[0],'error_type':type(error).__name__})
            fill()
    index['elapsed_seconds']=time.monotonic()-started
    index['header_candidates']=len(headers);index['errors']=errors
    C.write_new(output/'cache.json',(json.dumps(index,indent=2)+'\n').encode())
    return index


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rpc',required=True);p.add_argument('--kv',type=Path,required=True)
    p.add_argument('--candidate',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seconds',type=int,default=180);p.add_argument('--workers',type=int,default=8);p.add_argument('--count',type=int,default=128)
    a=p.parse_args()
    try:
        r=prefetch(a.rpc,a.kv,a.candidate,a.output,a.seconds,a.workers,a.count)
        print(json.dumps({k:v for k,v in r.items()if k!='blocks'},indent=2))
        print(json.dumps({'cached_blocks':len(r['blocks'])}))
    except(C.RpcFailure,ValueError,KeyError,TypeError,OSError)as error:
        print(json.dumps({'status':'transport_prefetch_failed','error_type':type(error).__name__}));raise SystemExit(1)from None
