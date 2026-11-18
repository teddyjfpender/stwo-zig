#!/usr/bin/env python3
"""Recover an exact missing trie node with a standard authenticated absence proof.

A bounded slot search selects a query whose secure-key prefix enters the missing
subtree. The returned account/storage proof MUST validate under the pinned prior
header and contain the exact requested node hash before any supplement is saved.
No unknown node is manufactured, and slot absence is verified normally.
"""
import argparse
import json
import re
from pathlib import Path
import sys
import subprocess
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import transition_capture as C
import transition_rpc_adapter as A
from capture_host.cache_refresh import read_hash


def missing_path(kv,root,target):
    seen=set();found=[]
    def walk(ref,path):
        if len(path)>64:raise ValueError('storage path depth')
        if isinstance(ref,bytes):
            if ref==target:found.append(tuple(path));return
            if len(ref)!=32:return
            if (ref,len(path))in seen:return
            seen.add((ref,len(path)))
            if len(seen)>262144:raise ValueError('storage inspection cap')
            raw=read_hash(kv,ref,4096)
            if raw is None:return
            node=C.decode_rlp(raw)
        else:node=ref
        if not isinstance(node,list):return
        if len(node)==17:
            for i,v in enumerate(node[:16]):walk(v,path+[i])
        elif len(node)==2 and isinstance(node[0],bytes)and node[0]:
            ns=[n for b in node[0]for n in(b>>4,b&15)];flag=ns[0]
            if flag>3 or(not flag&1 and ns[1]):raise ValueError('compact storage path')
            if not flag&2:walk(node[1],path+ns[1 if flag&1 else 2:])
        else:raise ValueError('storage node framing')
    walk(root,[])
    if len(found)!=1:raise ValueError('missing node must have one authenticated reachable path')
    if len(found[0])>7:raise ValueError('search prefix exceeds28bit cap')
    return ''.join(format(n,'x')for n in found[0])


def find_slot(prefix,seconds=60,start=0,limit=1<<26):
    if not isinstance(prefix,str)or any(c not in'0123456789abcdef'for c in prefix)or len(prefix)>7:raise ValueError('bounded slot prefix')
    if not 0<seconds<=60 or not 0<=start<1<<64 or not 0<limit<=1<<26 or start+limit>1<<64:raise ValueError('slot search bounds')
    deadline=time.monotonic()+seconds
    # Integer mask avoids hexadecimal allocation on every candidate.
    bits=len(prefix)*4;want=int(prefix or'0',16);shift=256-bits
    for number in range(start,start+limit):
        if number&4095==0 and time.monotonic()>=deadline:raise ValueError('slot search deadline')
        slot=number.to_bytes(32,'big')
        if int.from_bytes(C.keccak(slot),'big')>>shift==want:return slot,number-start+1
    raise ValueError('slot search exhausted')


class SearchExhausted(ValueError):
    def __init__(self,count):super().__init__('bounded slot range exhausted');self.count=count


def helper_slot(helper,prefix,seconds,start=0):
    if not 1<=seconds<=60 or not 1<=len(prefix)<=7 or any(c not in'0123456789abcdef'for c in prefix):raise ValueError('bounded helper search')
    if type(start)is not int or not 0<=start<=(1<<64)-1-(1<<28):raise ValueError('slot offset overflow/range')
    completed=subprocess.run([str(helper),prefix,str(seconds),'4',str(start)],capture_output=True,timeout=seconds+1,env={'PATH':'/usr/bin:/bin'})
    if completed.returncode==2 and len(completed.stderr)<=128:
        match=re.fullmatch(rb'bounded search stopped after ([0-9]+) hashes\n',completed.stderr)
        if match and int(match[1])==1<<28:raise SearchExhausted(1<<28)
    if completed.returncode!=0 or len(completed.stdout)>4096:raise ValueError('bounded native slot search failed')
    result=json.loads(completed.stdout);candidate=result['candidate'];attempts=result['attempts']
    if type(candidate)is not int or not start<=candidate<start+(1<<28) or type(attempts)is not int or not 1<=attempts<=1<<28:raise ValueError('native slot advice bounds')
    slot=candidate.to_bytes(32,'big')
    if not C.keccak(slot).hex().startswith(prefix):raise ValueError('native slot advice independent Keccak mismatch')
    return slot,attempts


class WindowStopped(ValueError):
    def __init__(self,message,work):super().__init__(message);self.work=work


def helper_windows(helper,prefix,seconds,start=0,windows=1):
    if type(windows)is not int or not 1<=windows<=4 or type(start)is not int or start<0 or start+windows*(1<<28)>(1<<64)-1:raise ValueError('bounded disjoint windows')
    if not 1<=seconds<=60:raise ValueError('shared search deadline bound')
    deadline=time.monotonic()+seconds;exhausted=[];count=0
    for offset in range(start,start+windows*(1<<28),1<<28):
        remaining=int(deadline-time.monotonic())
        if remaining<1:raise WindowStopped('shared window deadline',{'exhausted_intervals':exhausted,'cumulative_completed_hashes':count,'shared_seconds_cap':seconds})
        try:slot,tries=helper_slot(helper,prefix,remaining,offset)
        except SearchExhausted as error:
            exhausted.append([offset,offset+(1<<28)]);count+=error.count;continue
        except ValueError as error:
            raise WindowStopped(str(error),{'exhausted_intervals':exhausted,'cumulative_completed_hashes':count,'incomplete_interval':[offset,offset+(1<<28)],'shared_seconds_cap':seconds})from None
        return slot,tries,{'exhausted_intervals':exhausted,'selected_interval':[offset,offset+(1<<28)],'cumulative_hashes':count+tries,'shared_seconds_cap':seconds}
    raise WindowStopped('all disjoint search windows exhausted',{'exhausted_intervals':exhausted,'cumulative_completed_hashes':count,'shared_seconds_cap':seconds})


def recover(kv,header_path,provenance,address,target,url,output,seconds=60,search_helper=None,search_start=0,search_windows=1):
    raw=header_path.read_bytes();header=C.decode_rlp(raw);block_hash=C.keccak(raw)
    entries=C.read_json(provenance,16<<20)['entries'];matches=[]
    for entry in entries.values():
        if C.unhex(entry['address'],20)==C.unhex(address,20):
            if C.unhex(entry['header_rlp'])!=raw:raise ValueError('provenance block mismatch')
            _,_,storage=A.verified_account(header[3],address,entry['account']);matches.append(storage)
    if not matches or len(set(matches))!=1:raise ValueError('authenticated storage owner required')
    prefix=missing_path(kv,matches[0],target)
    search_work=None
    if search_helper:slot,attempts,search_work=helper_windows(search_helper,prefix,seconds,search_start,search_windows)
    else:
        if search_windows!=1:raise ValueError('window mode requires explicit bounded native helper')
        slot,attempts=find_slot(prefix,seconds,start=search_start)
    block=C.rpc(url,'eth_getBlockByHash',['0x'+block_hash.hex(),False])
    if C.header_rlp(block)!=raw:raise ValueError('independent RPC pinned header mismatch')
    proof=C.rpc(url,'eth_getProof',[address,['0x'+slot.hex()],{'blockHash':'0x'+block_hash.hex(),'requireCanonical':True}])
    records,_=A.verified_proof(block,address,[slot],proof)
    if target not in records:raise ValueError('verified proof did not contain exact missing node')
    output.mkdir(parents=True,exist_ok=False)
    C.write_new(output/'proof.json',(json.dumps(proof)+'\n').encode())
    C.write_new(output/'header.rlp',raw)
    C.write_new(output/'target-node.rlp',records[target])
    C.write_new(output/'records.json',(json.dumps([(k.hex(),v.hex())for k,v in sorted(records.items())])+'\n').encode())
    result={'schema':'op-exact-storage-sibling-recovery-v1','block_hash':block_hash.hex(),'state_root':header[3].hex(),'address':address,'target':target.hex(),'prefix':prefix,'slot':slot.hex(),'search_attempts':attempts,'search_work':search_work,'search_helper_sha256':C.sha(search_helper.read_bytes())if search_helper else None,'verified_nodes':len(records),'rpc':C.endpoint_label(url),'complete_witness':False,'derivation_accepted':False,'proof_verified':False}
    C.write_new(output/'recovery.json',(json.dumps(result,indent=2)+'\n').encode());return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in('kv','header','provenance','output'):p.add_argument('--'+name,type=Path,required=True)
    for name in('address','target','rpc'):p.add_argument('--'+name,required=True)
    p.add_argument('--seconds',type=int,default=60);p.add_argument('--search-helper',type=Path);p.add_argument('--search-start',type=int,default=0);p.add_argument('--search-windows',type=int,default=1);args=p.parse_args()
    try:print(json.dumps(recover(args.kv,args.header,args.provenance,args.address,C.unhex(args.target,32),args.rpc,args.output,args.seconds,args.search_helper,args.search_start,args.search_windows),indent=2))
    except(ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError)as error:
        result={'status':'storage_sibling_recovery_failed','error_type':type(error).__name__,'error':str(error)if isinstance(error,ValueError)else'source/transport failure'}
        if isinstance(error,WindowStopped):
            result['search_work']=error.work
            args.output.mkdir(parents=True,exist_ok=False)
            C.write_new(args.output/'search-failure.json',(json.dumps(result,indent=2)+'\n').encode())
        print(json.dumps(result));raise SystemExit(1)from None
