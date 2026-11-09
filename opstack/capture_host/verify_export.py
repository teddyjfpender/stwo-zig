#!/usr/bin/env python3
"""Pack independently pinned OPD, verify native transition, then reverify pruning.

No network, RV64 execution or STARK proving. Native verifier and KZG checker are
explicit caller-selected trusted executables, whose hashes enter the receipt.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import transition_capture as C
import transition_transactions as T
from transition_transport_cache import ancestry


def public_output(statement):
    data=bytearray(b'stwo/opstack/anchored-transition/v1\0')
    data+=struct.pack('<QQ',statement['chain_id'],statement['l1_chain_id'])
    for number,key in [('anchor_number','anchor_hash'),('previous_number','previous_root'),('next_number','next_root'),('next_origin_number','next_origin_hash')]:
        data+=struct.pack('<Q',statement[number])+C.unhex(statement[key],32)
    data+=C.unhex(statement['payload_commitment'],32)+C.unhex(statement['block_hash'],32)
    return hashlib.sha256(data).digest()+b'\x01'+struct.pack('<Q',statement['chain_id'])+b'OD'


def expected_statement(statement,claim,block_hash):
    expected={'schema':'stwo.opstack.anchored-transition.v1','chain_id':10,'l1_chain_id':1,
              'anchor_number':claim['anchor']['number'],'anchor_hash':claim['anchor']['hash'],
              'previous_number':claim['previous_number'],'previous_root':claim['previous_root'],
              'next_number':claim['next_number'],'next_root':claim['next_root'],
              'next_origin_number':claim['next_origin']['number'],'next_origin_hash':claim['next_origin']['hash'],
              'block_hash':block_hash}
    if set(statement)!=set(expected)|{'payload_commitment'}:raise ValueError('native statement fields')
    for key,value in expected.items():
        if isinstance(value,str)and(key.endswith('hash')or key.endswith('root')):
            if C.unhex(statement[key],32)!=C.unhex(value,32):raise ValueError('native statement expected hash mismatch')
        elif type(statement[key])is not type(value)or statement[key]!=value:raise ValueError('native statement expected field mismatch')
    C.unhex(statement['payload_commitment'],32)
    return public_output(statement)


def run_native(host,input,trace,directory,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise ValueError('offline deadline exhausted')
    started=time.monotonic();proc=None
    with ExitStack() as resources:
        stdout=resources.enter_context((directory/(input.stem+'-stdout.json')).open('xb'))
        stderr=resources.enter_context((directory/(input.stem+'-stderr.log')).open('xb'))
        try:
            proc=subprocess.Popen([str(host),'run-transition',str(input),str(trace)],stdout=stdout,stderr=stderr,start_new_session=True,env={'PATH':'/usr/bin:/bin'})
            proc.wait(timeout=remaining)
        finally:
            if proc is not None and proc.poll()is None:
                os.killpg(proc.pid,signal.SIGKILL);proc.wait()
    if proc.returncode!=0:raise ValueError('independent native transition rejected')
    statement=C.read_json(directory/(input.stem+'-stdout.json'),1<<20)
    return statement,time.monotonic()-started


def check_sidecars(checker,setup,rows,path,deadline):
    if len(rows)>256:raise ValueError('sidecar count')
    ordered=sorted(rows,key=lambda r:C.unhex(r['kzg_commitment'],48))
    data=struct.pack('<I',len(ordered))+b''.join(C.unhex(r['kzg_commitment'],48)+C.unhex(r['kzg_proof'],48)+C.unhex(r['blob'],C.BLOB_BYTES)for r in ordered)
    C.write_new(path,data)
    result=subprocess.run([str(checker),str(setup),str(path)],capture_output=True,timeout=max(.01,deadline-time.monotonic()),env={'PATH':'/usr/bin:/bin'})
    if result.returncode!=0:raise ValueError('standard sidecar checker rejected')
    receipt=json.loads(result.stdout)
    if receipt.get('kzg_verified')is not True or receipt.get('verified_standard_sidecars')!=len(ordered):raise ValueError('sidecar checker receipt')
    return receipt


def verify(host,checker,setup,candidate,block,kv,exported,output,seconds=180):
    if not 1<=seconds<=180:raise ValueError('offline deadline bound')
    claim=C.read_json(candidate/'claim.json',1<<20);v=C.read_json(candidate/'capture.json',1<<20)['candidate'];C.claim_header(claim)
    # Reauthenticate the selected claim independently of packed input metadata.
    for label,number,digest in [('l1-anchor',claim['anchor']['number'],claim['anchor']['hash']),('previous',claim['previous_number'],v['previous']['hash']),('next',claim['next_number'],v['next']['hash'])]:
        raw=(candidate/(label+'.rlp')).read_bytes();header=C.decode_rlp(raw)
        if C.keccak(raw)!=C.unhex(digest,32)or int.from_bytes(header[8],'big')!=number:raise ValueError('selected claim header mismatch')
        if label!='l1-anchor':
            root=claim['previous_root'if label=='previous'else'next_root']
            if C.keccak(bytes(32)+header[3]+header[16]+C.unhex(digest,32))!=C.unhex(root,32):raise ValueError('selected output root mismatch')
    origin=T.l1_origin(block)
    if claim['next_origin']!={'number':origin['number'],'hash':origin['hash']}:raise ValueError('selected origin mismatch')
    if(origin['number'],origin['hash'])not in ancestry(kv,claim['anchor']['hash'],512):raise ValueError('selected origin not anchored')
    if C.unhex(block['hash'],32)!=C.unhex(v['next']['hash'],32) or C.header_rlp(block)!=(candidate/'next.rlp').read_bytes():raise ValueError('selected block header mismatch')
    following=C.decode_rlp((candidate/'next.rlp').read_bytes())
    if following[0]!=C.keccak((candidate/'previous.rlp').read_bytes()) or claim['next_number']!=claim['previous_number']+1:raise ValueError('selected adjacency mismatch')
    records=C.read_json(exported/'records.json');sidecars=C.read_json(exported/'sidecars.json')
    output.mkdir(parents=True,exist_ok=False);deadline=time.monotonic()+seconds
    first=C.pack(claim,records,sidecars);C.write_new(output/'input.opd',first)
    kzg=check_sidecars(checker,setup,sidecars,output/'sidecars.bin',deadline)
    statement,elapsed=run_native(host,output/'input.opd',output/'reads.json',output,deadline)
    od=expected_statement(statement,claim,v['next']['hash'])
    trace=C.read_json(output/'reads.json');needed={C.unhex(k,32)for k in trace['preimages']};used={C.unhex(k,32)for k in trace['versioned_blob_hashes']}
    pruned_records=[r for r in records if C.unhex(r[0],32)in needed]
    if {C.unhex(r[0],32)for r in pruned_records}!=needed:raise ValueError('trace key outside original material')
    pruned_sidecars=[r for r in sidecars if b'\x01'+hashlib.sha256(C.unhex(r['kzg_commitment'],48)).digest()[1:]in used]
    if {b'\x01'+hashlib.sha256(C.unhex(r['kzg_commitment'],48)).digest()[1:]for r in pruned_sidecars}!=used:raise ValueError('trace sidecar outside original material')
    pruned=C.pack(claim,pruned_records,pruned_sidecars);C.write_new(output/'input-pruned.opd',pruned)
    second,pruned_seconds=run_native(host,output/'input-pruned.opd',output/'pruned-reads.json',output,deadline)
    if expected_statement(second,claim,v['next']['hash'])!=od or second!=statement:raise ValueError('pruned statement mismatch')
    C.write_new(output/'records-pruned.json',(json.dumps(pruned_records)+'\n').encode());C.write_new(output/'sidecars-pruned.json',(json.dumps(pruned_sidecars)+'\n').encode())
    result={'schema':'op-independent-native-transition-v1','statement':statement,'od_public_output':od.hex(),
            'input':{'bytes':len(first),'sha256':C.sha(first),'records':len(records),'sidecars':len(sidecars)},
            'pruned_input':{'bytes':len(pruned),'sha256':C.sha(pruned),'records':len(pruned_records),'sidecars':len(pruned_sidecars)},
            'native_seconds':elapsed,'pruned_native_seconds':pruned_seconds,'kzg':kzg,
            'host_sha256':C.sha(host.read_bytes()),'checker_sha256':C.sha(checker.read_bytes()),
            'complete_witness':True,'derivation_accepted':True,'guest_executed':False,'proof_verified':False,
            'anchor_finality_external':True,'security_qualified':False}
    C.write_new(output/'verified.json',(json.dumps(result,indent=2)+'\n').encode());return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in('host','checker','trusted-setup','candidate','block-json','kv','exported','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--seconds',type=int,default=180);a=p.parse_args()
    try:print(json.dumps(verify(a.host.resolve(),a.checker.resolve(),a.trusted_setup,a.candidate,C.read_json(a.block_json,16<<20),a.kv,a.exported,a.output,a.seconds),indent=2))
    except(ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError)as error:
        print(json.dumps({'status':'independent_transition_rejected','error_type':type(error).__name__}));raise SystemExit(1)from None
