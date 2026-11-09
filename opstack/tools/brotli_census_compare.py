#!/usr/bin/env python3
"""Compare bounded native Brotli allocator runs with Node's independent C decoder."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

LIMIT = 64 * 1024 * 1024

def read_bounded(path, cap):
    with path.open("rb") as source:
        value=source.read(cap+1)
    if len(value)>cap: raise ValueError("file exceeds bound")
    return value

def compare(control, candidate, node):
    reports = [json.loads(read_bounded(p / "census.json", 1024*1024)) for p in (control,candidate)]
    rows = [r['rows'] for r in reports]
    if any(r.get('schema') != 'op-native-brotli-census-v1' or r.get('native_only') is not True for r in reports):
        raise ValueError('unexpected census format')
    if not 0 < len(rows[0]) <= 32 or len(rows[0]) != len(rows[1]):
        raise ValueError('channel coverage mismatch')
    version = subprocess.check_output([node,'-p','JSON.stringify({node:process.version,brotli:process.versions.brotli})'],timeout=10)
    result=[]
    total=0
    for i,(old,new) in enumerate(zip(*rows)):
        inputs=[read_bounded(p/f'channel-{i}.input', LIMIT) for p in (control,candidate)]
        outputs=[read_bounded(p/f'channel-{i}.output', LIMIT) for p in (control,candidate)]
        total+=len(inputs[0])+len(outputs[0])
        if total>LIMIT or inputs[0]!=inputs[1] or outputs[0]!=outputs[1] or inputs[0][:4]!=b'BRP1':
            raise ValueError('channel bytes or bound mismatch')
        cap=int.from_bytes(inputs[0][4:8],'little')
        if any(r['channel']!=i or r['max_output']!=cap or r['compressed_bytes']!=len(inputs[0])-8 or r['output_bytes']!=len(outputs[0]) for r in (old,new)):
            raise ValueError('channel metadata mismatch')
        if [s['limit'] for s in new['allocations']] != [32*1024*1024,1024*1024,4*1024*1024] or any(s['live'] or s['peak']>s['limit'] for s in new['allocations']):
            raise ValueError('allocation custody or capacity mismatch')
        ref=subprocess.run([node,'-e',"const z=require('node:zlib'),fs=require('node:fs');process.stdout.write(z.brotliDecompressSync(fs.readFileSync(0),{maxOutputLength:67108864}));"],input=inputs[0][8:],capture_output=True,timeout=30,check=True).stdout
        if ref!=outputs[0]:
            raise ValueError('independent C Brotli mismatch')
        result.append({'channel':i,'compressed_sha256':hashlib.sha256(inputs[0][8:]).hexdigest(),'output_sha256':hashlib.sha256(ref).hexdigest(),'compressed_bytes':len(inputs[0])-8,'output_bytes':len(ref),'control_upfront_zeroed_bytes':old['upfront_zeroed_bytes'],'candidate_initialized_bytes':sum(s['initialized_cells']*s['cell_bytes'] for s in new['allocations']),'candidate_peak_bytes':sum(s['peak']*s['cell_bytes'] for s in new['allocations']),'control_setup_ns':old['setup_ns'],'candidate_setup_ns':new['setup_ns'],'independent_c_reference':True})
    return {'schema':'op-brotli-lazy-native-v1','native_only':True,'whole_rv64_transition_executed':False,'security_qualified':False,'reference':json.loads(version),'rows':result}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('control',type=Path);p.add_argument('candidate',type=Path)
    p.add_argument('--node',default=shutil.which('node'));p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    value=compare(a.control,a.candidate,a.node)
    with a.output.open('x') as out: json.dump(value,out,indent=2);out.write('\n')
