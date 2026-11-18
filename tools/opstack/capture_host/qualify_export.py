#!/usr/bin/env python3
"""Actual native rejection controls for a completed independently verified OPD.

No guest execution or physical STARK proof. Timeout is NOT a successful rejection.
"""
import argparse
import copy
import json
from pathlib import Path
import sys
import subprocess
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import transition_capture as C
from capture_host.verify_export import run_native,expected_statement


def qualify(host,verified,candidate,output,seconds=60):
    if not 1<=seconds<=180:raise ValueError('qualification deadline cap')
    receipt=C.read_json(verified/'verified.json',1<<20)
    if receipt['derivation_accepted']is not True or C.sha(host.read_bytes())!=receipt['host_sha256']:raise ValueError('pinned native verifier authority mismatch')
    original=(verified/'input-pruned.opd').read_bytes()
    if C.sha(original)!=receipt['pruned_input']['sha256']:raise ValueError('baseline input hash mismatch')
    claim=C.read_json(candidate/'claim.json',1<<20);expected_statement(receipt['statement'],claim,receipt['statement']['block_hash'])
    records=C.read_json(verified/'records-pruned.json');sidecars=C.read_json(verified/'sidecars-pruned.json')
    if C.pack(claim,records,sidecars)!=original:raise ValueError('baseline material differs from accepted input')
    if len(sidecars)<2:raise ValueError('swapped-valid-proof control requires two sidecars')
    output.mkdir(parents=True,exist_ok=False);deadline=time.monotonic()+seconds;results={}
    for name in('anchor_hash','next_output_root','consumed_blob_byte','proof_byte','swapped_valid_proofs'):
        c=copy.deepcopy(claim);s=copy.deepcopy(sidecars)
        if name=='anchor_hash':
            v=bytearray(C.unhex(c['anchor']['hash'],32));v[0]^=1;c['anchor']['hash']=v.hex()
        elif name=='next_output_root':
            v=bytearray(C.unhex(c['next_root'],32));v[0]^=1;c['next_root']=v.hex()
        elif name=='consumed_blob_byte':
            v=bytearray(C.unhex(s[0]['blob'],C.BLOB_BYTES));v[31]^=1;s[0]['blob']=v.hex()
        elif name=='proof_byte':
            v=bytearray(C.unhex(s[0]['kzg_proof'],48));v[-1]^=1;s[0]['kzg_proof']=v.hex()
        else:s[0]['kzg_proof'],s[1]['kzg_proof']=s[1]['kzg_proof'],s[0]['kzg_proof']
        data=C.pack(c,records,s);path=output/(name+'.opd');C.write_new(path,data);started=time.monotonic()
        try:run_native(host,path,output/(name+'-reads.json'),output,deadline)
        except ValueError as error:
            if str(error)!='independent native transition rejected':raise
        else:raise ValueError('forged anchored input accepted')
        stderr=(output/(name+'-stderr.log')).read_bytes()
        results[name]={'rejected':True,'input_sha256':C.sha(data),'stderr_sha256':C.sha(stderr),'seconds':time.monotonic()-started}
    result={'schema':'op-native-anchored-negative-qualification-v1','baseline_input_sha256':C.sha(original),'host_sha256':receipt['host_sha256'],'cases':results,'guest_executed':False,'proof_verified':False,'security_qualified':False}
    C.write_new(output/'qualification.json',(json.dumps(result,indent=2)+'\n').encode());return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in('host','verified','candidate','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--seconds',type=int,default=60);a=p.parse_args()
    try:print(json.dumps(qualify(a.host,a.verified,a.candidate,a.output,a.seconds),indent=2))
    except(ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError)as error:
        print(json.dumps({'status':'native_control_failed','error_type':type(error).__name__}));raise SystemExit(1)from None
