#!/usr/bin/env python3
"""Opt-in native KZG qualification over actual captured sidecars; no proving."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile


def sha(data):return hashlib.sha256(data).hexdigest()

def qualify(checker,setup,bundle,output):
    if bundle.stat().st_size>64<<20 or setup.stat().st_size>1<<20:raise ValueError('input cap')
    data=bundle.read_bytes();count=struct.unpack_from('<I',data)[0];width=131168
    if count<2 or len(data)!=4+count*width:raise ValueError('two actual sidecars required')
    def invoke(trusted,path):
        return subprocess.run([str(checker),str(trusted),str(path)],capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin'})
    positive=invoke(setup,bundle)
    if positive.returncode!=0:raise ValueError('positive KZG rejection')
    mutations={}
    bad=bytearray(data);bad[4+96+31]^=1;mutations['blob_byte']=bytes(bad)
    bad=bytearray(data);bad[4+48+47]^=1;mutations['proof_byte']=bytes(bad)
    other=next((i for i in range(1,count)if data[4+i*width+48:4+i*width+96]!=data[52:100]),None)
    if other is None:raise ValueError('distinct valid proofs required')
    bad=bytearray(data);a=4+48;b=4+other*width+48;bad[a:a+48],bad[b:b+48]=bad[b:b+48],bad[a:a+48];mutations['swapped_valid_proofs']=bytes(bad)
    mutations['truncated']=data[:-1];mutations['oversized_count']=struct.pack('<I',257)
    mutations['duplicate_commitment']=struct.pack('<I',count+1)+data[4:4+width]+data[4:]
    controls=[]
    with tempfile.TemporaryDirectory()as directory:
        root=Path(directory)
        for name,raw in mutations.items():
            path=root/(name+'.bin');path.write_bytes(raw);result=invoke(setup,path)
            if result.returncode==0:raise ValueError('forged KZG bundle accepted')
            controls.append({'name':name,'status':'rejected','input_sha256':sha(raw),'stderr_sha256':sha(result.stderr)})
        raw=bytearray(setup.read_bytes());raw[-2]^=1;path=root/'wrong-setup.txt';path.write_bytes(raw);result=invoke(path,bundle)
        if result.returncode==0:raise ValueError('wrong trusted setup accepted')
        controls.append({'name':'trusted_setup_byte','status':'rejected','input_sha256':sha(raw)})
    report={'schema':'op-standard-kzg-qualification-v1','sidecars':count,'positive':json.loads(positive.stdout),
            'controls':controls,'checker_sha256':sha(checker.read_bytes()),'sidecar_bundle_sha256':sha(data),
            'complete_witness':False,'derivation_accepted':False,'proof_verified':False}
    with output.open('x')as f:f.write(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--checker',type=Path,required=True);p.add_argument('--trusted-setup',type=Path,required=True);p.add_argument('--bundle',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps(qualify(a.checker.resolve(),a.trusted_setup,a.bundle,a.output),indent=2))
