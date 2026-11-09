#!/usr/bin/env python3
"""Bounded dense Fq12 service experiment; no OP or pairing validity assertion."""
import argparse, hashlib, json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from opstack.cpu import measured
from opstack.oracle import execute
from scripts.riscv64_csp_compare import elf_info
from Crypto.Hash import keccak
P=21888242871839275222246405745257275088696311157297823662689037894645226208583

def product(a,b):
    """Independent schoolbook in Fp[i,v,w]/(i²+1,v³-9-i,w²-v)."""
    if len(a)!=12 or len(b)!=12:raise ValueError('tower width')
    out=[0]*12
    for x,av in enumerate(a):
        for y,bv in enumerate(b):
            ie=x%2+y%2;ve=(x//2)%3+(y//2)%3;we=x//6+y//6
            ve+=we//2;we%=2
            reductions=[(ie,1)] if ve<3 else [(ie,9),(ie+1,1)]
            ve%=3
            for ii,c in reductions:
                at=ii%2+2*ve+6*we
                out[at]=(out[at]+av*bv*c*(-1 if (ii//2)%2 else 1))%P
    return out

def expected():
    a=list(range(1,13));b=list(range(21,33))
    value=product(product(a,a),b)
    return b'OPDENSE0001'+keccak.new(digest_bits=256,data=b''.join(v.to_bytes(32,'little') for v in value)).digest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True);p.add_argument('--artifacts',type=Path,required=True)
    p.add_argument('--runner',type=Path,help='explicit retained OP-capable VM; identity recorded separately from the build reference')
    p.add_argument('--candidate',action='store_true');p.add_argument('--oracle',action='store_true')
    a=p.parse_args();a.artifacts.mkdir(parents=True,exist_ok=False)
    build=a.build.resolve();out=a.artifacts.resolve();elf=build/'guest.elf';payload=b'DENSE1';want=expected()
    native=subprocess.check_output([str(build/'host'),'pairing-dense-probe'],text=True,timeout=30).strip()
    if native!=want.hex():raise ValueError('native/independent tower mismatch')
    _,symbols,_=elf_info(elf)
    names=('input_start','input_end','halt_flag','output_len','output_data','output_end','stack_bottom','stack_top','heap_start','heap_end')
    inp=out/'probe.input';inp.write_bytes(payload)
    config={'elf':str(elf),'input':str(inp),'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),'input_sha256':hashlib.sha256(payload).hexdigest(),'expected_output':want.hex(),'max_steps':4_000_000,'engine':'fast','execution_profile':'ethereum_services_op_v1','symbols':{n:symbols['__'+n] for n in names}}
    request=out/'probe.config.json';request.write_text(json.dumps(config,indent=2)+'\n');prefix=out/'probe'
    runner=a.runner.resolve() if a.runner else build/'rv64-execution'
    resources=measured([str(runner),str(request)],prefix,60,os.environ.copy())
    run=json.loads(prefix.with_suffix('.stdout').read_text())
    if run['status']!='completed' or not run['verified_output'] or run['output']!=want.hex():raise ValueError('RV64 mismatch/incomplete')
    if run['op_sparse034_calls']!=(6 if a.candidate else 0):raise ValueError('unexpected sparse call count')
    if a.oracle:
        oracle=execute(config,run['instructions'],timeout=60,output_kind='pairing-dense-probe')
        if oracle['output']!=run['output'] or oracle['final_registers']!=run['final_registers'] or oracle['post_store_pc']!=run['pc']:raise ValueError('Unicorn state mismatch')
        for key,val in oracle['services'].items():
            native_key='keccak_sponge_calls' if key=='sponge_calls' else key
            if run[native_key]!=val:raise ValueError('Unicorn service mismatch '+key)
        (out/'oracle.json').write_text(json.dumps(oracle,indent=2)+'\n')
    (out/'receipt.json').write_text(json.dumps({'schema':'op-dense-fq12-probe-v1','scope':'square+multiply only, not heavy block execution or proving','security_qualified':False,'production_default_changed':False,'candidate':a.candidate,'elf_sha256':config['elf_sha256'],'runner_sha256':hashlib.sha256(runner.read_bytes()).hexdigest(),'runner':str(runner),'expected_output':want.hex(),'resources':resources,'execution':run,'independent_arithmetic':'Python schoolbook polynomial quotient ring','unicorn':a.oracle},indent=2)+'\n')
    print(run['instructions'],run['op_sparse034_calls'],run['curve_calls'],flush=True)
if __name__=='__main__':main()
