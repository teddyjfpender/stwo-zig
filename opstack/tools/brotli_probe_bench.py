#!/usr/bin/env python3
"""Bounded RV64 Brotli probes; a diagnostic BP output is never OP acceptance."""
import argparse, hashlib, json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from opstack.cpu import measured
from opstack.oracle import execute
from scripts.riscv64_csp_compare import elf_info

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True);p.add_argument('--artifacts',type=Path,required=True)
    p.add_argument('--max-steps',type=int,default=4_000_000);p.add_argument('--oracle',action='store_true')
    p.add_argument('--first-only',action='store_true')
    a=p.parse_args()
    if not 1<=a.max_steps<=4_000_000:p.error('max-steps must be within 1..4000000')
    a.artifacts.mkdir(parents=True,exist_ok=False)
    build=a.build.resolve(); out=a.artifacts.resolve(); elf=build/'guest.elf'
    _,syms,_=elf_info(elf)
    names=('input_start','input_end','halt_flag','output_len','output_data','output_end','stack_bottom','stack_top','heap_start','heap_end')
    compressed=bytes.fromhex('8b048075ed184249e9bc19675e03'); decoded=bytes.fromhex('75ed184249e9bc19675e')
    records=[]
    for name,cap,data,want,accepted in [('golden',1000,compressed,decoded,1),('cap-five',5,compressed,decoded[:5],1),('malformed',1000,b'\xff',b'',0)]:
        payload=b'BRP1'+cap.to_bytes(4,'little')+data
        expected=hashlib.sha256(want).digest()+b'BRP1'+bytes([accepted])+len(want).to_bytes(4,'little')+b'BP'
        prefix=out/name; inp=prefix.with_suffix('.input');inp.write_bytes(payload)
        native=subprocess.check_output([str(build/'host'),'brotli-probe',str(inp)],timeout=30,text=True).strip()
        if native!=expected.hex():raise ValueError('native/independent golden mismatch')
        config={'elf':str(elf),'input':str(inp),'expected_output':expected.hex(),'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),'input_sha256':hashlib.sha256(payload).hexdigest(),'max_steps':a.max_steps,'engine':'fast','execution_profile':'ethereum_services_v3','symbols':{n:syms['__'+n] for n in names}}
        request=prefix.with_suffix('.config.json');request.write_text(json.dumps(config,indent=2)+'\n')
        resource=measured([str(build/'rv64-execution'),str(request)],prefix,60,os.environ.copy())
        run=json.loads(prefix.with_suffix('.stdout').read_text())
        if run['status']=='completed':
            if not run['verified_output'] or run['output']!=expected.hex():raise ValueError('RV64 output mismatch')
            if a.oracle:
                independent=execute(config,run['instructions'],timeout=60,output_kind='brotli-probe')
                if independent['output']!=run['output'] or independent['final_registers']!=run['final_registers'] or independent['post_store_pc']!=run['pc']:raise ValueError('independent Unicorn mismatch')
                prefix.with_suffix('.oracle.json').write_text(json.dumps(independent,indent=2)+'\n')
        elif run['status']!='step_limit':raise ValueError('unexpected execution failure')
        records.append({'case':name,'resources':resource,'execution':run})
        (out/'receipt.json').write_text(json.dumps({'schema':'op-brotli-rv64-probes-v1','scope':'bounded isolated diagnostic, not whole transition execution/proving','elf_sha256':config['elf_sha256'],'max_steps':a.max_steps,'records':records},indent=2)+'\n')
        print(name,run['status'],run['instructions'],flush=True)
        if a.first_only:break
if __name__=='__main__':main()
