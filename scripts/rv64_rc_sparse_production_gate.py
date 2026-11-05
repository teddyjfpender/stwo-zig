#!/usr/bin/env python3
"""Bounded existing-dev proof gate for selected sparse Keccak role.
Two profiles remain separate; accepted controls are pinned explicitly.
"""
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path
import rv64_m3_pod as P
import rv64_resident_basket as R

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--profile',choices=['d2','m6'],required=True);ap.add_argument('--block',type=int,choices=[26235156,24628607],required=True);ap.add_argument('--repeat',type=int,default=2);a=ap.parse_args()
 root=Path('/workspace/m3/src/m7-rc-sparse');out=Path('/workspace/m3/runs/m7-rc-sparse');build=Path('/workspace/m3/build/m7-rc-sparse');out.mkdir(exist_ok=True)
 refroot=Path('/workspace/m3/runs/m7-device-fs-p2');name=f'{a.block}'+('' if a.profile=='d2' else '-m6')+'-command.json';cmd=json.loads((refroot/name).read_text());cmd[1]=str(root/'scripts/rv64_m4_resident.py')
 def option(flag,value):
  if flag in cmd:cmd[cmd.index(flag)+1]=str(value)
  else:cmd.extend([flag,str(value)])
 option('--stream','m7-rc-sparse');option('--build-stream','m7-rc-sparse');option('--repeat',a.repeat);option('--tag',f'sparse-{a.profile}-22g');option('--driver',build/'rv64-word16-ethereum-gpu-combined')
 env={};index=0
 while index<len(cmd):
  if cmd[index]=='--env':key,value=cmd[index+1].split('=',1);env[key]=value;del cmd[index:index+2]
  else:index+=1
 env.update(STWO_RV64_TRUTH_SPARSE_RC='1',STWO_RV64_TRUTH_SPARSE_LIBRARY=str(build/'libstwo-rc-sparse.so'),STWO_RV64_DEVICE_ARENA='22G',STWO_RV64_GLOBAL_ADMISSION='0',STWO_RV64_RECURSION_LANES_PER_DEVICE='1',STWO_RV64_OUTER_DEVICE_FS='0')
 for k,v in sorted(env.items()):cmd+=['--env',k+'='+v]
 frozen={'driver_sha256':P.sha(build/'rv64-word16-ethereum-gpu-combined'),'addon_sha256':P.sha(build/'libstwo-rc-sparse.so'),'base_sha256':P.sha('/workspace/m3/build/m7-combined-residency/cuda/native/libstwo-rv64-native.so'),'command':cmd}
 (out/f'{a.block}-{a.profile}-command.json').write_text(json.dumps(frozen,indent=2)+'\n')
 with (out/f'{a.block}-{a.profile}-gate.log').open('w') as log:result=subprocess.run(cmd,cwd=root,stdout=log,stderr=subprocess.STDOUT)
 if result.returncode:raise SystemExit(result.returncode)
 run=out/f'daemon-{a.block}-r{a.repeat}-sparse-{a.profile}-22g';receipt=json.loads((run/'receipt.json').read_text());tag='outer-device-fs-rc-check' if a.profile=='d2' else 'outer-device-fs-rc-m6-check';repeats=2 if a.profile=='d2' else 1
 ref=refroot/f'daemon-{a.block}-r{repeats}-{tag}'/'receipt.json';control=json.loads(ref.read_text());assert control['all_received']
 def snap(request):
  proof=Path(request['proof']);return {'native':{p.name:P.sha(p) for p in sorted(proof.glob('*.bin'))},'bundle':P.sha(proof/'bundle.json'),'recursive':R.recursive_snapshot(proof,request['leaves'])}
 expected=snap(control['requests'][0]);checks=[]
 for request in receipt['requests']:
  actual=snap(request);checks.append({'trial':request['trial'],'byte_identical':actual==expected,'proof_sha256':actual,'stages':request['stages']})
 received=receipt['all_received'];coverage=sum(1 for line in (run/'producer.stderr').read_text().splitlines() if line.startswith('GPU_RC_SPARSE_COMPLETE'))
 assert coverage==a.repeat,(coverage,a.repeat)
 final={'schema':'rv64-rc-sparse-production-gate/v1','profile':a.profile,'block':a.block,'run':str(run),'reference':str(ref),'reference_receipt_sha256':P.sha(ref),'assets':frozen,'sparse_role_calls':coverage,'checks':checks,'all_byte_identical':all(x['byte_identical'] for x in checks),'all_received':received,'receivers':receipt['receivers'],'memory_scope':'arena22GiB;exactwholeprocesspeaknotyetqualified','two_lanes':False}
 (out/f'{a.block}-{a.profile}-qualification.json').write_text(json.dumps(final,indent=2)+'\n');print(json.dumps({k:final[k] for k in ('profile','block','sparse_role_calls','all_byte_identical','all_received')}),flush=True)
 if not final['all_byte_identical'] or not received:raise SystemExit(1)
if __name__=='__main__':main()
