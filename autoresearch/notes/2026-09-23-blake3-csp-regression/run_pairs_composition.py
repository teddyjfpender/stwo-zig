import json,os,subprocess
from pathlib import Path
p=Path(__file__).resolve().parent/'composition-cache'
p.mkdir(exist_ok=False)
runs=[]
for backend in ['cpu','metal']:
 for index,control in enumerate([True,False,False,True]):
  name=f'{backend}-'+('control' if control else 'candidate')+f'-{index}'
  env=os.environ.copy();env.pop('STWO_RISCV_METAL_AOT_BUNDLE',None);env['STWO_RISCV_EXECUTION_PROFILE']='1'
  for key in ['STWO_RISCV_SERIAL_PARENT_LOOKUPS','STWO_RISCV_NO_EXECUTION_COEFFICIENT_CACHE']:
   env.pop(key,None)
   if control:env[key]='1'
  cmd=[f'zig-out/bin/stwo-zig-riscv-{backend}','ecdsa-csp-bench','--elf','vectors/riscv_csp/guests/ecdsa_secp256k1_precompile_odd.elf','--input','vectors/riscv_csp/inputs/ecdsa_secp256k1.bin','--proof-out',str(p/f'{name}.b3proof'),'--report-out',str(p/f'{name}.json'),'--profile-out',str(p/f'{name}-phases.json'),'--warmups','0','--samples','1','--workers','16','--host-byte-budget','38654705664']
  with (p/f'{name}.log').open('w') as f:r=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT)
  runs.append({'name':name,'command':cmd,'control':control,'exit_code':r.returncode});(p/'pair-commands.json').write_text(json.dumps(runs,indent=2)+'\n')
  if r.returncode:raise SystemExit(f'{name}: exit {r.returncode}')
  report=json.loads((p/f'{name}.json').read_text());print(name,report['median_seconds'],report['proof_sha256'],flush=True)
