import os,subprocess,json,hashlib
from pathlib import Path
binary=Path('.zig-cache/products/riscv_cpu/o/db41c74139017da775a0bd3c4a8fad73/test').resolve()
p=Path('autoresearch/notes/2026-09-23-blake3-parent-stage-profile')
runs=[]
for name,serial in [('serial-1',True),('serial-2',True),('parallel-2',False)]:
 env=os.environ.copy();env['STWO_RISCV_RECURSIVE_PARENT_PROFILE']='1';env.pop('STWO_RISCV_SERIAL_PARENT_LOOKUPS',None)
 if serial:env['STWO_RISCV_SERIAL_PARENT_LOOKUPS']='1'
 with (p/(name+'.log')).open('w') as f:r=subprocess.run([str(binary)],env=env,stdout=f,stderr=subprocess.STDOUT)
 runs.append({'name':name,'serial_lookup_counts':serial,'exit_code':r.returncode,'executable':str(binary),'executable_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
 (p/'runs.json').write_text(json.dumps(runs,indent=2)+'\n')
 print(name,'exit',r.returncode,flush=True)
 if r.returncode:raise SystemExit(r.returncode)
