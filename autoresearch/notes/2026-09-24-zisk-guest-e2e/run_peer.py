from pathlib import Path
import hashlib,json,os,signal,subprocess,sys,time
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
n=int(sys.argv[1]) if len(sys.argv)>1 else 4096
tag='-'+sys.argv[2] if len(sys.argv)>2 else ''
if any((H/f'peer-{n}{tag}.{ext}').exists() for ext in ('proof','json')): raise SystemExit('Retained peer result exists; provide a new run label.')
b=Path('/tmp/stwo-zisk-guest-e2e-20260924/target/release/zisk-large-guest-benchmark');elf=H/'guest-zisk/target/riscv64ima-zisk-zkvm-elf/release/sha256-chain-peer-guest'
env=os.environ.copy();env['RAYON_NUM_THREADS']='16';env['OMP_NUM_THREADS']='16'
cmd=['/usr/bin/time','-l',str(b),str(elf),str(n),'/tmp/stwo-zisk-guest-e2e-20260924/provingKey',str(H/f'peer-{n}{tag}.proof'),str(H/f'peer-{n}{tag}.json')]
m={'command':cmd,'binary_sha256':hashlib.sha256(b.read_bytes()).hexdigest(),'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),'requested_rayon_threads':16,'requested_omp_threads':16,'timeout_seconds':600}
with build_lock(label='peer-full-guest-proof'):
 m['power_before']=subprocess.check_output(['pmset','-g','batt'],text=True);t=time.monotonic()
 with (H/f'peer-proof-{n}{tag}.log').open('w') as f:
  process=subprocess.Popen(cmd,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
  try:m['exit_code']=process.wait(timeout=600)
  except subprocess.TimeoutExpired:
   os.killpg(process.pid,signal.SIGKILL);process.wait();m['timed_out']=True
 if m.get('exit_code')==0:
  result=json.loads((H/f'peer-{n}{tag}.json').read_text());expected=bytes(32)
  for _ in range(n):expected=hashlib.sha256(expected).digest()
  actual=bytes(result['output_bytes'])
  assert result['verified'] and result['aggregation']
  assert actual[:32]==expected and actual[32:]==n.to_bytes(4,'little')
  m['independent_public_output_check']=True
 m['wall_seconds']=time.monotonic()-t;m['power_after']=subprocess.check_output(['pmset','-g','batt'],text=True)
 (H/f'peer-proof-{n}{tag}.invocation.json').write_text(json.dumps(m,indent=2)+'\n');print(json.dumps(m),flush=True)
