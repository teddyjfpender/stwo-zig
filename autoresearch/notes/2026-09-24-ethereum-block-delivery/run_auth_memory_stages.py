from pathlib import Path
import subprocess,sys,time,json,hashlib,argparse
H=Path(__file__).resolve().parent;R=H.parents[2];M=H.parent/'2026-09-24-recursive-memory'
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
parser=argparse.ArgumentParser()
parser.add_argument('--batch', type=int, choices=(1,16,32,64), default=64)
batch=parser.parse_args().batch
stem=f'auth-{batch}-memory-stages'
with build_lock(label='ethereum-auth-subtree-qualification'):
 paths=[H/'auth-host-memory-stages',M/'eth-auth-stwo-expanded.elf',M/f'fixtures/batch-{batch}.input',M/f'fixtures/batch-{batch}.expected']
 identity={str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
 started=time.monotonic()
 with (H/(stem+'.log')).open('x') as log:
  result=subprocess.run(['/usr/bin/time','-l',*[str(p) for p in paths],str(H/(stem+'.proof')),str(H/(stem+'.json')),'prove'],cwd=R,stdout=log,stderr=subprocess.STDOUT)
 (H/(stem+'-invocation.json')).write_text(json.dumps({'exit_code':result.returncode,'wall_seconds':time.monotonic()-started,'sha256':identity},indent=2)+'\n')
 sys.exit(result.returncode)
