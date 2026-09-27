from pathlib import Path
import subprocess,sys,time,json,hashlib,os
H=Path(__file__).resolve().parent;R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='ethereum-first-real-block-leaf'):
 paths=[H/'block-leaf',H/'ethereum-block.elf',H/'fixture/stwo-runner-input.bin']
 identity={str(p.relative_to(H)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
 env=os.environ.copy();env.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_BLAKE3_WITNESS_PROFILE='1')
 started=time.monotonic()
 with (H/'first-leaf.log').open('x') as log:
  result=subprocess.run(['/usr/bin/time','-l',*[str(p) for p in paths],'1048576',str(H/'first-leaf.proof'),str(H/'first-leaf.json')],cwd=R,env=env,stdout=log,stderr=subprocess.STDOUT)
 (H/'first-leaf-invocation.json').write_text(json.dumps({'exit_code':result.returncode,'wall_seconds':time.monotonic()-started,'sha256':identity},indent=2)+'\n')
 sys.exit(result.returncode)
