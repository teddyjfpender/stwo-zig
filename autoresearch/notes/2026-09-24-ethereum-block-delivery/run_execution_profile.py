from pathlib import Path
import subprocess,sys,hashlib,json,time
H=Path(__file__).resolve().parent;R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
with build_lock(label='ethereum-block-execution'):
 paths=[H/'block-execute-profile',H/'ethereum-block.elf',H/'fixture/stwo-runner-input.bin',H/'fixture/expected-output.bin']
 identity={str(p.relative_to(H)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
 started=time.monotonic()
 with (H/'execution-profile.log').open('x') as log:
  result=subprocess.run(['/usr/bin/time','-l',*[str(p) for p in paths],str(H/'execution-profile.json'),'262144',str(H/'execution-pc-counts.json')],cwd=R,stdout=log,stderr=subprocess.STDOUT)
 (H/'execution-profile-invocation.json').write_text(json.dumps({'exit_code':result.returncode,'wall_seconds':time.monotonic()-started,'sha256':identity},indent=2)+'\n')
 sys.exit(result.returncode)
