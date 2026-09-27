from pathlib import Path
import argparse,subprocess,sys,time,json,hashlib,os
H=Path(__file__).resolve().parent;R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
p=argparse.ArgumentParser();p.add_argument('--index',type=int,default=0);p.add_argument('--cycles',type=int,default=32768);p.add_argument('--stride',type=int,default=262144);args=p.parse_args()
if args.index<0 or args.cycles<=0 or args.stride<=0: p.error('index must be nonnegative and cycles positive')
stem=f'leaf-cached-window-{args.index}-{args.cycles}-{args.stride}'
with build_lock(label='ethereum-paired-memory-block-leaf'):
 paths=[H/'block-leaf-cached',H/'ethereum-block.elf',H/'fixture/stwo-runner-input.bin']
 identity={str(p.relative_to(H)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
 env=os.environ.copy();env.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_BLAKE3_WITNESS_PROFILE='1')
 started=time.monotonic()
 with (H/(stem+'.log')).open('x') as log:
  result=subprocess.run(['/usr/bin/time','-l',*[str(p) for p in paths],str(args.cycles),str(H/(stem+'.proof')),str(H/(stem+'.json')),str(args.index),str(args.stride)],cwd=R,env=env,stdout=log,stderr=subprocess.STDOUT)
 (H/(stem+'-invocation.json')).write_text(json.dumps({'exit_code':result.returncode,'wall_seconds':time.monotonic()-started,'segment_index':args.index,'cycles':args.cycles,'stride':args.stride,'sha256':identity},indent=2)+'\n')
 sys.exit(result.returncode)
