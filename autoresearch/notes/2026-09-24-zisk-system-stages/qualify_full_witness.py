from pathlib import Path
import json,subprocess,sys,shutil,ctypes as C,random,hashlib
H=Path(__file__).resolve().parent;R=H.parents[2];m=Path(json.loads((H/'proof-baseline-mirror.json').read_text())['path']);sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
rel=Path('src/frontends/riscv/zisk_system_benchmark.zig');shutil.copy2(R/rel,m/rel)
with build_lock(label='complete-witness-parity'):
 libs={}
 for arm,root in [('before',m),('after',R)]:
  binary=H/(arm+'-full-parity.dylib')
  subprocess.run(['/opt/homebrew/opt/zig@0.15/bin/zig','build-lib','-dynamic','-OReleaseFast','-mcpu=native','--dep','stwo_core','-Mroot='+str(root/rel),'-Mstwo_core='+str(root/'src/core/mod.zig'),'-femit-bin='+str(binary)],check=True)
  f=C.CDLL(str(binary)).system_slot_case;f.argtypes=[C.POINTER(C.c_uint64),C.POINTER(C.c_uint64),C.POINTER(C.c_uint8),C.POINTER(C.c_uint32)];libs[arm]=f
 rng=random.Random(198);n=29*(2+1600+320)
 for i in range(32):
  a=(C.c_uint64*25)(*[rng.getrandbits(64) for _ in range(25)]);b=(C.c_uint64*25)(*[rng.getrandbits(64) for _ in range(25)])
  output={k:((C.c_uint8*n)(),(C.c_uint32*9216)()) for k in libs}
  for k,f in libs.items():f(a,b,*output[k])
  assert bytes(output['before'][0])==bytes(output['after'][0]),('witness',i)
  assert list(output['before'][1])==list(output['after'][1]),('histogram',i)
 result=dict(paired_cases=32,witness_bytes_per_case=n,histogram_entries_per_case=9216,all_equal=True,binaries={arm:hashlib.sha256((H/(arm+'-full-parity.dylib')).read_bytes()).hexdigest() for arm in libs})
 (H/'full-witness-parity.json').write_text(json.dumps(result,indent=2)+'\n');print(result)
