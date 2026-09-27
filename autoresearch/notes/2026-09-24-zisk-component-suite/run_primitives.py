from pathlib import Path
import ctypes as C,random,time,statistics,json,subprocess,sys,hashlib
H=Path(__file__).resolve().parent;sys.path.insert(0,str(H.parents[2]/'scripts'))
from zig_serial_build import build_lock
U=C.c_uint64;I=C.c_uint32;B=C.c_uint8
paths={'zisk':H/'rust-peer/target/release/libzisk_component_primitives.dylib','stwo':H/'local_primitives.dylib'}
libs={k:C.CDLL(str(p)) for k,p in paths.items()};prefix={'zisk':'peer','stwo':'local'}
for k,l in libs.items():
 for name,args,res in [('keccak',[C.POINTER(U)],None),('blake3',[C.POINTER(I),C.POINTER(I),U,I,I,C.POINTER(I)],None),('sha',[C.POINTER(B),I,C.POINTER(B)],None),('primitive_batch',[I,I,I],U)]:
  f=getattr(l,prefix[k]+'_'+name);f.argtypes=args;f.restype=res

def call(k,n,*a):return getattr(libs[k],prefix[k]+'_'+n)(*a)
def ac():
 s=subprocess.check_output(['pmset','-g','batt'],text=True)
 if "'AC Power'" not in s:raise RuntimeError(s)
 return s
rows=[]
with build_lock(label='zisk-primitives'):
 power=ac();rng=random.Random(198)
 for i in range(256):
  data=[rng.getrandbits(64) for _ in range(25)];out={k:(U*25)(*data) for k in libs}
  for k in libs:call(k,'keccak',out[k])
  assert list(out['zisk'])==list(out['stwo'])
  cv=(I*8)(*[rng.getrandbits(32) for _ in range(8)]);b=(I*16)(*[rng.getrandbits(32) for _ in range(16)]);counter=rng.getrandbits(64);out={k:(I*16)() for k in libs}
  for k in libs:call(k,'blake3',cv,b,counter,i%65,i%128,out[k])
  assert list(out['zisk'])==list(out['stwo'])
 for n in (0,1,55,56,63,64,65,1024,65536):
  data=rng.randbytes(n);buf=(B*max(n,1))(*data);out={k:(B*32)() for k in libs}
  for k in libs:call(k,'sha',buf,n,out[k]);assert bytes(out[k])==hashlib.sha256(data).digest()
 for op,n,name in [(0,200,'keccak_f1600'),(1,64,'sha256'),(1,1024,'sha256'),(1,65536,'sha256'),(2,64,'zisk_rust_blake3_compression')]:
  rounds=1
  while True:
   t=time.perf_counter_ns();call('zisk','primitive_batch',op,n,rounds);dt=time.perf_counter_ns()-t
   if dt>=80_000_000 or rounds>=1<<22:break
   rounds*=2
  expected={k:call(k,'primitive_batch',op,n,rounds) for k in libs};assert expected['zisk']==expected['stwo']
  samples=[]
  for k in ('zisk','stwo','stwo','zisk','stwo','zisk','zisk','stwo'):
   t=time.perf_counter_ns();v=call(k,'primitive_batch',op,n,rounds);dt=time.perf_counter_ns()-t;assert v==expected[k]
   samples.append(dict(arm=k,elapsed_ns=dt,ns_per_call=dt/rounds,checksum=v))
  row=dict(name=name,input_bytes=n,rounds=rounds,samples=samples,median_ns={k:statistics.median(s['ns_per_call'] for s in samples if s['arm']==k) for k in libs});rows.append(row)
  (H/'primitive-results.json').write_text(json.dumps(rows,indent=2)+'\n');print(name,n,row['median_ns'],flush=True);ac()
 (H/'primitive-qualification.json').write_text(json.dumps(dict(power_before=power,power_after=ac(),parity=dict(keccak=256,blake3=256,sha256=9),binaries={k:hashlib.sha256(p.read_bytes()).hexdigest() for k,p in paths.items()}),indent=2)+'\n')
