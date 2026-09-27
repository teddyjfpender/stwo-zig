from pathlib import Path
import ctypes as C, random, time, statistics, json, subprocess, sys, hashlib
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from zig_serial_build import build_lock
u32=C.c_uint32;u64=C.c_uint64;u8=C.c_uint8
libs={k:C.CDLL(str(HERE/(v+'.dylib'))) for k,v in [('zisk','peer'),('stwo','local')]}
prefix={'zisk':'peer','stwo':'local'}
for k,lib in libs.items():
 for suffix,args,res in [('hash',[C.POINTER(u64),u32,C.POINTER(u64),u32],None),('compress_case',[C.POINTER(u32),C.POINTER(u32),u64,u8,u8,C.POINTER(u32)],None),('expand_case',[C.POINTER(u32),C.POINTER(u32),u32,u32,u32,C.POINTER(u32),C.POINTER(u64)],None),('batch',[u32,u32,u32],u64)]:
  f=getattr(lib,prefix[k]+'_'+suffix);f.argtypes=args;f.restype=res

def call(k,suffix,*args):return getattr(libs[k],prefix[k]+'_'+suffix)(*args)
def ac():
 s=subprocess.check_output(['pmset','-g','batt'],text=True)
 if "'AC Power'" not in s:raise RuntimeError(s)
 return s
sizes=[0,1,7,8,9,16,127,128,129,512,8192]
rng=random.Random(198)
with build_lock(label='zisk-components'):
 power_before=ac()
 # Hash parity covers canonical and noncanonical Goldilocks inputs and chunk edges.
 for n in sizes:
  data=(u64*max(1,n))(*[rng.getrandbits(64) if i%3 else 0xffffffffffffffff for i in range(max(1,n))])
  for op in (0,1):
   out={k:(u64*8)() for k in libs}
   for k in libs:call(k,'hash',data,n,out[k],op)
   assert list(out['zisk'])[:4 if op==0 else 8]==list(out['stwo'])[:4 if op==0 else 8],('hash',n,op)
 data=(u64*8)(*[rng.getrandbits(64) for _ in range(8)])
 out={k:(u64*8)() for k in libs}
 for k in libs:call(k,'hash',data,8,out[k],2)
 assert list(out['zisk'])==list(out['stwo'])
 for i in range(1024):
  cv=(u32*8)(*[rng.getrandbits(32) for _ in range(8)]);block=(u32*16)(*[rng.getrandbits(32) for _ in range(16)])
  counter=rng.getrandbits(64);length=i%65;flags=i%128
  out={k:(u32*16)() for k in libs}
  for k in libs:call(k,'compress_case',cv,block,counter,length,flags,out[k])
  assert list(out['zisk'])==list(out['stwo']),('compress',i)
  if i<128:
   expected=list(out['zisk'])
   # Peer recursion band only represents a 32-bit counter; compare that subset.
   for k in libs:call(k,'expand_case',cv,block,counter&0xffffffff,length,flags,out[k],C.byref(u64()))
   assert list(out['zisk'])==list(out['stwo']),('expand',i)
 print('PARITY hashes=23 compression=1024 witness_outputs=128 passed',flush=True)
 cases=[('hash_le64',0,n) for n in sizes]+[('stream_xof',1,n) for n in (0,8,128,129,4096)]+[('permute8',2,8),('compress_xof',3,8),('compression_witness',4,8)]
 results=[]
 for name,op,n in cases:
  rounds=16
  while True:
   t=time.perf_counter_ns();call('zisk','batch',op,n,rounds);elapsed=time.perf_counter_ns()-t
   if elapsed>100_000_000 or rounds>=1<<23:break
   rounds*=2
  checks={k:call(k,'batch',op,n,rounds) for k in libs}
  if op<4:assert checks['zisk']==checks['stwo'],(name,n,'batch')
  samples=[]
  for k in ('zisk','stwo','stwo','zisk','stwo','zisk','zisk','stwo'):
   t=time.perf_counter_ns();checksum=call(k,'batch',op,n,rounds);elapsed=time.perf_counter_ns()-t
   assert checksum==checks[k]
   samples.append(dict(arm=k,elapsed_ns=elapsed,ns_per_call=elapsed/rounds,checksum=checksum))
  ac()
  row=dict(name=name,input_words=n,rounds=rounds,comparison='identical_outputs_goldilocks_canonical_adapter' if op<3 else 'identical_raw_compression' if op==3 else 'different_witness_layout_and_work',samples=samples,median_ns={k:statistics.median(x['ns_per_call'] for x in samples if x['arm']==k) for k in libs})
  results.append(row);(HERE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
  print(name,n,row['median_ns'],flush=True)
 (HERE/'qualification.json').write_text(json.dumps(dict(power_before=power_before,power_after=ac(),parity=dict(hash_cases=23,raw_compressions=1024,witness_outputs=128),binaries={k:hashlib.sha256((HERE/(v+'.dylib')).read_bytes()).hexdigest() for k,v in [('zisk','peer'),('stwo','local')]}),indent=2)+'\n')
