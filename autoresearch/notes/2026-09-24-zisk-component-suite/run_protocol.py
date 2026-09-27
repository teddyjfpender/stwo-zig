from pathlib import Path
import ctypes as C,time,statistics,json,subprocess,sys,hashlib,random
H=Path(__file__).resolve().parent;sys.path.insert(0,str(H.parents[2]/'scripts'))
from zig_serial_build import build_lock
allow_battery="--allow-battery" in sys.argv
O=H/"battery-protocol" if allow_battery else H
O.mkdir(exist_ok=True)
power_source=None
U=C.c_uint64;I=C.c_uint32;A=U*96
libs={k:C.CDLL(str(H/(v+'_protocol.dylib'))) for k,v in [('zisk','peer'),('stwo','local')]};prefix={'zisk':'peer','stwo':'local'}
for k,l in libs.items():
 for name,args,res in [('protocol_batch',[I,I,I],U),('transcript_case',[C.POINTER(U),I,I,C.POINTER(U)],None)]:
  f=getattr(l,prefix[k]+'_'+name);f.argtypes=args;f.restype=res
libs['stwo'].local_pow_case.argtypes=[U,I,U];libs['stwo'].local_pow_case.restype=I
libs['stwo'].local_pow_valid.argtypes=[U,I,U];libs['stwo'].local_pow_valid.restype=C.c_bool
libs['zisk'].peer_grind_case.argtypes=[U,I];libs['zisk'].peer_grind_case.restype=U
oracle=C.CDLL(str(H/'local.dylib'));oracle.local_hash.argtypes=[C.POINTER(U),I,C.POINTER(U),I]
def ac():
 global power_source
 s=subprocess.check_output(['pmset','-g','batt'],text=True)
 source="AC" if "'AC Power'" in s else "battery"
 if source!="AC" and not allow_battery:raise RuntimeError(s)
 if power_source is not None and source!=power_source:raise RuntimeError("Power source changed during run: "+s)
 power_source=source
 return s
def call(k,n,*a):return getattr(libs[k],prefix[k]+'_'+n)(*a)
rows=[]
with build_lock(label='zisk-protocol'):
 qualify_only="--qualify-only" in sys.argv
 power=subprocess.check_output(["pmset","-g","batt"],text=True) if qualify_only else ac();rng=random.Random(198);checks=0
 if not qualify_only:(O/"protocol-qualification.json").unlink(missing_ok=True)
 for n in (0,1,8,9,128,129,4096):
  data=(U*max(1,n))(*[rng.getrandbits(64) for _ in range(max(1,n))])
  for draws in (1,2,3,8,32):
   out={k:A() for k in libs}
   for k in libs:call(k,'transcript_case',data,n,draws,out[k])
   assert list(out['zisk'])==list(out['stwo']);checks+=1
 for i in range(1024):
  seed=rng.getrandbits(64);nonce=rng.getrandbits(64);bits=i%27;word=libs['stwo'].local_pow_case(seed,bits,nonce)
  assert libs['stwo'].local_pow_valid(seed,bits,nonce)==((word&((1<<bits)-1))==0)
 grinding=[]
 for seed in (17,29,41,53):
  t=time.perf_counter_ns();nonce=libs['zisk'].peer_grind_case(seed,12);dt=time.perf_counter_ns()-t;out=(U*8)()
  for i in range(nonce+1):
   oracle.local_hash((U*8)(seed,29,41,i,0,0,0,0),8,out,2)
   assert (out[0]<1<<(64-12))==(i==nonce)
  grinding.append(dict(seed=seed,bits=12,nonce=nonce,attempts=nonce+1,elapsed_ns=dt))
 (O/'protocol-preflight.json').write_text(json.dumps(dict(power=power,canonical_xof_cases=checks,pow_scalar_batch_checks=1024,peer_grinding_checks=grinding,timing_accepted=False),indent=2)+'\n')
 if qualify_only:
  print('PASS: 35 transcript XOF, 1024 scalar/batch PoW, 4 minimum-nonce checks; no accepted timings',flush=True)
  sys.exit(0)
 for op,n,name in [(0,8,'native_transcript_absorb_draw8'),(0,128,'native_transcript_absorb_draw8'),(0,4096,'native_transcript_absorb_draw8'),(1,8,'native_pow_candidate')]:
  rounds=1
  while True:
   t=time.perf_counter_ns();call('zisk','protocol_batch',op,n,rounds);dt=time.perf_counter_ns()-t
   if dt>=70_000_000 or rounds>=1<<22:break
   rounds*=2
  expected={k:call(k,'protocol_batch',op,n,rounds) for k in libs};samples=[]
  for k in ('zisk','stwo','stwo','zisk','stwo','zisk','zisk','stwo'):
   t=time.perf_counter_ns();v=call(k,'protocol_batch',op,n,rounds);dt=time.perf_counter_ns()-t;assert v==expected[k]
   samples.append(dict(arm=k,elapsed_ns=dt,ns_per_call=dt/rounds,checksum=v))
  row=dict(name=name,input_bytes=n*8,rounds=rounds,comparison='different_native_protocols',power_source=power_source,samples=samples,median_ns={k:statistics.median(s['ns_per_call'] for s in samples if s['arm']==k) for k in libs});rows.append(row);(O/'protocol-results.json').write_text(json.dumps(rows,indent=2)+'\n');print(name,n,row['median_ns'],flush=True);ac()
 (O/'protocol-qualification.json').write_text(json.dumps(dict(power_before=power,power_after=ac(),power_source=power_source,canonical_xof_cases=checks,pow_scalar_batch_checks=1024,peer_grinding_checks=grinding,binaries={k:hashlib.sha256((H/(v+'_protocol.dylib')).read_bytes()).hexdigest() for k,v in [('zisk','peer'),('stwo','local')]}),indent=2)+'\n')
