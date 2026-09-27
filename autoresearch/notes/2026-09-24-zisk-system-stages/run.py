from pathlib import Path
import ctypes as C,json,time,statistics,hashlib,subprocess,sys,random,os
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
I=C.c_uint32;U=C.c_uint64;B=C.c_uint8;P=C.POINTER
candidate=sys.argv[1] if len(sys.argv)>1 else "after"
serial="--serial-pipeline" in sys.argv
if serial:os.environ["STWO_ZIG_MERKLE_WORKERS"]="1"
O=H/(candidate+"-serial" if serial else candidate);O.mkdir(exist_ok=True)
old=H.parent/'2026-09-24-zisk-component-suite';libs={}
for arm in ('before','after'):
 for kind in ('system','protocol','pipeline'):
  l=C.CDLL(str(H/((candidate if arm=='after' else arm)+'-'+kind+'.dylib')));libs[arm,kind]=l
  if kind=='system':l.system_batch.argtypes=[I,I];l.system_batch.restype=U;l.system_trace.argtypes=[P(U),P(U)]
  elif kind=='protocol':l.local_protocol_batch.argtypes=[I,I,I];l.local_protocol_batch.restype=U
  else:l.local_pipeline.argtypes=[I,I,I,I,P(U),P(B)];l.local_pipeline.restype=U
peer=C.CDLL(str(H/'peer-pipeline.dylib'));peer.peer_pipeline.argtypes=[I,I,I,I,P(U),P(B)];peer.peer_pipeline.restype=U
proto=C.CDLL(str(old/'peer_protocol.dylib'));proto.peer_protocol_batch.argtypes=[I,I,I];proto.peer_protocol_batch.restype=U
primitive=C.CDLL(str(old/'rust-peer/target/release/libzisk_component_primitives.dylib'));primitive.peer_primitive_batch.argtypes=[I,I,I];primitive.peer_primitive_batch.restype=U;primitive.peer_keccak.argtypes=[P(U)]
results=[]
def power():return subprocess.check_output(['pmset','-g','batt'],text=True)
def measure(name,fn,arms,meta):
 rounds=1
 while True:
  t=time.perf_counter_ns();fn('before',rounds);dt=time.perf_counter_ns()-t
  if dt>=80_000_000 or rounds>=65536:break
  rounds*=2
 expected={k:fn(k,rounds) for k in arms};assert expected['before'][0]==expected['after'][0],name
 samples=[]
 for order in (arms,tuple(reversed(arms)),tuple(reversed(arms)),arms):
  for k in order:
   t=time.perf_counter_ns();v,stages=fn(k,rounds);dt=time.perf_counter_ns()-t;assert v==expected[k][0]
   samples.append(dict(arm=k,elapsed_ns=dt,ns_per_call=dt/rounds,checksum=v,stage_ns_per_call=[s/rounds for s in stages]))
 row=dict(name=name,rounds=rounds,samples=samples,median_ns={k:statistics.median(s['ns_per_call'] for s in samples if s['arm']==k) for k in arms},**meta)
 results.append(row);(O/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(name,meta,row['median_ns'],flush=True)
def pipeline(k,log,w,rounds,constant=0):
 t=(U*2)();root=(B*32)();f=peer.peer_pipeline if k=='zisk' else libs[k,'pipeline'].local_pipeline
 v=f(log,w,rounds,constant,t,root);assert v!=2**64-1
 return v,list(t)
with build_lock(label='zisk-system-stages'):
 start=power();rng=random.Random(198)
 for i in range(256):
  data=(U*25)(*[rng.getrandbits(64) for _ in range(25)]);traces={k:(U*625)() for k in ('before','after')}
  for k in traces:libs[k,'system'].system_trace(data,traces[k])
  assert list(traces['before'])==list(traces['after'])
  primitive.peer_keccak(data);assert list(data)==list(traces['after'])[600:]
 for op,name in enumerate(() if serial else ('keccak_permute','keccak_full_trace','keccak_paired_witness','keccak_paired_witness_validate_count')):
  def fn(k,r):return (primitive.peer_primitive_batch(0,200,r) if k=='zisk' else libs[k,'system'].system_batch(op,r)),[]
  measure(name,fn,('before','after','zisk') if op==0 else ('before','after'),dict(comparison='identical_output' if op<2 else 'same_local_complete_stage',calls_per_item=2 if op>=2 else 1))
 for n in (() if serial else (8,128,4096)):
  def fn(k,r):return (proto.peer_protocol_batch(0,n,r) if k=='zisk' else libs[k,'protocol'].local_protocol_batch(0,n,r)),[]
  measure('transcript_absorb_draw8',fn,('before','after','zisk'),dict(input_bytes=n*8,comparison='native_protocols_differ'))
 for log,w in ((10,8),(14,8),(16,8),(14,64)):
  for k in ('before','after','zisk'):pipeline(k,log,w,1,1)
  measure('lde_commit_pipeline',lambda k,r:pipeline(k,log,w,r),('before','after','zisk'),dict(input_rows=1<<log,columns=w,expansion=2,comparison='different_fields_native_protocols_and_layouts',stage_order=['lde','commit'],peer_workers=1,local_merkle_workers=1 if serial else 'automatic'))
 end=power();assert ("'AC Power'" in start)==("'AC Power'" in end),'power source changed'
 binaries={str(p.relative_to(H)):hashlib.sha256(p.read_bytes()).hexdigest() for p in H.glob('*.dylib')}
 (O/'qualification.json').write_text(json.dumps(dict(power_before=start,power_after=end,merkle_worker_override=os.environ.get("STWO_ZIG_MERKLE_WORKERS"),trace_parity_cases=256,trace_words_each=625,pipeline_constant_cases=12,identical_before_after_checksums=True,binaries=binaries),indent=2)+'\n')
