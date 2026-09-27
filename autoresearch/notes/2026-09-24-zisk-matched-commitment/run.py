"""Matched commitment + 70 openings, then authentication, single CPU worker."""
import ctypes as C
import hashlib,json,os,platform,random,statistics,subprocess,sys,time
from pathlib import Path
H=Path(__file__).resolve().parent; R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
os.environ['STWO_ZIG_MERKLE_WORKERS']='1'
os.environ['STWO_ZIG_MERKLE_POOL_REUSE']='0'
libs={k:C.CDLL(str(H/(k+'.dylib'))) for k in ('local','peer')}
for lib in libs.values():
 lib.matched_commit.argtypes=[C.c_uint32,C.c_uint32]+[C.c_void_p]*4
 lib.matched_commit.restype=C.c_uint32
 lib.matched_verify.argtypes=[C.c_uint32,C.c_uint32]+[C.c_void_p]*3
 lib.matched_verify.restype=C.c_uint32
results={'host':platform.platform(),'power_before':subprocess.check_output(['pmset','-g','batt'],text=True),'workers':1,'samples':7,'binaries':{k:hashlib.sha256((H/(k+'.dylib')).read_bytes()).hexdigest() for k in libs},'cases':[]}
with build_lock(label='matched-commitment-benchmark'):
 for log,width in ((10,4),(16,4),(20,4),(16,32),(16,128)):
  n=1<<log
  # Uniform 64-bit words with values >= p replaced by zero. Same bytes both arms.
  raw=bytearray(random.Random(20260924+log).randbytes(n*width*8))
  words=memoryview(raw).cast('Q')
  for i,x in enumerate(words):
   if x>=0xffffffff00000001:words[i]=0
  inp=(C.c_ubyte*len(raw)).from_buffer(raw)
  buffers={k:(C.create_string_buffer((2*n-1)*32),C.create_string_buffer(70*log*32),C.create_string_buffer(32)) for k in libs}
  for k,lib in libs.items():
   nodes,paths,root=buffers[k]
   assert lib.matched_commit(log,width,inp,nodes,paths,root)==0
  assert buffers['local'][0].raw==buffers['peer'][0].raw,'node mismatch'
  assert buffers['local'][1].raw==buffers['peer'][1].raw,'path mismatch'
  assert buffers['local'][2].raw==buffers['peer'][2].raw,'root mismatch'
  for lib in libs.values():
   for _,paths,root in buffers.values():
    assert lib.matched_verify(log,width,inp,paths,root)==0
    paths[0]=bytes([paths.raw[0]^1])
    assert lib.matched_verify(log,width,inp,paths,root)!=0
    paths[0]=bytes([paths.raw[0]^1])
    root[0]=bytes([root.raw[0]^1])
    assert lib.matched_verify(log,width,inp,paths,root)!=0
    root[0]=bytes([root.raw[0]^1])
  samples={k:[] for k in libs}
  for sample in range(8): # first pair warms both arms, remaining seven retained
   for k in (('local','peer') if sample%2==0 else ('peer','local')):
    lib=libs[k];_,paths,root=buffers[k]
    t=time.perf_counter_ns();assert lib.matched_commit(log,width,inp,None,paths,root)==0
    t1=time.perf_counter_ns();assert lib.matched_verify(log,width,inp,paths,root)==0
    t2=time.perf_counter_ns()
    if sample:samples[k].append({'commit_open_ns':t1-t,'verify_ns':t2-t1,'total_ns':t2-t})
  case={'log_rows':log,'rows':n,'row_words':width,'input_bytes':len(raw),'input_sha256':hashlib.sha256(raw).hexdigest(),'root':buffers['local'][2].raw.hex(),'qualification':'all nodes and paths equal; both cross-verifiers accept; corrupted path/root rejected','samples':samples,'median_ms':{k:{stage:statistics.median(x[stage] for x in ss)/1e6 for stage in ss[0]} for k,ss in samples.items()}}
  results['cases'].append(case);print(json.dumps({k:v for k,v in case.items() if k!='samples'}),flush=True)
 results['power_after']=subprocess.check_output(['pmset','-g','batt'],text=True)
 (H/'results.json').write_text(json.dumps(results,indent=2)+'\n')
