from pathlib import Path
import ctypes as C,os,sys,time,json,statistics,subprocess,hashlib
H=Path(__file__).resolve().parent;sys.path.insert(0,str(H.parents[2]/'scripts'))
from zig_serial_build import build_lock
os.environ['STWO_ZIG_MERKLE_WORKERS']='1'
paths={'before':H.parent/'2026-09-24-zisk-system-stages/candidate3-pipeline.dylib','after':H/'optimization/native-after.dylib'}
libs={k:C.CDLL(str(p)) for k,p in paths.items()}
for l in libs.values():
 l.local_pipeline.argtypes=[C.c_uint32]*4+[C.c_void_p]*2;l.local_pipeline.restype=C.c_uint64
out={'binaries':{k:hashlib.sha256(p.read_bytes()).hexdigest() for k,p in paths.items()},'power':subprocess.check_output(['pmset','-g','batt'],text=True),'cases':[]}
with build_lock(label='native-framed-commitment-comparison'):
 for log,width in ((10,8),(14,8),(16,8),(14,64)):
  samples={k:[] for k in libs};roots={}
  for rep in range(8):
   for k in (('before','after') if rep%2==0 else ('after','before')):
    stages=(C.c_uint64*2)();root=C.create_string_buffer(32)
    t=time.perf_counter_ns();checksum=libs[k].local_pipeline(log,width,1,0,stages,root);elapsed=time.perf_counter_ns()-t
    assert checksum != 2**64-1
    roots[k]=root.raw
    if rep:samples[k].append({'total_ns':elapsed,'lde_ns':stages[0],'commit_ns':stages[1]})
  assert roots['before']==roots['after']
  case={'input_rows':1<<log,'width':width,'root':roots['after'].hex(),'samples':samples,'median_ms':{k:{s:statistics.median(x[s] for x in v)/1e6 for s in v[0]} for k,v in samples.items()}}
  out['cases'].append(case);print(case['input_rows'],width,case['median_ms'],flush=True)
 (H/'optimization/native-results.json').write_text(json.dumps(out,indent=2)+'\n')
