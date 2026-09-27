from pathlib import Path
import ctypes as C, random,time,statistics,json,subprocess,sys,hashlib
H=Path(__file__).resolve().parent;sys.path.insert(0,str(H.parents[2]/'scripts'))
from zig_serial_build import build_lock
U=C.c_uint64;I=C.c_uint32;P=C.c_void_p
libs={k:C.CDLL(str(H/(v+'_stages.dylib'))) for k,v in [('zisk','peer'),('stwo','local')]};prefix={'zisk':'peer','stwo':'local'}
for k,l in libs.items():
 for name,args,res in [('field',[I,U,U],U),('field_batch',[I,I],U),('transform_create',[I],P),('transform_destroy',[P],None),('transform_run',[P,I,I],U)]:
  f=getattr(l,prefix[k]+'_'+name);f.argtypes=args;f.restype=res

def call(k,n,*args):return getattr(libs[k],prefix[k]+'_'+n)(*args)
def ac():
 s=subprocess.check_output(['pmset','-g','batt'],text=True)
 if "'AC Power'" not in s:raise RuntimeError(s)
 return s
rows=[]
def measure(name,run,extra):
 rounds=1
 while True:
  t=time.perf_counter_ns();run('zisk',rounds);dt=time.perf_counter_ns()-t
  if dt>=60_000_000 or rounds>=1<<24:break
  rounds*=2
 expected={k:run(k,rounds) for k in libs};samples=[]
 for k in ('zisk','stwo','stwo','zisk','stwo','zisk','zisk','stwo'):
  t=time.perf_counter_ns();v=run(k,rounds);dt=time.perf_counter_ns()-t
  assert v==expected[k] and v!=2**64-1,(name,k,v)
  samples.append(dict(arm=k,elapsed_ns=dt,ns_per_call=dt/rounds,checksum=v))
 row=dict(name=name,rounds=rounds,samples=samples,median_ns={k:statistics.median(s['ns_per_call'] for s in samples if s['arm']==k) for k in libs},**extra)
 rows.append(row);(H/'stage-results.json').write_text(json.dumps(rows,indent=2)+'\n');print(name,row['median_ns'],flush=True);ac()
with build_lock(label='zisk-stages'):
 power=ac();rng=random.Random(198);checks=0
 for k,mod in [('zisk',2**64-2**32+1),('stwo',2**31-1)]:
  for i in range(1000):
   a=rng.randrange(1,mod);b=rng.randrange(mod)
   for op,expect in enumerate(((a+b)%mod,a*b%mod,pow(a,-1,mod))):
    assert call(k,'field',op,a,b)==expect,(k,i,op);checks+=1
 for op,name in enumerate(['field_add','field_mul','field_inv']):measure(name,lambda k,r:call(k,'field_batch',op,r),dict(comparison='different_fields',pattern='dependent_recurrence' if op<2 else 'inverse_of_consecutive_nonzero_inputs'))
 setup=[]
 for log in (10,14,18):
  ctx={}
  for k in libs:
   t=time.perf_counter_ns();ctx[k]=call(k,'transform_create',log);setup.append(dict(arm=k,log_size=log,elapsed_ns=time.perf_counter_ns()-t))
   v=call(k,'transform_run',ctx[k],2,1);assert v==(2**log)*(2**log+1)//2,(k,log,v)
  try:
   for op,name in ((0,'forward_transform'),(1,'inverse_transform'),(3,'lde_2x')):measure(name,lambda k,r:call(k,'transform_run',ctx[k],op,r),dict(log_size=log,comparison='goldilocks_multiplicative_vs_m31_circle',workers=1,setup_included=False))
  finally:
   for k in libs:call(k,'transform_destroy',ctx[k])
 (H/'stage-qualification.json').write_text(json.dumps(dict(power_before=power,power_after=ac(),field_checks=checks,roundtrip_sizes=[1024,16384,262144],setup_samples=setup,binaries={k:hashlib.sha256((H/(v+'_stages.dylib')).read_bytes()).hexdigest() for k,v in [('zisk','peer'),('stwo','local')]}),indent=2)+'\n')
