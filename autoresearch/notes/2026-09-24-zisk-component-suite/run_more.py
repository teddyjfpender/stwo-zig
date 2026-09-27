from pathlib import Path
import ctypes as C,random,time,statistics,json,subprocess,sys,hashlib
H=Path(__file__).resolve().parent;sys.path.insert(0,str(H.parents[2]/'scripts'))
from zig_serial_build import build_lock
U=C.c_uint64;I=C.c_uint32;P=C.c_void_p;A=U*4
libs={k:C.CDLL(str(H/(v+'_more.dylib'))) for k,v in [('zisk','peer'),('stwo','local')]};prefix={'zisk':'peer','stwo':'local'}
for k,l in libs.items():
 for name,args,res in [('ext',[I,C.POINTER(U),C.POINTER(U),C.POINTER(U)],None),('ext_batch',[I,I],U),('more_create',[I,I],P),('more_destroy',[P],None),('more_run',[P,I,I,C.POINTER(U)],U),('native_batch',[I,I],U)]:
  f=getattr(l,prefix[k]+'_'+name);f.argtypes=args;f.restype=res

def call(k,n,*a):return getattr(libs[k],prefix[k]+'_'+n)(*a)
def ac():
 s=subprocess.check_output(['pmset','-g','batt'],text=True)
 if "'AC Power'" not in s:raise RuntimeError(s)
 return s
rows=[]
def measure(name,fn,extra,equal=False):
 rounds=1
 while True:
  t=time.perf_counter_ns();fn('zisk',rounds);dt=time.perf_counter_ns()-t
  if dt>=60_000_000 or rounds>=1<<22:break
  rounds*=2
 expected={k:fn(k,rounds) for k in libs}
 if equal:assert expected['zisk']==expected['stwo'],(name,expected)
 samples=[]
 for k in ('zisk','stwo','stwo','zisk','stwo','zisk','zisk','stwo'):
  t=time.perf_counter_ns();v=fn(k,rounds);dt=time.perf_counter_ns()-t;assert v==expected[k]
  samples.append(dict(arm=k,elapsed_ns=dt,ns_per_call=dt/rounds,checksum=v))
 row=dict(name=name,rounds=rounds,samples=samples,median_ns={k:statistics.median(s['ns_per_call'] for s in samples if s['arm']==k) for k in libs},**extra);rows.append(row)
 (H/'more-results.json').write_text(json.dumps(rows,indent=2)+'\n');print(name,extra,row['median_ns'],flush=True);ac()

def mul(k,a,b,p):
 if k=='zisk':
  c=[0]*5
  for i in range(3):
   for j in range(3):c[i+j]+=a[i]*b[j]
  for i in (4,3):c[i-2]+=c[i];c[i-3]+=c[i]
  return [v%p for v in c[:3]]+[0]
 def cm(x,y):return (x[0]*y[0]-x[1]*y[1],x[0]*y[1]+x[1]*y[0])
 ac=cm(a[:2],b[:2]);bd=cm(a[2:],b[2:]);rbd=cm(bd,(2,1));ad=cm(a[:2],b[2:]);bc=cm(a[2:],b[:2])
 return [(ac[0]+rbd[0])%p,(ac[1]+rbd[1])%p,(ad[0]+bc[0])%p,(ad[1]+bc[1])%p]
with build_lock(label='zisk-more'):
 power=ac();rng=random.Random(198);checks=0
 for k,p,degree in [('zisk',2**64-2**32+1,3),('stwo',2**31-1,4)]:
  for _ in range(512):
   a=[rng.randrange(1,p) for _ in range(degree)]+[0]*(4-degree);b=[rng.randrange(p) for _ in range(degree)]+[0]*(4-degree)
   for op in (0,1,2):
    out=A();call(k,'ext',op,A(*a),A(*b),out)
    if op==0:assert list(out)==[(x+y)%p for x,y in zip(a,b)]
    elif op==1:assert list(out)==mul(k,a,b,p)
    else:assert mul(k,a,list(out),p)==[1,0,0,0]
    checks+=1
 for op,name in enumerate(['extension_add','extension_mul','extension_inv']):measure(name,lambda k,r:call(k,'ext_batch',op,r),dict(comparison='goldilocks_cubic_vs_m31_quartic'))
 for n,cols in [(1024,8),(16384,8),(262144,8),(16384,64)]:
  ctx={k:call(k,'more_create',n,cols) for k in libs};roots={k:A() for k in libs}
  try:
   for k in libs:call(k,'more_run',ctx[k],1,1,roots[k])
   assert list(roots['zisk'])==list(roots['stwo']),('root',n,cols)
   if cols==8:measure('batch_inverse',lambda k,r:call(k,'more_run',ctx[k],0,r,roots[k]),dict(n=n,comparison='different_base_fields',setup_included=False))
   measure('binary_merkle_canonical_words',lambda k,r:call(k,'more_run',ctx[k],1,r,roots[k]),dict(n=n,input_words_per_leaf=cols,comparison='identical_protocol_peer_production_tree_local_research_tree',workers=1,setup_included=False),True)
  finally:
   for k in libs:call(k,'more_destroy',ctx[k])
 for op,name in enumerate(['native_node_hash','native_leaf_64_payload_bytes']):measure(name,lambda k,r:call(k,'native_batch',op,r),dict(comparison='different_protocol_framing_and_inputs'))
 (H/'more-qualification.json').write_text(json.dumps(dict(power_before=power,power_after=ac(),extension_oracle_checks=checks,merkle_root_parity_cases=4,binaries={k:hashlib.sha256((H/(v+'_more.dylib')).read_bytes()).hexdigest() for k,v in [('zisk','peer'),('stwo','local')]}),indent=2)+'\n')
