from pathlib import Path
import ctypes as C,time,statistics,json,subprocess,sys,hashlib
H=Path(__file__).resolve().parent;sys.path.insert(0,str(H.parents[2]/'scripts'))
from zig_serial_build import build_lock
libs={k:C.CDLL(str(H/(v+'_fri.dylib'))) for k,v in [('zisk','peer'),('stwo','local')]};fs={k:getattr(l,('peer' if k=='zisk' else 'local')+'_fri_batch') for k,l in libs.items()}
for f in fs.values():f.argtypes=[C.c_uint32]*3;f.restype=C.c_uint64
rows=[]
def ac():
 s=subprocess.check_output(['pmset','-g','batt'],text=True)
 if "'AC Power'" not in s:raise RuntimeError(s)
 return s
with build_lock(label='zisk-fri'):
 power=ac()
 for log in (10,14,18):
  assert fs['zisk'](log,1,1)==(1<<log)//2*6
  assert fs['stwo'](log,1,1)==(1<<log)//2*20
  rounds=1
  while True:
   t=time.perf_counter_ns();fs['zisk'](log,rounds,0);dt=time.perf_counter_ns()-t
   if dt>=60_000_000:break
   rounds*=2
  expected={k:f(log,rounds,0) for k,f in fs.items()};samples=[]
  for k in ('zisk','stwo','stwo','zisk','stwo','zisk','zisk','stwo'):
   t=time.perf_counter_ns();v=fs[k](log,rounds,0);dt=time.perf_counter_ns()-t;assert v==expected[k]
   samples.append(dict(arm=k,elapsed_ns=dt,ns_per_call=dt/rounds,checksum=v))
  row=dict(name='fri_fold_2x',log_size=log,rounds=rounds,comparison='different_fields_domains_normalization_and_allocation',samples=samples,median_ns={k:statistics.median(s['ns_per_call'] for s in samples if s['arm']==k) for k in libs});rows.append(row);(H/'fri-results.json').write_text(json.dumps(rows,indent=2)+'\n');print(log,row['median_ns'],flush=True);ac()
 (H/'fri-qualification.json').write_text(json.dumps(dict(power_before=power,power_after=ac(),constant_fold_checks=6,binaries={k:hashlib.sha256((H/(v+'_fri.dylib')).read_bytes()).hexdigest() for k,v in [('zisk','peer'),('stwo','local')]}),indent=2)+'\n')
