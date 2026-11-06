from pathlib import Path
import sys,json,time,os,fcntl,subprocess,ctypes as C,shutil
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'));import rv64_m7_integration_stack as S;import rv64_m3_pod as P
b=Path('/workspace/m3/runs/m7-integrate');out=b/'p1-compact-state-preflight-20261106-04';prior=b/'p1-compact-state-preflight-20261106-02'
old=json.loads((prior/'preflight.json').read_text())
d={'status':'RUNNING','source_commit':'26a15d9515a654ecd5ce6824417bde6f943ac4fb+compact-state-v1','source_sha256':old['source_sha256'],'prior':str(prior),'reason':'All compile stages passed; final link failed ENOSPC on workspace. Link exact successful objects in tmp, directly with canonical SONAME, avoiding duplicate runtime images.','inherited_pass_steps':old['steps'][:2],'steps':[]}
S.write(out/'preflight.json',d)
try:
 assert S.source_hashes(root)==d['source_sha256']
 argv=json.loads((prior/'failed-native-link-argv.json').read_text())
 objects=[x for x in argv if x.endswith('.o')]
 native=Path('/workspace/m3/build/m7-integrate/cuda/native');prev=json.loads((native/'build.json').read_text())
 assert set(prev['objects']).issubset(objects) and len(objects)==len(set(objects))
 hashes={};stamps={};changed=[]
 for name in objects:
  p=Path(name);h=S.sha(p);hashes[name]=h
  stamp=p.with_suffix('.json')
  if stamp.exists():
   r=json.loads(stamp.read_text());assert r['object_sha256']==h
   for dep,digest in r['dependencies'].items():assert S.sha(dep)==digest,'stale dependency '+dep
   stamps[str(stamp)]=S.sha(stamp)
  else:assert h==prev['objects'][name],'changed unstamped input '+name
  if h!=prev['objects'].get(name):changed.append(name)
 pin=Path('/tmp/rv64-m7-compact-state-integrated-v1');pin.mkdir(exist_ok=False)
 library=pin/'libstwo-rv64-native.so'
 argv[argv.index('-o')+1]=str(library)
 argv[4:4]=['-Xlinker=-soname','-Xlinker=/workspace/m3/build/m7-combined-residency/cuda/native/libstwo-rv64-native.so']
 S.write(out/'link-inputs.json',{'argv':argv,'objects_sha256':hashes,'dependency_stamps_sha256':stamps,'changed_vs_prior_successful_build':changed})
 with open('/workspace/m3/locks/build.1.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  start=time.monotonic()
  with (out/'link.log').open('w') as log:r=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,env=dict(os.environ,TMPDIR='/workspace/m3/tmp'))
  d['steps'].append({'name':'native-link','exit_code':r.returncode,'seconds':time.monotonic()-start});assert r.returncode==0
  lib=C.CDLL(str(library))
  required=json.loads((root/'src/backends/cuda/native/rv64/required_symbols.json').read_text())['symbols']
  required+=['stwo_rv64_compact_eager_state_capability','stwo_blake2s_mixed_seeded_eager_compact_on','stwo_exec_context_admission_configure_v2','stwo_exec_context_admission_reserve_v2','stwo_exec_context_admission_snapshot_v2']
  assert all(hasattr(lib,n) for n in required);assert lib.stwo_rv64_compact_eager_state_capability()==1
  d['stack_admission']=P.stack_admission(library,12544);assert d['stack_admission']['admitted']
  for name in ['rv64-word16-ethereum-gpu-combined','rv64-word16-ethereum-recursion-receiver']:
   shutil.copy2(Path('/workspace/m3/build/m7-integrate/zig-out/bin')/name,pin/name)
  d.update(library=str(library),library_sha256=S.sha(library),driver=str(pin/'rv64-word16-ethereum-gpu-combined'),receiver=str(pin/'rv64-word16-ethereum-recursion-receiver'),required_exports_checked=len(required))
 assert S.source_hashes(root)==d['source_sha256']
 assert hashes=={name:S.sha(name) for name in hashes}
 d['status']='UNIT_ZIG_AND_NATIVE_BUILD_PASS'
except BaseException as e:d.update(status='FAIL',error=str(e));raise
finally:S.write(out/'preflight.json',d)
(out/'exit').write_text('0\n')
