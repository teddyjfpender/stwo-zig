from pathlib import Path
import json,subprocess,time,fcntl,sys,os
root=Path('/workspace/m3/src/m7-integrate');out=Path('/workspace/m3/runs/m7-integrate/p1-compact-state-preflight-20261106-02')
sys.path.insert(0,str(root/'scripts'));import rv64_m7_integration_stack as S
env=S.clean_environment(os.environ);env.update(ZIG_GLOBAL_CACHE_DIR='/workspace/m3/cache/zig-global',TMPDIR='/workspace/m3/tmp')
r={'status':'RUNNING','source_commit':(root/'.m3-commit').read_text().strip(),'source_sha256':S.source_hashes(root),'steps':[]}
S.write(out/'preflight.json',r)
def run(name,argv,cwd=root):
 t=time.monotonic();entry={'name':name,'argv':argv};r['steps'].append(entry);S.write(out/'preflight.json',r)
 with (out/(name+'.log')).open('w') as log:p=subprocess.run(argv,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT)
 entry.update(exit_code=p.returncode,seconds=time.monotonic()-t);S.write(out/'preflight.json',r)
 if p.returncode:raise RuntimeError(name+' failed')
try:
 with open('/workspace/m3/locks/build.1.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  run('unit',['/workspace/zig/zig','build','test','test-rv64-recursion-ready','test-rv64-batch-plan','test-rv64-gkr-plan','test-rv64-pcs-geometry','-j2','-Doptimize=ReleaseSafe','-Dtarget=x86_64-linux-gnu','-Dcpu=x86_64_v4+sha','--cache-dir',str(root/'.zig-cache')],root/'src/integrations/riscv_cuda')
  run('zig-build',[sys.executable,'scripts/rv64_m3_pod.py','build','--stream','m7-integrate','--only','zig'])
  run('cuda-build',[sys.executable,'scripts/rv64_m3_pod.py','build','--stream','m7-integrate','--only','cuda','--jobs','2'])
  assert S.source_hashes(root)==r['source_sha256']
  r.update(status='UNIT_ZIG_AND_NATIVE_BUILD_PASS',library='/workspace/m3/build/m7-integrate/cuda/native/libstwo-rv64-native.so',library_sha256=S.sha('/workspace/m3/build/m7-integrate/cuda/native/libstwo-rv64-native.so'))
except BaseException as e:r.update(status='FAIL',error=str(e));raise
finally:S.write(out/'preflight.json',r)
