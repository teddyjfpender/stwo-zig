from pathlib import Path
import json,subprocess,fcntl,time,hashlib
root=Path('/workspace/m3/src/m7-integrate');out=Path('/workspace/m3/runs/m7-integrate/p1-compact-state-kernel-build-20261106-01')
build=Path('/workspace/m3/build/m7-integrate/p1-compact-state-v1');build.mkdir(exist_ok=False)
source=root/'src/backends/cuda/native/commitment/progressive.cu'
record={'status':'BUILDING_COMPANION_ONLY','source_commit':'26a15d9515a654ecd5ce6824417bde6f943ac4fb+compact-state-v1','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'steps':[]}
def save():(out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
def run(name,argv):
 t=time.monotonic()
 with (out/(name+'.log')).open('w') as log:p=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT)
 record['steps'].append({'name':name,'argv':argv,'exit_code':p.returncode,'seconds':time.monotonic()-t});save()
 if p.returncode:raise RuntimeError(name)
try:
 with open('/workspace/m3/locks/build.1.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  obj=build/'progressive.o';lib=build/'libstwo-compact-state.so'
  run('compile',['/usr/local/cuda/bin/nvcc','-O3','-std=c++17','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-fPIC','-c',str(source),'-o',str(obj)])
  run('link',['/usr/local/cuda/bin/nvcc','-shared','-gencode','arch=compute_120,code=sm_120','-Xlinker=-Bsymbolic',str(obj),'-o',str(lib)])
  run('resources',['/usr/local/cuda/bin/cuobjdump','-res-usage',str(lib)])
  record.update(status='COMPANION_BUILD_PASS_NOT_GPU_QUALIFIED',library=str(lib),library_sha256=hashlib.sha256(lib.read_bytes()).hexdigest())
except BaseException as e:record.update(status='FAIL',error=str(e));raise
finally:save()
