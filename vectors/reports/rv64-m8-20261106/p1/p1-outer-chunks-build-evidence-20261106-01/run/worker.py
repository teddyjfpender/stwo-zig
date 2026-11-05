from pathlib import Path
import os,json,subprocess,fcntl,time,hashlib
root=Path('/workspace/m3/src/m7-integrate')
out=Path('/workspace/m3/runs/m7-integrate/p1-outer-chunks-build-20261106-01')
build=Path('/workspace/m3/build/m7-integrate/p1-outer-chunks-v1')
build.mkdir(exist_ok=False); gen=build/'generated';gen.mkdir()
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR='/workspace/m3/cache/zig-global',TMPDIR='/workspace/m3/tmp')
record={'status':'BUILDING','steps':[],'source_commit':'1a01682f8+outer-chunks-v1','source_sha256':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [root/'src/integrations/riscv_cuda/rv64/outer_chunks_aot.zig',root/'src/integrations/riscv_cuda/rv64_joined_fixture_main.zig']}}
def save(): (out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
def run(name,argv,cwd=root):
 t=time.monotonic()
 with (out/(name+'.log')).open('w') as log:r=subprocess.run(argv,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT)
 record['steps'].append({'name':name,'argv':argv,'exit_code':r.returncode,'seconds':time.monotonic()-t});save()
 if r.returncode:raise RuntimeError(name+' failed')
try:
 with open('/workspace/m3/locks/build.1.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  run('tool',['/workspace/zig/zig','build','build-rv64-joined-tool','-j2','-Dtarget=x86_64-linux-gnu','-Dcpu=x86_64_v4+sha','-Doptimize=ReleaseFast','--cache-dir',str(root/'.zig-cache'),'--prefix',str(build/'tools')],root/'src/integrations/riscv_cuda')
  run('generate',[str(build/'tools/bin/rv64-joined-fixtures'),'--outer-chunks',str(gen)])
  objects=[]
  for source in sorted(gen.glob('*.cu')):
   obj=build/(source.stem+'.o')
   run(source.stem,['/usr/local/cuda/bin/nvcc','-O3','-std=c++17','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-fPIC,-pthread','-I'+str(root/'src/backends/cuda/native'),'-c',str(source),'-o',str(obj)])
   objects.append(str(obj))
  library=build/'libstwo-outer-chunks.so'
  run('link',['/usr/local/cuda/bin/nvcc','-shared','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-pthread','-Xlinker=-Bsymbolic',*objects,'/workspace/m3/build/m7-owner-v2/libstwo-rv64-native.so','-Xlinker=-rpath,/workspace/m3/build/m7-owner-v2','-o',str(library)])
  record.update(status='COMPANION_BUILD_PASS_NOT_GPU_QUALIFIED',library=str(library),library_sha256=hashlib.sha256(library.read_bytes()).hexdigest())
except BaseException as e:record.update(status='FAIL',error=str(e));raise
finally:save()
