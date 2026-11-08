from pathlib import Path
import hashlib,json,subprocess,time,ctypes
out=Path('/workspace/m3/build/m7-owner-cleanup');native=Path('/workspace/m3/src/m7-rc-workspace/src/backends/cuda/native');base=Path('/workspace/m3/build/m7-controller-graphs/cuda/native/libstwo-rv64-native.so');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(base)=='69f18a25c23c042b7fc00d2477097de64c69ea59fd46d2eee6fc9e154dc665e0'
obj=out/'rv64-pcs_native.cu.o';lib=out/'cleanup-overlay.so';nvcc='/usr/local/cuda/bin/nvcc';start=time.monotonic()
compile=[nvcc,'-O3','-std=c++17','-lineinfo','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-fPIC,-pthread',f'-I{out}',f'-I{out}/rv64',f'-I{native}/rv64',f'-I{native}','-c',str(out/'pcs_native.cu'),'-o',str(obj)]
subprocess.run(compile,check=True)
link=[nvcc,'-shared','-Xcompiler=-pthread','-Xlinker=-Bsymbolic','-rdc=true','-gencode','arch=compute_120,code=sm_120',str(obj),str(base),'-o',str(lib)]
subprocess.run(link,check=True);image=ctypes.CDLL(str(lib));assert hasattr(image,'stwo_rv64_gpu_session_cleanup')
r={'schema':'rv64-m7-cleanup-overlay/v1','label':'M','scope':'Fixture overlay only; everyServiceAPI must originate here; arithmetic/runtime/graphs dependency69f. Not standalone production qualification. NewPCSobject includes integrated D2rolling header.','seconds':time.monotonic()-start,'compile_command':compile,'link_command':link,'object_sha256':sha(obj),'library_sha256':sha(lib),'base_sha256':sha(base),'source_sha256':{str(p):sha(p) for p in [out/'pcs_native.cu',out/'rv64/pcs_native.h',native/'rv64/pcs_pipeline.cuh']}}
(out/'build.json').write_text(json.dumps(r,indent=2)+'\n');print(r['object_sha256'])
