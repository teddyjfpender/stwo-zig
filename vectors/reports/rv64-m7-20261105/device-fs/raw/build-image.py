#!/usr/bin/env python3
"""Rebuild PCS service TU over the exact matched128+qualified prefill image."""
from pathlib import Path
import ctypes,hashlib,json,os,subprocess,time
src=Path('/workspace/m3/src/m7-device-fs');base=Path('/workspace/m3/build/m7-integrate/cuda/native');out=Path('/workspace/m3/build/m7-device-fs/cuda/native');out.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
j=json.loads((base/'build.json').read_text());assert j['library_sha256']=='11e622367774e1b8b0c525a5d46dfeb75c96bfa185f1863d546ef69dd22fdda4';assert sha(base/'libstwo-rv64-native.so')==j['library_sha256']
blake_dir=Path('/workspace/m3/build/m7-blake-prefill/cuda/native');b=json.loads((blake_dir/'blake-build.json').read_text());fused=blake_dir/'rv64-fused_blake2s.cu.o';assert sha(fused)==b['object_sha256']
native=src/'src/backends/cuda/native';source=native/'rv64/pcs_native.cu';obj=out/'rv64-pcs_native.cu.o';nvcc='/usr/local/cuda/bin/nvcc'
compile=[nvcc,'-O3','-std=c++17','-lineinfo','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-fPIC,-pthread',f'-I{native}','-c',str(source),'-o',str(obj)]
started=time.monotonic();subprocess.run(compile,check=True)
localized={r['original']:r for r in j['localized_private_host_helpers']};objects=[]
for p,h in j['objects'].items():
 assert sha(p)==h,p
 if p==str(base/'rv64-pcs_native.cu.o'):objects.append(str(obj));continue
 if p==str(base/'rv64-fused_blake2s.cu.o'):objects.append(str(fused));continue
 if p in localized:
  r=localized[p];p=r['localized'];assert sha(p)==r['localized_sha256']
 objects.append(p)
assert objects.count(str(obj))==1
library=out/'libstwo-rv64-native.so';pending=out/'.libstwo-rv64-native.pending.so'
link=[nvcc,'-shared','-Xcompiler=-pthread','-Xlinker=-Bsymbolic','-rdc=true','-gencode','arch=compute_120,code=sm_120',*objects,'-o',str(pending)]
subprocess.run(link,check=True);image=ctypes.CDLL(str(pending))
for name in ['stwo_exec_context_nvtx_push','stwo_exec_context_nvtx_pop','stwo_circuit_blake_sample_prefill_on','stwo_rv64_pcs_native_prove']:assert hasattr(image,name)
os.replace(pending,library)
receipt={'schema':'rv64-m7-device-fs-image/v1','label':'M','scope':'Matched128 root11e+qualified148c fusedBlake; PCS service/header changes only. NVTX observational checkpoint; fullrequestparity pending.','seconds':time.monotonic()-started,'baseline_library_sha256':j['library_sha256'],'reused_fused_object_sha256':b['object_sha256'],'source_sha256':{str(p.relative_to(src)):sha(p) for p in [source,native/'rv64/pcs_pipeline.cuh']},'object_sha256':sha(obj),'library_sha256':sha(library),'compile_command':compile,'link_command':link,'unmodified_objects_sha256':j['objects']}
(out/'build.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:v for k,v in receipt.items() if k not in ['compile_command','link_command','unmodified_objects_sha256']}))
