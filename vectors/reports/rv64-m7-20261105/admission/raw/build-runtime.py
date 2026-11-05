#!/usr/bin/env python3
"""Rebuild the admission runtime TU in the matched128 image and reuse qualified Blake prefill."""
import ctypes, hashlib, json, os
from pathlib import Path
import subprocess, time
root=Path('/workspace/m3/src/m7-admission')
base=Path('/workspace/m3/build/m7-integrate/cuda/native')
out=Path('/workspace/m3/build/m7-admission/cuda/native');out.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
j=json.load(open(base/'build.json'))
assert sha(base/'libstwo-rv64-native.so')==j['library_sha256']
source=root/'src/backends/cuda/native/runtime/context.cu';obj=out/'runtime-context.cu.o'
native=root/'src/backends/cuda/native';nvcc='/usr/local/cuda/bin/nvcc'
compile=[nvcc,'-O3','-std=c++17','-lineinfo','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-fPIC,-pthread',f'-I{native}','-c',str(source),'-o',str(obj)]
started=time.monotonic();subprocess.run(compile,check=True)
localized={r['original']:r for r in j['localized_private_host_helpers']}
objects=[]
blake_dir=Path('/workspace/m3/build/m7-blake-prefill/cuda/native')
blake=json.load(open(blake_dir/'blake-build.json'))
assert sha(blake_dir/'rv64-fused_blake2s.cu.o')==blake['object_sha256']
for p,h in j['objects'].items():
 assert sha(p)==h, p
 if p==str(base/'runtime-context.cu.o'):objects.append(str(obj));continue
 if p==str(base/'rv64-fused_blake2s.cu.o'):objects.append(str(blake_dir/'rv64-fused_blake2s.cu.o'));continue
 if p in localized:
  r=localized[p];p=r['localized'];assert sha(p)==r['localized_sha256']
 objects.append(p)
assert objects.count(str(obj))==1
library=out/'libstwo-rv64-native.so'
pending=out/'.libstwo-rv64-native.pending.so'
link=[nvcc,'-shared','-Xcompiler=-pthread','-Xlinker=-Bsymbolic','-rdc=true','-gencode','arch=compute_120,code=sm_120',*objects,'-o',str(pending)]
subprocess.run(link,check=True)
image=ctypes.CDLL(str(pending))
required=['stwo_exec_context_arena_snapshot_v1','stwo_exec_context_admission_configure_v1','stwo_exec_context_admission_begin_v1','stwo_exec_context_admission_end_v1','stwo_circuit_blake_sample_prefill_on']
assert all(hasattr(image,s) for s in required)
os.replace(pending,library)
receipt=dict(schema='rv64-m7-admission-runtime-build/v1',label='M',scope='Matched128 root image; runtime/context.cu+arena header rebuilt; qualified148c fused-Blake object reused; no request/GKR promotion',seconds=time.monotonic()-started,baseline_library_sha256=j['library_sha256'],source_sha256=sha(source),arena_header_sha256=sha(native/'runtime/device_arena_runtime.cuh'),object_sha256=sha(obj),reused_prefill_object_sha256=blake['object_sha256'],library_sha256=sha(library),compile_command=compile,link_command=link,unmodified_objects_sha256=j['objects'],new_exports=required)
(out/'admission-build.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:v for k,v in receipt.items() if k not in ['unmodified_objects_sha256','compile_command','link_command']}))
