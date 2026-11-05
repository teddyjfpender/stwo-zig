#!/usr/bin/env python3
"""Relink the admitted M6 image with exactly one rebuilt native context TU."""
import ctypes, hashlib, json, os
from pathlib import Path
import subprocess, time
root=Path('/workspace/m3/src/m7-device-graphs')
base=Path('/workspace/m3/build/m6-integrate/cuda/native')
out=Path('/workspace/m3/build/m7-device-graphs/cuda/native');out.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
j=json.load(open(base/'build.json'))
assert sha(base/'libstwo-rv64-native.so')==j['library_sha256']
source=root/'src/backends/cuda/native/runtime/context.cu';obj=out/'runtime-context.cu.o'
native=root/'src/backends/cuda/native';nvcc='/usr/local/cuda/bin/nvcc'
compile=[nvcc,'-O3','-std=c++17','-lineinfo','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-fPIC,-pthread',f'-I{native}','-c',str(source),'-o',str(obj)]
started=time.monotonic();subprocess.run(compile,check=True)
localized={r['original']:r for r in j['localized_private_host_helpers']}
objects=[]
for p,h in j['objects'].items():
 assert sha(p)==h, p
 if p==str(base/'runtime-context.cu.o'):objects.append(str(obj));continue
 if p in localized:
  r=localized[p];p=r['localized'];assert sha(p)==r['localized_sha256']
 objects.append(p)
assert objects.count(str(obj))==1
library=out/'libstwo-rv64-native.so'
link=[nvcc,'-shared','-Xcompiler=-pthread','-Xlinker=-Bsymbolic','-rdc=true','-gencode','arch=compute_120,code=sm_120',*objects,'-o',str(library)]
subprocess.run(link,check=True)
image=ctypes.CDLL(str(library))
required=['stwo_rv64_graph_cache_lookup_on','stwo_rv64_graph_capture_begin_on','stwo_rv64_graph_capture_store_on','stwo_rv64_graph_launch_on','stwo_exec_context_h2d_enqueued_bytes']
assert all(hasattr(image,s) for s in required)
receipt=dict(schema='rv64-m7-graph-context-build/v1',label='M',scope='M6 admitted image with only runtime/context.cu object replaced; no GPU qualification implied',seconds=time.monotonic()-started,baseline_library_sha256=j['library_sha256'],source_sha256=sha(source),object_sha256=sha(obj),library_sha256=sha(library),compile_command=compile,link_command=link,unmodified_objects_sha256=j['objects'],new_exports=required)
(out/'graph-build.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:v for k,v in receipt.items() if k not in ['unmodified_objects_sha256','compile_command','link_command']}))
