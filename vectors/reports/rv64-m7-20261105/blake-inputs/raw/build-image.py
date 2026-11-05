#!/usr/bin/env python3
"""Relink the matched128 image with only the Blake shadow-check TU rebuilt."""
import ctypes, hashlib, json, os
from pathlib import Path
import subprocess, time
root=Path('/workspace/m3/src/m7-blake-inputs')
base=Path('/workspace/m3/build/m7-integrate/cuda/native')
out=Path('/workspace/m3/build/m7-blake-inputs/cuda/native');out.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
j=json.load(open(base/'build.json'))
assert sha(base/'libstwo-rv64-native.so')==j['library_sha256']
source=root/'src/backends/cuda/native/rv64/fused_blake2s.cu';obj=out/'rv64-fused_blake2s.cu.o'
native=root/'src/backends/cuda/native';nvcc='/usr/local/cuda/bin/nvcc'
compile=[nvcc,'-O3','-std=c++17','-lineinfo','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-fPIC,-pthread',f'-I{native}','-c',str(source),'-o',str(obj)]
started=time.monotonic();subprocess.run(compile,check=True)
localized={r['original']:r for r in j['localized_private_host_helpers']}
objects=[]
for p,h in j['objects'].items():
 assert sha(p)==h, p
 if p==str(base/'rv64-fused_blake2s.cu.o'):objects.append(str(obj));continue
 if p in localized:
  r=localized[p];p=r['localized'];assert sha(p)==r['localized_sha256']
 objects.append(p)
assert objects.count(str(obj))==1
library=out/'libstwo-rv64-native.so'
pending=out/'.libstwo-rv64-native.pending.so'
link=[nvcc,'-shared','-Xcompiler=-pthread','-Xlinker=-Bsymbolic','-rdc=true','-gencode','arch=compute_120,code=sm_120',*objects,'-o',str(pending)]
subprocess.run(link,check=True)
image=ctypes.CDLL(str(pending))
required=['stwo_circuit_blake_sample_inputs_check_on']
assert all(hasattr(image,s) for s in required)
os.replace(pending,library)
receipt=dict(schema='rv64-m7-blake-input-check-build/v1',label='M',scope='Matched128 root image with only rv64/fused_blake2s.cu replaced; no production/GPU performance qualification implied',seconds=time.monotonic()-started,baseline_library_sha256=j['library_sha256'],source_sha256=sha(source),object_sha256=sha(obj),library_sha256=sha(library),compile_command=compile,link_command=link,unmodified_objects_sha256=j['objects'],new_exports=required)
(out/'blake-build.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:v for k,v in receipt.items() if k not in ['unmodified_objects_sha256','compile_command','link_command']}))
