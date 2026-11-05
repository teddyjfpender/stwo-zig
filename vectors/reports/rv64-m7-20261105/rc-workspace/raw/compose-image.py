#!/usr/bin/env python3
from pathlib import Path
import ctypes,hashlib,json,os,subprocess,time
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
base=Path('/workspace/m3/build/m7-integrate/cuda/native');out=Path('/workspace/m3/build/m7-controller-graphs/cuda/native');out.mkdir(parents=True,exist_ok=True)
j=json.loads((base/'build.json').read_text());assert j['library_sha256']=='11e622367774e1b8b0c525a5d46dfeb75c96bfa185f1863d546ef69dd22fdda4'
replacements={
 'rv64-pcs_native.cu.o':('/workspace/m3/build/m7-device-controller/cuda/native/rv64-pcs_native.cu.o','877736d81150a1d30acebdda90f5d56f7c0b422f577a0cba05424c9009070625'),
 'rv64-fused_blake2s.cu.o':('/workspace/m3/build/m7-blake-prefill/cuda/native/rv64-fused_blake2s.cu.o','681025c69450eea77fea787401ac0071568ae65f87259bb4073db7c01b6ab460'),
 'rv64-circuit_fill_chain.cu.o':('/workspace/m3/build/m7-assignment-graphs/circuit_fill_chain.o','acab4135828b34effe4e6ec3e52238d3dec3ebb64d935ca6ccd71d597d299de3'),
 'runtime-context.cu.o':('/workspace/m3/build/m7-admission/cuda/native/runtime-context.cu.o','76d7c70e2e858636c3a0e61a61a1e23bfdccec681f8541e53ae1162ff8b0b172'),
}
localized={r['original']:r for r in j['localized_private_host_helpers']};objects=[];used=[]
for p,h in j['objects'].items():
 assert sha(p)==h,p
 name=Path(p).name
 if name in replacements:
  target,expected=replacements[name];assert sha(target)==expected;objects.append(target);used.append(name);continue
 if p in localized:
  r=localized[p];p=r['localized'];assert sha(p)==r['localized_sha256']
 objects.append(p)
assert set(used)==set(replacements),(used,replacements)
lib=out/'libstwo-rv64-native.so';pending=out/'.pending.so'
cmd=['/usr/local/cuda/bin/nvcc','-shared','-Xcompiler=-pthread','-Xlinker=-Bsymbolic','-rdc=true','-gencode','arch=compute_120,code=sm_120',*objects,'-o',str(pending)]
start=time.monotonic();subprocess.run(cmd,check=True);image=ctypes.CDLL(str(pending))
for name in ['stwo_exec_context_arena_snapshot_v1','stwo_rv64_gpu_session_controller','stwo_circuit_blake_sample_prefill_on']:assert hasattr(image,name),name
os.replace(pending,lib)
receipt={'schema':'rv64-m7-controller-graphs-image/v1','label':'M','seconds':time.monotonic()-start,'baseline_library_sha256':j['library_sha256'],'replacements':replacements,'library_sha256':sha(lib),'link_command':cmd,'all_link_objects_sha256':{p:sha(p) for p in objects},'status':'link/export gate only; production parity pending; plannerOFF/GKROFF'}
(out/'build.json').write_text(json.dumps(receipt,indent=2)+'\n');print(receipt['library_sha256'])
