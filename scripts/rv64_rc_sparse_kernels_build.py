#!/usr/bin/env python3
"""Build source-bound signed-cover kernels; no GPU or performance claim."""
from pathlib import Path
import argparse,fcntl,hashlib,json,subprocess,time,sys,signal
ap=argparse.ArgumentParser();ap.add_argument('--source-root',type=Path,required=True);ap.add_argument('--build',type=Path,required=True);ap.add_argument('--report',type=Path,required=True);ap.add_argument('--base',type=Path,required=True);ap.add_argument('--indices');ap.add_argument('--lock-index',type=int,default=3);ap.add_argument('--compile-only',action='store_true');args=ap.parse_args()
r=args.build;s=args.source_root;meta=json.load(open(args.report));assert meta['groups']==54 and meta['program_roots']==5650 and meta['input_masks']==6733
sys.path.insert(0,str(s/'scripts'));import rv64_cuda_partition_grouped as G
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
objects=r/'objects';objects.mkdir(exist_ok=True);logs=r/'logs';logs.mkdir(exist_ok=True);bounded=r/'bounded';bounded.mkdir(exist_ok=True)
flags=['-O3','-std=c++17','-lineinfo','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-fPIC,-pthread','-Xptxas=-v','-I'+str(s/'src/backends/cuda/native')]
compiler=subprocess.check_output(['/usr/local/cuda/bin/nvcc','--version'],text=True)
header_hash=hashlib.sha256()
for h in sorted((s/'src/backends/cuda/native').rglob('*')):
 if h.suffix in ('.h','.cuh'):header_hash.update(str(h.relative_to(s)).encode()+bytes.fromhex(sha(h)))
compile_key=hashlib.sha256((compiler+json.dumps(flags)+header_hash.hexdigest()).encode()).hexdigest()
paused=False
def pause_after_group(sig,frame):
 global paused;paused=True
signal.signal(signal.SIGUSR1,pause_after_group)
manifest={'compile_key':compile_key,'nvcc_version':compiler,'flags':flags,'native_headers_sha256':header_hash.hexdigest(),'schema':'rv64-rc-sparse-signed-kernels-build/v1','program_identity':meta['source_identity'],'plan_identity':meta['plan_identity'],'base_sha256':sha(args.base),'groups':[],'numerically_gpu_qualified':False}
start=time.monotonic()
with open(f'/workspace/m3/locks/build.{args.lock_index}.lock','a') as lock:
 for i in (list(map(int,args.indices.split(','))) if args.indices else range(meta['groups'])):
  if paused or (r/'PAUSE').exists():print('PAUSED_BETWEEN_GROUPS',i,flush=True);raise SystemExit(0)
  fcntl.flock(lock,fcntl.LOCK_EX)
  src=r/'generated'/f'group-{i}.cu';target=bounded/src.name;target.write_bytes(src.read_bytes());bank=G.bound_ssa_module(target);assert bank['private_frame_bytes']<=8192
  obj=objects/f'group-{i}.o';log=logs/f'group-{i}.log';source_pin=sha(target);pin=hashlib.sha256((source_pin+compile_key).encode()).hexdigest()
  if not obj.exists() or not obj.with_suffix('.sha').exists() or obj.with_suffix('.sha').read_text()!=pin:
   cmd=['/usr/local/cuda/bin/nvcc',*flags,'-c',str(target),'-o',str(obj)]
   with log.open('w') as f:p=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=240)
   if p.returncode:print(log.read_text()[-4000:]);raise SystemExit(p.returncode)
   obj.with_suffix('.sha').write_text(pin)
  manifest['groups'].append({'id':i,'raw_source_sha256':sha(src),'bounded_source_sha256':source_pin,'compile_cache_key':pin,'object':str(obj),'object_sha256':sha(obj),'bank':bank})
  (r/f'kernels-build-partial-{args.lock_index}.json').write_text(json.dumps(manifest,indent=2)+'\n');print('COMPILED_SPARSE_GROUP',i,flush=True)
  fcntl.flock(lock,fcntl.LOCK_UN);time.sleep(.15)
 if args.compile_only:print('SELECTED_GROUPS_COMPILED',args.indices,flush=True);raise SystemExit(0)
 proto='const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t'
 text='#include "rv64/composition_dispatch.cuh"\n#include <cstring>\n'
 for i in range(meta['groups']):text+=f'extern "C" __global__ void stwo_rv64_truth0_sparse_{i}({proto});\n'
 text+='static const void*kernels[]={'+','.join(f'(const void*)stwo_rv64_truth0_sparse_{i}' for i in range(meta['groups']))+'};\n'
 text+='static const uint32_t group_sizes[54]={};\n'
 ident=bytes.fromhex(meta['source_identity'])+bytes.fromhex(meta['plan_identity']);text+='static const uint8_t identity[64]={'+','.join(str(x) for x in ident)+'};\n'
 text+='extern "C" int stwo_rv64_rc_sparse_identity(uint8_t*out){if(!out)return 1;std::memcpy(out,identity,64);return 0;}\n'
 text+='extern "C" int stwo_rv64_rc_sparse_group_on(void*c,uint32_t lane,uint32_t group,const StwoRv64CompositionRole*j,uint32_t*n){if(n)*n=0;if(!j||!n||lane||group>=54||j->role||j->trace_log!=18||j->eval_log!=20||j->constraint_count!=5650||j->mask_count!=6733||j->parameter_count!=31||j->trees[0]!=j->trees[1]||j->trees[0]!=j->trees[2]||j->tree_words[0]!=(uint64_t(1024)<<20)||j->tree_words[1]!=j->tree_words[0]||j->tree_words[2]!=j->tree_words[0])return int(cudaErrorInvalidValue);auto local=*j;local.role=group;return stwo::cuda::rv64::composition_dispatch(c,lane,&local,n,kernels,group_sizes,54);}\n'
 fcntl.flock(lock,fcntl.LOCK_EX)
 dispatch=r/'dispatch.cu';dispatch.write_text(text);cmd=['/usr/local/cuda/bin/nvcc',*flags,'-c',str(dispatch),'-o',str(objects/'dispatch.o')]
 with open(logs/'dispatch.log','w') as f:p=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=120)
 if p.returncode:print((logs/'dispatch.log').read_text()[-4000:]);raise SystemExit(p.returncode)
 link=['/usr/local/cuda/bin/nvcc','-shared','-gencode','arch=compute_120,code=sm_120','-Xcompiler=-pthread','-Xlinker=-Bsymbolic',str(r/'rc_sparse_lde.o'),str(objects/'dispatch.o'),*[str(objects/f'group-{i}.o') for i in range(54)],str(args.base),'-Xlinker=-rpath,'+str(args.base.parent),'-o',str(r/'libstwo-rc-sparse.so')]
 with open(logs/'link.log','w') as f:p=subprocess.run(link,stdout=f,stderr=subprocess.STDOUT,timeout=180)
 if p.returncode:print((logs/'link.log').read_text()[-4000:]);raise SystemExit(p.returncode)
manifest.update(seconds=time.monotonic()-start,link_command=link,addon_sha256=sha(r/'libstwo-rc-sparse.so'));(r/'kernels-build.json').write_text(json.dumps(manifest,indent=2)+'\n');print('SPARSE_KERNEL_BUILD_PASS',manifest['addon_sha256'],flush=True)
