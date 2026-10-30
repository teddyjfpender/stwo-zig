#!/usr/bin/env python3
"""Mechanically lower original typed parent direct row constructors to CUDA."""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path
from riscv_native_witness_cuda import decorate, sha, integer_runtime
from zig_protocol_lib.command import protocol_module_args
ROOT=Path(__file__).resolve().parents[1]
INDICES=(2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19)
# Checked by the generated Zig width/fixed/input functions, not an AIR authority.
DYNAMIC=(4,12,4,8,8,8,1,1,4,4,1,3,10,3,4,2,40,28)
def wrappers():
    out=[]
    for i in INDICES:
        out.append(f'''
__global__ void stwo_parent_direct_kernel_{i}(const uint32_t *fixed,const uint32_t *dynamic,uint32_t active,uint32_t rows,uint32_t *main,uint32_t *status) {{
 uint32_t index=blockIdx.x*blockDim.x+threadIdx.x;if(index>=rows)return;
 if(index>=active) {{
  uint32_t log=31u-__clz(rows);uint32_t circle=(index&1u)?(2*rows-index)/2:index/2;
  uint32_t physical=__brev(circle)>>(32-log);
  for(uint32_t c=0;c<stwo_parent_direct_width_{i}_v1();++c)main[(size_t)c*rows+physical]=0;
  return;
 }}
 uint32_t e=stwo_parent_direct_row_{i}_v1(fixed+(size_t)index*stwo_parent_direct_fixed_{i}_v1(),dynamic+(size_t)index*stwo_parent_direct_input_{i}_v1(),main,rows,index);
 if(e)atomicCAS(status,0u,e);
}}
''')
    out.append('''extern "C" cudaError_t stwo_parent_direct_launch_v1(uint32_t family,const uint32_t *fixed,const uint32_t *dynamic,uint32_t active,uint32_t rows,uint32_t *main,uint32_t *status,cudaStream_t stream) {
 if(!stream||!fixed||!dynamic||!main||!status||rows<2||(rows&(rows-1))||rows>(1u<<27)||active>rows)return cudaErrorInvalidValue;
 dim3 grid((rows+127u)/128u),block(128);switch(family){
''')
    for i in INDICES:out.append(f'case {i}: stwo_parent_direct_kernel_{i}<<<grid,block,0,stream>>>(fixed,dynamic,active,rows,main,status);break;\n')
    out.append('default:return cudaErrorInvalidValue;}return cudaGetLastError();}\n')
    return ''.join(out)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out-dir',type=Path,required=True);p.add_argument('--zig',default='zig');p.add_argument('--append-cuda',type=Path,action='append',default=[]);o=p.parse_args()
    dst=o.out_dir.resolve();dst.mkdir(parents=True,exist_ok=False)
    version=subprocess.check_output([o.zig,'version'],text=True).strip()
    if version!='0.15.2':raise ValueError('pinned Zig0.15.2 required')
    env=subprocess.check_output([o.zig,'env'],text=True);m=re.search(r'^\s*\.lib_dir = ("(?:[^"\\]|\\.)*"),$',env,re.M)
    if m is None:raise ValueError('missing compiler library path')
    header=(Path(json.loads(m[1]))/'zig.h').read_bytes();generated=dst/'parent-direct.c'
    cmd=[o.zig,'build-obj','-ofmt=c',f'-femit-bin={generated}',*protocol_module_args('src/riscv_cuda_parent_direct_export_v1.zig',optimize='ReleaseFast',target='x86_64-linux-gnu.2.39',cpu_only=True,extra_packages=('stwo_riscv_frontend',))]
    subprocess.run(cmd,cwd=ROOT,check=True);raw=generated.read_bytes()
    code,counts=decorate(raw.decode(),header.decode(),export_prefix='stwo_parent_direct_row_',families=tuple(map(str,INDICES)))
    # Additional exact pinned compiler helpers used by original counter overflow
    # and canonical scatter. Select the compiler's portable branches verbatim.
    h=header.decode()
    extra='#define zig_has_builtin(x) 0\n'
    extra+=h[h.index('static inline uint8_t zig_bit_reverse_u8'):h.index('#define zig_builtin_clz_common')]
    start=h.index('static inline bool zig_addo_u64');end=h.index('\n}\n',start)+3
    extra+=h[start:end]
    extra=extra.replace('static inline','static __device__ inline')
    body=integer_runtime(h)
    if code.count(body)!=1:raise ValueError('compiler helper insertion not unique')
    code=code.replace(body,body+'\n'+extra,1)
    # NVCC/GCC predefines linux; Zig may emit an inert Target union member with that name.
    code=re.sub(r'\blinux\b', 'zig_target_linux', code)
    code+=wrappers()
    appended=[]
    for path in o.append_cuda:
        payload=path.read_bytes()
        if len(payload)>2*1024*1024:raise ValueError('launcher source byte cap exceeded')
        code+='\n'+payload.decode()+'\n'
        appended.append({'path':str(path.resolve()),'sha256':sha(payload),'bytes':len(payload)})
    final=code.encode();(dst/'parent-direct.cu').write_bytes(final)
    manifest={'schema':'stwo-parent-direct-cuda-v1','zig_version':version,'indices':INDICES,'dynamic_words':DYNAMIC,'generated_c_sha256':sha(raw),'compiler_header_sha256':sha(header),'cuda_sha256':sha(final),'counts':counts,'appended_launchers':appended,'command':cmd,'scope':'original typed row primitive; not a complete resident proof'}
    (dst/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({'output':str(dst),'cuda_sha256':sha(final),**counts}))
if __name__=='__main__':main()
