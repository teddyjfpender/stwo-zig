#!/usr/bin/env python3
"""Mechanical CUDA lowering of original clock-gap and physical-frame row writers."""
import argparse, json, re, subprocess
from pathlib import Path
from riscv_native_witness_cuda import decorate, sha, integer_runtime
from zig_protocol_lib.command import protocol_module_args
ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir',type=Path,required=True)
    parser.add_argument('--zig',default='zig')
    args=parser.parse_args();dst=args.out_dir.resolve();dst.mkdir(parents=True,exist_ok=False)
    if subprocess.check_output([args.zig,'version'],text=True).strip()!='0.15.2':raise ValueError('pinned Zig required')
    env=subprocess.check_output([args.zig,'env'],text=True)
    match=re.search(r'^\s*\.lib_dir = ("(?:[^"\\]|\\.)*"),$',env,re.M)
    if match is None:raise ValueError('missing Zig library')
    header=(Path(json.loads(match[1]))/'zig.h').read_bytes()
    generated=dst/'native-infra.c'
    cmd=[args.zig,'build-obj','-ofmt=c',f'-femit-bin={generated}',*protocol_module_args('src/riscv_cuda_native_infra_witness_export_v1.zig',optimize='ReleaseFast',target='x86_64-linux-gnu.2.39',cpu_only=True)]
    subprocess.run(cmd,cwd=ROOT,check=True);raw=generated.read_bytes()
    code,counts=decorate(raw.decode(),header.decode(),export_prefix='stwo_native_infra_',families=('clock','frame','fixed'))
    h=header.decode();base=integer_runtime(h)
    extra='#define zig_has_builtin(x) 0\n'+h[h.index('static inline uint8_t zig_bit_reverse_u8'):h.index('#define zig_builtin_clz_common')]
    code=code.replace(base,base+'\n'+extra.replace('static inline','static __device__ inline'),1)
    code+=r"""
__global__ void native_infra_fixed(uint*first,uint*active,uint rows,uint count,uint frame,uint*status){
 uint i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=rows)return;uint e=stwo_native_infra_fixed_v1(first,active,rows,count,i,frame);if(e)atomicCAS(status,0u,e);
}
extern "C" int stwo_native_infra_fixed_on(uint*first,uint*active,uint rows,uint count,uint frame,uint*status,void*stream){
 if(!first||!active||!status||rows<2||rows>(1u<<24)||(rows&(rows-1))||count>rows||frame>1u||(!frame&&first==active))return int(cudaErrorInvalidValue);
 native_infra_fixed<<<(rows+127u)/128u,128,0,static_cast<cudaStream_t>(stream)>>>(first,active,rows,count,frame,status);return int(cudaGetLastError());
}
__global__ void native_infra_clock(const uint*raw,uint*out,uint count,uint rows,uint*status){
 uint i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=rows)return;uint e=stwo_native_infra_clock_v1(raw,out,count,rows,i);if(e)atomicCAS(status,0u,e);
}
extern "C" int stwo_native_infra_clock_on(const uint*raw,uint*out,uint count,uint rows,uint*status,void*stream){
 if(!raw||!out||!status||rows<2||rows>(1u<<24)||(rows&(rows-1))||count>rows)return int(cudaErrorInvalidValue);
 native_infra_clock<<<(rows+127u)/128u,128,0,static_cast<cudaStream_t>(stream)>>>(raw,out,count,rows,status);return int(cudaGetLastError());
}
__global__ void native_infra_frame(uint*out,uint steps,uint external,uint*status){
 uint e=stwo_native_infra_frame_v1(out,4,threadIdx.x,steps,external);if(e)atomicCAS(status,0u,e);
}
extern "C" int stwo_native_infra_frame_on(uint*out,uint steps,uint external,uint*status,void*stream){
 if(!out||!status||!steps||steps!=external||steps>=2147483647u)return int(cudaErrorInvalidValue);
 native_infra_frame<<<1,4,0,static_cast<cudaStream_t>(stream)>>>(out,steps,external,status);return int(cudaGetLastError());
}
"""
    result=code.encode();(dst/'native-infra.cu').write_bytes(result)
    manifest={'schema':'stwo-native-infra-witness-cuda-v1','cuda_sha256':sha(result),'generated_c_sha256':sha(raw),'compiler_header_sha256':sha(header),'counts':counts,'command':cmd,'device_executed':False}
    (dst/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest))
if __name__=='__main__':main()
