#!/usr/bin/env python3
"""Lower the exact original native access witness constructor using Zig C."""
from __future__ import annotations
import argparse, json, re, subprocess
from pathlib import Path
from riscv_native_witness_cuda import decorate, sha, integer_runtime
from zig_protocol_lib.command import protocol_module_args
ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--zig', default='zig')
    parser.add_argument('--append-cuda', type=Path)
    options = parser.parse_args()
    dst = options.out_dir.resolve()
    dst.mkdir(parents=True, exist_ok=False)
    if subprocess.check_output([options.zig, 'version'], text=True).strip() != '0.15.2':
        raise ValueError('pinned Zig0.15.2 required')
    env = subprocess.check_output([options.zig, 'env'], text=True)
    match = re.search(r'^\s*\.lib_dir = ("(?:[^"\\]|\\.)*"),$', env, re.M)
    if match is None:
        raise ValueError('missing compiler library path')
    header = (Path(json.loads(match[1])) / 'zig.h').read_bytes()
    generated = dst / 'native-access-witness.c'
    cmd = [options.zig, 'build-obj', '-ofmt=c', f'-femit-bin={generated}',
           *protocol_module_args('src/riscv_cuda_native_access_witness_export_v1.zig',
                                 optimize='ReleaseFast', target='x86_64-linux-gnu.2.39', cpu_only=True)]
    subprocess.run(cmd, cwd=ROOT, check=True)
    raw = generated.read_bytes()
    code, counts = decorate(raw.decode(), header.decode(),
                            export_prefix='stwo_native_access_witness_', families=('1', '2'))
    # Checked global clock addition comes from the pinned compiler helper.
    h = header.decode()
    extra = '#define zig_has_builtin(x) 0\n'
    for name in ('zig_addo_u64', 'zig_mulo_u32'):
        start = h.index('static inline bool ' + name)
        end = h.index('\n}\n', start) + 3
        extra += h[start:end].replace('static inline', 'static __device__ inline')
    body = integer_runtime(h)
    if code.count(body) != 1:
        raise ValueError('compiler helper insertion not unique')
    code = code.replace(body, body + '\n' + extra, 1)
    code = re.sub(r'\blinux\b', 'zig_target_linux', code)
    code += '''
__global__ void native_access_witness_rows(uint slot,const uint*main,uint*output,uint rows,unsigned long long base_clock,uint*status){
 uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;
 uint e=slot==1?stwo_native_access_witness_1_v1(main,output,rows,row,base_clock):stwo_native_access_witness_2_v1(main,output,rows,row,base_clock);
 if(e)atomicCAS(status,0u,e);
}
extern "C" int stwo_native_access_witness_on(uint slot,const uint*main,uint*output,uint rows,unsigned long long base_clock,uint*status,void*stream){
 if((slot!=1&&slot!=2)||!main||!output||!status||rows<2||rows>(1u<<24)||(rows&(rows-1)))return int(cudaErrorInvalidValue);
 native_access_witness_rows<<<(rows+127u)/128u,128,0,static_cast<cudaStream_t>(stream)>>>(slot,main,output,rows,base_clock,status);
 return int(cudaGetLastError());
}
__device__ void native_access_count_add(uint*cell,uint*status){
 uint previous=atomicAdd(cell,0u);
 for(;;){if(previous>=2147483647u){atomicCAS(status,0u,4u);return;}uint next=previous==2147483646u?0u:previous+1u;uint observed=atomicCAS(cell,previous,next);if(observed==previous)return;previous=observed;}
}
__global__ void native_access_count_rows(uint slot,const uint*main,const uint*witness,uint*counter,uint rows,uint*status){
 uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;uint bytes[29];
 uint e=slot==1?stwo_native_access_bytes_1_v1(main,witness,rows,row,&bytes):stwo_native_access_bytes_2_v1(main,witness,rows,row,&bytes);
 if(e){atomicCAS(status,0u,e);return;}if(!bytes[0])return;
 for(uint i=0;i<14u;i++)native_access_count_add(counter+bytes[1u+2u*i]+256u*bytes[2u+2u*i],status);
}
extern "C" int stwo_native_access_count_on(uint slot,const uint*main,const uint*witness,uint*counter,uint rows,uint*status,void*stream){
 if((slot!=1&&slot!=2)||!main||!witness||!counter||!status||rows<2||rows>(1u<<24)||(rows&(rows-1)))return int(cudaErrorInvalidValue);
 native_access_count_rows<<<(rows+127u)/128u,128,0,static_cast<cudaStream_t>(stream)>>>(slot,main,witness,counter,rows,status);
 return int(cudaGetLastError());
}
'''
    appended = None
    if options.append_cuda:
        payload = options.append_cuda.read_bytes()
        if len(payload) > 2 * 1024 * 1024:
            raise ValueError('oracle byte cap exceeded')
        code += '\n' + payload.decode()
        appended = {'sha256': sha(payload), 'bytes': len(payload)}
    final = code.encode()
    (dst / 'native-access-witness.cu').write_bytes(final)
    manifest = {'schema': 'stwo-native-access-witness-cuda-v1', 'slots': [1, 2],
                'generated_c_sha256': sha(raw), 'compiler_header_sha256': sha(header),
                'cuda_sha256': sha(final), 'counts': counts, 'command': cmd,
                'appended_oracle': appended, 'scope': 'original48-column witness primitive; not a complete resident proof'}
    (dst / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'output': str(dst), 'cuda_sha256': sha(final), **counts}))

if __name__ == '__main__':
    main()
