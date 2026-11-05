#!/usr/bin/env python3
"""Generate a benchmark-only, byte-equivalent M31 CUDA arithmetic variant."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--variant',choices=('fast32','common-rotate'),default='fast32');a=p.parse_args()
root=Path(__file__).resolve().parents[1];src=root/'src/backends/cuda/native/rv64/poseidon2_m31.cuh';s=src.read_text()
old='__device__ __forceinline__ uint32_t add(uint32_t a,uint32_t b){return reduce(uint64_t(a)+b);}\n__device__ __forceinline__ uint32_t mul(uint32_t a,uint32_t b){return reduce(uint64_t(a)*b);}'
new='''// Exact canonical M31 arithmetic: low/high32 product, then two folds.
// x<2^32 after splitting a*b at bit31; x cannot overflow for a,b<p.
__device__ __forceinline__ uint32_t add(uint32_t a,uint32_t b){
 const uint32_t x=a+b,r=(x&modulus)+(x>>31);return r>=modulus?r-modulus:r;
}
__device__ __forceinline__ uint32_t mul(uint32_t a,uint32_t b){
 const uint32_t low=a*b,high=__umulhi(a,b);
 const uint32_t x=(low&modulus)+(low>>31)+(high<<1);
 const uint32_t r=(x&modulus)+(x>>31);return r>=modulus?r-modulus:r;
}'''
assert s.count(old)==1
if a.variant=='common-rotate':
 new="""__device__ __forceinline__ uint32_t add(uint32_t a,uint32_t b){return stwo::cuda::m31_add(a,b);}
__device__ __forceinline__ uint32_t mul(uint32_t a,uint32_t b){return stwo::cuda::m31_mul(a,b);}
__device__ __forceinline__ uint32_t mul_power2(uint32_t a,uint32_t k){return k?((a<<k)&modulus)|(a>>(31-k)):a;}"""
 s=s.replace('#include <stdint.h>','#include <stdint.h>\n#include "common/m31.cuh"').replace('mul(s[i],1u<<(i-1))','mul_power2(s[i],i-1)')
s=s.replace(old,new)
a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(s)
print(json.dumps(dict(source_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),generated_sha256=hashlib.sha256(s.encode()).hexdigest(),variant=a.variant,numerical_formula='production common/m31.cuh add/mul +exact31bitdiagonalrotate' if a.variant=='common-rotate' else 'mul_lo32/mul_hi32 + two Mersenne folds; canonical add32',production_selected=False)))
