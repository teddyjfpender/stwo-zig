#!/usr/bin/env python3
"""Generate a benchmark-only, byte-equivalent M31 CUDA arithmetic variant."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
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
assert s.count(old)==1;s=s.replace(old,new)
a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(s)
print(json.dumps(dict(source_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),generated_sha256=hashlib.sha256(s.encode()).hexdigest(),numerical_formula='mul_lo32/mul_hi32 + two Mersenne folds; canonical add32',production_selected=False)))
