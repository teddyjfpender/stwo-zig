// Field ABI for the shared authenticated framework emitter. No AIR equations.
#include "oods/field.cuh"
using uint = std::uint32_t;
using ulong = std::uint64_t;
struct RiscvQm31 { uint a, b, c, d; };
__device__ __forceinline__ uint riscv_m31_add(uint a, uint b) { return stwo::cuda::oods::add(a,b); }
__device__ __forceinline__ uint riscv_m31_sub(uint a, uint b) { return stwo::cuda::oods::sub(a,b); }
__device__ __forceinline__ uint riscv_m31_mul(uint a, uint b) { return stwo::cuda::oods::mul(a,b); }
__device__ __forceinline__ uint riscv_m31_neg(uint a) { return a == 0u ? 0u : 0x7fffffffu-a; }
__device__ __forceinline__ auto riscv_to_q(RiscvQm31 v) { return stwo::cuda::oods::QM31{{v.a,v.b},{v.c,v.d}}; }
__device__ __forceinline__ RiscvQm31 riscv_from_q(stwo::cuda::oods::QM31 v) { return {v.a.a,v.a.b,v.b.a,v.b.b}; }
__device__ __forceinline__ RiscvQm31 riscv_qm_add(RiscvQm31 a, RiscvQm31 b) { return riscv_from_q(stwo::cuda::oods::add(riscv_to_q(a),riscv_to_q(b))); }
__device__ __forceinline__ RiscvQm31 riscv_qm_sub(RiscvQm31 a, RiscvQm31 b) { return riscv_from_q(stwo::cuda::oods::sub(riscv_to_q(a),riscv_to_q(b))); }
__device__ __forceinline__ RiscvQm31 riscv_qm_mul(RiscvQm31 a, RiscvQm31 b) { return riscv_from_q(stwo::cuda::oods::mul(riscv_to_q(a),riscv_to_q(b))); }
__device__ __forceinline__ RiscvQm31 riscv_qm_mul_base(RiscvQm31 a, uint b) { return {riscv_m31_mul(a.a,b),riscv_m31_mul(a.b,b),riscv_m31_mul(a.c,b),riscv_m31_mul(a.d,b)}; }
__device__ __forceinline__ RiscvQm31 riscv_load_qm31(const uint *v, uint i) { return {v[i],v[i+1u],v[i+2u],v[i+3u]}; }
__device__ __forceinline__ ulong riscv_column_offset(uint column, uint rows, uint row) { return ulong(column)*rows+row; }
__device__ __forceinline__ uint riscv_previous_circle_row(uint row, uint rows, uint denominator_count) {
    const uint bits=uint(__ffs(rows)-1), half=rows/2u, step=denominator_count/2u;
    uint n=__brev(row)>>(32u-bits);
    n=n<half?(n+half-step)%half:((n-half+step)%half)+half;
    return __brev(n)>>(32u-bits);
}
