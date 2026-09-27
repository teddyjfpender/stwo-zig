#include "oods/field.cuh"
using uint=std::uint32_t;
using ulong=std::uint64_t;
constexpr uint RISCV_M31_P=0x7fffffffu;
constexpr int memory_order_relaxed=0;
struct RiscvQm31 { uint a,b,c,d; };
__device__ __forceinline__ void atomic_fetch_or_explicit(uint *p,uint v,int) { atomicOr(p,v); }
__device__ __forceinline__ uint ctz(uint v) { return uint(__ffs(v)-1); }
__device__ __forceinline__ uint riscv_bit_reverse(uint v,uint bits) { return bits==0u?v:__brev(v)>>(32u-bits); }
__device__ __forceinline__ auto riscv_to_q(RiscvQm31 v) { return stwo::cuda::oods::QM31{{v.a,v.b},{v.c,v.d}}; }
__device__ __forceinline__ RiscvQm31 riscv_from_q(stwo::cuda::oods::QM31 v) { return {v.a.a,v.a.b,v.b.a,v.b.b}; }
__device__ __forceinline__ uint riscv_m31_add(uint a,uint b) { return stwo::cuda::oods::add(a,b); }
__device__ __forceinline__ uint riscv_m31_mul(uint a,uint b) { return stwo::cuda::oods::mul(a,b); }
__device__ __forceinline__ RiscvQm31 riscv_qm_add(RiscvQm31 a,RiscvQm31 b) { return riscv_from_q(stwo::cuda::oods::add(riscv_to_q(a),riscv_to_q(b))); }
__device__ __forceinline__ RiscvQm31 riscv_qm_sub(RiscvQm31 a,RiscvQm31 b) { return riscv_from_q(stwo::cuda::oods::sub(riscv_to_q(a),riscv_to_q(b))); }
__device__ __forceinline__ RiscvQm31 riscv_qm_mul(RiscvQm31 a,RiscvQm31 b) { return riscv_from_q(stwo::cuda::oods::mul(riscv_to_q(a),riscv_to_q(b))); }
__device__ __forceinline__ RiscvQm31 riscv_qm_mul_base(RiscvQm31 v,uint s) { return {riscv_m31_mul(v.a,s),riscv_m31_mul(v.b,s),riscv_m31_mul(v.c,s),riscv_m31_mul(v.d,s)}; }
__device__ __forceinline__ RiscvQm31 framework_interaction_inverse(RiscvQm31 v) { return riscv_from_q(stwo::cuda::oods::inverse(riscv_to_q(v))); }
__device__ __forceinline__ RiscvQm31 riscv_load_qm31(const uint *v,uint i) { return {v[i],v[i+1u],v[i+2u],v[i+3u]}; }
__device__ __forceinline__ uint framework_interaction_row(uint logical,uint rows) { uint circle=(logical&1u)?rows-1u-logical/2u:logical/2u;return riscv_bit_reverse(circle,ctz(rows)); }
__device__ __forceinline__ uint riscv_previous_circle_row(uint row,uint rows,uint denoms) { uint bits=ctz(rows),n=riscv_bit_reverse(row,bits),half=rows/2u,step=denoms/2u;n=n<half?(n+half-step)%half:((n-half+step)%half)+half;return riscv_bit_reverse(n,bits); }
__device__ __forceinline__ void framework_interaction_store(uint *v,uint rows,uint batch,uint row,RiscvQm31 q) { ulong start=4ull*batch*rows+row;v[start]=q.a;v[start+rows]=q.b;v[start+2ull*rows]=q.c;v[start+3ull*rows]=q.d; }
extern "C" __global__ void stwo_cuda_range16_inverse_table_v1(const uint *z_words,uint *output) {
    uint value=blockIdx.x*blockDim.x+threadIdx.x;
    if(value>=65536u) return;
    RiscvQm31 denominator=riscv_qm_sub(RiscvQm31{value,0u,0u,0u},riscv_load_qm31(z_words,0u));
    bool pole=(denominator.a|denominator.b|denominator.c|denominator.d)==0u;
    RiscvQm31 inverse=pole?RiscvQm31{0u,0u,0u,0u}:framework_interaction_inverse(denominator);
    output[4u*value]=inverse.a;output[4u*value+1u]=inverse.b;output[4u*value+2u]=inverse.c;output[4u*value+3u]=inverse.d;
    output[262144u+value]=uint(pole);
}
