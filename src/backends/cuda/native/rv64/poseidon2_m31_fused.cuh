// Experimental, default-off, pipe-balanced Poseidon2-M31-W24 commitment
// kernels. Same pinned parameters, framing and outputs as poseidon2_m31.cuh:
// byte parity is gated by tests/cuda/rv64/poseidon2_m31_smoke.cu (KATs), the
// all-retained-node CPU reference (scripts/rv64_m8_poseidon_fused_bench.py)
// and a bit-exact u32 model with asserted fold bounds
// (scripts/rv64_m8_poseidon_fused_model.py). Selected only by compiling a
// numerical gate with STWO_P2_FUSED; no production PCS, transcript, PoW or
// profile selection is implied.
//
// Why this shape [M, tests/cuda/rv64/sm_int_pipes_probe.cu, RTX 5090 @2.55
// GHz]: LOP3/IADD3/SHF/LEA issue at 64 lanes/clk/SM on the integer ALU pipe;
// IMAD at 64 lanes/clk/SM on the separate FMA pipe, and the two overlap
// (LOP3+IMAD pairs 57.8 T inst/s vs 29.1-29.6 T for either alone);
// IMAD.WIDE and IMAD.HI are half rate; IADD.64 costs about two ALU slots. Mask/shift M31
// arithmetic is ALU-only, which bounded every earlier formulation (v1
// common-rotate, register-packed, weak-residue rewrites, tree sums, two
// rows per thread) at 15-16 ms on 479x2^20. Here:
//  * residues stay weak in [0, p] (p is a second zero) inside the
//    permutation; digests are canonicalised once;
//  * folds are x - h p, computed mod 2^32 as x + h * 0x80000001 (IMAD):
//    exact because every true result is < 2^32;
//  * u64 sums are split between IMAD.WIDE accumulates (x * 1 + acc, half
//    rate on the FMA pipe) and add.cc/addc carry chains on the ALU, never
//    IADD.64;
//  * multipliers come from __constant__ so ptxas cannot strength-reduce
//    them back into ALU shifts (with immediates it did: an IMAD-intent
//    build measured 18.404 ms vs 15.718 ms, more SHF/IADD3, no extra IMAD);
//  * the external layer is out_b = M4(x_b + X), X_j = sum_b x_{b,j}: one M4
//    per block instead of M4 per block plus column sums of M4 outputs.
//
// A/B record [M], 479x2^20 retained tree (2.0 GB slab, 44.0 M permutations),
// RTX 5090, CUDA events, median of 5; Blake2s control 1.364-1.376 ms:
//   v1 common-rotate (M7 baseline)               15.882 ms
//   register-packed v1                           15.140 ms
//   weak residues, ALU folds, unrolled rounds    17.354 ms  (I-cache bound)
//   weak residues, ALU folds, rolled rounds      15.874 ms
//   + pair/tree state sums                       15.718 ms
//   + two rows per thread in lockstep            16.263 ms  (rejected)
//   pipe-balanced (IMAD folds + IMAD.WIDE sums)  12.697 ms
//   + product-fold 2*hi as ALU shift-add         13.562 ms  (rejected)
//   + rotation sums (a << k) + s on ALU          12.263 ms
//   + round-constant folds on ALU (alone)        12.414 ms
//   + both                                       12.192 ms
//   + state sums as ALU carry chains (partial
//     rounds, 3 of 6 external M4 blocks)         11.814 ms  (this file)
//   12.192 ms build, two rows per thread         12.773 ms  (rejected)
//   pipe-balanced, fully unrolled rounds         illegal address in the
//     smoke (~26k SASS instructions; not investigated, rejected)
// Round loops stay rolled; one row per thread; 128 threads per block.
#pragma once
#include <stdint.h>
#include "poseidon2_m31.cuh"

namespace stwo { namespace cuda { namespace p2m31_fused {
using p2m31::modulus;
using p2m31::canonical;
using p2m31::transcript;

// [0] 1, [1] 2, [2] -p, [3] -2, [4] 2p, all mod 2^32.
static __device__ __constant__ uint32_t pipe_k[5] = {1u, 2u, 0x80000001u, 0xfffffffeu,
                                                     0xfffffffeu};
__device__ __forceinline__ uint32_t mad_lo(uint32_t a, uint32_t b, uint32_t c) {
    uint32_t d;
    asm("mad.lo.u32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
    return d;
}
__device__ __forceinline__ uint64_t mad_wide(uint32_t a, uint32_t b, uint64_t c) {
    uint64_t d;
    asm("mad.wide.u32 %0, %1, %2, %3;" : "=l"(d) : "r"(a), "r"(b), "l"(c));
    return d;
}
__device__ __forceinline__ uint64_t mul_wide(uint32_t a, uint32_t b) {
    uint64_t d;
    asm("mul.wide.u32 %0, %1, %2;" : "=l"(d) : "r"(a), "r"(b));
    return d;
}

// x <= 2^32 - 2  ->  [0, p], congruent mod p: x - (x >> 31) p on the FMA pipe.
__device__ __forceinline__ uint32_t fold32(uint32_t x) {
    return mad_lo(x >> 31, pipe_k[2], x);
}
// Same contract on the ALU pipe, used where the FMA pipe is the busier one.
__device__ __forceinline__ uint32_t fold32_alu(uint32_t x) {
    return (x & modulus) + (x >> 31);
}
// v = (hi:lo) with (lo & p) + (v >> 31) <= 2^32 - 2  ->  [0, p]. That sum is
// exactly lo + 2 hi - (lo >> 31) p, so wrapping mod 2^32 is harmless.
__device__ __forceinline__ uint32_t fold64(uint64_t v) {
    const uint32_t lo = uint32_t(v), hi = uint32_t(v >> 32);
    return fold32(mad_lo(lo >> 31, pipe_k[2], mad_lo(hi, pipe_k[1], lo)));
}
// Two-word accumulator on the ALU pipe: add.cc/addc carry chains (IADD3 with
// a carry predicate), for sums where the FMA pipe is the busier one.
struct Carry {
    uint32_t lo, hi;
};
__device__ __forceinline__ void carry_add(Carry& w, uint32_t x) {
    asm("add.cc.u32 %0, %0, %2;\n\taddc.u32 %1, %1, 0;" : "+r"(w.lo), "+r"(w.hi) : "r"(x));
}
__device__ __forceinline__ uint32_t fold_carry(Carry w) {
    return fold64((uint64_t(w.hi) << 32) | w.lo);
}
// u64 accumulate of a u32 on the FMA pipe.
__device__ __forceinline__ uint64_t acc(uint64_t sum, uint32_t x) {
    return mad_wide(x, pipe_k[0], sum);
}
__device__ __forceinline__ uint64_t widen(uint32_t x) {
    return mul_wide(x, pipe_k[0]);
}
// Weak operands in [0, p]: sum <= 2p = 2^32 - 2.
__device__ __forceinline__ uint32_t wadd(uint32_t a, uint32_t b) {
    return fold32(a + b);
}
// Weak operands in [0, p]: product <= p^2, (lo & p) + (v >> 31) <= 2^32 - 3.
__device__ __forceinline__ uint32_t wmul(uint32_t a, uint32_t b) {
    return fold64(mul_wide(a, b));
}
__device__ __forceinline__ uint32_t wfifth(uint32_t a) {
    const uint32_t square = wmul(a, a);
    return wmul(wmul(square, square), a);
}
// [0, p] -> canonical [0, p).
__device__ __forceinline__ uint32_t canon(uint32_t x) {
    return x == modulus ? 0u : x;
}
// sum + 2^k a for weak sum, a (0 <= k <= 22; true value <= 2p). The 31-bit
// rotation is a 2^k - (a >> (31 - k)) p, so this is (a << k) + sum on the
// ALU, then one IMAD, mod 2^32.
__device__ __forceinline__ uint32_t add_rot31(uint32_t sum, uint32_t a, uint32_t k) {
    return fold32(mad_lo(a >> (31 - k), pipe_k[2], (a << k) + sum));
}
// Round-constant addition, folded on the ALU.
__device__ __forceinline__ uint32_t add_rc(uint32_t a, uint32_t rc) {
    return fold32_alu(a + rc);
}

// M4 = circ(2,3,1,1) on one block of weak inputs z_j <= 2p (u32).
// out_j = T + z_j + 2 z_{j+1}, with T the block sum: < 14p < 2^35.
// External M4 blocks summed with ALU carry chains instead of FMA-pipe
// IMAD.WIDE (which is half rate: IMAD.WIDE+IADD3 pairs 0.575 ms vs 0.288 ms
// for IMAD+IADD3 in the probe). A/B [M] 479x2^20, with partial-round sums on
// the ALU: 0 blocks 11.921 ms, 3 blocks 11.814 ms, 6 blocks 12.253 ms.
static constexpr uint32_t alu_m4_blocks = 3;
__device__ __forceinline__ void m4_block_alu(uint32_t* s, const uint32_t z0,
                                             const uint32_t z1, const uint32_t z2,
                                             const uint32_t z3) {
    Carry t{z0, 0};
    carry_add(t, z1);
    carry_add(t, z2);
    carry_add(t, z3);
    const uint32_t z[4] = {z0, z1, z2, z3};
#pragma unroll
    for (uint32_t j = 0; j < 4; ++j) {
        Carry o = t;
        carry_add(o, z[j]);
        carry_add(o, z[(j + 1) & 3]);
        carry_add(o, z[(j + 1) & 3]);
        s[j] = fold_carry(o);
    }
}
__device__ __forceinline__ void m4_block(uint32_t* s, const uint32_t z0,
                                         const uint32_t z1, const uint32_t z2,
                                         const uint32_t z3) {
    const uint64_t t = acc(acc(acc(widen(z0), z1), z2), z3);
    s[0] = fold64(mad_wide(z1, pipe_k[1], acc(t, z0)));
    s[1] = fold64(mad_wide(z2, pipe_k[1], acc(t, z1)));
    s[2] = fold64(mad_wide(z3, pipe_k[1], acc(t, z2)));
    s[3] = fold64(mad_wide(z0, pipe_k[1], acc(t, z3)));
}

// External layer, out_b = 2 M4 x_b + sum_{b' != b} M4 x_b' = M4(x_b + X)
// with X_j = sum_b x_{b,j}. Inputs and outputs weak.
__device__ __forceinline__ void external(uint32_t* s) {
    uint32_t column[4];
#pragma unroll
    for (uint32_t j = 0; j < 4; ++j)  // pairs of weak residues fit u32 (<= 2p)
        column[j] = fold64(acc(acc(widen(s[j] + s[4 + j]), s[8 + j] + s[12 + j]),
                               s[16 + j] + s[20 + j]));
#pragma unroll
    for (uint32_t b = 0; b < 6; ++b) {
        if (b < alu_m4_blocks)
            m4_block_alu(s + 4 * b, s[4 * b] + column[0], s[4 * b + 1] + column[1],
                         s[4 * b + 2] + column[2], s[4 * b + 3] + column[3]);
        else
            m4_block(s + 4 * b, s[4 * b] + column[0], s[4 * b + 1] + column[1],
                     s[4 * b + 2] + column[2], s[4 * b + 3] + column[3]);
    }
}

__device__ __forceinline__ void full_round(uint32_t* s, const uint32_t* rc) {
#pragma unroll
    for (uint32_t i = 0; i < 24; ++i) s[i] = wfifth(add_rc(s[i], rc[i]));
    external(s);
}

// Internal layer: diag(p-2, 1, 2, ..., 2^22) + J.
__device__ __forceinline__ void partial_round(uint32_t* s, uint32_t rc) {
    s[0] = wfifth(add_rc(s[0], rc));
    // Twelve u32 pair sums (<= 2p each; the total is <= 24p < 2^36).
    uint32_t pair[12];
#pragma unroll
    for (uint32_t i = 0; i < 12; ++i) pair[i] = s[2 * i] + s[2 * i + 1];
    // Twelve pair sums into two ALU carry chains (IMAD.WIDE chains: 12.192
    // ms vs 11.921 ms [M] at 479x2^20).
    Carry wide[2] = {{pair[0], 0}, {pair[1], 0}};
#pragma unroll
    for (uint32_t i = 2; i < 12; ++i) carry_add(wide[i & 1], pair[i]);
    carry_add(wide[0], wide[1].lo);
    wide[0].hi += wide[1].hi;
    const uint32_t sum = fold_carry(wide[0]);
    s[0] = wadd(sum, fold32(mad_lo(s[0], pipe_k[3], pipe_k[4])));  // sum + (2p - 2 s0)
#pragma unroll
    for (uint32_t i = 1; i < 24; ++i) s[i] = add_rot31(sum, s[i], i - 1);
}

__device__ __forceinline__ void permute(uint32_t* s) {
    external(s);
#pragma unroll 1
    for (uint32_t r = 0; r < 4; ++r) full_round(s, p2m31::initial + 24 * r);
#pragma unroll 1
    for (uint32_t r = 0; r < 22; ++r) partial_round(s, p2m31::internal_rc[r]);
#pragma unroll 1
    for (uint32_t r = 0; r < 4; ++r) full_round(s, p2m31::final_rc + 24 * r);
}

__device__ __forceinline__ void hash_parent(const uint32_t* children, uint32_t* out) {
    uint32_t s[24] = {};
    s[22] = 1;
    s[23] = 2;
#pragma unroll
    for (uint32_t i = 0; i < 12; ++i) s[i] = children[i];
    permute(s);
#pragma unroll
    for (uint32_t i = 0; i < 6; ++i) s[i] = wadd(s[i], children[12 + i]);
    s[6] = wadd(s[6], 1);
    permute(s);
#pragma unroll
    for (uint32_t i = 0; i < 9; ++i) out[i] = canon(s[i]);
}

// Column-major source, row-major nine-limb digests (same as v1). One
// permutation call site: the padded final block runs through the same loop.
// Adjacent threads read adjacent rows, so every column load is coalesced.
static __global__ void leaves(const uint32_t* values, uint32_t columns,
                             uint32_t rows, uint32_t* out, uint32_t* status) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    uint32_t s[24] = {};
    s[22] = 1;
    s[23] = 1;
    uint32_t bad = 0;
    const uint32_t blocks = columns / 12 + 1;  // last block carries the marker
#pragma unroll 1
    for (uint32_t block = 0; block < blocks; ++block) {
        const uint32_t c = block * 12;
#pragma unroll
        for (uint32_t i = 0; i < 12; ++i) {
            uint32_t v = c + i == columns ? 1u : 0u;
            if (c + i < columns) {
                v = values[uint64_t(c + i) * rows + row];
                bad |= v >= modulus;
            }
            s[i] = wadd(s[i], v);
        }
        permute(s);
    }
    // Non-canonical input: flag, and write nothing (v1 contract).
    if (bad) { atomicOr(status, 1u); return; }
#pragma unroll
    for (uint32_t i = 0; i < 9; ++i) out[uint64_t(row) * 9 + i] = canon(s[i]);
}

static __global__ void parents(const uint32_t* children, uint32_t rows,
                              uint32_t* out, uint32_t* status) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    const uint32_t* source = children + uint64_t(row) * 18;
    if (!canonical(source, 18, status)) return;
    hash_parent(source, out + uint64_t(row) * 9);
}

static __global__ void permutations(const uint32_t* input, uint32_t count,
                                   uint32_t* out, uint32_t* status) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= count) return;
    const uint32_t* source = input + uint64_t(row) * 24;
    if (!canonical(source, 24, status)) return;
    uint32_t s[24];
#pragma unroll
    for (uint32_t i = 0; i < 24; ++i) s[i] = source[i];
    permute(s);
#pragma unroll
    for (uint32_t i = 0; i < 24; ++i) out[uint64_t(row) * 24 + i] = canon(s[i]);
}
}}}
