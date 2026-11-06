// Experimental numerical-only, default-off packed-rate implementation.
// Same pinned parameters and leaf/node framing as poseidon2_m31.cuh.
// Compile the numerical gates with STWO_P2_REGISTER_PACKED to select it.
// No production PCS, transcript-v2, PoW or native-profile selection is implied.
#pragma once
#include "poseidon2_m31.cuh"
#include "common/m31.cuh"

namespace stwo { namespace cuda { namespace p2m31_register {
using p2m31::modulus;
using p2m31::canonical;
// The transcript gate remains the unchanged v1 u64-counter reference. This
// experiment tunes only permutations and leaf/parent commitments.
using p2m31::transcript;

__device__ __forceinline__ uint32_t add(uint32_t a, uint32_t b) {
    return m31_add(a, b);
}
__device__ __forceinline__ uint32_t mul(uint32_t a, uint32_t b) {
    return m31_mul(a, b);
}
__device__ __forceinline__ uint32_t fifth(uint32_t a) {
    const uint32_t square = mul(a, a);
    return mul(mul(square, square), a);
}
__device__ __forceinline__ uint32_t mul_power2(uint32_t a, uint32_t k) {
    // Canonical M31 a, 0<=k<=22: exact rotation in the 31-bit residue.
    return k ? ((a << k) & modulus) | (a >> (31 - k)) : a;
}

__device__ __forceinline__ void external(uint32_t* state) {
#pragma unroll
    for (uint32_t i = 0; i < 24; i += 4) {
        const uint32_t a = state[i], b = state[i + 1];
        const uint32_t c = state[i + 2], d = state[i + 3];
        const uint32_t ab = add(a, b), cd = add(c, d);
        const uint32_t all = add(ab, cd);
        const uint32_t all_b = add(all, b), all_d = add(all, d);
        state[i + 3] = add(all_d, add(a, a));
        state[i + 1] = add(all_b, add(c, c));
        state[i] = add(all_b, ab);
        state[i + 2] = add(all_d, cd);
    }
#pragma unroll
    for (uint32_t i = 0; i < 4; ++i) {
        uint32_t sum = 0;
#pragma unroll
        for (uint32_t j = i; j < 24; j += 4) sum = add(sum, state[j]);
#pragma unroll
        for (uint32_t j = i; j < 24; j += 4) state[j] = add(state[j], sum);
    }
}

__device__ __forceinline__ void permute(uint32_t* state) {
    external(state);
    // Round loops stay rolled to bound code size. Every state index within
    // a round is compile-time unrolled; register residency must be measured.
#pragma unroll 1
    for (uint32_t round = 0; round < 4; ++round) {
#pragma unroll
        for (uint32_t i = 0; i < 24; ++i)
            state[i] = fifth(add(state[i], p2m31::initial[24 * round + i]));
        external(state);
    }
#pragma unroll 1
    for (uint32_t round = 0; round < 22; ++round) {
        state[0] = fifth(add(state[0], p2m31::internal_rc[round]));
        uint32_t sum = 0;
#pragma unroll
        for (uint32_t i = 0; i < 24; ++i) sum = add(sum, state[i]);
        state[0] = add(sum, m31_neg(add(state[0], state[0])));
#pragma unroll
        for (uint32_t i = 1; i < 24; ++i)
            state[i] = add(sum, mul_power2(state[i], i - 1));
    }
#pragma unroll 1
    for (uint32_t round = 0; round < 4; ++round) {
#pragma unroll
        for (uint32_t i = 0; i < 24; ++i)
            state[i] = fifth(add(state[i], p2m31::final_rc[24 * round + i]));
        external(state);
    }
}

// Caller has checked all eighteen limbs. Exactly one full rate block, then
// six remaining limbs and the mandatory marker: two permutations, as before.
__device__ __forceinline__ void hash_parent(const uint32_t* children, uint32_t* out) {
    uint32_t state[24] = {};
    state[22] = 1;
    state[23] = 2;
#pragma unroll
    for (uint32_t i = 0; i < 12; ++i) state[i] = children[i];
    permute(state);
#pragma unroll
    for (uint32_t i = 0; i < 6; ++i) state[i] = add(state[i], children[12 + i]);
    state[6] = add(state[6], 1);
    permute(state);
#pragma unroll
    for (uint32_t i = 0; i < 9; ++i) out[i] = state[i];
}

// Column-major source, row-major nine-limb digests. No dynamic state[at].
static __global__ void leaves(const uint32_t* values, uint32_t columns,
                             uint32_t rows, uint32_t* out, uint32_t* status) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    uint32_t state[24] = {};
    state[22] = 1;
    state[23] = 1;
    const uint32_t full_columns = columns - columns % 12;
    for (uint32_t column = 0; column < full_columns; column += 12) {
#pragma unroll
        for (uint32_t i = 0; i < 12; ++i) {
            const uint32_t value = values[uint64_t(column + i) * rows + row];
            if (value >= modulus) { atomicOr(status, 1u); return; }
            state[i] = add(state[i], value);
        }
        permute(state);
    }
    const uint32_t remainder = columns % 12;
#pragma unroll
    for (uint32_t i = 0; i < 12; ++i) {
        if (i < remainder) {
            const uint32_t value = values[uint64_t(full_columns + i) * rows + row];
            if (value >= modulus) { atomicOr(status, 1u); return; }
            state[i] = add(state[i], value);
        }
        if (i == remainder) state[i] = add(state[i], 1);
    }
    permute(state);
#pragma unroll
    for (uint32_t i = 0; i < 9; ++i) out[uint64_t(row) * 9 + i] = state[i];
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
    uint32_t state[24];
#pragma unroll
    for (uint32_t i = 0; i < 24; ++i) state[i] = source[i];
    permute(state);
#pragma unroll
    for (uint32_t i = 0; i < 24; ++i) out[uint64_t(row) * 24 + i] = state[i];
}
}}}
