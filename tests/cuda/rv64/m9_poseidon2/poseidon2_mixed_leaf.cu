// M9 (default-off: STWO_RV64_M9_POSEIDON2_LEAVES) Poseidon2-M31-W24 lifted
// Merkle leaves with the SAME layout contract as the Blake2s mixed_leaf_kernel
// in progressive.cu: the MixedSegment descriptor ABI (mixed_layout.h), the
// lifted source-row map, ordered segment/column absorption, power-of-two leaf
// domain and seeded prefix chaining. Hash framing is the experimental M7
// sponge (src/core/crypto/poseidon2_m31_sponge.zig: rate 12, capacity 12,
// domain word 1 for leaves at state[23], version 1 at state[22], additive
// absorption, mandatory 1-marker, 9-limb digest) and is byte-identical to the
// Zig reference src/core/vcs_lifted/poseidon2_m31_mixed_leaf.zig.
//
// Differences from the Blake contract, all forced by the hash:
//   * digests are 9 canonical M31 words (36 bytes), row-major;
//   * a prefix state is the 24-limb sponge state, stored word-major (SoA:
//     limb k of row r at k * rows + r). The absorb position is
//     absorbed % 12 and is owned by the caller; there are no pending words
//     because full rate blocks are permuted eagerly;
//   * every absorbed word must be canonical (< p). A violation sets bit 0 of
//     *status and the row's output is left unwritten (the caller must check).
// Nothing selects this file in the production PCS; see design doc
// design/riscv-proving-stack/rv64-m9-poseidon2-leaves.md for integration.
// STAGED OUTSIDE src/backends/cuda/native ON PURPOSE: the CUDA and CuMetal
// product builds compile every .cu under native/ (native_closure.py), so this
// file moves to native/commitment/ only at integration (after a CuMetal
// compile check). Build with -I src/backends/cuda/native.

#include "commitment/mixed_layout.h"
#include "commitment/resident_layout.cuh"
#include "rv64/poseidon2_m31_register.cuh"

#include <cuda_runtime_api.h>
#include <stdint.h>

namespace stwo::cuda::p2m31_mixed {

using blake2s::MixedSegment;
using blake2s::kMaxMixedSegments;
static constexpr uint32_t kBlock = 128;
static constexpr uint32_t kRate = 12;
static constexpr uint32_t kWidth = 24;
static constexpr uint32_t kDigest = 9;
static constexpr uint32_t P = p2m31::modulus;

struct MixedInputs {
    MixedSegment segments[kMaxMixedSegments];
};

__device__ __forceinline__ uint32_t lifted_row(uint32_t row, uint32_t log_ratio) {
    if (log_ratio == 0) return row;
    return ((row >> (log_ratio + 1u)) << 1u) | (row & 1u);
}

__device__ __forceinline__ uint32_t add(uint32_t a, uint32_t b) {
    const uint32_t s = a + b;
    return s < P ? s : s - P;
}
__device__ __forceinline__ uint32_t mul(uint32_t a, uint32_t b) {
    const uint64_t p = uint64_t(a) * b;
    const uint32_t f = uint32_t(p & P) + uint32_t(p >> 31);
    return f < P ? f : f - P;
}
__device__ __forceinline__ uint32_t fifth(uint32_t a) {
    const uint32_t q = mul(a, a);
    return mul(mul(q, q), a);
}
// Canonical a, 0 <= k <= 22: 2^k * a mod p is a 31-bit rotation.
__device__ __forceinline__ uint32_t rot(uint32_t a, uint32_t k) {
    return k ? ((a << k) & P) | (a >> (31 - k)) : a;
}
// x < 2^37: one fold then one correction gives the canonical residue.
__device__ __forceinline__ uint32_t reduce_sum(uint64_t x) {
    const uint32_t f = uint32_t(x & P) + uint32_t(x >> 31);
    return f < P ? f : f - P;
}

// Variant 2: fully unrolled rounds, u64 lane/column sums (one reduction per
// sum instead of one per addition). Same permutation as p2m31::permute.
__device__ __forceinline__ void external_v2(uint32_t* s) {
#pragma unroll
    for (uint32_t i = 0; i < kWidth; i += 4) {
        const uint32_t a = s[i], b = s[i + 1], c = s[i + 2], d = s[i + 3];
        const uint32_t ab = add(a, b), cd = add(c, d);
        const uint32_t all = add(ab, cd);
        const uint32_t all_b = add(all, b), all_d = add(all, d);
        s[i + 3] = add(all_d, add(a, a));
        s[i + 1] = add(all_b, add(c, c));
        s[i] = add(all_b, ab);
        s[i + 2] = add(all_d, cd);
    }
#pragma unroll
    for (uint32_t lane = 0; lane < 4; ++lane) {
        uint64_t sum = 0;
#pragma unroll
        for (uint32_t j = lane; j < kWidth; j += 4) sum += s[j];
        const uint32_t v = reduce_sum(sum);
#pragma unroll
        for (uint32_t j = lane; j < kWidth; j += 4) s[j] = add(s[j], v);
    }
}
__device__ __forceinline__ void full_v2(uint32_t* s, const uint32_t* rc) {
#pragma unroll
    for (uint32_t i = 0; i < kWidth; ++i) s[i] = fifth(add(s[i], rc[i]));
    external_v2(s);
}
__device__ __forceinline__ void partial_v2(uint32_t* s, uint32_t rc) {
    s[0] = fifth(add(s[0], rc));
    uint64_t acc = 0;
#pragma unroll
    for (uint32_t i = 0; i < kWidth; ++i) acc += s[i];
    const uint32_t sum = reduce_sum(acc);
    const uint32_t twice = add(s[0], s[0]);
    s[0] = add(sum, twice ? P - twice : 0);
#pragma unroll
    for (uint32_t i = 1; i < kWidth; ++i) s[i] = add(sum, rot(s[i], i - 1));
}
__device__ __forceinline__ void permute_v2(uint32_t* s) {
    external_v2(s);
#pragma unroll
    for (uint32_t r = 0; r < 4; ++r) full_v2(s, p2m31::initial + 24 * r);
#pragma unroll
    for (uint32_t r = 0; r < 22; ++r) partial_v2(s, p2m31::internal_rc[r]);
#pragma unroll
    for (uint32_t r = 0; r < 4; ++r) full_v2(s, p2m31::final_rc + 24 * r);
}

template <uint32_t Variant>
__device__ __forceinline__ void permute(uint32_t* s) {
    if constexpr (Variant == 2) permute_v2(s);
    else p2m31_register::permute(s);
}

// Static-register absorb at a runtime position (no local-memory indexing).
__device__ __forceinline__ void absorb_at(uint32_t* s, uint32_t at, uint32_t v) {
#pragma unroll
    for (uint32_t i = 0; i < kRate; ++i)
        if (i == at) s[i] = add(s[i], v);
}

template <uint32_t Variant>
__global__ void __launch_bounds__(kBlock) mixed_leaf_kernel(
    uint32_t size, uint32_t count, MixedInputs inputs, uint32_t absorbed_before,
    uint32_t seed_size, const uint32_t* __restrict__ seed,
    uint32_t* __restrict__ prefix, uint32_t* __restrict__ result,
    uint32_t* __restrict__ status) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;
    uint32_t s[kWidth];
    if (seed != nullptr) {
        const uint32_t seed_row = lifted_row(row, __ffs(size / seed_size) - 1);
#pragma unroll
        for (uint32_t k = 0; k < kWidth; ++k) s[k] = seed[size_t(k) * seed_size + seed_row];
    } else {
#pragma unroll
        for (uint32_t k = 0; k < kWidth; ++k) s[k] = 0;
        s[22] = 1;
        s[23] = 1;  // Domain::leaf
    }
    uint32_t at = absorbed_before % kRate;
    bool bad = false;
    for (uint32_t segment = 0; segment < count; ++segment) {
        const MixedSegment in = inputs.segments[segment];
        const uint32_t source_row = lifted_row(row, __ffs(size / in.source_size) - 1);
        const uint32_t columns = uint32_t(in.capacity_words / in.stride_words);
        const uint32_t* base = in.columns + source_row;
        uint32_t column = 0;
        // Head: fill the open rate block one word at a time.
        for (; column < columns && at != 0; ++column) {
            const uint32_t v = base[size_t(column) * in.stride_words];
            bad |= v >= P;
            absorb_at(s, at, v);
            if (++at == kRate) { permute<Variant>(s); at = 0; }
        }
        // Body: whole rate blocks straight into registers.
        for (; column + kRate <= columns; column += kRate) {
#pragma unroll
            for (uint32_t i = 0; i < kRate; ++i) {
                const uint32_t v = base[size_t(column + i) * in.stride_words];
                bad |= v >= P;
                s[i] = add(s[i], v);
            }
            permute<Variant>(s);
        }
        // Tail: fewer than 12 words remain; at == 0 here.
        for (; column < columns; ++column) {
            const uint32_t v = base[size_t(column) * in.stride_words];
            bad |= v >= P;
            absorb_at(s, at, v);
            ++at;
        }
    }
    if (bad) { atomicOr(status, 1u); return; }
    if (prefix != nullptr) {
#pragma unroll
        for (uint32_t k = 0; k < kWidth; ++k) prefix[size_t(k) * size + row] = s[k];
        return;
    }
    absorb_at(s, at, 1u);  // mandatory marker; at == 0 adds an extra block
    permute<Variant>(s);
#pragma unroll
    for (uint32_t k = 0; k < kDigest; ++k) result[size_t(row) * kDigest + k] = s[k];
}

template <uint32_t Variant>
__global__ void __launch_bounds__(kBlock) parent_kernel(
    const uint32_t* __restrict__ children, uint32_t rows, uint32_t* __restrict__ out) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    const uint32_t* c = children + size_t(row) * 18;
    uint32_t s[kWidth] = {};
    s[22] = 1;
    s[23] = 2;  // Domain::node
#pragma unroll
    for (uint32_t i = 0; i < 12; ++i) s[i] = c[i];
    permute<Variant>(s);
#pragma unroll
    for (uint32_t i = 0; i < 6; ++i) s[i] = add(s[i], c[12 + i]);
    s[6] = add(s[6], 1);
    permute<Variant>(s);
#pragma unroll
    for (uint32_t i = 0; i < kDigest; ++i) out[size_t(row) * kDigest + i] = s[i];
}

inline uint32_t blocks(uint32_t n) { return (n - 1) / kBlock + 1; }

}  // namespace stwo::cuda::p2m31_mixed

// Host entry. Validation mirrors stwo_blake2s_mixed_seeded_eager_compact_on:
// power-of-two sizes, at most kMaxMixedSegments, exact column slabs, no
// overlap between sources and outputs, explicit word capacities.
// variant: 1 = p2m31_register::permute (M7 rotate baseline), 2 = unrolled/u64-sum.
extern "C" int stwo_p2m31_mixed_seeded_on(
    uint32_t size, uint32_t count,
    const stwo::cuda::blake2s::MixedSegment* segments,
    uint32_t absorbed_before, uint32_t seed_size,
    const uint32_t* seed, uint64_t seed_capacity_words,
    uint32_t* prefix, uint64_t prefix_capacity_words,
    uint32_t* result, uint64_t result_capacity_words,
    uint32_t* status, uint32_t variant, void* stream) {
    using namespace stwo::cuda::blake2s;
    namespace X = stwo::cuda::p2m31_mixed;
    if (!stream || !segments || !status || size < 2 || size > (1u << 28) ||
        (size & (size - 1)) || count > kMaxMixedSegments ||
        ((prefix == nullptr) == (result == nullptr)) ||
        (!prefix && prefix_capacity_words) || (!result && result_capacity_words) ||
        (variant != 1 && variant != 2))
        return int(cudaErrorInvalidValue);
    X::MixedInputs inputs{};
    uint64_t words = absorbed_before;
    DeviceRange sources[kMaxMixedSegments]{};
    for (uint32_t i = 0; i < count; ++i) {
        const auto s = segments[i];
        uint32_t columns = 0;
        if (s.reserved || s.source_size < 2 || s.source_size > size ||
            (s.source_size & (s.source_size - 1)) ||
            !exact_word_slab_range(s.columns, s.capacity_words, s.stride_words,
                                   s.source_size, &columns, &sources[i]))
            return int(cudaErrorInvalidValue);
        words += columns;
        if (words > UINT32_MAX) return int(cudaErrorInvalidValue);
        inputs.segments[i] = s;
    }
    DeviceRange output_range{}, previous{};
    const uint64_t needed = uint64_t(size) * (prefix ? X::kWidth : X::kDigest);
    const uint64_t capacity = prefix ? prefix_capacity_words : result_capacity_words;
    uint32_t* output = prefix ? prefix : result;
    if (capacity < needed || capacity > SIZE_MAX / 4 ||
        !element_range(output, size_t(capacity), &output_range))
        return int(cudaErrorInvalidValue);
    if (seed) {
        if (!absorbed_before || seed_size < 2 || seed_size > size ||
            (seed_size & (seed_size - 1)) ||
            seed_capacity_words < uint64_t(seed_size) * X::kWidth ||
            seed_capacity_words > SIZE_MAX / 4 ||
            !element_range(seed, size_t(seed_capacity_words), &previous) ||
            ranges_overlap(previous, output_range))
            return int(cudaErrorInvalidValue);
    } else if (absorbed_before || seed_size || seed_capacity_words) {
        return int(cudaErrorInvalidValue);
    }
    for (uint32_t i = 0; i < count; ++i)
        if (ranges_overlap(sources[i], output_range)) return int(cudaErrorInvalidValue);
    auto st = reinterpret_cast<cudaStream_t>(stream);
    if (variant == 2)
        X::mixed_leaf_kernel<2><<<X::blocks(size), X::kBlock, 0, st>>>(
            size, count, inputs, absorbed_before, seed_size, seed, prefix, result, status);
    else
        X::mixed_leaf_kernel<1><<<X::blocks(size), X::kBlock, 0, st>>>(
            size, count, inputs, absorbed_before, seed_size, seed, prefix, result, status);
    return int(cudaPeekAtLastError());
}

// One Merkle layer: rows parents from 2*rows row-major 9-word children.
extern "C" int stwo_p2m31_parent_layer_on(const uint32_t* children, uint32_t rows,
                                          uint32_t* out, uint32_t variant, void* stream) {
    namespace X = stwo::cuda::p2m31_mixed;
    if (!stream || !children || !out || !rows || (variant != 1 && variant != 2))
        return int(cudaErrorInvalidValue);
    auto st = reinterpret_cast<cudaStream_t>(stream);
    if (variant == 2) X::parent_kernel<2><<<X::blocks(rows), X::kBlock, 0, st>>>(children, rows, out);
    else X::parent_kernel<1><<<X::blocks(rows), X::kBlock, 0, st>>>(children, rows, out);
    return int(cudaPeekAtLastError());
}
