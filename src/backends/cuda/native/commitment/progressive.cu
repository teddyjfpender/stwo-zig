// Extracted from the pinned Rust CUDA authority's progressive Blake2s path.
// The product form is allocation-free and requires the proof-owned stream.

#include "blake2s_core.cuh"
#include "progressive_scalar.cuh"

#include <cuda_runtime_api.h>

#include <stdint.h>

namespace stwo::cuda::blake2s {

#define STWO_LOAD_PROGRESSIVE(state) \
    uint32_t h0 = state.hash[0];      \
    uint32_t h1 = state.hash[1];      \
    uint32_t h2 = state.hash[2];      \
    uint32_t h3 = state.hash[3];      \
    uint32_t h4 = state.hash[4];      \
    uint32_t h5 = state.hash[5];      \
    uint32_t h6 = state.hash[6];      \
    uint32_t h7 = state.hash[7];      \
    uint32_t p0 = state.pending[0];   \
    uint32_t p1 = state.pending[1];   \
    uint32_t p2 = state.pending[2];   \
    uint32_t p3 = state.pending[3];   \
    uint32_t p4 = state.pending[4];   \
    uint32_t p5 = state.pending[5];   \
    uint32_t p6 = state.pending[6];   \
    uint32_t p7 = state.pending[7];   \
    uint32_t p8 = state.pending[8];   \
    uint32_t p9 = state.pending[9];   \
    uint32_t p10 = state.pending[10]; \
    uint32_t p11 = state.pending[11]; \
    uint32_t p12 = state.pending[12]; \
    uint32_t p13 = state.pending[13]; \
    uint32_t p14 = state.pending[14]; \
    uint32_t p15 = state.pending[15]

#define STWO_COMPRESS_PROGRESSIVE(counter, last)                          \
    progressive_compress(                                                 \
        h0,h1,h2,h3,h4,h5,h6,h7,                                         \
        p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,          \
        counter,last)

#define STWO_STORE_PROGRESSIVE(state) \
    state.hash[0] = h0;               \
    state.hash[1] = h1;               \
    state.hash[2] = h2;               \
    state.hash[3] = h3;               \
    state.hash[4] = h4;               \
    state.hash[5] = h5;               \
    state.hash[6] = h6;               \
    state.hash[7] = h7;               \
    state.pending[0] = p0;            \
    state.pending[1] = p1;            \
    state.pending[2] = p2;            \
    state.pending[3] = p3;            \
    state.pending[4] = p4;            \
    state.pending[5] = p5;            \
    state.pending[6] = p6;            \
    state.pending[7] = p7;            \
    state.pending[8] = p8;            \
    state.pending[9] = p9;            \
    state.pending[10] = p10;          \
    state.pending[11] = p11;          \
    state.pending[12] = p12;          \
    state.pending[13] = p13;          \
    state.pending[14] = p14;          \
    state.pending[15] = p15

__host__ __device__ constexpr uint32_t pending_words(
    uint32_t absorbed_columns) {
    return absorbed_columns == 0 ? 0 : ((absorbed_columns - 1) & 15u) + 1;
}

__global__ void progressive_init_kernel(
    uint32_t size,
    ProgressiveState *states) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;
    ProgressiveState state{};
    initialize(state.hash);
    states[row] = state;
}

__global__ void progressive_absorb_kernel(
    uint32_t size,
    uint32_t column_count,
    uint32_t absorbed_before,
    uint32_t **columns,
    ProgressiveState *states) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;

    ProgressiveState &state = states[row];
    STWO_LOAD_PROGRESSIVE(state);
    uint32_t pending = pending_words(absorbed_before);
    uint64_t compressed_bytes =
        static_cast<uint64_t>(absorbed_before - pending) * sizeof(uint32_t);
    for (uint32_t column = 0; column < column_count; ++column) {
        if (pending == 16) {
            compressed_bytes += 64;
            STWO_COMPRESS_PROGRESSIVE(compressed_bytes, 0);
            pending = 0;
        }
        const uint32_t word = columns[column][row];
        switch (pending++) {
            case 0: p0 = word; break;
            case 1: p1 = word; break;
            case 2: p2 = word; break;
            case 3: p3 = word; break;
            case 4: p4 = word; break;
            case 5: p5 = word; break;
            case 6: p6 = word; break;
            case 7: p7 = word; break;
            case 8: p8 = word; break;
            case 9: p9 = word; break;
            case 10: p10 = word; break;
            case 11: p11 = word; break;
            case 12: p12 = word; break;
            case 13: p13 = word; break;
            case 14: p14 = word; break;
            default: p15 = word; break;
        }
    }
    STWO_STORE_PROGRESSIVE(state);
}

__global__ void progressive_finalize_kernel(
    uint32_t size,
    uint32_t absorbed_columns,
    const ProgressiveState *states,
    Hash *result) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;

    const ProgressiveState &state = states[row];
    STWO_LOAD_PROGRESSIVE(state);
    const uint32_t pending = pending_words(absorbed_columns);
    if (pending < 1) p0 = 0;
    if (pending < 2) p1 = 0;
    if (pending < 3) p2 = 0;
    if (pending < 4) p3 = 0;
    if (pending < 5) p4 = 0;
    if (pending < 6) p5 = 0;
    if (pending < 7) p6 = 0;
    if (pending < 8) p7 = 0;
    if (pending < 9) p8 = 0;
    if (pending < 10) p9 = 0;
    if (pending < 11) p10 = 0;
    if (pending < 12) p11 = 0;
    if (pending < 13) p12 = 0;
    if (pending < 14) p13 = 0;
    if (pending < 15) p14 = 0;
    if (pending < 16) p15 = 0;
    STWO_COMPRESS_PROGRESSIVE(
        static_cast<uint64_t>(absorbed_columns) * sizeof(uint32_t),
        0xffffffffu);
    result[row].words[0] = h0;
    result[row].words[1] = h1;
    result[row].words[2] = h2;
    result[row].words[3] = h3;
    result[row].words[4] = h4;
    result[row].words[5] = h5;
    result[row].words[6] = h6;
    result[row].words[7] = h7;
}

#undef STWO_STORE_PROGRESSIVE
#undef STWO_COMPRESS_PROGRESSIVE
#undef STWO_LOAD_PROGRESSIVE

}  // namespace stwo::cuda::blake2s

extern "C" int stwo_blake2s_progressive_init_on(
    uint32_t size,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    if (size == 0 || states == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::blake2s::progressive_init_kernel<<<
        stwo::cuda::blake2s::blocks_for(size),
        stwo::cuda::blake2s::kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(size, states);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_progressive_absorb_on(
    uint32_t size,
    uint32_t column_count,
    uint32_t absorbed_before,
    uint32_t **columns,
    stwo::cuda::blake2s::ProgressiveState *states,
    void *stream) {
    if (size == 0 || column_count == 0 || columns == nullptr ||
        states == nullptr || stream == nullptr ||
        absorbed_before > UINT32_MAX - column_count) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::blake2s::progressive_absorb_kernel<<<
        stwo::cuda::blake2s::blocks_for(size),
        stwo::cuda::blake2s::kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            size,
            column_count,
            absorbed_before,
            columns,
            states);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_progressive_finalize_on(
    uint32_t size,
    uint32_t absorbed_columns,
    const stwo::cuda::blake2s::ProgressiveState *states,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    if (size == 0 || states == nullptr || result == nullptr ||
        stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::blake2s::progressive_finalize_kernel<<<
        stwo::cuda::blake2s::blocks_for(size),
        stwo::cuda::blake2s::kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            size,
            absorbed_columns,
            states,
            result);
    return static_cast<int>(cudaPeekAtLastError());
}
