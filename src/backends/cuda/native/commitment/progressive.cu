// Extracted from the pinned Rust CUDA authority's progressive Blake2s path.
// The product form is allocation-free and requires the proof-owned stream.

#include "blake2s_core.cuh"

#include <cuda_runtime_api.h>

#include <stdint.h>

namespace stwo::cuda::blake2s {

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

    ProgressiveState state = states[row];
    uint32_t pending = pending_words(absorbed_before);
    uint64_t compressed_bytes =
        static_cast<uint64_t>(absorbed_before - pending) * sizeof(uint32_t);
    for (uint32_t column = 0; column < column_count; ++column) {
        if (pending == 16) {
            compressed_bytes += 64;
            compress(state.hash, state.pending, compressed_bytes, 0);
            pending = 0;
        }
        state.pending[pending++] = columns[column][row];
    }
    states[row] = state;
}

__global__ void progressive_finalize_kernel(
    uint32_t size,
    uint32_t absorbed_columns,
    const ProgressiveState *states,
    Hash *result) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= size) return;

    ProgressiveState state = states[row];
    const uint32_t pending = pending_words(absorbed_columns);
    for (uint32_t index = pending; index < 16; ++index) {
        state.pending[index] = 0;
    }
    compress(
        state.hash,
        state.pending,
        static_cast<uint64_t>(absorbed_columns) * sizeof(uint32_t),
        0xffffffffu);
#pragma unroll
    for (int index = 0; index < 8; ++index) {
        result[row].words[index] = state.hash[index];
    }
}

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
