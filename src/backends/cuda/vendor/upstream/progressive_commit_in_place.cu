#include "blake2s.cuh"

#include <cuda_runtime.h>

// Single-slab progressive commitment primitives. The pure Rust planner in
// progressive_commit_in_place.rs is the source of truth for these geometric
// bands. Every kernel launch reads and writes disjoint byte ranges; stream
// order permits an earlier band to overwrite only already-consumed sources.

namespace {

constexpr uint32_t kBlockSize = 256;

uint32_t blocks_for(uint32_t size) {
    return (size + kBlockSize - 1) / kBlockSize;
}

__global__ void progressive_expand_pair_band(
    uint32_t source_pair_first,
    uint32_t destination_pair_first,
    uint32_t pair_count,
    uint32_t expansion,
    const ProgressiveBlake2sState *sources,
    ProgressiveBlake2sState *destinations) {
    const uint32_t local = blockIdx.x * blockDim.x + threadIdx.x;
    if (local >= pair_count) return;

    const uint32_t source_pair = source_pair_first + local;
    // Both sources are in registers before the first destination write.
    const ProgressiveBlake2sState even = sources[2 * source_pair];
    const ProgressiveBlake2sState odd = sources[2 * source_pair + 1];
    const uint32_t destination_pair = destination_pair_first + local;
    const uint32_t first_row = 2 * expansion * destination_pair;
    for (uint32_t child = 0; child < expansion; ++child) {
        destinations[first_row + 2 * child] = even;
        destinations[first_row + 2 * child + 1] = odd;
    }
}

int launch_expand_band(
    uint32_t source_pair_first,
    uint32_t destination_pair_first,
    uint32_t pair_count,
    uint32_t expansion,
    const ProgressiveBlake2sState *sources,
    ProgressiveBlake2sState *destinations,
    cudaStream_t stream) {
    progressive_expand_pair_band<<<blocks_for(pair_count), kBlockSize, 0, stream>>>(
        source_pair_first,
        destination_pair_first,
        pair_count,
        expansion,
        sources,
        destinations);
    return cudaGetLastError();
}

__global__ void compact_expand_pair_band(
    uint32_t source_pair_first,
    uint32_t destination_pair_first,
    uint32_t pair_count,
    uint32_t expansion,
    const Blake2sHash *sources,
    Blake2sHash *destinations) {
    const uint32_t local = blockIdx.x * blockDim.x + threadIdx.x;
    if (local >= pair_count) return;

    const uint32_t source_pair = source_pair_first + local;
    const Blake2sHash even = sources[2 * source_pair];
    const Blake2sHash odd = sources[2 * source_pair + 1];
    const uint32_t destination_pair = destination_pair_first + local;
    const uint32_t first_row = 2 * expansion * destination_pair;
    for (uint32_t child = 0; child < expansion; ++child) {
        destinations[first_row + 2 * child] = even;
        destinations[first_row + 2 * child + 1] = odd;
    }
}

int launch_compact_expand_band(
    uint32_t source_pair_first,
    uint32_t destination_pair_first,
    uint32_t pair_count,
    uint32_t expansion,
    const Blake2sHash *sources,
    Blake2sHash *destinations,
    cudaStream_t stream) {
    compact_expand_pair_band<<<blocks_for(pair_count), kBlockSize, 0, stream>>>(
        source_pair_first,
        destination_pair_first,
        pair_count,
        expansion,
        sources,
        destinations);
    return cudaGetLastError();
}

}  // namespace

extern "C" int stwo_blake2s_progressive_expand_in_place_on(
    uint32_t from_log_size,
    uint32_t to_log_size,
    ProgressiveBlake2sState *states,
    ProgressiveBlake2sState *scratch_pair,
    void *stream) {
    if (from_log_size == 0 || from_log_size >= to_log_size ||
        to_log_size >= 31 || states == nullptr || scratch_pair == nullptr ||
        states == scratch_pair || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    cudaError_t error = cudaMemcpyAsync(
        scratch_pair,
        states,
        2 * sizeof(ProgressiveBlake2sState),
        cudaMemcpyDeviceToDevice,
        cuda_stream);
    if (error != cudaSuccess) return error;

    const uint32_t expansion = 1u << (to_log_size - from_log_size);
    uint32_t pair_end = 1u << (from_log_size - 1);
    while (pair_end > 1) {
        const uint32_t pair_begin = (pair_end + expansion - 1) / expansion;
        error = static_cast<cudaError_t>(launch_expand_band(
            pair_begin,
            pair_begin,
            pair_end - pair_begin,
            expansion,
            states,
            states,
            cuda_stream));
        if (error != cudaSuccess) return error;
        pair_end = pair_begin;
    }
    return launch_expand_band(
        0, 0, 1, expansion, scratch_pair, states, cuda_stream);
}

extern "C" int stwo_blake2s_compact_expand_in_place_on(
    uint32_t from_log_size,
    uint32_t to_log_size,
    Blake2sHash *states,
    Blake2sHash *scratch_pair,
    void *stream) {
    if (from_log_size == 0 || from_log_size >= to_log_size ||
        to_log_size >= 31 || states == nullptr || scratch_pair == nullptr ||
        states == scratch_pair || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    cudaError_t error = cudaMemcpyAsync(
        scratch_pair,
        states,
        2 * sizeof(Blake2sHash),
        cudaMemcpyDeviceToDevice,
        cuda_stream);
    if (error != cudaSuccess) return error;

    const uint32_t expansion = 1u << (to_log_size - from_log_size);
    uint32_t pair_end = 1u << (from_log_size - 1);
    while (pair_end > 1) {
        const uint32_t pair_begin = (pair_end + expansion - 1) / expansion;
        error = static_cast<cudaError_t>(launch_compact_expand_band(
            pair_begin,
            pair_begin,
            pair_end - pair_begin,
            expansion,
            states,
            states,
            cuda_stream));
        if (error != cudaSuccess) return error;
        pair_end = pair_begin;
    }
    return launch_compact_expand_band(
        0, 0, 1, expansion, scratch_pair, states, cuda_stream);
}

extern "C" int stwo_blake2s_progressive_finalize_in_place_on(
    uint32_t size,
    uint32_t absorbed_columns,
    ProgressiveBlake2sState *states_and_hashes,
    ProgressiveBlake2sState *scratch_pair,
    void *stream) {
    if (size == 0 || (size & (size - 1)) != 0 ||
        states_and_hashes == nullptr || scratch_pair == nullptr ||
        states_and_hashes == scratch_pair || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    cudaError_t error = cudaMemcpyAsync(
        scratch_pair,
        states_and_hashes,
        sizeof(ProgressiveBlake2sState),
        cudaMemcpyDeviceToDevice,
        cuda_stream);
    if (error != cudaSuccess) return error;

    Blake2sHash *hashes = reinterpret_cast<Blake2sHash *>(states_and_hashes);
    uint32_t first = 1;
    while (first < size) {
        const uint32_t end = min(size, 3 * first);
        error = static_cast<cudaError_t>(stwo_blake2s_progressive_finalize_on(
            end - first,
            absorbed_columns,
            states_and_hashes + first,
            hashes + first,
            stream));
        if (error != cudaSuccess) return error;
        first = end;
    }
    return stwo_blake2s_progressive_finalize_on(
        1, absorbed_columns, scratch_pair, hashes, stream);
}

extern "C" int stwo_blake2s_layer_in_place_on(
    uint32_t output_size,
    Blake2sHash *hashes,
    ProgressiveBlake2sState *scratch_pair,
    void *stream) {
    if (output_size == 0 || (output_size & (output_size - 1)) != 0 ||
        hashes == nullptr || scratch_pair == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    cudaError_t error = cudaMemcpyAsync(
        scratch_pair,
        hashes,
        2 * sizeof(Blake2sHash),
        cudaMemcpyDeviceToDevice,
        cuda_stream);
    if (error != cudaSuccess) return error;

    uint32_t first = 1;
    while (first < output_size) {
        const uint32_t end = min(output_size, 2 * first);
        error = static_cast<cudaError_t>(stwo_blake2s_layer_on(
            hashes + 2 * first,
            end - first,
            hashes + first,
            stream));
        if (error != cudaSuccess) return error;
        first = end;
    }
    return stwo_blake2s_layer_on(
        reinterpret_cast<const Blake2sHash *>(scratch_pair), 1, hashes, stream);
}
