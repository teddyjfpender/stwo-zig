// Blake2s semantics derive from the pinned Rust CUDA authority. These kernels
// operate only on checked caller-owned device ranges and proof streams.

#include "blake2s_core.cuh"
#include "resident_layout.cuh"

#include <cuda_runtime_api.h>

#include <stdint.h>

namespace stwo::cuda::blake2s {

__global__ void child_layer_kernel(
    const Hash *previous,
    uint32_t output_size,
    Hash *result) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= output_size) return;
    result[index] = hash_children(previous[2 * index], previous[2 * index + 1]);
}

__global__ void fri_leaf_kernel(
    uint32_t evaluation_size,
    const uint32_t *coordinates,
    size_t coordinate_stride_words,
    uint32_t log_rows_per_leaf,
    Hash *result) {
    const uint32_t leaf = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t leaf_count = evaluation_size >> log_rows_per_leaf;
    if (leaf >= leaf_count) return;

    uint32_t hash[8];
    uint32_t message[16] = {};
    initialize(hash);
    if (log_rows_per_leaf == 0) {
#pragma unroll
        for (int coordinate = 0; coordinate < 4; ++coordinate) {
            message[coordinate] =
                coordinates[
                    static_cast<size_t>(coordinate) *
                        coordinate_stride_words +
                    leaf];
        }
        compress(hash, message, 16, 0xffffffffu);
    } else {
#pragma unroll
        for (int offset = 0; offset < 4; ++offset) {
#pragma unroll
            for (int coordinate = 0; coordinate < 4; ++coordinate) {
                message[coordinate + 4 * offset] =
                    coordinates[
                        static_cast<size_t>(coordinate) *
                            coordinate_stride_words +
                        4 * leaf +
                        offset];
            }
        }
        compress(hash, message, 64, 0xffffffffu);
    }
#pragma unroll
    for (int index = 0; index < 8; ++index) {
        result[leaf].words[index] = hash[index];
    }
}

constexpr uint32_t kInteriorBlock = 256;
constexpr uint32_t kInteriorOutputsPerBlock = kInteriorBlock / 8;

__global__ void interior4_kernel(
    const Hash *previous,
    uint32_t output_size,
    Hash *result) {
    __shared__ Hash level_one[kInteriorBlock];
    __shared__ Hash level_two[kInteriorBlock / 2];
    __shared__ Hash level_three[kInteriorBlock / 4];

    const uint32_t first_output =
        blockIdx.x * kInteriorOutputsPerBlock;
    const uint32_t window =
        min(output_size - first_output, kInteriorOutputsPerBlock);
    const uint32_t lane = threadIdx.x;
    const Hash *children = previous + 16 * first_output;

    if (lane < 8 * window) {
        level_one[lane] =
            hash_children(children[2 * lane], children[2 * lane + 1]);
    }
    __syncthreads();
    if (lane < 4 * window) {
        level_two[lane] =
            hash_children(level_one[2 * lane], level_one[2 * lane + 1]);
    }
    __syncthreads();
    if (lane < 2 * window) {
        level_three[lane] =
            hash_children(level_two[2 * lane], level_two[2 * lane + 1]);
    }
    __syncthreads();
    if (lane < window) {
        result[first_output + lane] =
            hash_children(level_three[2 * lane], level_three[2 * lane + 1]);
    }
}

__host__ __device__ constexpr bool is_power_of_two(uint32_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

}  // namespace stwo::cuda::blake2s

extern "C" int stwo_blake2s_layer_on(
    const stwo::cuda::blake2s::Hash *previous,
    uint32_t output_size,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    if (previous == nullptr ||
        !stwo::cuda::blake2s::is_power_of_two(output_size) ||
        result == nullptr || stream == nullptr ||
        stwo::cuda::blake2s::ranges_overlap(
            previous,
            static_cast<size_t>(output_size) * 2 * sizeof(*previous),
            result,
            static_cast<size_t>(output_size) * sizeof(*result))) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::blake2s::child_layer_kernel<<<
        stwo::cuda::blake2s::blocks_for(output_size),
        stwo::cuda::blake2s::kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            previous,
            output_size,
            result);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_fri_leaf_on(
    uint32_t evaluation_size,
    const uint32_t *coordinates,
    size_t coordinate_stride_words,
    size_t coordinate_capacity_words,
    uint32_t log_rows_per_leaf,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    using namespace stwo::cuda::blake2s;
    DeviceRange coordinate_range{};
    DeviceRange result_range{};
    if (!stwo::cuda::blake2s::is_power_of_two(evaluation_size) ||
        (log_rows_per_leaf != 0 && log_rows_per_leaf != 2) ||
        evaluation_size < (1u << log_rows_per_leaf) ||
        result == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const uint32_t leaf_count = evaluation_size >> log_rows_per_leaf;
    uint32_t coordinate_count = 0;
    if (!exact_word_slab_range(
            coordinates,
            coordinate_capacity_words,
            coordinate_stride_words,
            evaluation_size,
            &coordinate_count,
            &coordinate_range) ||
        coordinate_count != 4 ||
        !element_range(result, leaf_count, &result_range) ||
        ranges_overlap(coordinate_range, result_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::blake2s::fri_leaf_kernel<<<
        stwo::cuda::blake2s::blocks_for(leaf_count),
        stwo::cuda::blake2s::kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            evaluation_size,
            coordinates,
            coordinate_stride_words,
            log_rows_per_leaf,
            result);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_interior4_on(
    const stwo::cuda::blake2s::Hash *previous,
    uint32_t output_size,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    if (previous == nullptr ||
        !stwo::cuda::blake2s::is_power_of_two(output_size) ||
        result == nullptr || stream == nullptr ||
        stwo::cuda::blake2s::ranges_overlap(
            previous,
            static_cast<size_t>(output_size) * 16 * sizeof(*previous),
            result,
            static_cast<size_t>(output_size) * sizeof(*result))) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const uint32_t blocks =
        (output_size + stwo::cuda::blake2s::kInteriorOutputsPerBlock - 1) /
        stwo::cuda::blake2s::kInteriorOutputsPerBlock;
    stwo::cuda::blake2s::interior4_kernel<<<
        blocks,
        stwo::cuda::blake2s::kInteriorBlock,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            previous,
            output_size,
            result);
    return static_cast<int>(cudaPeekAtLastError());
}
