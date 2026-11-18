// Plain and domain-prefixed Blake2s protocols share the same kernels. These kernels
// operate only on checked caller-owned device ranges and proof streams.

#include "blake2s_protocol.cuh"
#include "resident_layout.cuh"
#include "merkle_fused.cuh"

#include <cuda_runtime_api.h>

#include <stdint.h>

namespace stwo::cuda::blake2s {

template <bool Prefixed>
__global__ void child_layer_kernel(
    const Hash *previous,
    uint32_t output_size,
    Hash *result) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= output_size) return;
    result[index] = hash_children_for<Prefixed>(previous[2 * index], previous[2 * index + 1]);
}

template <bool Prefixed>
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
    initialize_leaf_for<Prefixed>(hash);
    if (log_rows_per_leaf == 0) {
#pragma unroll
        for (int coordinate = 0; coordinate < 4; ++coordinate) {
            message[coordinate] =
                coordinates[
                    static_cast<size_t>(coordinate) *
                        coordinate_stride_words +
                    leaf];
        }
        compress(hash, message, (Prefixed ? kDomainPrefixBytes : 0) + 16, 0xffffffffu);
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
        compress(hash, message, (Prefixed ? kDomainPrefixBytes : 0) + 64, 0xffffffffu);
    }
#pragma unroll
    for (int index = 0; index < 8; ++index) {
        result[leaf].words[index] = hash[index];
    }
}

constexpr uint32_t kInteriorBlock = 256;
constexpr uint32_t kInteriorOutputsPerBlock = kInteriorBlock / 8;
constexpr uint32_t kTailBlock = 256;

template <bool Prefixed>
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
            hash_children_for<Prefixed>(children[2 * lane], children[2 * lane + 1]);
    }
    __syncthreads();
    if (lane < 4 * window) {
        level_two[lane] =
            hash_children_for<Prefixed>(level_one[2 * lane], level_one[2 * lane + 1]);
    }
    __syncthreads();
    if (lane < 2 * window) {
        level_three[lane] =
            hash_children_for<Prefixed>(level_two[2 * lane], level_two[2 * lane + 1]);
    }
    __syncthreads();
    if (lane < window) {
        result[first_output + lane] =
            hash_children_for<Prefixed>(level_three[2 * lane], level_three[2 * lane + 1]);
    }
}

template <bool Prefixed>
__global__ void upper_tail_kernel(
    const Hash *previous,
    uint32_t previous_size,
    Hash *outputs,
    uint32_t level_count) {
    Hash *next = outputs;
    uint32_t size = previous_size;
    for (uint32_t level = 0; level < level_count; ++level) {
        const uint32_t next_size = size / 2;
        for (uint32_t index = threadIdx.x;
             index < next_size;
             index += blockDim.x) {
            next[index] =
                hash_children_for<Prefixed>(previous[2 * index], previous[2 * index + 1]);
        }
        __syncthreads();
        previous = next;
        next += next_size;
        size = next_size;
    }
}

__host__ __device__ constexpr bool is_power_of_two(uint32_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

}  // namespace stwo::cuda::blake2s

template <bool Prefixed>
static int stwo_blake2s_layer_on_impl(
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
    stwo::cuda::blake2s::child_layer_kernel<Prefixed><<<
        stwo::cuda::blake2s::blocks_for(output_size),
        stwo::cuda::blake2s::kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            previous,
            output_size,
            result);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_layer_on(
    const stwo::cuda::blake2s::Hash *previous,
    uint32_t output_size,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_layer_on_impl<true>(previous, output_size, result, stream);
}

extern "C" int stwo_blake2s_layer_plain_on(
    const stwo::cuda::blake2s::Hash *previous,
    uint32_t output_size,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_layer_on_impl<false>(previous, output_size, result, stream);
}

template <bool Prefixed>
static int stwo_blake2s_fri_leaf_on_impl(
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
    stwo::cuda::blake2s::fri_leaf_kernel<Prefixed><<<
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

extern "C" int stwo_blake2s_fri_leaf_on(
    uint32_t evaluation_size,
    const uint32_t *coordinates,
    size_t coordinate_stride_words,
    size_t coordinate_capacity_words,
    uint32_t log_rows_per_leaf,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_fri_leaf_on_impl<true>(evaluation_size, coordinates, coordinate_stride_words, coordinate_capacity_words, log_rows_per_leaf, result, stream);
}

extern "C" int stwo_blake2s_fri_leaf_plain_on(
    uint32_t evaluation_size,
    const uint32_t *coordinates,
    size_t coordinate_stride_words,
    size_t coordinate_capacity_words,
    uint32_t log_rows_per_leaf,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_fri_leaf_on_impl<false>(evaluation_size, coordinates, coordinate_stride_words, coordinate_capacity_words, log_rows_per_leaf, result, stream);
}

template <bool Prefixed>
static int stwo_blake2s_interior4_on_impl(
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
    stwo::cuda::blake2s::interior4_kernel<Prefixed><<<
        blocks,
        stwo::cuda::blake2s::kInteriorBlock,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            previous,
            output_size,
            result);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_interior4_on(
    const stwo::cuda::blake2s::Hash *previous,
    uint32_t output_size,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_interior4_on_impl<true>(previous, output_size, result, stream);
}

extern "C" int stwo_blake2s_interior4_plain_on(
    const stwo::cuda::blake2s::Hash *previous,
    uint32_t output_size,
    stwo::cuda::blake2s::Hash *result,
    void *stream) {
    return stwo_blake2s_interior4_on_impl<false>(previous, output_size, result, stream);
}

template <bool Prefixed>
static int stwo_blake2s_contiguous_tail_on_impl(
    const stwo::cuda::blake2s::Hash *previous,
    uint32_t previous_size,
    stwo::cuda::blake2s::Hash *outputs,
    size_t output_capacity,
    uint32_t level_count,
    void *stream) {
    using namespace stwo::cuda::blake2s;
    if (previous == nullptr || !is_power_of_two(previous_size) ||
        outputs == nullptr || level_count == 0 || level_count >= 32 ||
        stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const uint32_t final_size = previous_size >> level_count;
    if (final_size == 0 ||
        output_capacity !=
            static_cast<size_t>(previous_size - final_size) ||
        ranges_overlap(
            previous,
            static_cast<size_t>(previous_size) * sizeof(*previous),
            outputs,
            output_capacity * sizeof(*outputs))) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    upper_tail_kernel<Prefixed><<<
        1,
        kTailBlock,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            previous,
            previous_size,
            outputs,
            level_count);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_contiguous_tail_on(
    const stwo::cuda::blake2s::Hash *previous,
    uint32_t previous_size,
    stwo::cuda::blake2s::Hash *outputs,
    size_t output_capacity,
    uint32_t level_count,
    void *stream) {
    return stwo_blake2s_contiguous_tail_on_impl<true>(previous, previous_size, outputs, output_capacity, level_count, stream);
}

extern "C" int stwo_blake2s_contiguous_tail_plain_on(
    const stwo::cuda::blake2s::Hash *previous,
    uint32_t previous_size,
    stwo::cuda::blake2s::Hash *outputs,
    size_t output_capacity,
    uint32_t level_count,
    void *stream) {
    return stwo_blake2s_contiguous_tail_on_impl<false>(previous, previous_size, outputs, output_capacity, level_count, stream);
}

namespace stwo::cuda::blake2s {

// Three-level subtrees retain all intermediate hashes; one CTA finishes the
// small upper tail. Geometry is shared by plain and prefixed hash protocols.
constexpr uint32_t kFusedTailNodes = STWO_T6_TAIL_NODES;
constexpr uint32_t kSubtreeBlock = STWO_T6_SUBTREE_BLOCK;
constexpr uint32_t kFusedTailBlock = STWO_T6_TAIL_BLOCK;
// Layers above the tail are power-of-two sized, so a power-of-two tail makes
// every pass 3 levels except at most one 2-level pass (nodes == 2 * tail).
static_assert(is_power_of_two(kFusedTailNodes) && kFusedTailNodes >= 2, "tail nodes");

template <bool Prefixed>
static int fused_tree_layers(Hash *tree, uint32_t leaves, cudaStream_t stream) {
    uint64_t offset = 0;
    uint32_t nodes = leaves;
    while (nodes > kFusedTailNodes) {
        const uint32_t levels = (nodes >> 3) >= kFusedTailNodes / 2 ? 3 : 2;
        const uint32_t top = nodes >> levels;
        Hash *layer1 = tree + offset + nodes;
        Hash *layer2 = layer1 + nodes / 2;
        const uint32_t blocks = (top + kSubtreeBlock - 1) / kSubtreeBlock;
        if (levels == 3) {
            subtree_levels_kernel<Prefixed, 3><<<blocks, kSubtreeBlock, 0, stream>>>(
                tree + offset, top, layer1, layer2, layer2 + nodes / 4);
        } else {
            subtree_levels_kernel<Prefixed, 2><<<blocks, kSubtreeBlock, 0, stream>>>(
                tree + offset, top, layer1, layer2, nullptr);
        }
        for (uint32_t l = 0; l < levels; ++l) {
            offset += nodes;
            nodes >>= 1;
        }
    }
    if (nodes > 1) {
        const uint32_t threads = nodes / 2 < kFusedTailBlock ? nodes / 2 : kFusedTailBlock;
        fused_tail_kernel<Prefixed><<<1, threads, 0, stream>>>(
            tree + offset, nodes, tree + offset + nodes);
    }
    return static_cast<int>(cudaPeekAtLastError());
}

}  // namespace stwo::cuda::blake2s

// Test/bench oracle selection (0 or 1; -2 restores the canonical schedule).
extern "C" void stwo_blake2s_m8_merkle_fused_override(int mode) {
    __atomic_store_n(&stwo::cuda::blake2s::merkle_fused_override_slot(), mode,
                     __ATOMIC_RELAXED);
}

// Builds every layer above the leaves of a contiguous tree in place: layer 0
// (`leaves` hashes) at tree[0], each next layer right after the previous one,
// the root at tree[2 * leaves - 2]. This is exactly the layout (and result)
// of the callers' loop
//   for (n = leaves, off = 0; n > 1; off += n, n /= 2)
//     stwo_blake2s_layer_on(tree + off, n / 2, tree + off + n, stream);
// retained as the explicit test oracle. The canonical schedule uses
// subtree passes and one tail CTA, preserving every hash. The capacity
// must cover 2 * leaves - 1 hashes.
template <bool Prefixed>
static int stwo_blake2s_merkle_layers_on_impl(
    stwo::cuda::blake2s::Hash *tree, uint32_t leaves, uint64_t tree_capacity_nodes,
    void *stream) {
    using namespace stwo::cuda::blake2s;
    DeviceRange range{};
    if (tree == nullptr || stream == nullptr || leaves < 2 || !is_power_of_two(leaves) ||
        tree_capacity_nodes < 2ull * leaves - 1 ||
        tree_capacity_nodes > SIZE_MAX / sizeof(Hash) ||
        !element_range(tree, size_t(tree_capacity_nodes), &range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const int mode = merkle_fused_mode();
    const cudaStream_t s = reinterpret_cast<cudaStream_t>(stream);
    if (mode == 1) return fused_tree_layers<Prefixed>(tree, leaves, s);
    if (mode != 0) return static_cast<int>(cudaErrorInvalidValue);
    uint64_t offset = 0;
    for (uint32_t nodes = leaves; nodes > 1; offset += nodes, nodes >>= 1) {
        const int status = stwo_blake2s_layer_on_impl<Prefixed>(
            tree + offset, nodes / 2, tree + offset + nodes, stream);
        if (status != 0) return status;
    }
    return 0;
}

extern "C" int stwo_blake2s_merkle_layers_on(
    stwo::cuda::blake2s::Hash *tree, uint32_t leaves, uint64_t tree_capacity_nodes,
    void *stream) {
    return stwo_blake2s_merkle_layers_on_impl<true>(tree, leaves, tree_capacity_nodes, stream);
}

extern "C" int stwo_blake2s_merkle_layers_plain_on(
    stwo::cuda::blake2s::Hash *tree, uint32_t leaves, uint64_t tree_capacity_nodes,
    void *stream) {
    return stwo_blake2s_merkle_layers_on_impl<false>(tree, leaves, tree_capacity_nodes, stream);
}
