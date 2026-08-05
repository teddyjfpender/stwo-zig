#include "merkle_walk.cuh"

namespace stwo::cuda::decommit {
namespace {

__device__ __forceinline__ bool contains_sorted(
    const uint32_t *values,
    uint32_t count,
    uint32_t target) {
    uint32_t lower = 0;
    uint32_t upper = count;
    while (lower < upper) {
        const uint32_t middle = lower + ((upper - lower) >> 1);
        if (values[middle] < target) {
            lower = middle + 1;
        } else {
            upper = middle;
        }
    }
    return lower < count && values[lower] == target;
}

struct FriAssemblyShared {
    MerkleWalkShared walk;
    uint32_t tree_start;
    uint32_t query_offset;
    uint32_t witness_offset;
    uint32_t witness_count;
    uint32_t prefix_base;
    uint32_t query_count;
    uint32_t expanded_count;
    uint32_t all_values_offset;
    uint32_t failed;
};

__global__ __launch_bounds__(kBlockSize)
void assemble_fri_kernel(
    uint32_t tree_index,
    uint32_t leaf_log_size,
    const uint32_t *tree_queries,
    const uint32_t *tree_query_count_pointer,
    uint32_t tree_query_capacity,
    const uint32_t *expanded_positions,
    const uint32_t *expanded_count_pointer,
    uint32_t expanded_capacity,
    const uint32_t *coordinate_slab,
    uint64_t coordinate_stride_words,
    uint64_t coordinate_slab_words,
    uint32_t *walk_queries,
    uint32_t *walk_scratch,
    const uint32_t *walk_count_pointer,
    uint32_t workspace_capacity,
    const Hash *retained_slab,
    uint64_t retained_slab_hashes,
    const RetainedLayer *retained_layers,
    uint32_t retained_layer_count,
    uint32_t *assembly,
    uint32_t assembly_capacity_words) {
    if (blockIdx.x != 0) return;
    const uint32_t lane = threadIdx.x;
    __shared__ FriAssemblyShared state;
    if (lane == 0) {
        state.query_count = *tree_query_count_pointer;
        state.expanded_count = *expanded_count_pointer;
        state.tree_start = assembly[kHeaderUsedWords];
        state.witness_count = 0;
        state.failed = checked_tree_meta(
                assembly, assembly_capacity_words, tree_index) == nullptr ||
            state.query_count == 0 ||
            state.query_count > tree_query_capacity ||
            state.expanded_count == 0 ||
            state.expanded_count > expanded_capacity ||
            state.expanded_count > workspace_capacity;
        for (uint32_t index = 0;
             !state.failed && index < state.query_count;
             ++index) {
            state.failed = index != 0 &&
                tree_queries[index - 1] >= tree_queries[index];
        }
        for (uint32_t index = 0;
             !state.failed && index < state.expanded_count;
             ++index) {
            state.failed =
                expanded_positions[index] >= coordinate_stride_words ||
                (index != 0 &&
                 expanded_positions[index - 1] >= expanded_positions[index]);
        }
        if (!state.failed) {
            const uint32_t cursor = assembly[kHeaderUsedWords];
            if (state.query_count > assembly_capacity_words - cursor) {
                assembly[kHeaderUsedWords] = 0;
                state.failed = 1;
            } else {
                state.query_offset = cursor;
                assembly[kHeaderUsedWords] = cursor + state.query_count;
            }
        }
    }
    __syncthreads();
    if (state.failed) {
        if (lane == 0) fail_assembly(assembly);
        return;
    }
    for (uint32_t index = lane;
         index < state.query_count;
         index += kBlockSize) {
        assembly[state.query_offset + index] = tree_queries[index];
    }

    for (uint32_t base = 0;
         base < state.expanded_count;
         base += kBlockSize) {
        const uint32_t index = base + lane;
        const bool emit = index < state.expanded_count &&
            !contains_sorted(
                tree_queries, state.query_count, expanded_positions[index]);
        if (index < state.expanded_count) walk_scratch[index] = emit;
        state.walk.group_scan[lane] = emit;
        __syncthreads();
        inclusive_scan(state.walk.group_scan);
        if (lane == 0) {
            const uint32_t active =
                min(kBlockSize, state.expanded_count - base);
            state.witness_count += state.walk.group_scan[active - 1u];
        }
        __syncthreads();
    }
    if (lane == 0) {
        const uint64_t witness_words = 4ull * state.witness_count;
        const uint32_t cursor = assembly[kHeaderUsedWords];
        state.failed = witness_words > UINT32_MAX ||
            witness_words > assembly_capacity_words - cursor;
        if (state.failed) {
            assembly[kHeaderUsedWords] = 0;
        } else {
            state.witness_offset = cursor;
            assembly[kHeaderUsedWords] =
                cursor + static_cast<uint32_t>(witness_words);
        }
        state.prefix_base = 0;
    }
    __syncthreads();
    if (state.failed) {
        if (lane == 0) fail_assembly(assembly);
        return;
    }

    for (uint32_t base = 0;
         base < state.expanded_count;
         base += kBlockSize) {
        const uint32_t index = base + lane;
        const bool emit =
            index < state.expanded_count && walk_scratch[index] != 0;
        state.walk.group_scan[lane] = emit;
        __syncthreads();
        inclusive_scan(state.walk.group_scan);
        if (emit) {
            const uint32_t destination =
                state.prefix_base + state.walk.group_scan[lane] - 1u;
#pragma unroll
            for (uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
                assembly[
                    state.witness_offset + 4u * destination + coordinate] =
                    canonical_m31(
                        coordinate_slab[
                            static_cast<uint64_t>(coordinate) *
                                coordinate_stride_words +
                            expanded_positions[index]]);
            }
        }
        __syncthreads();
        if (lane == 0) {
            const uint32_t active =
                min(kBlockSize, state.expanded_count - base);
            state.prefix_base += state.walk.group_scan[active - 1u];
        }
        __syncthreads();
    }

    const RetainedNodeSource source{
        retained_slab,
        retained_slab_hashes,
        retained_layers,
        retained_layer_count,
    };
    if (!merkle_walk(
            leaf_log_size,
            workspace_capacity,
            walk_queries,
            walk_scratch,
            walk_count_pointer,
            source,
            assembly,
            assembly_capacity_words,
            state.walk)) {
        return;
    }

    if (lane == 0) {
        const uint64_t all_value_words = 5ull * state.expanded_count;
        const uint32_t cursor = assembly[kHeaderUsedWords];
        state.failed = all_value_words > UINT32_MAX ||
            all_value_words > assembly_capacity_words - cursor;
        if (state.failed) {
            assembly[kHeaderUsedWords] = 0;
        } else {
            state.all_values_offset = cursor;
            assembly[kHeaderUsedWords] =
                cursor + static_cast<uint32_t>(all_value_words);
        }
    }
    __syncthreads();
    if (state.failed) {
        if (lane == 0) fail_assembly(assembly);
        return;
    }
    for (uint32_t index = lane;
         index < state.expanded_count;
         index += kBlockSize) {
        assembly[state.all_values_offset + 5u * index] =
            expanded_positions[index];
#pragma unroll
        for (uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
            assembly[
                state.all_values_offset + 5u * index + 1u + coordinate] =
                canonical_m31(
                    coordinate_slab[
                        static_cast<uint64_t>(coordinate) *
                            coordinate_stride_words +
                        expanded_positions[index]]);
        }
    }
    __syncthreads();
    if (lane == 0) {
        uint32_t *meta =
            assembly + kHeaderWords + tree_index * kTreeMetaWords;
        meta[kMetaKind] = 1;
        meta[kMetaRole] = tree_index;
        meta[kMetaQueryOffset] = state.query_offset;
        meta[kMetaQueryCount] = state.query_count;
        meta[kMetaValuesOffset] = 0;
        meta[kMetaValuesCount] = 0;
        meta[kMetaFriWitnessOffset] =
            state.witness_count == 0 ? 0 : state.witness_offset;
        meta[kMetaFriWitnessCount] = state.witness_count;
        meta[kMetaHashWitnessOffset] =
            state.walk.hash_count == 0 ? 0 : state.walk.hash_offset;
        meta[kMetaHashWitnessCount] = state.walk.hash_count;
        meta[kMetaAuxOffset] =
            state.walk.aux_count == 0 ? 0 : state.walk.aux_offset;
        meta[kMetaAuxCount] = state.walk.aux_count;
        meta[kMetaAllValuesOffset] = state.all_values_offset;
        meta[kMetaAllValuesCount] = state.expanded_count;
        meta[kMetaLeafLogSize] = leaf_log_size;
        meta[kMetaUsedWords] =
            assembly[kHeaderUsedWords] - state.tree_start;
    }
    __syncthreads();

    // The outer proof transport has a geometry-fixed capacity while query
    // collisions shorten this nested bundle. Merkle walking uses that tail as
    // temporary staging, so the final tree must restore canonical zero
    // padding before the sole terminal device-to-host read.
    if (tree_index + 1u == assembly[kHeaderTreeCount]) {
        const uint32_t used_words = assembly[kHeaderUsedWords];
        for (uint32_t index = used_words + lane;
             index < assembly_capacity_words;
             index += kBlockSize) {
            assembly[index] = 0;
        }
    }
}

}  // namespace
}  // namespace stwo::cuda::decommit

extern "C" int stwo_decommit_assemble_fri_on(
    uint32_t tree_index,
    uint32_t leaf_log_size,
    const uint32_t *tree_queries,
    const uint32_t *tree_query_count,
    uint32_t tree_query_capacity,
    const uint32_t *expanded_positions,
    const uint32_t *expanded_count,
    uint32_t expanded_capacity,
    const uint32_t *coordinate_slab,
    size_t coordinate_stride_words,
    size_t coordinate_slab_words,
    uint32_t *walk_queries,
    uint32_t *walk_scratch,
    const uint32_t *walk_count,
    uint32_t workspace_capacity,
    const stwo::cuda::decommit::Hash *retained_slab,
    uint64_t retained_slab_hashes,
    const stwo::cuda::decommit::RetainedLayer *retained_layers,
    uint32_t retained_layer_count,
    uint32_t *assembly,
    uint32_t assembly_capacity_words,
    void *stream) {
    using namespace stwo::cuda::decommit;
    size_t coordinate_bytes = 0;
    size_t workspace_bytes = 0;
    size_t retained_bytes = 0;
    size_t assembly_bytes = 0;
    if (leaf_log_size >= 31 || tree_queries == nullptr ||
        tree_query_count == nullptr || tree_query_capacity == 0 ||
        expanded_positions == nullptr || expanded_count == nullptr ||
        expanded_capacity == 0 || coordinate_slab == nullptr ||
        coordinate_stride_words == 0 ||
        !slab_fits(
            coordinate_stride_words, 4, coordinate_slab_words) ||
        walk_queries == nullptr || walk_scratch == nullptr ||
        walk_count == nullptr || workspace_capacity < expanded_capacity ||
        retained_slab == nullptr || retained_slab_hashes == 0 ||
        retained_layers == nullptr ||
        retained_layer_count <= leaf_log_size ||
        assembly == nullptr || assembly_capacity_words < kHeaderWords ||
        stream == nullptr ||
        !checked_bytes(
            coordinate_slab_words, sizeof(uint32_t), &coordinate_bytes) ||
        !checked_bytes(
            workspace_capacity, sizeof(uint32_t), &workspace_bytes) ||
        !checked_bytes(
            retained_slab_hashes, sizeof(Hash), &retained_bytes) ||
        !checked_bytes(
            assembly_capacity_words, sizeof(uint32_t), &assembly_bytes) ||
        device_ranges_overlap(
            walk_queries, workspace_bytes, walk_scratch, workspace_bytes) ||
        device_ranges_overlap(
            coordinate_slab, coordinate_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            walk_queries, workspace_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            walk_scratch, workspace_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            retained_slab, retained_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            retained_layers,
            static_cast<size_t>(retained_layer_count) * sizeof(RetainedLayer),
            assembly,
            assembly_bytes)) {
        return cudaErrorInvalidValue;
    }
    assemble_fri_kernel<<<
        1, kBlockSize, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        tree_index,
        leaf_log_size,
        tree_queries,
        tree_query_count,
        tree_query_capacity,
        expanded_positions,
        expanded_count,
        expanded_capacity,
        coordinate_slab,
        coordinate_stride_words,
        coordinate_slab_words,
        walk_queries,
        walk_scratch,
        walk_count,
        workspace_capacity,
        retained_slab,
        retained_slab_hashes,
        retained_layers,
        retained_layer_count,
        assembly,
        assembly_capacity_words);
    return cudaGetLastError();
}
