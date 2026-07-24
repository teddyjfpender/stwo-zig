#include "merkle_walk.cuh"

namespace stwo::cuda::decommit {
namespace {

__device__ bool contains_sorted(
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
    __shared__ MerkleWalkShared walk_state;
    __shared__ uint32_t *meta;
    __shared__ uint32_t tree_start;
    __shared__ uint32_t query_offset;
    __shared__ uint32_t witness_offset;
    __shared__ uint32_t witness_count;
    __shared__ uint32_t prefix_base;
    __shared__ uint32_t query_count;
    __shared__ uint32_t expanded_count;
    __shared__ uint32_t failed;
    if (lane == 0) {
        meta = checked_tree_meta(
            assembly, assembly_capacity_words, tree_index);
        query_count = *tree_query_count_pointer;
        expanded_count = *expanded_count_pointer;
        tree_start = assembly[kHeaderUsedWords];
        witness_count = 0;
        failed = meta == nullptr || query_count == 0 ||
            query_count > tree_query_capacity || expanded_count == 0 ||
            expanded_count > expanded_capacity ||
            expanded_count > workspace_capacity;
        for (uint32_t index = 0; !failed && index < query_count; ++index) {
            failed = (index != 0 &&
                      tree_queries[index - 1] >= tree_queries[index]);
        }
        for (uint32_t index = 0; !failed && index < expanded_count; ++index) {
            failed = expanded_positions[index] >= coordinate_stride_words ||
                (index != 0 &&
                 expanded_positions[index - 1] >= expanded_positions[index]);
        }
        if (!failed) {
            failed = !reserve_words(
                assembly,
                assembly_capacity_words,
                query_count,
                &query_offset);
        }
    }
    __syncthreads();
    if (failed) {
        if (lane == 0) fail_assembly(assembly);
        return;
    }
    for (uint32_t index = lane;
         index < query_count;
         index += kBlockSize) {
        assembly[query_offset + index] = tree_queries[index];
    }

    for (uint32_t base = 0;
         base < expanded_count;
         base += kBlockSize) {
        const uint32_t index = base + lane;
        const bool emit = index < expanded_count &&
            !contains_sorted(
                tree_queries, query_count, expanded_positions[index]);
        if (index < expanded_count) walk_scratch[index] = emit;
        walk_state.group_scan[lane] = emit;
        __syncthreads();
        inclusive_scan(walk_state.group_scan);
        if (lane == 0) {
            const uint32_t active =
                min(kBlockSize, expanded_count - base);
            witness_count += walk_state.group_scan[active - 1u];
        }
        __syncthreads();
    }
    if (lane == 0) {
        const uint64_t witness_words = 4ull * witness_count;
        failed = witness_words > UINT32_MAX ||
            !reserve_words(
                assembly,
                assembly_capacity_words,
                static_cast<uint32_t>(witness_words),
                &witness_offset);
        prefix_base = 0;
    }
    __syncthreads();
    if (failed) {
        if (lane == 0) fail_assembly(assembly);
        return;
    }

    for (uint32_t base = 0;
         base < expanded_count;
         base += kBlockSize) {
        const uint32_t index = base + lane;
        const bool emit =
            index < expanded_count && walk_scratch[index] != 0;
        walk_state.group_scan[lane] = emit;
        __syncthreads();
        inclusive_scan(walk_state.group_scan);
        if (emit) {
            const uint32_t destination =
                prefix_base + walk_state.group_scan[lane] - 1u;
#pragma unroll
            for (uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
                assembly[
                    witness_offset + 4u * destination + coordinate] =
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
                min(kBlockSize, expanded_count - base);
            prefix_base += walk_state.group_scan[active - 1u];
        }
        __syncthreads();
    }

    __shared__ uint32_t hash_offset;
    __shared__ uint32_t hash_count;
    __shared__ uint32_t aux_offset;
    __shared__ uint32_t aux_count;
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
            walk_state,
            &hash_offset,
            &hash_count,
            &aux_offset,
            &aux_count)) {
        return;
    }

    __shared__ uint32_t all_values_offset;
    if (lane == 0) {
        const uint64_t all_value_words = 5ull * expanded_count;
        failed = all_value_words > UINT32_MAX ||
            !reserve_words(
                assembly,
                assembly_capacity_words,
                static_cast<uint32_t>(all_value_words),
                &all_values_offset);
    }
    __syncthreads();
    if (failed) {
        if (lane == 0) fail_assembly(assembly);
        return;
    }
    for (uint32_t index = lane;
         index < expanded_count;
         index += kBlockSize) {
        assembly[all_values_offset + 5u * index] =
            expanded_positions[index];
#pragma unroll
        for (uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
            assembly[
                all_values_offset + 5u * index + 1u + coordinate] =
                canonical_m31(
                    coordinate_slab[
                        static_cast<uint64_t>(coordinate) *
                            coordinate_stride_words +
                        expanded_positions[index]]);
        }
    }
    __syncthreads();
    if (lane == 0) {
        meta[kMetaKind] = 1;
        meta[kMetaRole] = tree_index;
        meta[kMetaQueryOffset] = query_offset;
        meta[kMetaQueryCount] = query_count;
        meta[kMetaValuesOffset] = 0;
        meta[kMetaValuesCount] = 0;
        meta[kMetaFriWitnessOffset] =
            witness_count == 0 ? 0 : witness_offset;
        meta[kMetaFriWitnessCount] = witness_count;
        meta[kMetaHashWitnessOffset] =
            hash_count == 0 ? 0 : hash_offset;
        meta[kMetaHashWitnessCount] = hash_count;
        meta[kMetaAuxOffset] = aux_count == 0 ? 0 : aux_offset;
        meta[kMetaAuxCount] = aux_count;
        meta[kMetaAllValuesOffset] = all_values_offset;
        meta[kMetaAllValuesCount] = expanded_count;
        meta[kMetaLeafLogSize] = leaf_log_size;
        meta[kMetaUsedWords] =
            assembly[kHeaderUsedWords] - tree_start;
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
