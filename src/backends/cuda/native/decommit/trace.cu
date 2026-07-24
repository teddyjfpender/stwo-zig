#include "merkle_walk.cuh"

namespace stwo::cuda::decommit {
namespace {

__global__ __launch_bounds__(kBlockSize)
void pack_trace_group_kernel(
    uint32_t tree_index,
    uint32_t total_column_count,
    uint32_t first_column,
    uint32_t group_column_count,
    const uint32_t *column_slab,
    uint64_t column_stride_words,
    uint64_t column_slab_words,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    const uint32_t *mapped_queries,
    const uint32_t *mapped_count_pointer,
    uint32_t mapped_capacity,
    uint32_t *assembly,
    uint32_t assembly_capacity_words) {
    if (blockIdx.x != 0) return;
    const uint32_t lane = threadIdx.x;
    __shared__ uint32_t *meta;
    __shared__ uint32_t query_offset;
    __shared__ uint32_t value_offset;
    __shared__ uint32_t mapped_count;
    __shared__ uint32_t failed;
    if (lane == 0) {
        meta = checked_tree_meta(
            assembly, assembly_capacity_words, tree_index);
        mapped_count = *mapped_count_pointer;
        failed = meta == nullptr || mapped_count == 0 ||
            mapped_count > mapped_capacity;
        const uint64_t value_words =
            static_cast<uint64_t>(total_column_count) * mapped_count;
        if (value_words > UINT32_MAX) failed = 1;
        for (uint32_t index = 0; !failed && index < mapped_count; ++index) {
            failed = mapped_queries[index] >= (1u << lifting_log_size) ||
                (index != 0 &&
                 mapped_queries[index - 1] > mapped_queries[index]);
        }

        if (!failed && first_column == 0) {
            failed = !reserve_words(
                assembly,
                assembly_capacity_words,
                mapped_count,
                &query_offset);
            if (!failed &&
                !reserve_words(
                    assembly,
                    assembly_capacity_words,
                    static_cast<uint32_t>(value_words),
                    &value_offset)) {
                failed = 1;
            }
            if (!failed) {
                meta[kMetaQueryOffset] = query_offset;
                meta[kMetaQueryCount] = mapped_count;
                meta[kMetaValuesOffset] = value_offset;
                meta[kMetaValuesCount] =
                    static_cast<uint32_t>(value_words);
            }
        } else if (!failed) {
            query_offset = meta[kMetaQueryOffset];
            value_offset = meta[kMetaValuesOffset];
            const uint32_t used = assembly[kHeaderUsedWords];
            failed = meta[kMetaQueryCount] != mapped_count ||
                meta[kMetaValuesCount] != value_words ||
                query_offset > used || mapped_count > used - query_offset ||
                value_offset > used || value_words > used - value_offset ||
                value_offset != query_offset + mapped_count;
        }
    }
    __syncthreads();

    for (uint32_t column = lane;
         column < group_column_count;
         column += kBlockSize) {
        const uint32_t column_log = column_log_sizes[column];
        if (column_log > lifting_log_size ||
            (1ull << column_log) > column_stride_words ||
            static_cast<uint64_t>(column + 1u) * column_stride_words >
                column_slab_words) {
            atomicExch(&failed, 1u);
        }
    }
    __syncthreads();
    if (failed) {
        if (lane == 0) fail_assembly(assembly);
        return;
    }

    if (first_column == 0) {
        for (uint32_t query = lane;
             query < mapped_count;
             query += kBlockSize) {
            assembly[query_offset + query] = mapped_queries[query];
        }
    }
    for (uint32_t column = 0; column < group_column_count; ++column) {
        const uint32_t *values =
            column_slab + static_cast<uint64_t>(column) *
                column_stride_words;
        for (uint32_t query = lane;
             query < mapped_count;
             query += kBlockSize) {
            const uint32_t row = lifted_index(
                mapped_queries[query],
                lifting_log_size,
                column_log_sizes[column]);
            assembly[
                value_offset +
                static_cast<uint64_t>(first_column + column) * mapped_count +
                query] = canonical_m31(values[row]);
        }
    }
}

__global__ __launch_bounds__(kBlockSize)
void assemble_trace_kernel(
    uint32_t tree_index,
    uint32_t tree_role,
    uint32_t leaf_log_size,
    uint32_t first_retained_log_size,
    uint32_t column_count,
    const uint32_t *mapped_count_pointer,
    uint32_t mapped_capacity,
    uint32_t *walk_queries,
    uint32_t *walk_scratch,
    const uint32_t *walk_count_pointer,
    uint32_t walk_capacity,
    const Hash *retained_slab,
    uint64_t retained_slab_hashes,
    const RetainedLayer *retained_layers,
    uint32_t retained_layer_count,
    const uint32_t *sparse_indices,
    const Hash *sparse_hashes,
    uint32_t sparse_capacity,
    const uint32_t *sparse_level_offsets,
    const uint32_t *sparse_level_counts,
    uint32_t sparse_level_count,
    uint32_t *assembly,
    uint32_t assembly_capacity_words) {
    if (blockIdx.x != 0) return;
    const uint32_t lane = threadIdx.x;
    __shared__ uint32_t *meta;
    __shared__ uint32_t tree_start;
    __shared__ uint32_t query_offset;
    __shared__ uint32_t value_offset;
    __shared__ uint32_t mapped_count;
    __shared__ uint32_t failed;
    if (lane == 0) {
        meta = checked_tree_meta(
            assembly, assembly_capacity_words, tree_index);
        mapped_count = *mapped_count_pointer;
        const uint64_t value_words =
            static_cast<uint64_t>(column_count) * mapped_count;
        const uint32_t used = assembly[kHeaderUsedWords];
        failed = meta == nullptr || mapped_count == 0 ||
            mapped_count > mapped_capacity || value_words > UINT32_MAX;
        if (!failed) {
            query_offset = meta[kMetaQueryOffset];
            value_offset = meta[kMetaValuesOffset];
            tree_start = query_offset;
            failed = meta[kMetaQueryCount] != mapped_count ||
                meta[kMetaValuesCount] != value_words ||
                query_offset > used || mapped_count > used - query_offset ||
                value_offset > used || value_words > used - value_offset ||
                value_offset != query_offset + mapped_count;
        }
    }
    __syncthreads();
    if (failed) {
        if (lane == 0) fail_assembly(assembly);
        return;
    }

    __shared__ MerkleWalkShared walk_state;
    __shared__ uint32_t hash_offset;
    __shared__ uint32_t hash_count;
    __shared__ uint32_t aux_offset;
    __shared__ uint32_t aux_count;
    const RetainedNodeSource retained{
        retained_slab,
        retained_slab_hashes,
        retained_layers,
        retained_layer_count,
    };
    const TraceNodeSource source{
        leaf_log_size,
        first_retained_log_size,
        retained,
        sparse_indices,
        sparse_hashes,
        sparse_capacity,
        sparse_level_offsets,
        sparse_level_counts,
        sparse_level_count,
    };
    if (!merkle_walk(
            leaf_log_size,
            walk_capacity,
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

    if (lane == 0) {
        meta[kMetaKind] = 0;
        meta[kMetaRole] = tree_role;
        meta[kMetaQueryOffset] = query_offset;
        meta[kMetaQueryCount] = mapped_count;
        meta[kMetaValuesOffset] = value_offset;
        meta[kMetaValuesCount] = column_count * mapped_count;
        meta[kMetaFriWitnessOffset] = 0;
        meta[kMetaFriWitnessCount] = 0;
        meta[kMetaHashWitnessOffset] = hash_offset;
        meta[kMetaHashWitnessCount] = hash_count;
        meta[kMetaAuxOffset] = aux_offset;
        meta[kMetaAuxCount] = aux_count;
        meta[kMetaAllValuesOffset] = 0;
        meta[kMetaAllValuesCount] = 0;
        meta[kMetaLeafLogSize] = leaf_log_size;
        meta[kMetaUsedWords] =
            assembly[kHeaderUsedWords] - tree_start;
    }
}

}  // namespace
}  // namespace stwo::cuda::decommit

extern "C" int stwo_decommit_pack_trace_group_on(
    uint32_t tree_index,
    uint32_t total_column_count,
    uint32_t first_column,
    uint32_t group_column_count,
    const uint32_t *column_slab,
    size_t column_stride_words,
    size_t column_slab_words,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    const uint32_t *mapped_queries,
    const uint32_t *mapped_count,
    uint32_t mapped_capacity,
    uint32_t *assembly,
    uint32_t assembly_capacity_words,
    void *stream) {
    using namespace stwo::cuda::decommit;
    size_t slab_bytes = 0;
    size_t mapped_bytes = 0;
    size_t assembly_bytes = 0;
    if (total_column_count == 0 || group_column_count == 0 ||
        first_column > total_column_count ||
        group_column_count > total_column_count - first_column ||
        column_slab == nullptr || column_stride_words == 0 ||
        !slab_fits(
            column_stride_words, group_column_count, column_slab_words) ||
        !checked_bytes(column_slab_words, sizeof(uint32_t), &slab_bytes) ||
        column_log_sizes == nullptr || lifting_log_size >= 31 ||
        mapped_queries == nullptr || mapped_count == nullptr ||
        mapped_capacity == 0 || assembly == nullptr ||
        assembly_capacity_words < kHeaderWords || stream == nullptr ||
        !checked_bytes(mapped_capacity, sizeof(uint32_t), &mapped_bytes) ||
        !checked_bytes(
            assembly_capacity_words, sizeof(uint32_t), &assembly_bytes) ||
        device_ranges_overlap(column_slab, slab_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            column_log_sizes,
            static_cast<size_t>(group_column_count) * sizeof(uint32_t),
            assembly,
            assembly_bytes) ||
        device_ranges_overlap(
            mapped_queries, mapped_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            mapped_count, sizeof(uint32_t), assembly, assembly_bytes)) {
        return cudaErrorInvalidValue;
    }
    pack_trace_group_kernel<<<
        1, kBlockSize, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        tree_index,
        total_column_count,
        first_column,
        group_column_count,
        column_slab,
        column_stride_words,
        column_slab_words,
        column_log_sizes,
        lifting_log_size,
        mapped_queries,
        mapped_count,
        mapped_capacity,
        assembly,
        assembly_capacity_words);
    return cudaGetLastError();
}

extern "C" int stwo_decommit_assemble_trace_on(
    uint32_t tree_index,
    uint32_t tree_role,
    uint32_t leaf_log_size,
    uint32_t first_retained_log_size,
    uint32_t column_count,
    const uint32_t *mapped_count,
    uint32_t mapped_capacity,
    uint32_t *walk_queries,
    uint32_t *walk_scratch,
    const uint32_t *walk_count,
    uint32_t walk_capacity,
    const stwo::cuda::decommit::Hash *retained_slab,
    uint64_t retained_slab_hashes,
    const stwo::cuda::decommit::RetainedLayer *retained_layers,
    uint32_t retained_layer_count,
    const uint32_t *sparse_indices,
    const stwo::cuda::decommit::Hash *sparse_hashes,
    uint32_t sparse_capacity,
    const uint32_t *sparse_level_offsets,
    const uint32_t *sparse_level_counts,
    uint32_t sparse_level_count,
    uint32_t *assembly,
    uint32_t assembly_capacity_words,
    void *stream) {
    using namespace stwo::cuda::decommit;
    size_t retained_bytes = 0;
    size_t assembly_bytes = 0;
    size_t walk_bytes = 0;
    size_t sparse_hash_bytes = 0;
    if (leaf_log_size >= 31 ||
        first_retained_log_size > leaf_log_size ||
        retained_layer_count <= first_retained_log_size ||
        column_count == 0 || mapped_count == nullptr ||
        mapped_capacity == 0 || walk_queries == nullptr ||
        walk_scratch == nullptr || walk_count == nullptr ||
        walk_capacity == 0 || retained_slab == nullptr ||
        retained_slab_hashes == 0 || retained_layers == nullptr ||
        assembly == nullptr || assembly_capacity_words < kHeaderWords ||
        stream == nullptr ||
        (sparse_level_count != 0 &&
         (sparse_indices == nullptr || sparse_hashes == nullptr ||
          sparse_level_offsets == nullptr || sparse_level_counts == nullptr ||
          sparse_capacity == 0)) ||
        !checked_bytes(
            retained_slab_hashes, sizeof(Hash), &retained_bytes) ||
        !checked_bytes(walk_capacity, sizeof(uint32_t), &walk_bytes) ||
        !checked_bytes(
            sparse_capacity, sizeof(Hash), &sparse_hash_bytes) ||
        !checked_bytes(
            assembly_capacity_words, sizeof(uint32_t), &assembly_bytes) ||
        device_ranges_overlap(
            walk_queries, walk_bytes, walk_scratch, walk_bytes) ||
        device_ranges_overlap(
            walk_queries, walk_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            walk_scratch, walk_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            retained_slab, retained_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            retained_layers,
            static_cast<size_t>(retained_layer_count) * sizeof(RetainedLayer),
            assembly,
            assembly_bytes) ||
        device_ranges_overlap(
            sparse_hashes, sparse_hash_bytes, assembly, assembly_bytes) ||
        device_ranges_overlap(
            sparse_indices,
            static_cast<size_t>(sparse_capacity) * sizeof(uint32_t),
            assembly,
            assembly_bytes)) {
        return cudaErrorInvalidValue;
    }
    assemble_trace_kernel<<<
        1, kBlockSize, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        tree_index,
        tree_role,
        leaf_log_size,
        first_retained_log_size,
        column_count,
        mapped_count,
        mapped_capacity,
        walk_queries,
        walk_scratch,
        walk_count,
        walk_capacity,
        retained_slab,
        retained_slab_hashes,
        retained_layers,
        retained_layer_count,
        sparse_indices,
        sparse_hashes,
        sparse_capacity,
        sparse_level_offsets,
        sparse_level_counts,
        sparse_level_count,
        assembly,
        assembly_capacity_words);
    return cudaGetLastError();
}
