#include "contract.cuh"

#if defined(STWO_CUMETAL)
extern "C" int stwo_cumetal_register_decommit_normalize(
    const void *host_stub);
#endif

namespace stwo::cuda::decommit {
namespace {

__global__ void normalize_queries_kernel(
    const uint32_t *raw_queries,
    uint32_t raw_query_count,
    uint32_t query_log_size,
    uint32_t tree_count,
    uint32_t *unique_queries,
    uint32_t *unique_count,
    uint32_t *assembly,
    uint32_t assembly_capacity_words) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    const uint32_t mask = (1u << query_log_size) - 1u;
    for (uint32_t index = 0; index < raw_query_count; ++index) {
        unique_queries[index] = raw_queries[index] & mask;
    }
    const uint32_t count = sort_unique(unique_queries, raw_query_count);
    *unique_count = count;

    const uint32_t raw_offset =
        kHeaderWords + tree_count * kTreeMetaWords;
    const uint32_t unique_offset = raw_offset + raw_query_count;
    const uint32_t used_words = unique_offset + count;
    if (used_words > assembly_capacity_words) {
        assembly[kHeaderUsedWords] = 0;
        return;
    }
    assembly[kHeaderMagic] = kMagic;
    assembly[kHeaderVersion] = kVersion;
    assembly[kHeaderTreeCount] = tree_count;
    assembly[kHeaderRawCount] = raw_query_count;
    assembly[kHeaderUniqueCount] = count;
    assembly[kHeaderRawOffset] = raw_offset;
    assembly[kHeaderUniqueOffset] = unique_offset;
    assembly[kHeaderUsedWords] = used_words;
    for (uint32_t index = 0; index < tree_count * kTreeMetaWords; ++index) {
        assembly[kHeaderWords + index] = 0;
    }
    for (uint32_t index = 0; index < raw_query_count; ++index) {
        assembly[raw_offset + index] = raw_queries[index] & mask;
    }
    for (uint32_t index = 0; index < count; ++index) {
        assembly[unique_offset + index] = unique_queries[index];
    }
}

__global__ void prepare_trace_queries_kernel(
    const uint32_t *unique_queries,
    const uint32_t *unique_count,
    uint32_t max_queries,
    uint32_t source_log_size,
    uint32_t tree_log_size,
    uint32_t leaf_log_size,
    uint32_t unretained_bottom_layers,
    uint32_t *mapped_queries,
    uint32_t *mapped_count,
    uint32_t *walk_queries,
    uint32_t *walk_count,
    uint32_t *leaf_indices,
    uint32_t leaf_capacity,
    uint32_t *leaf_count) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    const uint32_t count = *unique_count;
    if (count == 0 || count > max_queries) {
        *mapped_count = 0;
        *walk_count = 0;
        *leaf_count = 0;
        return;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (index != 0 && unique_queries[index - 1] >= unique_queries[index]) {
            *mapped_count = 0;
            *walk_count = 0;
            *leaf_count = 0;
            return;
        }
        mapped_queries[index] = map_query_log(
            unique_queries[index],
            source_log_size,
            tree_log_size);
        walk_queries[index] = mapped_queries[index];
    }
    *mapped_count = count;
    const uint32_t deduplicated = sort_unique(walk_queries, count);
    *walk_count = deduplicated;

    if (unretained_bottom_layers == 0) {
        *leaf_count = 0;
        return;
    }
    const uint32_t span = 1u << unretained_bottom_layers;
    uint32_t leaves = 0;
    for (uint32_t query = 0; query < deduplicated; ++query) {
        const uint32_t base =
            (walk_queries[query] >> unretained_bottom_layers) <<
            unretained_bottom_layers;
        if (span > leaf_capacity - leaves) {
            *leaf_count = 0;
            return;
        }
        for (uint32_t offset = 0; offset < span; ++offset) {
            leaf_indices[leaves++] = base + offset;
        }
    }
    *leaf_count = sort_unique(leaf_indices, leaves);
}

__global__ void prepare_fri_queries_kernel(
    const uint32_t *unique_queries,
    const uint32_t *unique_count,
    uint32_t max_queries,
    uint32_t cumulative_fold,
    uint32_t fold_step,
    uint32_t log_rows_per_leaf,
    uint32_t *tree_queries,
    uint32_t *tree_query_count,
    uint32_t *expanded_positions,
    uint32_t expanded_capacity,
    uint32_t *expanded_count,
    uint32_t *walk_queries,
    uint32_t walk_capacity,
    uint32_t *walk_count) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    const uint32_t count = *unique_count;
    if (count == 0 || count > max_queries) {
        *tree_query_count = 0;
        *expanded_count = 0;
        *walk_count = 0;
        return;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (index != 0 && unique_queries[index - 1] >= unique_queries[index]) {
            *tree_query_count = 0;
            *expanded_count = 0;
            *walk_count = 0;
            return;
        }
        tree_queries[index] = unique_queries[index] >> cumulative_fold;
    }
    const uint32_t query_count = sort_unique(tree_queries, count);
    *tree_query_count = query_count;

    const uint32_t coset_size = 1u << fold_step;
    uint32_t output_count = 0;
    uint32_t previous_coset = UINT32_MAX;
    for (uint32_t index = 0; index < query_count; ++index) {
        const uint32_t coset = tree_queries[index] >> fold_step;
        if (coset == previous_coset) continue;
        previous_coset = coset;
        const uint64_t start = static_cast<uint64_t>(coset) << fold_step;
        if (start > UINT32_MAX ||
            coset_size > expanded_capacity - output_count) {
            *expanded_count = 0;
            *walk_count = 0;
            return;
        }
        for (uint32_t offset = 0; offset < coset_size; ++offset) {
            expanded_positions[output_count++] =
                static_cast<uint32_t>(start) + offset;
        }
    }
    *expanded_count = output_count;
    if (output_count > walk_capacity) {
        *expanded_count = 0;
        *walk_count = 0;
        return;
    }
    for (uint32_t index = 0; index < output_count; ++index) {
        walk_queries[index] =
            expanded_positions[index] >> log_rows_per_leaf;
    }
    *walk_count = sort_unique(walk_queries, output_count);
}

bool disjoint_ranges(const void *const *pointers, const size_t *bytes, size_t count) {
    for (size_t left = 0; left < count; ++left) {
        for (size_t right = left + 1; right < count; ++right) {
            if (device_ranges_overlap(
                    pointers[left], bytes[left], pointers[right], bytes[right])) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace
}  // namespace stwo::cuda::decommit

extern "C" int stwo_decommit_normalize_queries_on(
    const uint32_t *raw_queries,
    uint32_t raw_query_count,
    uint32_t query_log_size,
    uint32_t tree_count,
    uint32_t *unique_queries,
    uint32_t *unique_count,
    uint32_t *assembly,
    uint32_t assembly_capacity_words,
    void *stream) {
    using namespace stwo::cuda::decommit;
    const uint64_t minimum_assembly =
        kHeaderWords + static_cast<uint64_t>(tree_count) * kTreeMetaWords +
        2ull * raw_query_count;
    const void *pointers[] = {
        raw_queries, unique_queries, unique_count, assembly,
    };
    const size_t bytes[] = {
        static_cast<size_t>(raw_query_count) * sizeof(uint32_t),
        static_cast<size_t>(raw_query_count) * sizeof(uint32_t),
        sizeof(uint32_t),
        static_cast<size_t>(assembly_capacity_words) * sizeof(uint32_t),
    };
    if (raw_queries == nullptr || raw_query_count == 0 ||
        raw_query_count > kMaxProtocolQueries ||
        query_log_size == 0 || query_log_size >= 31 || tree_count == 0 ||
        unique_queries == nullptr || unique_count == nullptr ||
        assembly == nullptr || minimum_assembly > assembly_capacity_words ||
        stream == nullptr || !disjoint_ranges(pointers, bytes, 4)) {
        return cudaErrorInvalidValue;
    }
#if defined(STWO_CUMETAL)
    if (stwo_cumetal_register_decommit_normalize(
            reinterpret_cast<const void *>(normalize_queries_kernel)) != 0) {
        return cudaErrorUnknown;
    }
#endif
    normalize_queries_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        raw_queries,
        raw_query_count,
        query_log_size,
        tree_count,
        unique_queries,
        unique_count,
        assembly,
        assembly_capacity_words);
    return cudaGetLastError();
}

extern "C" int stwo_decommit_prepare_trace_queries_on(
    const uint32_t *unique_queries,
    const uint32_t *unique_count,
    uint32_t max_queries,
    uint32_t source_log_size,
    uint32_t tree_log_size,
    uint32_t leaf_log_size,
    uint32_t unretained_bottom_layers,
    uint32_t *mapped_queries,
    uint32_t *mapped_count,
    uint32_t *walk_queries,
    uint32_t *walk_count,
    uint32_t *leaf_indices,
    uint32_t leaf_capacity,
    uint32_t *leaf_count,
    void *stream) {
    using namespace stwo::cuda::decommit;
    const uint64_t required_leaves = unretained_bottom_layers == 0
        ? 1
        : unretained_bottom_layers < 31
        ? static_cast<uint64_t>(max_queries) << unretained_bottom_layers
        : UINT64_MAX;
    const void *pointers[] = {
        unique_queries, unique_count, mapped_queries, mapped_count,
        walk_queries, walk_count, leaf_indices, leaf_count,
    };
    const size_t bytes[] = {
        static_cast<size_t>(max_queries) * sizeof(uint32_t),
        sizeof(uint32_t),
        static_cast<size_t>(max_queries) * sizeof(uint32_t),
        sizeof(uint32_t),
        static_cast<size_t>(max_queries) * sizeof(uint32_t),
        sizeof(uint32_t),
        static_cast<size_t>(leaf_capacity) * sizeof(uint32_t),
        sizeof(uint32_t),
    };
    if (unique_queries == nullptr || unique_count == nullptr ||
        max_queries == 0 || max_queries > kMaxProtocolQueries ||
        source_log_size >= 31 || tree_log_size >= 31 ||
        leaf_log_size >= 31 ||
        unretained_bottom_layers > leaf_log_size ||
        unretained_bottom_layers >= 31 ||
        required_leaves > leaf_capacity ||
        mapped_queries == nullptr || mapped_count == nullptr ||
        walk_queries == nullptr || walk_count == nullptr ||
        leaf_indices == nullptr || leaf_count == nullptr || stream == nullptr ||
        !disjoint_ranges(pointers, bytes, 8)) {
        return cudaErrorInvalidValue;
    }
    prepare_trace_queries_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        unique_queries,
        unique_count,
        max_queries,
        source_log_size,
        tree_log_size,
        leaf_log_size,
        unretained_bottom_layers,
        mapped_queries,
        mapped_count,
        walk_queries,
        walk_count,
        leaf_indices,
        leaf_capacity,
        leaf_count);
    return cudaGetLastError();
}

extern "C" int stwo_decommit_prepare_fri_queries_on(
    const uint32_t *unique_queries,
    const uint32_t *unique_count,
    uint32_t max_queries,
    uint32_t cumulative_fold,
    uint32_t fold_step,
    uint32_t log_rows_per_leaf,
    uint32_t *tree_queries,
    uint32_t *tree_query_count,
    uint32_t *expanded_positions,
    uint32_t expanded_capacity,
    uint32_t *expanded_count,
    uint32_t *walk_queries,
    uint32_t walk_capacity,
    uint32_t *walk_count,
    void *stream) {
    using namespace stwo::cuda::decommit;
    const uint64_t maximum_expansion = fold_step < 31
        ? static_cast<uint64_t>(max_queries) << fold_step
        : UINT64_MAX;
    const void *pointers[] = {
        unique_queries, unique_count, tree_queries, tree_query_count,
        expanded_positions, expanded_count, walk_queries, walk_count,
    };
    const size_t bytes[] = {
        static_cast<size_t>(max_queries) * sizeof(uint32_t),
        sizeof(uint32_t),
        static_cast<size_t>(max_queries) * sizeof(uint32_t),
        sizeof(uint32_t),
        static_cast<size_t>(expanded_capacity) * sizeof(uint32_t),
        sizeof(uint32_t),
        static_cast<size_t>(walk_capacity) * sizeof(uint32_t),
        sizeof(uint32_t),
    };
    if (unique_queries == nullptr || unique_count == nullptr ||
        max_queries == 0 || max_queries > kMaxProtocolQueries ||
        cumulative_fold >= 31 || fold_step >= 31 ||
        log_rows_per_leaf >= 31 || maximum_expansion > expanded_capacity ||
        maximum_expansion > walk_capacity || tree_queries == nullptr ||
        tree_query_count == nullptr || expanded_positions == nullptr ||
        expanded_count == nullptr || walk_queries == nullptr ||
        walk_count == nullptr || stream == nullptr ||
        !disjoint_ranges(pointers, bytes, 8)) {
        return cudaErrorInvalidValue;
    }
    prepare_fri_queries_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        unique_queries,
        unique_count,
        max_queries,
        cumulative_fold,
        fold_step,
        log_rows_per_leaf,
        tree_queries,
        tree_query_count,
        expanded_positions,
        expanded_capacity,
        expanded_count,
        walk_queries,
        walk_capacity,
        walk_count);
    return cudaGetLastError();
}
