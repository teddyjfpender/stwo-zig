#ifndef STWO_DECOMMIT_H
#define STWO_DECOMMIT_H

#include <cstdint>
#include "utils.cuh"

// Compact output ABI consumed by PreparedDecommitGraph. All offsets/counts are
// u32 words and every hash is eight consecutive little-endian words.
constexpr uint32_t STWO_DECOMMIT_HEADER_WORDS = 8;
constexpr uint32_t STWO_DECOMMIT_TREE_META_WORDS = 16;
constexpr uint32_t STWO_DECOMMIT_MAGIC = 0x44575453u; // "STWD"
constexpr uint32_t STWO_DECOMMIT_VERSION = 1;

extern "C" int stwo_decommit_normalize_queries_on(
    const uint32_t *raw_queries,
    uint32_t raw_query_count,
    uint32_t query_log_size,
    uint32_t tree_count,
    uint32_t *unique_queries,
    uint32_t *unique_count,
    uint32_t *assembly,
    uint32_t assembly_capacity_words,
    void *stream);

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
    uint32_t *leaf_count,
    void *stream);

extern "C" int stwo_decommit_pack_trace_group_on(
    uint32_t tree_index,
    uint32_t total_column_count,
    uint32_t first_column,
    uint32_t group_column_count,
    const uint32_t *const *columns,
    const uint32_t *column_log_sizes,
    uint32_t lifting_log_size,
    const uint32_t *mapped_queries,
    const uint32_t *mapped_count,
    uint32_t max_queries,
    uint32_t *assembly,
    uint32_t assembly_capacity_words,
    void *stream);

extern "C" int stwo_decommit_sparse_parent_on(
    const uint32_t *child_indices,
    const Blake2sHash *child_hashes,
    const uint32_t *child_count,
    uint32_t max_child_count,
    uint32_t *parent_indices,
    Blake2sHash *parent_hashes,
    uint32_t *parent_count,
    void *stream);

extern "C" int stwo_decommit_assemble_trace_on(
    uint32_t tree_index,
    uint32_t tree_role,
    uint32_t leaf_log_size,
    uint32_t first_retained_log_size,
    uint32_t column_count,
    const uint32_t *mapped_count,
    uint32_t max_queries,
    uint32_t *walk_queries,
    uint32_t *walk_scratch,
    const uint32_t *walk_count,
    const Blake2sHash *const *retained_layers_by_log,
    const uint32_t *sparse_indices,
    const Blake2sHash *sparse_hashes,
    const uint32_t *sparse_level_offsets,
    const uint32_t *sparse_level_counts,
    uint32_t sparse_level_count,
    uint32_t *assembly,
    uint32_t assembly_capacity_words,
    void *stream);

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
    uint32_t *expanded_count,
    uint32_t *walk_queries,
    uint32_t *walk_count,
    void *stream);

extern "C" int stwo_decommit_assemble_fri_on(
    uint32_t tree_index,
    uint32_t leaf_log_size,
    const uint32_t *tree_queries,
    const uint32_t *tree_query_count,
    const uint32_t *expanded_positions,
    const uint32_t *expanded_count,
    const uint32_t *const *coordinate_columns,
    uint32_t *walk_queries,
    uint32_t *walk_scratch,
    const uint32_t *walk_count,
    const Blake2sHash *const *retained_layers_by_log,
    uint32_t *assembly,
    uint32_t assembly_capacity_words,
    void *stream);

#endif
