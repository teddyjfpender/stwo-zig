#ifndef STWO_ZIG_METAL_RUNTIME_ABI_H
#define STWO_ZIG_METAL_RUNTIME_ABI_H

#import <Foundation/Foundation.h>

#include <stddef.h>
#include <stdint.h>

typedef NS_ENUM(uint32_t, StwoZigCommitmentHashFamilyV1) {
    StwoZigCommitmentHashFamilyBlake2sV1 = 1u,
    StwoZigCommitmentHashFamilyPoseidon2M31V1 = 2u,
};

typedef NS_ENUM(uint32_t, StwoZigResidentMerkleLeafEncodingV1) {
    StwoZigResidentMerkleLeafEncodingWideV1 = 0u,
    StwoZigResidentMerkleLeafEncodingStagedPoseidonV1 = 1u,
};

static inline bool stwo_zig_valid_commitment_hash_family_v1(uint32_t family) {
    return family == StwoZigCommitmentHashFamilyBlake2sV1 ||
        family == StwoZigCommitmentHashFamilyPoseidon2M31V1;
}

typedef struct {
    uint64_t command_buffers;
    uint64_t wait_count;
    uint64_t intermediate_wait_count;
    uint64_t compute_encoders;
    uint64_t blit_encoders;
    uint64_t dispatches;
    double gpu_milliseconds;
} StwoZigCommandEpochStats;

typedef NS_ENUM(uint32_t, StwoZigCommandEpochState) {
    StwoZigCommandEpochStateEncoding = 0u,
    StwoZigCommandEpochStateSubmitted = 1u,
    StwoZigCommandEpochStateCompleted = 2u,
    StwoZigCommandEpochStateFailed = 3u,
};

typedef struct {
    uint32_t offset, length, batch, shift, direct;
    uint32_t coeff_a, coeff_b, coeff_c, coeff_d;
} StwoZigRawQuotientView;

// Host-side raw quotient descriptors name columns in the complete logical
// source stream.  That stream may exceed 2^32 words even though every view
// handed to a Metal kernel is rebased into one bounded source buffer.
typedef struct {
    uint64_t offset;
    uint32_t length, batch, shift, direct;
    uint32_t coeff_a, coeff_b, coeff_c, coeff_d;
} StwoZigRawQuotientSourceViewV2;

typedef NS_ENUM(uint32_t, StwoZigQuotientParityPhaseV1) {
    StwoZigQuotientParityRawSegmentV1 = 1u,
    StwoZigQuotientParityFinalizedV1 = 2u,
};

typedef NS_OPTIONS(uint32_t, StwoZigQuotientParityFlagsV1) {
    StwoZigQuotientParityResidentSourceV1 = 1u << 0u,
    StwoZigQuotientParityPageAliasSourceV1 = 1u << 1u,
};

typedef struct {
    uint32_t schema_version;
    uint32_t phase;
    uint32_t segment_index;
    uint32_t segment_count;
    uint32_t first_column;
    uint32_t column_count;
    uint32_t view_count;
    uint32_t batch_count;
    uint64_t row_count;
    uint64_t flat_offset;
    uint64_t run_words;
    uint64_t source_binding_offset;
    uint32_t flags;
    uint32_t min_batch;
    uint32_t max_batch;
    uint32_t reserved;
    uint64_t min_original_offset;
    uint64_t max_original_offset;
    uint64_t min_rebased_offset;
    uint64_t max_rebased_offset;
} StwoZigQuotientParityEventV1;

typedef bool (*StwoZigQuotientParityObserverV1)(
    void *context,
    const StwoZigQuotientParityEventV1 *event,
    const StwoZigRawQuotientView *mapped_views,
    const uint32_t *domain_x,
    const uint32_t *domain_y,
    const uint32_t *values,
    size_t value_count
);

typedef struct {
    uint32_t schema_version;
    uint32_t path;
    uint32_t reserved0;
    uint32_t reserved1;
    uint64_t row_count;
    uint64_t batch_count;
    uint64_t view_count;
    uint64_t grouped_partial_count;
    uint64_t numerator_additions;
    uint64_t numerator_multiplications;
    uint64_t domain_circle_additions;
    uint64_t batch_inverse_calls;
} StwoZigQuotientWorkReceipt;

typedef struct {
    uint32_t coefficient_offset, coefficient_length, basis_offset, log_size, output_index;
} StwoZigPolynomialEvalTask;

typedef struct {
    uint32_t factor_offset, log_size, basis_offset, basis_length;
} StwoZigPolynomialBasisTask;

typedef struct {
    uint32_t log_size, first_group, group_count, reserved;
    uint32_t point[8];
    uint32_t si0[4];
    uint32_t vanishing_rotation[2];
} StwoZigSampledBarycentricPointPlanV1;

typedef struct {
    uint32_t tree_index, first_column, column_count, reserved;
} StwoZigSampledBarycentricColumnGroupV1;

typedef struct {
    uint32_t schema_version, command_buffers, wait_count, reserved;
    uint64_t unique_point_count;
    uint64_t unique_domain_count;
    uint64_t resident_column_evaluations;
    uint64_t weight_values;
    uint64_t dot_product_terms;
    uint64_t inverse_tree_blocks;
    uint64_t direct_inversions;
    uint64_t reduction_additions;
    uint32_t evaluation_threadgroup_width;
    uint32_t inverse_threadgroup_width;
} StwoZigSampledBarycentricReceiptV1;

_Static_assert(sizeof(StwoZigSampledBarycentricPointPlanV1) == 72,
    "sampled barycentric point-plan ABI size drift");
_Static_assert(offsetof(StwoZigSampledBarycentricPointPlanV1, point) == 16,
    "sampled barycentric point-plan ABI point offset drift");
_Static_assert(sizeof(StwoZigSampledBarycentricColumnGroupV1) == 16,
    "sampled barycentric column-group ABI size drift");
_Static_assert(sizeof(StwoZigSampledBarycentricReceiptV1) == 88,
    "sampled barycentric receipt ABI size drift");

bool stwo_zig_metal_eval_barycentric_resident_v1(
    void *runtime,
    void *const *resident_trees,
    uint32_t tree_count,
    const uint32_t *const *columns,
    const size_t *column_lengths,
    const uint32_t *output_indices,
    uint32_t column_count,
    const StwoZigSampledBarycentricPointPlanV1 *point_plans,
    uint32_t point_plan_count,
    const StwoZigSampledBarycentricColumnGroupV1 *groups,
    uint32_t group_count,
    uint32_t output_count,
    uint32_t *output,
    StwoZigSampledBarycentricReceiptV1 *receipt,
    double *gpu_milliseconds,
    char *error_message,
    size_t error_message_len
);

typedef struct {
    uint64_t unique_base, unique_count_base;
    uint64_t tree_queries_base, tree_count_base;
    uint64_t expanded_base, expanded_count_base;
    uint64_t walk_base, walk_count_base;
    uint64_t coordinate_bases, values_base, walk_scratch_base;
    uint64_t retained_offsets, assembly_base;
    uint32_t max_queries, cumulative_fold, fold_step, packed_log;
    uint32_t max_positions, tree_index, leaf_log, assembly_capacity;
} StwoZigDecommitFriRoundParams;

typedef struct {
    uint64_t column_offsets, column_logs;
    uint64_t queries, query_count_at, values;
    uint64_t leaf_indices, leaf_count_at, output_hashes;
    uint32_t column_count, lifting_log, max_queries, first_column;
    uint32_t stride, total_columns, max_leaf_count, domain_prefix_bytes;
    uint32_t leaf_seed[8];
} StwoZigDecommitTraceGroupParams;

typedef struct {
    uint64_t library_cache_hits;
    uint64_t library_cache_misses;
    uint64_t pipeline_cache_hits;
    uint64_t binary_archive_hits;
    uint64_t binary_archive_misses;
    uint64_t direct_compiles;
    uint64_t archive_populations;
    uint64_t archive_serializations;
    double pipeline_preparation_seconds;
    double library_preparation_seconds;
    uint64_t library_cache_entries;
    uint64_t library_cache_bytes;
    uint64_t library_cache_peak_entries;
    uint64_t library_cache_peak_bytes;
    uint64_t library_cache_evictions;
    uint64_t library_cache_rejections;
    uint64_t pipeline_cache_entries;
    uint64_t pipeline_cache_bytes;
    uint64_t pipeline_cache_peak_entries;
    uint64_t pipeline_cache_peak_bytes;
    uint64_t pipeline_cache_evictions;
    uint64_t pipeline_cache_invalidations;
    uint64_t pipeline_cache_rejections;
    uint64_t library_cache_entry_limit;
    uint64_t library_cache_byte_limit;
    uint64_t pipeline_cache_entry_limit;
    uint64_t pipeline_cache_byte_limit;
} StwoZigPipelineCacheStats;

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t archive_disk_hits;
    uint64_t archive_disk_misses;
    uint64_t archive_disk_evictions;
    uint64_t archive_disk_rebuilds;
    uint64_t archive_disk_rejections;
    uint64_t archive_disk_quarantines;
    uint64_t archive_lock_acquisitions;
    uint64_t archive_lock_contentions;
    uint64_t archive_lock_timeouts;
    uint64_t archive_publication_successes;
    uint64_t archive_publication_failures;
    uint64_t archive_bytes_published;
    uint64_t archive_bytes_evicted;
    uint64_t archive_persistence_bypasses;
    double archive_lock_wait_seconds;
    uint64_t archive_disk_entries;
    uint64_t archive_disk_bytes;
    uint64_t archive_disk_entry_limit;
    uint64_t archive_disk_byte_limit;
    uint64_t archive_per_entry_byte_limit;
    uint64_t archive_quarantine_entries;
    uint64_t archive_quarantine_bytes;
    uint64_t archive_quarantine_entry_limit;
    uint64_t archive_quarantine_byte_limit;
} StwoZigArchiveStoreStatsV1;

_Static_assert(sizeof(StwoZigArchiveStoreStatsV1) == 200,
    "Metal archive store stats ABI size drift");
_Static_assert(offsetof(StwoZigArchiveStoreStatsV1, archive_disk_hits) == 8,
    "Metal archive store stats ABI hit offset drift");
_Static_assert(offsetof(StwoZigArchiveStoreStatsV1, archive_lock_wait_seconds) == 120,
    "Metal archive store stats ABI timing offset drift");
_Static_assert(offsetof(StwoZigArchiveStoreStatsV1, archive_quarantine_byte_limit) == 192,
    "Metal archive store stats ABI tail offset drift");

typedef struct {
    uint64_t source_word_offset;
    uint32_t source_word_count;
    uint32_t value_coefficients[4];
} StwoZigQuotientCoefficientTerm;

typedef struct {
    uint64_t source_word_offset;
    uint64_t destination_word_offset;
    uint32_t word_count;
    uint32_t reserved;
} StwoZigArenaCopyRange;

typedef struct {
    uint64_t arena_byte_offset;
    uint64_t snapshot_byte_offset;
    uint64_t byte_count;
} StwoZigPreparedStateRange;

bool stwo_zig_metal_validate_raw_quotient_source_views_v2(
    const size_t *raw_column_lengths,
    uint32_t raw_column_count,
    const StwoZigRawQuotientSourceViewV2 *views,
    uint32_t view_count,
    uint32_t row_count,
    uint32_t batch_count
);
bool stwo_zig_metal_local_raw_quotient_view_v2(
    const StwoZigRawQuotientSourceViewV2 *source,
    uint64_t local_offset,
    uint32_t row_count,
    uint32_t batch_count,
    StwoZigRawQuotientView *destination
);
size_t stwo_zig_metal_runtime_identity(void *runtime, char *output, size_t output_len);

_Static_assert(sizeof(StwoZigCommandEpochStats) == 56u, "StwoZigCommandEpochStats ABI");
_Static_assert(sizeof(StwoZigRawQuotientView) == 36u, "StwoZigRawQuotientView ABI");
_Static_assert(sizeof(StwoZigRawQuotientSourceViewV2) == 40u,
               "StwoZigRawQuotientSourceViewV2 ABI");
_Static_assert(offsetof(StwoZigRawQuotientSourceViewV2, offset) == 0u,
               "raw quotient source offset ABI");
_Static_assert(offsetof(StwoZigRawQuotientSourceViewV2, length) == 8u,
               "raw quotient source length ABI");
_Static_assert(sizeof(StwoZigQuotientParityEventV1) == 112u,
               "StwoZigQuotientParityEventV1 ABI");
_Static_assert(offsetof(StwoZigQuotientParityEventV1, row_count) == 32u,
               "quotient parity row-count ABI");
_Static_assert(offsetof(StwoZigQuotientParityEventV1, flags) == 64u,
               "quotient parity flags ABI");
_Static_assert(offsetof(StwoZigQuotientParityEventV1, min_original_offset) == 80u,
               "quotient parity original-offset ABI");
_Static_assert(sizeof(StwoZigQuotientWorkReceipt) == 80u, "StwoZigQuotientWorkReceipt ABI");
_Static_assert(offsetof(StwoZigQuotientWorkReceipt, row_count) == 16u, "quotient work row ABI");
_Static_assert(sizeof(StwoZigPolynomialEvalTask) == 20u, "StwoZigPolynomialEvalTask ABI");
_Static_assert(offsetof(StwoZigPolynomialEvalTask, coefficient_offset) == 0u, "coefficient_offset ABI");
_Static_assert(offsetof(StwoZigPolynomialEvalTask, coefficient_length) == 4u, "coefficient_length ABI");
_Static_assert(offsetof(StwoZigPolynomialEvalTask, basis_offset) == 8u, "basis_offset ABI");
_Static_assert(offsetof(StwoZigPolynomialEvalTask, log_size) == 12u, "log_size ABI");
_Static_assert(offsetof(StwoZigPolynomialEvalTask, output_index) == 16u, "output_index ABI");
_Static_assert(sizeof(StwoZigPolynomialBasisTask) == 16u, "StwoZigPolynomialBasisTask ABI");
_Static_assert(offsetof(StwoZigPolynomialBasisTask, factor_offset) == 0u, "factor_offset ABI");
_Static_assert(offsetof(StwoZigPolynomialBasisTask, log_size) == 4u, "basis log_size ABI");
_Static_assert(offsetof(StwoZigPolynomialBasisTask, basis_offset) == 8u, "basis_offset ABI");
_Static_assert(offsetof(StwoZigPolynomialBasisTask, basis_length) == 12u, "basis_length ABI");
_Static_assert(sizeof(StwoZigDecommitFriRoundParams) == 136u, "StwoZigDecommitFriRoundParams ABI");
_Static_assert(offsetof(StwoZigDecommitFriRoundParams, assembly_base) == 96u, "FRI assembly_base ABI");
_Static_assert(offsetof(StwoZigDecommitFriRoundParams, max_queries) == 104u, "FRI max_queries ABI");
_Static_assert(sizeof(StwoZigDecommitTraceGroupParams) == 128u, "StwoZigDecommitTraceGroupParams ABI");
_Static_assert(offsetof(StwoZigDecommitTraceGroupParams, domain_prefix_bytes) == 92u, "trace domain_prefix_bytes ABI");
_Static_assert(offsetof(StwoZigDecommitTraceGroupParams, leaf_seed) == 96u, "trace leaf_seed ABI");
_Static_assert(sizeof(StwoZigPipelineCacheStats) == 216u, "StwoZigPipelineCacheStats ABI");
_Static_assert(offsetof(StwoZigPipelineCacheStats, pipeline_preparation_seconds) == 64u, "pipeline stats ABI");
_Static_assert(offsetof(StwoZigPipelineCacheStats, library_preparation_seconds) == 72u, "library stats ABI");
_Static_assert(offsetof(StwoZigPipelineCacheStats, library_cache_entries) == 80u, "library cache entries ABI");
_Static_assert(offsetof(StwoZigPipelineCacheStats, pipeline_cache_entries) == 128u, "pipeline cache entries ABI");
_Static_assert(offsetof(StwoZigPipelineCacheStats, pipeline_cache_byte_limit) == 208u, "pipeline cache limit ABI");
_Static_assert(sizeof(StwoZigQuotientCoefficientTerm) == 32u, "StwoZigQuotientCoefficientTerm ABI");
_Static_assert(offsetof(StwoZigQuotientCoefficientTerm, value_coefficients) == 12u, "quotient coefficients ABI");
_Static_assert(sizeof(StwoZigArenaCopyRange) == 24u, "StwoZigArenaCopyRange ABI");
_Static_assert(offsetof(StwoZigArenaCopyRange, reserved) == 20u, "arena copy reserved ABI");
_Static_assert(sizeof(StwoZigPreparedStateRange) == 24u, "StwoZigPreparedStateRange ABI");

#endif
