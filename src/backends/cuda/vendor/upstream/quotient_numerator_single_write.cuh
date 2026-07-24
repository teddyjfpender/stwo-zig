#ifndef QUOTIENT_NUMERATOR_SINGLE_WRITE_H
#define QUOTIENT_NUMERATOR_SINGLE_WRITE_H

#include "fields.cuh"

struct StwoCudaFunctionAttributes;

enum StwoQuotientNumeratorFunctionRole : uint32_t {
    STWO_QUOTIENT_NUMERATOR_STAGED_PACKED = 0,
    STWO_QUOTIENT_NUMERATOR_PREPACKED_PREPARE = 1,
    STWO_QUOTIENT_NUMERATOR_PREPACKED_VALIDATE = 2,
    STWO_QUOTIENT_NUMERATOR_PREPACKED_HOT = 3,
    STWO_QUOTIENT_NUMERATOR_GROUP_DIRECT = 4,
};

enum StwoQuotientNumeratorPrepackedStatus : uint32_t {
    STWO_QUOTIENT_PREPACKED_SUCCESS = 0,
    STWO_QUOTIENT_PREPACKED_PREPARE_GROUP_OFFSETS_NOT_CANONICAL = 1,
    STWO_QUOTIENT_PREPACKED_PREPARE_SOURCE_OUT_OF_BOUNDS = 2,
    STWO_QUOTIENT_PREPACKED_PREPARE_TERM_OUT_OF_BOUNDS = 3,
    STWO_QUOTIENT_PREPACKED_PREPARE_SOURCE_LOG_OUT_OF_BOUNDS = 4,
    STWO_QUOTIENT_PREPACKED_PREPARE_NULL_SOURCE = 5,
    STWO_QUOTIENT_PREPACKED_PREPARE_GROUP_RANGE_OUT_OF_BOUNDS = 6,
    STWO_QUOTIENT_PREPACKED_PREPARE_GROUP_TERM_OUT_OF_BOUNDS = 7,
    STWO_QUOTIENT_PREPACKED_HOT_ROW_OFFSETS_NOT_CANONICAL = 8,
    STWO_QUOTIENT_PREPACKED_HOT_GROUP_ROW_SHAPE_INVALID = 9,
    STWO_QUOTIENT_PREPACKED_HOT_GROUP_TERM_RANGE_INVALID = 10,
    STWO_QUOTIENT_PREPACKED_HOT_SOURCE_LOG_OUT_OF_BOUNDS = 11,
    STWO_QUOTIENT_PREPACKED_HOT_NULL_SOURCE = 12,
};

// Candidate-only quotient numerator entry. Descriptors are grouped by output
// group and contain [global_source, canonical_term, source_log_size]. Every
// sampled source must be a retained evaluation for the duration of the launch.
extern "C" int stwo_accumulate_quotient_numerator_single_write_on(
        const uint32_t *group_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint32_t max_output_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3,
        void *stream);

// Replacement-v1 coefficient-inclusive entry. `group_row_offsets` is a sealed
// u64 prefix sum with `group_count + 1` entries; its terminal entry must equal
// `packed_output_rows`. Exactly one 1-D thread is launched per useful row.
extern "C" int stwo_accumulate_quotient_numerator_packed_single_write_on(
        const uint64_t *group_row_offsets,
        const uint32_t *group_term_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint64_t packed_output_rows,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3,
        void *stream);

// Candidate-only direct group entry. The prepared host plan seals the exact
// term range, monotone source-log runs, row shape, and output ownership into
// scalar launch arguments. For log >= 1 each thread owns two half-separated
// rows; log 0 dispatches one exact scalar owner.
extern "C" int stwo_accumulate_quotient_numerator_group_direct_on(
        const uint32_t *term_descriptors,
        uint32_t term_begin,
        uint32_t term_end,
        uint32_t group_log_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const qm31 *group_b,
        uint32_t *output_0,
        uint32_t *output_1,
        uint32_t *output_2,
        uint32_t *output_3,
        void *stream);

// Candidate-only device preparation. It reuses term_points after group
// finalization: seven words per descriptor, one four-word B_g per group, then
// one status word. The wrapper resets status asynchronously on `stream`.
extern "C" int stwo_prepare_quotient_numerator_prepacked_terms_on(
        const uint32_t *group_term_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint32_t term_count,
        const uint32_t *const *source_evaluations,
        uint32_t source_count,
        const qm31 *line_coefficients,
        uint32_t *prepacked_storage,
        uint64_t prepacked_storage_words,
        void *stream);

// Candidate hot loop over the prepared records. Arithmetic uses the
// translation-unit-local canonical fast32 helpers; global field behavior is
// unchanged. The caller must observe the trailing status word as zero before
// accepting any output from the stream.
extern "C" int stwo_accumulate_quotient_numerator_prepacked_single_write_on(
        const uint64_t *group_row_offsets,
        const uint32_t *group_term_offsets,
        uint32_t group_count,
        uint32_t term_count,
        uint64_t packed_output_rows,
        uint32_t *prepacked_storage,
        uint64_t prepacked_storage_words,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3,
        void *stream);

// Exact attributes for the function loaded on the current CUDA device.
extern "C" int stwo_quotient_numerator_single_write_function_attributes(
        uint32_t role,
        StwoCudaFunctionAttributes *out);

#endif // QUOTIENT_NUMERATOR_SINGLE_WRITE_H
