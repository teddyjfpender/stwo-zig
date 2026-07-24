/*
 * Test-only link definitions for Zig wrapper type checking on non-CUDA hosts.
 * C's empty parameter list deliberately accepts the real ABI arguments; no
 * pointer is dereferenced and the production archive never compiles this file.
 */
#include <stddef.h>
#include <stdint.h>

#define STUB(name) int name() { return 0; }

static uint32_t transform_chunks(uint32_t columns) {
    return (columns + 65534u) / 65535u;
}

static uint32_t b2n_intervals(uint32_t log_n) {
    if (log_n >= 13u && log_n <= 18u) return 2u;
    if (log_n >= 19u && log_n <= 23u) return 3u;
    return log_n;
}

static uint32_t n2b_intervals(uint32_t log_n, int include_circle) {
    if (log_n >= 13u && log_n <= 19u) return 2u;
    if (log_n >= 20u && log_n <= 23u) return 3u;
    return include_circle ? log_n : log_n - 1u;
}

int stwo_ntt_b2n_columns_to_retained_on(
    const uint32_t *inputs,
    size_t input_stride,
    uint32_t *outputs,
    size_t output_stride,
    uint32_t log_n,
    uint32_t columns,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t domain_size,
    void *stream,
    uint32_t *launches_out) {
    (void)inputs;
    (void)input_stride;
    (void)outputs;
    (void)output_stride;
    (void)twiddles;
    (void)twiddle_words;
    (void)domain_size;
    (void)stream;
    *launches_out = transform_chunks(columns) * b2n_intervals(log_n);
    return 0;
}

int stwo_ntt_n2b_columns_on(
    uint32_t *columns_base,
    size_t stride,
    uint32_t log_n,
    uint32_t columns,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t domain_size,
    void *stream,
    uint32_t *launches_out) {
    (void)columns_base;
    (void)stride;
    (void)twiddles;
    (void)twiddle_words;
    (void)domain_size;
    (void)stream;
    *launches_out = transform_chunks(columns) * n2b_intervals(log_n, 1);
    return 0;
}

static int lde_stub(
    uint32_t log_n,
    uint32_t columns,
    int include_circle,
    uint32_t *launches_out) {
    const uint32_t chunks = transform_chunks(columns);
    *launches_out =
        chunks * (1u + n2b_intervals(log_n, include_circle));
    return 0;
}

#define LDE_STUB(name, include_circle)                                      \
    int name(                                                               \
        const uint32_t *coefficients,                                       \
        size_t coefficient_stride,                                          \
        const uint32_t *coefficient_logs,                                   \
        uint32_t *evaluations,                                               \
        size_t evaluation_stride,                                           \
        uint32_t log_n,                                                      \
        uint32_t columns,                                                    \
        const uint32_t *twiddles,                                            \
        uint32_t twiddle_words,                                              \
        uint32_t domain_size,                                                \
        void *stream,                                                        \
        uint32_t *launches_out) {                                            \
        (void)coefficients;                                                  \
        (void)coefficient_stride;                                            \
        (void)coefficient_logs;                                              \
        (void)evaluations;                                                   \
        (void)evaluation_stride;                                             \
        (void)twiddles;                                                       \
        (void)twiddle_words;                                                  \
        (void)domain_size;                                                    \
        (void)stream;                                                         \
        return lde_stub(log_n, columns, include_circle, launches_out);        \
    }

LDE_STUB(stwo_lde_n2b_columns_on, 1)
LDE_STUB(stwo_lde_n2b_columns_before_circle_on, 0)

int stwo_ntt_b2n_composition_split_compact_on(
    uint32_t *coordinate_values,
    size_t coordinate_capacity_words,
    size_t coordinate_stride_words,
    uint32_t *coefficients,
    size_t coefficient_capacity_words,
    size_t coefficient_stride_words,
    uint32_t log_n,
    const uint32_t *inverse_twiddles,
    uint32_t inverse_twiddle_words,
    uint32_t evaluation_domain_size,
    void *stream,
    uint32_t *launches_out) {
    (void)coordinate_values;
    (void)coordinate_capacity_words;
    (void)coordinate_stride_words;
    (void)coefficients;
    (void)coefficient_capacity_words;
    (void)coefficient_stride_words;
    (void)inverse_twiddles;
    (void)inverse_twiddle_words;
    (void)evaluation_domain_size;
    (void)stream;
    *launches_out = b2n_intervals(log_n);
    return 0;
}

STUB(stwo_accumulate_quotient_numerator_single_write_on)
STUB(stwo_blake2s_contiguous_leaf_on)
STUB(stwo_blake2s_fri_leaf_on)
STUB(stwo_blake2s_interior4_on)
STUB(stwo_blake2s_layer_on)
STUB(stwo_blake2s_pow_persistent_on)
STUB(stwo_blake2s_progressive_absorb_on)
STUB(stwo_blake2s_progressive_finalize_on)
STUB(stwo_blake2s_progressive_init_on)
STUB(stwo_blake2s_transcript_absorb_pow_on)
STUB(stwo_blake2s_transcript_draw_queries_on)
STUB(stwo_blake2s_transcript_draw_secure_on)
STUB(stwo_blake2s_transcript_draw_u32s_on)
STUB(stwo_blake2s_transcript_init_on)
STUB(stwo_blake2s_transcript_mix_words_on)
STUB(stwo_combine_quotients_from_numerators_on)
STUB(stwo_decommit_assemble_fri_on)
STUB(stwo_decommit_assemble_trace_on)
STUB(stwo_decommit_normalize_queries_on)
STUB(stwo_decommit_pack_trace_group_on)
STUB(stwo_decommit_prepare_fri_queries_on)
STUB(stwo_decommit_prepare_trace_queries_on)
STUB(stwo_decommit_sparse_parent_on)
STUB(stwo_finalize_quotient_numerator_groups_on)
STUB(stwo_fold_circle_into_line_on)
STUB(stwo_fold_line_on)
STUB(stwo_fri_fold_fused3_on)
STUB(stwo_fri_last_layer_on)
STUB(stwo_native_wide_fibonacci_trace_on)
STUB(stwo_oods_barycentric_eval_many_on)
STUB(stwo_oods_barycentric_weights_on)
STUB(stwo_oods_derive_points_on)
STUB(stwo_oods_eval_first_on)
STUB(stwo_oods_eval_reduce_on)
STUB(stwo_oods_store_results_on)
STUB(stwo_prepare_quotient_numerator_terms_on)
STUB(stwo_zero_quotient_numerator_outputs_on)
