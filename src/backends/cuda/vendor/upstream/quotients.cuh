#ifndef QUOTIENTS_H
#define QUOTIENTS_H

#include "fields.cuh"
#include "point.cuh"
#include "resource_attestation.cuh"
#include "utils.cuh"

const unsigned int BLOCK_SIZE = 1024;

extern "C"
void accumulate_quotients(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        m31 **columns,
        uint32_t number_of_columns,
        qm31 random_coefficient,
        secure_field_point *sample_points,
        uint32_t *sample_column_indexes,
        uint32_t sample_column_indexes_size,
        qm31 *sample_column_values,
        uint32_t *sample_column_and_values_sizes,
        uint32_t sample_size,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3,
        uint32_t flattened_line_coeffs_size
);

extern "C"
void accumulate_partial_quotient_numerators(
        uint32_t domain_size,
        m31 **columns,
        uint32_t *sample_column_indexes,
        uint32_t sample_column_indexes_size,
        qm31 *line_coeffs_b,
        qm31 *line_coeffs_c,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3
);

extern "C"
void combine_quotients_from_numerators(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        uint32_t domain_log_size,
        secure_field_point *sample_points,
        uint32_t sample_size,
        qm31 *first_linear_term_accs,
        uint32_t *partial_numerator_log_sizes,
        m31 **partial_numerators_0,
        m31 **partial_numerators_1,
        m31 **partial_numerators_2,
        m31 **partial_numerators_3,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3
);

// Allocation-free, explicit-stream quotient combination for prepared proof
// graphs. Denominator inverses are consumed immediately in canonical sample
// order and never materialized in global memory.
extern "C"
int stwo_combine_quotients_from_numerators_on(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        uint32_t domain_log_size,
        const secure_field_point *sample_points,
        uint32_t sample_size,
        const qm31 *first_linear_term_accs,
        const uint32_t *partial_numerator_log_sizes,
        const m31 *const *partial_numerators_0,
        const m31 *const *partial_numerators_1,
        const m31 *const *partial_numerators_2,
        const m31 *const *partial_numerators_3,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3,
        void *stream
);

// Exact SN2 producer boundary: combine every quotient row once and retain the
// four-coordinate tile through B2N stages 1..7 before its only global write.
extern "C"
int stwo_combine_quotients_b2n_init7_on(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        uint32_t domain_log_size,
        const secure_field_point *sample_points,
        uint32_t sample_size,
        const qm31 *first_linear_term_accs,
        const uint32_t *partial_numerator_log_sizes,
        const m31 *const *partial_numerators_0,
        const m31 *const *partial_numerators_1,
        const m31 *const *partial_numerators_2,
        const m31 *const *partial_numerators_3,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3,
        const uint32_t *inverse_twiddles,
        uint32_t inverse_twiddle_words,
        uint32_t eval_domain_size,
        void *stream
);

// Attributes of the exact producer function loaded for the current device.
extern "C"
int stwo_combine_quotients_b2n_init7_function_attributes(
        StwoCudaFunctionAttributes *out
);

// Prepared FRI-quotient numerator pipeline. All topology tables and scratch
// buffers are caller-owned device memory; every launch stays on `stream`.
extern "C"
int stwo_prepare_quotient_numerator_terms_on(
        const uint32_t *term_descriptors,
        uint32_t term_count,
        const secure_field_point *sample_points,
        const qm31 *sample_values,
        const qm31 *random_coefficient,
        secure_field_point *term_points,
        qm31 *line_coefficients,
        void *stream
);

extern "C"
int stwo_finalize_quotient_numerator_groups_on(
        const uint32_t *group_offsets,
        const uint32_t *group_term_indices,
        uint32_t group_count,
        const secure_field_point *term_points,
        qm31 *line_coefficients,
        secure_field_point *sample_points,
        qm31 *first_linear_terms,
        void *stream
);

extern "C"
int stwo_zero_quotient_numerator_outputs_on(
        const uint32_t *group_log_sizes,
        uint32_t group_count,
        uint32_t max_output_size,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3,
        void *stream
);

extern "C"
int stwo_accumulate_quotient_numerator_batch_on(
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
        void *stream
);

#endif // QUOTIENTS_H
