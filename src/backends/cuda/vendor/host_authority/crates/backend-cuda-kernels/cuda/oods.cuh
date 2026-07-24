#ifndef STWO_OODS_H
#define STWO_OODS_H

#include "fields.cuh"
#include "point.cuh"

// Allocation-free, explicit-stream OODS evaluation for arena-resident circle
// coefficients. All descriptor, scratch, input, and output memory is device-owned.
extern "C" int stwo_oods_derive_points_on(
    const qm31 *oods_parameter,
    const point *offset_points,
    const uint32_t *fold_counts,
    const uint32_t *output_indices,
    uint32_t sample_count,
    uint32_t coefficient_log_size,
    secure_field_point *sample_points,
    secure_field_point *evaluation_points,
    qm31 *folding_factors,
    void *stream);

extern "C" int stwo_oods_eval_first_on(
    const m31 *const *coefficients,
    uint32_t coefficient_size,
    uint32_t sample_count,
    const qm31 *folding_factors,
    qm31 *scratch,
    void *stream);

extern "C" int stwo_oods_eval_reduce_on(
    const qm31 *input,
    uint32_t input_size,
    uint32_t input_stride,
    uint32_t factor_index,
    uint32_t coefficient_log_size,
    uint32_t sample_count,
    const qm31 *folding_factors,
    qm31 *output,
    uint32_t output_stride,
    void *stream);

extern "C" int stwo_oods_store_results_on(
    const qm31 *reduced,
    uint32_t reduced_stride,
    const uint32_t *output_indices,
    uint32_t sample_count,
    qm31 *sampled_values,
    void *stream);

extern "C" int stwo_oods_barycentric_weights_on(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    const secure_field_point *evaluation_point,
    qm31 si0,
    point vanishing_rotation,
    qm31 *numerator_inverses,
    qm31 *weights,
    qm31 *scales,
    void *stream);

// One launch prepares disjoint final-weight ranges for a same-log group batch.
// Large domains preserve the legacy 1024-leaf/512-thread inverse partition.
extern "C" int stwo_oods_barycentric_weights_collapsed_cohort_on(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    const secure_field_point *evaluation_points,
    const uint32_t *descriptor_offsets,
    uint32_t group_count,
    qm31 si0,
    point vanishing_rotation,
    qm31 *weights,
    void *stream);

extern "C" int stwo_oods_barycentric_eval_many_on(
    const m31 *const *columns,
    uint32_t column_count,
    const qm31 *weights,
    uint32_t size,
    qm31 *partial_sums,
    uint32_t reduction_blocks,
    const uint32_t *output_indices,
    qm31 *sampled_values,
    void *stream);

#endif
