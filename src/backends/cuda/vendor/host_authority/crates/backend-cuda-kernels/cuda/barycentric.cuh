#ifndef BARYCENTRIC_H
#define BARYCENTRIC_H

#include "fields.cuh"

extern "C"
void barycentric_point_vanishings(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    qm31 p_x,
    qm31 p_y,
    qm31 *result
);

extern "C"
void barycentric_weights_from_point_vanishings(
    const qm31 *point_vanishings,
    uint32_t size,
    qm31 even_scale,
    qm31 odd_scale,
    qm31 *result_weights
);

extern "C"
qm31 barycentric_eval_base_field(
    const m31 *eval_values,
    const qm31 *weights,
    uint32_t size
);

#endif // BARYCENTRIC_H
