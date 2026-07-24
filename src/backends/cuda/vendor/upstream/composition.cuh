#ifndef STWO_PREPARED_COMPOSITION_H
#define STWO_PREPARED_COMPOSITION_H

#include "fields.cuh"

// Resident composition helpers. Every entry point is allocation-free and uses
// only the caller-provided stream.
extern "C" int stwo_composition_generate_descending_powers_on(
    const qm31 *random_coefficient,
    qm31 *powers,
    uint32_t count,
    void *stream
);

extern "C" int stwo_composition_lift_accumulate_on(
    const uint32_t *previous_coordinates,
    uint32_t previous_log_size,
    uint32_t *current_coordinates,
    uint32_t current_log_size,
    void *stream
);

// Materialize statement-dependent extension parameters into their persistent
// per-component destinations. source_kinds: 0=z, 1=alpha power, 2=claimed sum.
// claimed_sums may be null exactly when claimed_sum_count is zero.
extern "C" int stwo_composition_materialize_ext_params_on(
    qm31 *const *destinations,
    const uint32_t *source_kinds,
    const uint32_t *source_indices,
    const m31 *scales,
    uint32_t count,
    const qm31 *z,
    const qm31 *alpha_powers,
    uint32_t alpha_power_count,
    const qm31 *const *claimed_sums,
    uint32_t claimed_sum_count,
    void *stream
);

#endif  // STWO_PREPARED_COMPOSITION_H
