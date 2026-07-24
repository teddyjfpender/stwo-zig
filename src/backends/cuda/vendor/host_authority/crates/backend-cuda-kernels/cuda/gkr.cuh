#ifndef GKR_H
#define GKR_H

#include "fields.cuh"

extern "C"
void gen_eq_evals(qm31 v, qm31 *y, uint32_t y_size, qm31 *evals, uint32_t evals_size);

extern "C"
void gkr_next_grand_product_layer(
    const qm31 *input_layer,
    uint32_t input_size,
    qm31 *output_layer
);

extern "C"
void gkr_next_logup_generic_layer(
    const qm31 *numerators,
    const qm31 *denominators,
    uint32_t input_size,
    qm31 *next_numerators,
    qm31 *next_denominators
);

extern "C"
void gkr_next_logup_multiplicities_layer(
    const m31 *numerators,
    const qm31 *denominators,
    uint32_t input_size,
    qm31 *next_numerators,
    qm31 *next_denominators
);

extern "C"
void gkr_next_logup_singles_layer(
    const qm31 *denominators,
    uint32_t input_size,
    qm31 *next_numerators,
    qm31 *next_denominators
);

extern "C"
void gkr_sum_grand_product(
    const qm31 *eq_evals,
    const qm31 *input_layer,
    uint32_t n_terms,
    qm31 *eval_at_0,
    qm31 *eval_at_2
);

extern "C"
void gkr_sum_logup_generic(
    const qm31 *eq_evals,
    const qm31 *numerators,
    const qm31 *denominators,
    uint32_t n_terms,
    qm31 lambda,
    qm31 *eval_at_0,
    qm31 *eval_at_2
);

extern "C"
void gkr_sum_logup_multiplicities(
    const qm31 *eq_evals,
    const m31 *numerators,
    const qm31 *denominators,
    uint32_t n_terms,
    qm31 lambda,
    qm31 *eval_at_0,
    qm31 *eval_at_2
);

extern "C"
void gkr_sum_logup_singles(
    const qm31 *eq_evals,
    const qm31 *denominators,
    uint32_t n_terms,
    qm31 lambda,
    qm31 *eval_at_0,
    qm31 *eval_at_2
);

#endif // GKR_H
