#ifndef POLY_IFFT_H
#define POLY_IFFT_H

#include "fields.cuh"
#include "utils.cuh"
#include "poly_utils.cuh"
#include "resource_attestation.cuh"

__device__ __forceinline__ void exchg_dif(m31 &a, m31 &b, const m31 &twiddle) {
    const auto a_tmp = a;
    a = a_tmp + b;
    b = a_tmp - b;
    b = b * twiddle;
}

#define LOG_THREADS_PER_WARP 5


static constexpr size_t LAUNCH_B2N_CONFIG_13_18[6][2] = {
    {7, 6}, {8, 6}, {7, 8}, {8, 8}, {9, 8}, {10, 8}
};

static constexpr size_t LAUNCH_B2N_CONFIG_19_24[6][3] = {
    {7, 6, 6}, // 19
    {8, 6, 6}, // 20
    {7, 6, 8}, // 21
    {8, 6, 8}, // 22
    {7, 8, 8}, // 23
    {8, 8, 8}, // 24
};

static constexpr size_t LAUNCH_B2N_CONFIG_25_29[5][4] = {
    {7, 6, 6, 6}, // 25
    {8, 6, 6, 6}, // 26
    {7, 8, 6, 6}, //27
    {8, 8, 6, 6}, //28
    {7, 8, 8, 6}, //29
};

extern "C"
void interpolate(int eval_domain_size, m31 *values, m31 *inverse_twiddles_tree, int inverse_twiddles_size, int values_size);

extern "C"
void interpolate_columns(int eval_domain_size, m31 **values, m31 *inverse_twiddles_tree, int inverse_twiddles_size, int values_size, int number_of_rows);

// Allocation-free inverse transform for 3 <= log_n <= 30. `device_values` is
// a device-resident pointer table and all stages launch on `stream`.
extern "C"
int stwo_ntt_b2n_columns_on(
        uint32_t **device_values,
        uint32_t log_n,
        uint32_t num_poly,
        uint32_t *g_twiddles,
        uint32_t twiddles_size,
        uint32_t eval_domain_size,
        void *stream
);

// Exact SN2 continuation after the producer-owned stages 1..7. The log-23
// schedule is completed as two qualified 8-stage in-place intervals.
extern "C"
int stwo_ntt_b2n_columns_after_first_seven_on(
        uint32_t **device_values,
        uint32_t log_n,
        uint32_t num_poly,
        const uint32_t *g_twiddles,
        uint32_t twiddles_size,
        uint32_t eval_domain_size,
        void *stream
);

// Attributes of the exact no-init specialization used by one continuation.
// Only the two production intervals (8,8) and (16,8) are admitted.
extern "C"
int stwo_ntt_b2n_after_first_seven_function_attributes(
        uint32_t start_stage,
        uint32_t stages,
        StwoCudaFunctionAttributes *out
);

// Allocation-free inverse transform for 3 <= log_n <= 30 with separate pointer
// tables. An input may exactly alias its paired output: each init tile completes
// all reads before its first write. Partial and cross-column aliases are
// forbidden by the Rust binder. Every later interval runs in-place on `outputs`;
// all launches use `stream`.
extern "C"
int stwo_ntt_b2n_columns_out_of_place_on(
        const uint32_t *const *inputs,
        uint32_t *const *outputs,
        uint32_t log_n,
        uint32_t num_poly,
        const uint32_t *g_twiddles,
        uint32_t twiddles_size,
        uint32_t eval_domain_size,
        void *stream
);

// Allocation-free inverse transform whose paired outputs each have 2^(log_n+1)
// words. The normalized B2N result is written byte-identically to both halves,
// which is exactly the first forward N2B layer for a zero-extended polynomial.
// Inputs may exactly alias the lower half of their paired output; all other
// partial and cross-column aliases are forbidden by the Rust binder.
extern "C"
int stwo_ntt_b2n_columns_to_retained_on(
        const uint32_t *const *inputs,
        uint32_t *const *retained_outputs,
        uint32_t log_n,
        uint32_t num_poly,
        const uint32_t *g_twiddles,
        uint32_t twiddles_size,
        uint32_t eval_domain_size,
        void *stream
);

// Exact four-to-eight Composition fallback. It runs the qualified B2N prefix,
// splits the final coefficient image into canonical left/right coordinates,
// and writes each coefficient to both partners of the omitted first N2B
// butterfly. Outputs are ready for the ordinary stage-two successor.
extern "C"
int stwo_ntt_b2n_composition_to_retained_on(
        uint32_t **source_values,
        uint32_t **retained_outputs,
        uint32_t log_n,
        const uint32_t *inverse_twiddles,
        uint32_t inverse_twiddle_words,
        uint32_t eval_domain_size,
        void *stream
);

// Strong production boundary for log 24/25. In addition to the exact split
// above, this executes the first stage-two-successor N2B interval before the
// only retained global write. Both shapes use the legal 256-thread LOG3
// boundary; the caller continues at stage 7.
extern "C"
int stwo_ntt_b2n_composition_fused_first_forward_on(
        uint32_t **source_values,
        uint32_t **retained_outputs,
        uint32_t log_n,
        const uint32_t *inverse_twiddles,
        uint32_t inverse_twiddle_words,
        const uint32_t *forward_twiddles,
        uint32_t forward_twiddle_words,
        uint32_t eval_domain_size,
        void *stream
);

#endif // POLY_IFFT_H
