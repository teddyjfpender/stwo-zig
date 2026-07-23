#ifndef POLY_RFFT_H
#define POLY_RFFT_H

#include "fields.cuh"
#include "utils.cuh"

#define LOG_WARP 5

static const size_t LAUNCH_N2B_CONFIG_13_19[7][2] = {
    {6, 7}, // 13
    {6, 8}, // 14
    {8, 7},  //15
    {8, 8},  //16
    {6, 11}, //17
    {8, 10},// 18
    {8, 11} //19
};

static const size_t LAUNCH_N2B_CONFIG_20_27[8][3] = {
    {6, 6, 8},
    {6, 8, 7},
    {6, 8, 8},
    {8, 8, 7},
    {8, 8, 8},
    {6, 8, 11},
    {8, 8, 10},
    {8, 8, 11}
};

static const size_t LAUNCH_N2B_CONFIG_28_30[3][4] = {
    {6, 6, 6, 10},
    {6, 6, 6, 11},
    {6, 6, 8, 10}
};

extern "C"
void evaluate(int eval_domain_size, m31 *values, m31 *twiddles_tree, int twiddles_size, int values_size);

extern "C"
void evaluate_columns(const int *eval_domain_sizes, m31 **values, m31 *twiddles_tree, int twiddles_size, int number_of_columns, const int *column_sizes);

// Allocation-free explicit-stream N2B transform. `device_values` is a device
// pointer table; all buffers and the stream are caller-owned.
extern "C"
int stwo_ntt_n2b_columns_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
);

// Continue an in-place N2B from the exact post-stage-one image `[c, c]`.
// Stages 2..log_n run on `stream`; no staging, allocation, or sync occurs.
extern "C"
int stwo_ntt_n2b_columns_from_stage_two_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
);

// Same exact stage-two successor, stopping before the terminal circle
// butterfly. A paired compact consumer owns both siblings and writes the
// canonical retained values after loading the complete pair.
extern "C"
int stwo_ntt_n2b_columns_from_stage_two_before_circle_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
);

// Fixed-width compact-final candidate split. The prefix stops before the
// qualified final N2B interval; the second entry completes that interval but
// leaves only the circle butterfly for a generic remainder sink.
extern "C"
int stwo_ntt_n2b_columns_from_stage_two_before_final_interval_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
);
extern "C"
int stwo_ntt_n2b_columns_final_interval_before_circle_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
);

// Exact Composition continuation after its fused first forward interval:
// log24 runs [stage7..14, final10], log25 runs [stage7..14, final11].
// The pointer table contains exactly eight retained coordinate columns.
extern "C"
int stwo_ntt_n2b_columns_after_first_stage_two_interval_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
);

// Allocation-free explicit-stream LDE. Both pointer tables live on the device.
// `coefficient_sizes[i]` is the exact source length and may be smaller than
// `eval_domain_size` when blowup > 1. Each destination has
// `2 * eval_domain_size` words and is staged as coefficients followed by zeroes.
extern "C"
int stwo_lde_n2b_columns_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
);

// Same staging and transform, stopping immediately before the final circle
// butterfly. The commit leaf kernel consumes that last butterfly directly,
// avoiding a full evaluation write followed by a leaf-hash reread.
extern "C"
int stwo_lde_n2b_columns_before_circle_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
);

// Setup-time dynamic-shared-memory admission for the exact optimized final
// N2B kernel selected by `log_n`. Must run before graph capture.
extern "C"
int stwo_lde_n2b_hash16_configure(unsigned log_n);

// Same-log, full-lifting 16-column fast lane: stage coefficients, run the
// optimized N2B prefix, then feed final values from registers/shared directly
// into the running leaf states without materializing the completed LDE.
extern "C"
int stwo_lde_n2b_hash16_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states,
    void *stream
);

// Staging plus the NOFINAL N2B prefix of the 16-column hash16 lane, exported
// for cuda/ntt_leaf_fused.cu (Step 3.1 retained fusion). Runs exactly the
// launches ntt_n2b_hash16_dispatch_on performs before its final-stage kernel
// — same kernels, same LAUNCH_N2B_CONFIG rows, same order — and stops there,
// leaving `device_values` in the canonical prefinal state every final-stage
// kernel consumes. The caller attaches its own final-stage kernel covering
// the last `LAUNCH_N2B_CONFIG_*[log_n - base][last]` stages.
extern "C"
int stwo_lde_n2b_prefinal16_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    void *stream
);

#endif // POLY_RFFT_H
