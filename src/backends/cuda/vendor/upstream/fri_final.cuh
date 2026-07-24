#ifndef STWO_FRI_FINAL_H
#define STWO_FRI_FINAL_H

#include <cstdint>

// Interpolate one coordinate-major QM31 line evaluation, validate the exact
// degree bound, and emit the retained coefficients in the row-major word order
// consumed by Blake2sChannel::mix_felts. All buffers are device resident.
extern "C" int stwo_fri_last_layer_on(
    const uint32_t *evaluation,
    uint32_t evaluation_stride,
    uint32_t log_size,
    const uint32_t *inverse_twiddles,
    uint32_t inverse_twiddle_words,
    uint32_t log_degree_bound,
    uint32_t *coefficients,
    uint32_t *degree_error,
    uint32_t *transcript_coefficients,
    void *stream);

#endif  // STWO_FRI_FINAL_H
