#ifndef STWO_N2B_TERMINAL_H
#define STWO_N2B_TERMINAL_H

#include "fields.cuh"
#include "poly_utils.cuh"

// One owner must load both pre-final siblings before either canonical output
// is written.  Keep the final circle butterfly here so every fused consumer
// shares the already-qualified arithmetic and twiddle selection.
struct StwoN2bFinalPair {
    uint32_t even;
    uint32_t odd;
};

__device__ __forceinline__ StwoN2bFinalPair stwo_n2b_final_pair(
    const uint32_t *prefinal,
    uint32_t pair,
    uint32_t half_domain,
    uint32_t *twiddles,
    uint32_t twiddle_words
) {
    m31 *domain_twiddles = reinterpret_cast<m31 *>(
        twiddles + twiddle_words - half_domain);
    const m31 left = prefinal[2 * pair];
    const m31 right = prefinal[2 * pair + 1];
    const m31 product = mul(get_circle_twiddle(domain_twiddles, pair), right);
    return {
        static_cast<uint32_t>(add(left, product)),
        static_cast<uint32_t>(sub(left, product)),
    };
}

#endif
