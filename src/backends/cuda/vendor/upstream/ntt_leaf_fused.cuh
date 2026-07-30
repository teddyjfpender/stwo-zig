#ifndef NTT_LEAF_FUSED_H
#define NTT_LEAF_FUSED_H

#include "blake2s.cuh"
#include "fields.cuh"
#include "utils.cuh"

// LDE-write + leaf-absorb fusion UNDER RETENTION (plan Step 3.1). The same
// contract as stwo_lde_n2b_hash16_on with one addition: the final NTT stage
// also WRITES the completed evaluations back into `device_values`, so a
// retained (retain_evaluations = true) group keeps its LDE resident for
// decommitment while the leaf hash consumes the tile from registers/shared —
// one read of coefficients, one write of evaluations, zero re-read for
// hashing. Evaluations and digests are byte-identical to the unfused
// stwo_lde_n2b_columns_on + stwo_blake2s_leaf_update_on/leaf_finalize_on
// sequence (see the identity argument in ntt_leaf_fused.cu).

// Setup-time dynamic-shared-memory admission for the exact write+hash final
// N2B kernel selected by `log_n`. Must run before graph capture.
extern "C" int stwo_ntt_leaf_fused_configure(unsigned log_n);

extern "C" int stwo_ntt_leaf_fused_on(
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
    void *stream);

// Candidate-only fixed-width terminal interval. `device_values` is a device
// pointer table containing `16 * tiles` columns in canonical commitment order.
// Every column already contains the exact image immediately before its final
// configured N2B interval. One launch completes that interval and the circle
// butterfly, preserves the canonical evaluations in place, and advances the
// compact h[8]-only leaf states without a later evaluation reread.
//
// The lane remains dormant until CUDA byte parity, resource, and SASS gates
// qualify it; callers must retain the materialized fallback.
extern "C" int stwo_ntt_direct_compact_final16_configure(unsigned log_n);

extern "C" int stwo_ntt_direct_compact_final16_on(
    uint32_t **device_values,
    unsigned log_n,
    uint32_t tiles,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    const CompactBlake2sTailDescriptor *initial_tail,
    Blake2sHash *states,
    void *stream);

// Column-parallel successor for final seven/eight-stage intervals. The ABI is
// intentionally additive so the serial fixed16 implementation remains
// available only as a forensic control.
extern "C" int stwo_ntt_direct_compact_final16_col8_configure(
    unsigned log_n);

extern "C" int stwo_ntt_direct_compact_final16_col8_on(
    uint32_t **device_values,
    unsigned log_n,
    uint32_t tiles,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    const CompactBlake2sTailDescriptor *initial_tail,
    Blake2sHash *states,
    void *stream);

#endif // NTT_LEAF_FUSED_H
