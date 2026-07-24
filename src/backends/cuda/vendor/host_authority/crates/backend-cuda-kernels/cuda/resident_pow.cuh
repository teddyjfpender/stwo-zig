#ifndef STWO_RESIDENT_POW_H
#define STWO_RESIDENT_POW_H

#include <cstdint>

// Search the SIMD grind nonce lattice {(hi << 32) | low : 0 <= low < 2^20}
// with one persistent kernel, publishing the numerically smallest qualifying
// lattice nonce -- byte-identical to the SIMD reference grind, whose
// (hi ascending, low ascending) scan order equals numeric order on the
// lattice. The state is the 16-word device Blake2s transcript state; its
// first eight words are the current digest. `prefix_digest` is proof-owned
// eight-word scratch: one setup kernel writes it once, then every search block
// reads that shared prefix instead of recomputing the same Blake2s hash.
// `best_nonce` is initialized to UINT64_MAX and `completed_blocks` to zero by
// the prepared caller.
extern "C" int stwo_blake2s_pow_persistent_on(
    const uint32_t *transcript_state,
    uint32_t pow_bits,
    uint32_t *prefix_digest,
    unsigned long long *best_nonce,
    uint32_t *completed_blocks,
    uint32_t *transcript_nonce,
    void *stream);

// Search one exact global index tile on one fleet rank. Across all ranks,
// residues are disjoint and cover [tile_start, tile_end). Each rank publishes
// its local minimum or UINT64_MAX; the coordinator waits for every rank and
// chooses the minimum before advancing the transcript.
extern "C" int stwo_blake2s_pow_rank_tile_on(
    const uint32_t *transcript_state,
    uint32_t pow_bits,
    uint32_t rank_count,
    uint32_t rank,
    unsigned long long tile_start,
    unsigned long long tile_end,
    uint32_t grid_blocks,
    uint32_t *prefix_digest,
    unsigned long long *best_nonce,
    void *stream);

#endif  // STWO_RESIDENT_POW_H
