#ifndef STWO_DEVICE_TRANSCRIPT_H
#define STWO_DEVICE_TRANSCRIPT_H

#include <cstdint>

// Allocation-free ordinary-Blake2s Fiat-Shamir operations.  Every pointer is
// device-resident and every launch is enqueued on the explicit stream.  The
// state and snapshot ABI is 16 u32 words; its layout is private to the CUDA
// implementation and versioned by the Rust schedule key.
extern "C" int stwo_blake2s_transcript_init_on(
    uint32_t *state,
    const uint32_t *seed,
    uint32_t *seed_snapshot,
    uint64_t initial_chain,
    void *stream);

extern "C" int stwo_blake2s_transcript_mix_words_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *source,
    uint32_t n_words,
    uint32_t validate_m31,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot,
    void *stream);

extern "C" int stwo_blake2s_transcript_absorb_pow_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *nonce_words,
    uint32_t pow_bits,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot,
    void *stream);

extern "C" int stwo_blake2s_transcript_draw_u32s_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot,
    void *stream);

extern "C" int stwo_blake2s_transcript_draw_secure_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t n_felts,
    uint32_t max_rejection_rounds,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot,
    void *stream);

extern "C" int stwo_blake2s_transcript_draw_queries_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t log_domain_size,
    uint32_t n_queries,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot,
    void *stream);

#endif
