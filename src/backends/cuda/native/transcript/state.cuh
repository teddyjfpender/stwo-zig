#pragma once

#include "blake2s_words.cuh"

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::transcript {

constexpr std::uint32_t kM31Prime = 0x7fffffffu;
constexpr std::uint32_t kStateWords = 16;
constexpr std::uint32_t kMaximumSeedDraws = 1u << 20;
constexpr std::uint32_t kMaximumMixWords =
    (UINT32_MAX - 32u) / sizeof(std::uint32_t);

enum Status : std::uint32_t {
    kOk = 0,
    kOrder = 1,
    kRejectionLimit = 2,
    kInvalidPow = 3,
    kInvalidField = 4,
    kInvalidSeed = 5,
    kInvalidStatement = 6,
};

struct alignas(8) State {
    std::uint32_t digest[8];
    std::uint32_t draws;
    std::uint32_t cursor;
    std::uint32_t status;
    std::uint32_t reserved;
    std::uint64_t chain;
    std::uint32_t padding[2];
};

static_assert(sizeof(State) == kStateWords * sizeof(std::uint32_t));
static_assert(offsetof(State, digest) == 0);
static_assert(offsetof(State, draws) == 32);
static_assert(offsetof(State, cursor) == 36);
static_assert(offsetof(State, status) == 40);
static_assert(offsetof(State, chain) == 48);

__device__ __forceinline__ State *as_state(std::uint32_t *words) {
    return reinterpret_cast<State *>(words);
}

__device__ __forceinline__ void snapshot(
    const State *state,
    std::uint32_t *destination) {
    copy_words(
        destination,
        reinterpret_cast<const std::uint32_t *>(state),
        kStateWords);
}

__device__ __forceinline__ bool begin_step(
    State *state,
    std::uint32_t expected_step,
    std::uint64_t expected_chain) {
    if (state->status != kOk) return false;
    if (state->cursor != expected_step || state->chain != expected_chain) {
        state->status = kOrder;
        return false;
    }
    return true;
}

__device__ __forceinline__ void finish_step(
    State *state,
    std::uint64_t next_chain,
    std::uint32_t *boundary) {
    if (state->status == kOk) {
        ++state->cursor;
        state->chain = next_chain;
    }
    snapshot(state, boundary);
}

__device__ __forceinline__ Hash draw(State *state) {
    const Hash result = hash_draw(state->digest, state->draws);
    ++state->draws;
    return result;
}

__device__ __forceinline__ void update_digest(
    State *state,
    const std::uint32_t *words,
    std::uint32_t count) {
    const Hash result = hash_digest_and_words(state->digest, words, count);
    copy_words(state->digest, result.words, 8);
    state->draws = 0;
}

__device__ __forceinline__ bool valid_pow(
    const State *state,
    std::uint32_t pow_bits,
    const std::uint32_t nonce[2]) {
    const Hash prefix = pow_prefix(state->digest, pow_bits);
    const Hash result = hash_digest_and_words(prefix.words, nonce, 2);
    return trailing_zero_bits_128(result) >= pow_bits;
}

}  // namespace stwo::cuda::transcript
