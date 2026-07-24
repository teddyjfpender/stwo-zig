// Resident ordinary-Blake2s Fiat-Shamir channel. Every buffer belongs to the
// caller and every launch uses the proof's explicit non-null stream.

#include "blake2s_words.cuh"

#include <cuda_runtime_api.h>

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::transcript {

constexpr uint32_t kM31Prime = 0x7fffffffu;
constexpr uint32_t kStateWords = 16;
constexpr uint32_t kMaximumSeedDraws = 1u << 20;
constexpr uint32_t kMaximumMixWords = (UINT32_MAX - 32u) / sizeof(uint32_t);

enum Status : uint32_t {
    kOk = 0,
    kOrder = 1,
    kRejectionLimit = 2,
    kInvalidPow = 3,
    kInvalidField = 4,
    kInvalidSeed = 5,
};

struct alignas(8) State {
    uint32_t digest[8];
    uint32_t draws;
    uint32_t cursor;
    uint32_t status;
    uint32_t reserved;
    uint64_t chain;
    uint32_t padding[2];
};

static_assert(sizeof(State) == kStateWords * sizeof(uint32_t));
static_assert(offsetof(State, digest) == 0);
static_assert(offsetof(State, draws) == 32);
static_assert(offsetof(State, cursor) == 36);
static_assert(offsetof(State, status) == 40);
static_assert(offsetof(State, chain) == 48);

__device__ __forceinline__ State *as_state(uint32_t *words) {
    return reinterpret_cast<State *>(words);
}

__device__ __forceinline__ void snapshot(
    const State *state,
    uint32_t *destination) {
    copy_words(
        destination,
        reinterpret_cast<const uint32_t *>(state),
        kStateWords);
}

__device__ __forceinline__ bool begin_step(
    State *state,
    uint32_t expected_step,
    uint64_t expected_chain) {
    if (state->status != kOk) return false;
    if (state->cursor != expected_step || state->chain != expected_chain) {
        state->status = kOrder;
        return false;
    }
    return true;
}

__device__ __forceinline__ void finish_step(
    State *state,
    uint64_t next_chain,
    uint32_t *boundary) {
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
    const uint32_t *words,
    uint32_t count) {
    const Hash result = hash_digest_and_words(state->digest, words, count);
    copy_words(state->digest, result.words, 8);
    state->draws = 0;
}

__device__ __forceinline__ bool valid_pow(
    const State *state,
    uint32_t pow_bits,
    const uint32_t nonce[2]) {
    const Hash prefix = pow_prefix(state->digest, pow_bits);
    const Hash result = hash_digest_and_words(prefix.words, nonce, 2);
    return trailing_zero_bits_128(result) >= pow_bits;
}

__global__ void initialize_kernel(
    uint32_t *state_words,
    const uint32_t *seed,
    uint32_t *seed_snapshot,
    uint64_t initial_chain) {
    State *state = as_state(state_words);
    if (seed == nullptr) {
#pragma unroll
        for (uint32_t word = 0; word < 8; ++word) state->digest[word] = 0;
        state->draws = 0;
    } else {
        copy_words(state->digest, seed, 8);
        state->draws = seed[8];
        copy_words(seed_snapshot, seed, 9);
    }
    state->cursor = 0;
    state->status = state->draws <= kMaximumSeedDraws ? kOk : kInvalidSeed;
    state->reserved = 0;
    state->chain = initial_chain;
    state->padding[0] = 0;
    state->padding[1] = 0;
}

__global__ void mix_words_kernel(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *source,
    uint32_t word_count,
    uint32_t validate_m31,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot) {
    State *state = as_state(state_words);
    if (begin_step(state, expected_step, expected_chain)) {
        copy_words(input_snapshot, source, word_count);
        if (validate_m31 != 0) {
            for (uint32_t word = 0; word < word_count; ++word) {
                if (source[word] >= kM31Prime) state->status = kInvalidField;
            }
        }
        if (state->status == kOk) update_digest(state, source, word_count);
    }
    finish_step(state, next_chain, boundary_snapshot);
}

__global__ void mix_words_pair_kernel(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *first,
    uint32_t first_word_count,
    const uint32_t *second,
    uint32_t second_word_count,
    uint32_t validate_m31,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot) {
    State *state = as_state(state_words);
    if (begin_step(state, expected_step, expected_chain)) {
        copy_words(input_snapshot, first, first_word_count);
        copy_words(
            input_snapshot + first_word_count,
            second,
            second_word_count);
        if (validate_m31 != 0) {
            for (uint32_t word = 0; word < first_word_count; ++word) {
                if (first[word] >= kM31Prime) state->status = kInvalidField;
            }
            for (uint32_t word = 0; word < second_word_count; ++word) {
                if (second[word] >= kM31Prime) state->status = kInvalidField;
            }
        }
        if (state->status == kOk) {
            update_digest(state, first, first_word_count);
            update_digest(state, second, second_word_count);
        }
    }
    finish_step(state, next_chain, boundary_snapshot);
}

__global__ void absorb_pow_kernel(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *nonce,
    uint32_t pow_bits,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot) {
    State *state = as_state(state_words);
    if (begin_step(state, expected_step, expected_chain)) {
        copy_words(input_snapshot, nonce, 2);
        if (!valid_pow(state, pow_bits, nonce)) {
            state->status = kInvalidPow;
        } else {
            update_digest(state, nonce, 2);
        }
    }
    finish_step(state, next_chain, boundary_snapshot);
}

__global__ void draw_words_kernel(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot) {
    State *state = as_state(state_words);
    if (begin_step(state, expected_step, expected_chain)) {
        const Hash words = draw(state);
        copy_words(output, words.words, 8);
        copy_words(output_snapshot, words.words, 8);
    }
    finish_step(state, next_chain, boundary_snapshot);
}

__global__ void draw_secure_kernel(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t secure_count,
    uint32_t maximum_rejection_rounds,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot) {
    State *state = as_state(state_words);
    if (begin_step(state, expected_step, expected_chain)) {
        const uint32_t target_words = 4u * secure_count;
        uint32_t produced = 0;
        while (produced < target_words && state->status == kOk) {
            Hash words{};
            bool accepted = false;
            for (uint32_t attempt = 0;
                 attempt < maximum_rejection_rounds;
                 ++attempt) {
                words = draw(state);
                accepted = true;
#pragma unroll
                for (uint32_t word = 0; word < 8; ++word) {
                    if (words.words[word] >= 2u * kM31Prime) accepted = false;
                }
                if (accepted) break;
            }
            if (!accepted) {
                state->status = kRejectionLimit;
                break;
            }
#pragma unroll
            for (uint32_t word = 0; word < 8; ++word) {
                if (produced < target_words) {
                    const uint32_t reduced = words.words[word] >= kM31Prime
                        ? words.words[word] - kM31Prime
                        : words.words[word];
                    output[produced] = reduced;
                    output_snapshot[produced] = reduced;
                    ++produced;
                }
            }
        }
    }
    finish_step(state, next_chain, boundary_snapshot);
}

__global__ void draw_queries_kernel(
    uint32_t *state_words,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t log_domain_size,
    uint32_t query_count,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot) {
    State *state = as_state(state_words);
    if (begin_step(state, expected_step, expected_chain)) {
        const uint32_t mask =
            log_domain_size == 0 ? 0 : (1u << log_domain_size) - 1u;
        uint32_t produced = 0;
        while (produced < query_count) {
            const Hash words = draw(state);
#pragma unroll
            for (uint32_t word = 0; word < 8; ++word) {
                if (produced < query_count) {
                    const uint32_t query = words.words[word] & mask;
                    output[produced] = query;
                    output_snapshot[produced] = query;
                    ++produced;
                }
            }
        }
    }
    finish_step(state, next_chain, boundary_snapshot);
}

}  // namespace stwo::cuda::transcript

extern "C" int stwo_blake2s_transcript_init_on(
    uint32_t *state,
    const uint32_t *seed,
    uint32_t *seed_snapshot,
    uint64_t initial_chain,
    void *stream) {
    if (state == nullptr ||
        reinterpret_cast<uintptr_t>(state) % alignof(stwo::cuda::transcript::State) != 0 ||
        stream == nullptr ||
        (seed != nullptr && seed_snapshot == nullptr)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::transcript::initialize_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            state, seed, seed_snapshot, initial_chain);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_transcript_mix_words_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *source,
    uint32_t word_count,
    uint32_t validate_m31,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot,
    void *stream) {
    if (state == nullptr ||
        reinterpret_cast<uintptr_t>(state) % alignof(stwo::cuda::transcript::State) != 0 ||
        source == nullptr || word_count == 0 ||
        word_count > stwo::cuda::transcript::kMaximumMixWords ||
        validate_m31 > 1 || input_snapshot == nullptr ||
        boundary_snapshot == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::transcript::mix_words_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            state, expected_step, expected_chain, next_chain, source,
            word_count, validate_m31, input_snapshot, boundary_snapshot);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_transcript_mix_words_pair_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *first,
    uint32_t first_word_count,
    const uint32_t *second,
    uint32_t second_word_count,
    uint32_t validate_m31,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot,
    void *stream) {
    const uintptr_t first_begin = reinterpret_cast<uintptr_t>(first);
    const uintptr_t second_begin = reinterpret_cast<uintptr_t>(second);
    const uintptr_t first_bytes =
        static_cast<uintptr_t>(first_word_count) * sizeof(uint32_t);
    const uintptr_t second_bytes =
        static_cast<uintptr_t>(second_word_count) * sizeof(uint32_t);
    const bool sizes_valid =
        first_word_count != 0 && second_word_count != 0 &&
        first_word_count <= stwo::cuda::transcript::kMaximumMixWords &&
        second_word_count <= stwo::cuda::transcript::kMaximumMixWords;
    const bool ranges_valid =
        sizes_valid &&
        first_begin <= UINTPTR_MAX - first_bytes &&
        second_begin <= UINTPTR_MAX - second_bytes;
    const bool overlap =
        ranges_valid &&
        first_begin < second_begin + second_bytes &&
        second_begin < first_begin + first_bytes;
    if (state == nullptr ||
        reinterpret_cast<uintptr_t>(state) %
                alignof(stwo::cuda::transcript::State) !=
            0 ||
        first == nullptr || second == nullptr || !ranges_valid || overlap ||
        validate_m31 > 1 || input_snapshot == nullptr ||
        boundary_snapshot == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::transcript::mix_words_pair_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            state, expected_step, expected_chain, next_chain, first,
            first_word_count, second, second_word_count, validate_m31,
            input_snapshot, boundary_snapshot);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_transcript_absorb_pow_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    const uint32_t *nonce,
    uint32_t pow_bits,
    uint32_t *input_snapshot,
    uint32_t *boundary_snapshot,
    void *stream) {
    if (state == nullptr ||
        reinterpret_cast<uintptr_t>(state) % alignof(stwo::cuda::transcript::State) != 0 ||
        nonce == nullptr || pow_bits > 128 ||
        input_snapshot == nullptr || boundary_snapshot == nullptr ||
        stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::transcript::absorb_pow_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            state, expected_step, expected_chain, next_chain, nonce, pow_bits,
            input_snapshot, boundary_snapshot);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_transcript_draw_u32s_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot,
    void *stream) {
    if (state == nullptr ||
        reinterpret_cast<uintptr_t>(state) % alignof(stwo::cuda::transcript::State) != 0 ||
        output == nullptr || output_snapshot == nullptr ||
        boundary_snapshot == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::transcript::draw_words_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            state, expected_step, expected_chain, next_chain, output,
            output_snapshot, boundary_snapshot);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_transcript_draw_secure_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t secure_count,
    uint32_t maximum_rejection_rounds,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot,
    void *stream) {
    if (state == nullptr ||
        reinterpret_cast<uintptr_t>(state) % alignof(stwo::cuda::transcript::State) != 0 ||
        secure_count == 0 ||
        secure_count > UINT32_MAX / 4u || maximum_rejection_rounds == 0 ||
        output == nullptr || output_snapshot == nullptr ||
        boundary_snapshot == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::transcript::draw_secure_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            state, expected_step, expected_chain, next_chain, secure_count,
            maximum_rejection_rounds, output, output_snapshot,
            boundary_snapshot);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_blake2s_transcript_draw_queries_on(
    uint32_t *state,
    uint32_t expected_step,
    uint64_t expected_chain,
    uint64_t next_chain,
    uint32_t log_domain_size,
    uint32_t query_count,
    uint32_t *output,
    uint32_t *output_snapshot,
    uint32_t *boundary_snapshot,
    void *stream) {
    if (state == nullptr ||
        reinterpret_cast<uintptr_t>(state) % alignof(stwo::cuda::transcript::State) != 0 ||
        log_domain_size >= 32 || query_count == 0 ||
        output == nullptr || output_snapshot == nullptr ||
        boundary_snapshot == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    stwo::cuda::transcript::draw_queries_kernel<<<
        1, 1, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            state, expected_step, expected_chain, next_chain, log_domain_size,
            query_count, output, output_snapshot, boundary_snapshot);
    return static_cast<int>(cudaPeekAtLastError());
}
