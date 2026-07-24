#ifndef STWO_ZIG_CUDA_TRANSCRIPT_BLAKE2S_WORDS_CUH
#define STWO_ZIG_CUDA_TRANSCRIPT_BLAKE2S_WORDS_CUH

#include "../commitment/blake2s_core.cuh"

#include <stdint.h>

namespace stwo::cuda::transcript {

using blake2s::Hash;

__device__ __forceinline__ void copy_words(
    uint32_t *destination,
    const uint32_t *source,
    uint32_t count) {
    for (uint32_t index = 0; index < count; ++index) {
        destination[index] = source[index];
    }
}

__device__ __forceinline__ uint32_t stream_word(
    const uint32_t digest[8],
    const uint32_t *suffix,
    uint64_t index) {
    return index < 8 ? digest[index] : suffix[index - 8];
}

// Hashes digest || suffix as one little-endian word stream. The lazy final
// block is required for messages ending exactly on a Blake2s block boundary.
__device__ __forceinline__ Hash hash_digest_and_words(
    const uint32_t digest[8],
    const uint32_t *suffix,
    uint32_t suffix_words) {
    uint32_t hash[8];
    uint32_t message[16];
    blake2s::initialize(hash);

    const uint64_t total_words = 8ull + suffix_words;
    const uint64_t full_blocks = (total_words - 1ull) / 16ull;
    for (uint64_t block = 0; block < full_blocks; ++block) {
#pragma unroll
        for (uint32_t word = 0; word < 16; ++word) {
            message[word] =
                stream_word(digest, suffix, block * 16ull + word);
        }
        blake2s::compress(hash, message, (block + 1ull) * 64ull, 0);
    }

#pragma unroll
    for (uint32_t word = 0; word < 16; ++word) message[word] = 0;
    const uint64_t final_offset = full_blocks * 16ull;
    const uint32_t final_words =
        static_cast<uint32_t>(total_words - final_offset);
    for (uint32_t word = 0; word < final_words; ++word) {
        message[word] = stream_word(digest, suffix, final_offset + word);
    }
    blake2s::compress(
        hash,
        message,
        total_words * sizeof(uint32_t),
        0xffffffffu);

    Hash result;
#pragma unroll
    for (uint32_t word = 0; word < 8; ++word) {
        result.words[word] = hash[word];
    }
    return result;
}

// The channel draw suffix is counter.to_le_bytes() followed by one zero byte.
__device__ __forceinline__ Hash hash_draw(
    const uint32_t digest[8],
    uint32_t counter) {
    uint32_t hash[8];
    uint32_t message[16] = {};
    blake2s::initialize(hash);
#pragma unroll
    for (uint32_t word = 0; word < 8; ++word) {
        message[word] = digest[word];
    }
    message[8] = counter;
    blake2s::compress(hash, message, 37, 0xffffffffu);

    Hash result;
#pragma unroll
    for (uint32_t word = 0; word < 8; ++word) {
        result.words[word] = hash[word];
    }
    return result;
}

__device__ __forceinline__ Hash pow_prefix(
    const uint32_t digest[8],
    uint32_t pow_bits) {
    uint32_t hash[8];
    uint32_t message[16] = {};
    blake2s::initialize(hash);
    message[0] = 0x12345678u;
#pragma unroll
    for (uint32_t word = 0; word < 8; ++word) {
        message[4 + word] = digest[word];
    }
    message[12] = pow_bits;
    blake2s::compress(hash, message, 52, 0xffffffffu);

    Hash result;
#pragma unroll
    for (uint32_t word = 0; word < 8; ++word) {
        result.words[word] = hash[word];
    }
    return result;
}

__device__ __forceinline__ uint32_t trailing_zero_bits_128(
    const Hash &hash) {
    uint32_t result = 0;
#pragma unroll
    for (uint32_t word = 0; word < 4; ++word) {
        if (hash.words[word] == 0) {
            result += 32;
        } else {
            result += static_cast<uint32_t>(__ffs(hash.words[word]) - 1);
            break;
        }
    }
    return result;
}

}  // namespace stwo::cuda::transcript

#endif
