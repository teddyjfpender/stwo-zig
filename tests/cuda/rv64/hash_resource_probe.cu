// Compile-only resource probe for the unchanged ordinary word-hash operation.
// Not part of the product ABI and not evidence of GPU execution or speedup.
#include "transcript/blake2s_words.cuh"
__global__ void rv64_hash_resource_probe(const uint32_t* digest, const uint32_t* words,
                                         uint32_t length, uint32_t* output) {
    const auto hash = stwo::cuda::transcript::hash_digest_and_words(digest, words, length);
    for (uint32_t c = 0; c < 8; ++c) output[c] = hash.words[c];
}
