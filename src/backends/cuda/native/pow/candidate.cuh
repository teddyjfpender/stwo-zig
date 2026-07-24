#ifndef STWO_ZIG_CUDA_POW_CANDIDATE_CUH
#define STWO_ZIG_CUDA_POW_CANDIDATE_CUH

#include "../transcript/blake2s_words.cuh"

#include <stdint.h>

namespace stwo::cuda::pow {

using blake2s::Hash;

struct Prefix {
    uint32_t words[8];
};

template <uint32_t index>
__device__ __forceinline__ uint32_t message_word(
    const Prefix &prefix,
    unsigned long long nonce) {
    if constexpr (index < 8) return prefix.words[index];
    if constexpr (index == 8) return static_cast<uint32_t>(nonce);
    if constexpr (index == 9) return static_cast<uint32_t>(nonce >> 32);
    return 0;
}

__device__ __forceinline__ uint32_t rotate_right(
    uint32_t value,
    uint32_t shift) {
    return (value >> shift) | (value << (32u - shift));
}

#define STWO_POW_G(m0, m1, a, b, c, d)                    \
    do {                                                    \
        a = a + b + message_word<m0>(prefix, nonce);        \
        d = rotate_right(d ^ a, 16);                        \
        c += d;                                             \
        b = rotate_right(b ^ c, 12);                        \
        a = a + b + message_word<m1>(prefix, nonce);        \
        d = rotate_right(d ^ a, 8);                         \
        c += d;                                             \
        b = rotate_right(b ^ c, 7);                         \
    } while (0)

#define STWO_POW_ROUND(                                      \
    m00, m01, m10, m11, m20, m21, m30, m31,                \
    m40, m41, m50, m51, m60, m61, m70, m71)                \
    do {                                                     \
        STWO_POW_G(m00, m01, v0, v4, v8, v12);             \
        STWO_POW_G(m10, m11, v1, v5, v9, v13);             \
        STWO_POW_G(m20, m21, v2, v6, v10, v14);            \
        STWO_POW_G(m30, m31, v3, v7, v11, v15);            \
        STWO_POW_G(m40, m41, v0, v5, v10, v15);            \
        STWO_POW_G(m50, m51, v1, v6, v11, v12);            \
        STWO_POW_G(m60, m61, v2, v7, v8, v13);             \
        STWO_POW_G(m70, m71, v3, v4, v9, v14);             \
    } while (0)

// Fixed 40-byte Blake2s compression. Named scalar state and compile-time
// message indices prevent a per-thread message array from spilling to local
// memory in the persistent search.
__device__ __forceinline__ uint32_t candidate_hash_word(
    const Prefix &prefix,
    unsigned long long nonce) {
    uint32_t v0 = 0x6a09e667u ^ 0x01010020u;
    uint32_t v1 = 0xbb67ae85u;
    uint32_t v2 = 0x3c6ef372u;
    uint32_t v3 = 0xa54ff53au;
    uint32_t v4 = 0x510e527fu;
    uint32_t v5 = 0x9b05688cu;
    uint32_t v6 = 0x1f83d9abu;
    uint32_t v7 = 0x5be0cd19u;
    uint32_t v8 = 0x6a09e667u;
    uint32_t v9 = 0xbb67ae85u;
    uint32_t v10 = 0x3c6ef372u;
    uint32_t v11 = 0xa54ff53au;
    uint32_t v12 = 0x510e527fu ^ 40u;
    uint32_t v13 = 0x9b05688cu;
    uint32_t v14 = 0x1f83d9abu ^ 0xffffffffu;
    uint32_t v15 = 0x5be0cd19u;

    STWO_POW_ROUND(
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15);
    STWO_POW_ROUND(
        14, 10, 4, 8, 9, 15, 13, 6,
        1, 12, 0, 2, 11, 7, 5, 3);
    STWO_POW_ROUND(
        11, 8, 12, 0, 5, 2, 15, 13,
        10, 14, 3, 6, 7, 1, 9, 4);
    STWO_POW_ROUND(
        7, 9, 3, 1, 13, 12, 11, 14,
        2, 6, 5, 10, 4, 0, 15, 8);
    STWO_POW_ROUND(
        9, 0, 5, 7, 2, 4, 10, 15,
        14, 1, 11, 12, 6, 8, 3, 13);
    STWO_POW_ROUND(
        2, 12, 6, 10, 0, 11, 8, 3,
        4, 13, 7, 5, 15, 14, 1, 9);
    STWO_POW_ROUND(
        12, 5, 1, 15, 14, 13, 4, 10,
        0, 7, 6, 3, 9, 2, 8, 11);
    STWO_POW_ROUND(
        13, 11, 7, 14, 12, 1, 3, 9,
        5, 0, 15, 4, 8, 6, 2, 10);
    STWO_POW_ROUND(
        6, 15, 14, 9, 11, 3, 0, 8,
        12, 2, 13, 7, 1, 4, 10, 5);
    STWO_POW_ROUND(
        10, 2, 8, 4, 7, 6, 1, 5,
        15, 11, 9, 14, 3, 12, 13, 0);
    return (0x6a09e667u ^ 0x01010020u) ^ v0 ^ v8;
}

#undef STWO_POW_ROUND
#undef STWO_POW_G

__device__ __forceinline__ uint32_t trailing_zeros(uint32_t value) {
    return value == 0
        ? 32
        : static_cast<uint32_t>(__ffs(value) - 1);
}

}  // namespace stwo::cuda::pow

#endif
