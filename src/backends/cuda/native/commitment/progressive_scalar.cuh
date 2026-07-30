#ifndef STWO_ZIG_CUDA_BLAKE2S_PROGRESSIVE_SCALAR_CUH
#define STWO_ZIG_CUDA_BLAKE2S_PROGRESSIVE_SCALAR_CUH

#include <stdint.h>

namespace stwo::cuda::blake2s {

__device__ __forceinline__ uint32_t progressive_rotate_right(
    uint32_t value,
    uint32_t shift) {
    return (value >> shift) | (value << (32 - shift));
}

#define STWO_PROGRESSIVE_G(a, b, c, d, x, y) \
    do {                                       \
        a = a + b + x;                         \
        d = progressive_rotate_right(d ^ a, 16); \
        c += d;                                \
        b = progressive_rotate_right(b ^ c, 12); \
        a = a + b + y;                         \
        d = progressive_rotate_right(d ^ a, 8); \
        c += d;                                \
        b = progressive_rotate_right(b ^ c, 7); \
    } while (0)

#define STWO_PROGRESSIVE_ROUND(                                          \
    m0, m1, m2, m3, m4, m5, m6, m7,                                     \
    m8, m9, m10, m11, m12, m13, m14, m15)                               \
    do {                                                                  \
        STWO_PROGRESSIVE_G(v0, v4, v8, v12, m0, m1);                     \
        STWO_PROGRESSIVE_G(v1, v5, v9, v13, m2, m3);                     \
        STWO_PROGRESSIVE_G(v2, v6, v10, v14, m4, m5);                    \
        STWO_PROGRESSIVE_G(v3, v7, v11, v15, m6, m7);                    \
        STWO_PROGRESSIVE_G(v0, v5, v10, v15, m8, m9);                    \
        STWO_PROGRESSIVE_G(v1, v6, v11, v12, m10, m11);                  \
        STWO_PROGRESSIVE_G(v2, v7, v8, v13, m12, m13);                   \
        STWO_PROGRESSIVE_G(v3, v4, v9, v14, m14, m15);                   \
    } while (0)

// Scalar naming is intentional: ptxas otherwise places the clonable 96-byte
// state in thread-local memory even when it reports no compiler spill.
__device__ __forceinline__ void progressive_compress(
    uint32_t &h0, uint32_t &h1, uint32_t &h2, uint32_t &h3,
    uint32_t &h4, uint32_t &h5, uint32_t &h6, uint32_t &h7,
    uint32_t m0, uint32_t m1, uint32_t m2, uint32_t m3,
    uint32_t m4, uint32_t m5, uint32_t m6, uint32_t m7,
    uint32_t m8, uint32_t m9, uint32_t m10, uint32_t m11,
    uint32_t m12, uint32_t m13, uint32_t m14, uint32_t m15,
    uint64_t byte_count,
    uint32_t last_block) {
    uint32_t v0 = h0;
    uint32_t v1 = h1;
    uint32_t v2 = h2;
    uint32_t v3 = h3;
    uint32_t v4 = h4;
    uint32_t v5 = h5;
    uint32_t v6 = h6;
    uint32_t v7 = h7;
    uint32_t v8 = 0x6A09E667u;
    uint32_t v9 = 0xBB67AE85u;
    uint32_t v10 = 0x3C6EF372u;
    uint32_t v11 = 0xA54FF53Au;
    uint32_t v12 = 0x510E527Fu ^ static_cast<uint32_t>(byte_count);
    uint32_t v13 = 0x9B05688Cu ^ static_cast<uint32_t>(byte_count >> 32);
    uint32_t v14 = 0x1F83D9ABu ^ last_block;
    uint32_t v15 = 0x5BE0CD19u;

    STWO_PROGRESSIVE_ROUND(
        m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15);
    STWO_PROGRESSIVE_ROUND(
        m14,m10,m4,m8,m9,m15,m13,m6,m1,m12,m0,m2,m11,m7,m5,m3);
    STWO_PROGRESSIVE_ROUND(
        m11,m8,m12,m0,m5,m2,m15,m13,m10,m14,m3,m6,m7,m1,m9,m4);
    STWO_PROGRESSIVE_ROUND(
        m7,m9,m3,m1,m13,m12,m11,m14,m2,m6,m5,m10,m4,m0,m15,m8);
    STWO_PROGRESSIVE_ROUND(
        m9,m0,m5,m7,m2,m4,m10,m15,m14,m1,m11,m12,m6,m8,m3,m13);
    STWO_PROGRESSIVE_ROUND(
        m2,m12,m6,m10,m0,m11,m8,m3,m4,m13,m7,m5,m15,m14,m1,m9);
    STWO_PROGRESSIVE_ROUND(
        m12,m5,m1,m15,m14,m13,m4,m10,m0,m7,m6,m3,m9,m2,m8,m11);
    STWO_PROGRESSIVE_ROUND(
        m13,m11,m7,m14,m12,m1,m3,m9,m5,m0,m15,m4,m8,m6,m2,m10);
    STWO_PROGRESSIVE_ROUND(
        m6,m15,m14,m9,m11,m3,m0,m8,m12,m2,m13,m7,m1,m4,m10,m5);
    STWO_PROGRESSIVE_ROUND(
        m10,m2,m8,m4,m7,m6,m1,m5,m15,m11,m9,m14,m3,m12,m13,m0);

    h0 ^= v0 ^ v8;
    h1 ^= v1 ^ v9;
    h2 ^= v2 ^ v10;
    h3 ^= v3 ^ v11;
    h4 ^= v4 ^ v12;
    h5 ^= v5 ^ v13;
    h6 ^= v6 ^ v14;
    h7 ^= v7 ^ v15;
}

#undef STWO_PROGRESSIVE_ROUND
#undef STWO_PROGRESSIVE_G

}  // namespace stwo::cuda::blake2s

#endif
