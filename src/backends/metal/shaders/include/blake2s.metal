#ifndef STWO_ZIG_BLAKE2S_METAL
#define STWO_ZIG_BLAKE2S_METAL

#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/base.metal"
#endif

constant uint blake2s_iv[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

// The sparse cooperative parent kernel still schedules one state column per
// SIMD lane, so its lane-dependent word selection needs the permutation
// table. The scalar compression path below does not consult this table: its
// ten rounds are expanded with literal message indices for compile-time
// selection.
constant uchar blake2s_sigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

inline uint rotr32(uint value, uint shift) {
    return (value >> shift) | (value << (32u - shift));
}

inline void blake2s_g_words(
    uint first_word,
    uint second_word,
    thread uint &a,
    thread uint &b,
    thread uint &c,
    thread uint &d
) {
    a = a + b + first_word;
    d = rotr32(d ^ a, 16u);
    c += d;
    b = rotr32(b ^ c, 12u);
    a = a + b + second_word;
    d = rotr32(d ^ a, 8u);
    c += d;
    b = rotr32(b ^ c, 7u);
}

// BLAKE2s has ten fixed message permutations. Spell each permutation at the
// call site so Metal can select message words at compile time instead of
// issuing runtime constant-table lookups in every G function. This is the
// same compression function and round order; only its code-generation
// authority changes.
#define STWO_ZIG_BLAKE2S_ROUND(v, message, m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, ma, mb, mc, md, me, mf) do { \
    blake2s_g_words(message[m0], message[m1], v[0], v[4], v[8], v[12]); \
    blake2s_g_words(message[m2], message[m3], v[1], v[5], v[9], v[13]); \
    blake2s_g_words(message[m4], message[m5], v[2], v[6], v[10], v[14]); \
    blake2s_g_words(message[m6], message[m7], v[3], v[7], v[11], v[15]); \
    blake2s_g_words(message[m8], message[m9], v[0], v[5], v[10], v[15]); \
    blake2s_g_words(message[ma], message[mb], v[1], v[6], v[11], v[12]); \
    blake2s_g_words(message[mc], message[md], v[2], v[7], v[8], v[13]); \
    blake2s_g_words(message[me], message[mf], v[3], v[4], v[9], v[14]); \
} while (0)

inline void blake2s_compress(
    thread uint *state,
    thread const uint *message,
    uint total_bytes,
    bool is_last
) {
    uint v[16];
    for (uint i = 0; i < 8u; ++i) {
        v[i] = state[i];
        v[i + 8u] = blake2s_iv[i];
    }
    v[12] ^= total_bytes;
    if (is_last) v[14] ^= 0xFFFFFFFFu;

    STWO_ZIG_BLAKE2S_ROUND(v, message, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    STWO_ZIG_BLAKE2S_ROUND(v, message, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
    STWO_ZIG_BLAKE2S_ROUND(v, message, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
    STWO_ZIG_BLAKE2S_ROUND(v, message, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
    STWO_ZIG_BLAKE2S_ROUND(v, message, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
    STWO_ZIG_BLAKE2S_ROUND(v, message, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
    STWO_ZIG_BLAKE2S_ROUND(v, message, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
    STWO_ZIG_BLAKE2S_ROUND(v, message, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
    STWO_ZIG_BLAKE2S_ROUND(v, message, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
    STWO_ZIG_BLAKE2S_ROUND(v, message, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
    for (uint i = 0; i < 8u; ++i) state[i] ^= v[i] ^ v[i + 8u];
}

inline void blake2s_init_hash(thread uint *state) {
    for (uint i = 0u; i < 8u; ++i) state[i] = blake2s_iv[i];
    state[0] ^= 0x01010020u;
}

inline void blake2s_init_seeded(thread uint *state, constant uint *seed) {
    for (uint i = 0u; i < 8u; ++i) state[i] = seed[i];
}

#endif
