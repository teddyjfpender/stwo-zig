// Plain Blake2s-256 (no key, no personalisation, 32-byte digest), as the
// tensor PCS uses it (core.vcs.blake2_hash.Blake2sHasher.hash): Merkle leaves
// hash a column of the encoded table (R canonical M31 words, little-endian),
// nodes hash left || right (64 bytes, one block).
//
// The compression function follows the repo's CUDA backend
// (src/backends/cuda/native/commitment/blake2s_core.cuh, itself RFC 7693);
// that file's leaf/node states are domain-separated, which the tensor PCS is
// not, so only the compressor is shared in spirit and re-stated here in a
// form that also compiles for the CPU emulation.
#pragma once
#include "tc_prelude.cuh"

namespace tc {

#if defined(__CUDACC__)
#define TC_TABLE static __device__ __constant__
#else
#define TC_TABLE static const
#endif

TC_TABLE uint32_t kB2sIv[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};
TC_TABLE uint8_t kB2sSigma[10][16] = {
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

TC_DEV uint32_t b2s_rotr(uint32_t v, uint32_t s) { return (v >> s) | (v << (32u - s)); }

#define TC_B2S_G(r, i, a, b, c, d)                       \
    do {                                                 \
        a = a + b + m[kB2sSigma[r][2 * i]];              \
        d = b2s_rotr(d ^ a, 16);                         \
        c += d;                                          \
        b = b2s_rotr(b ^ c, 12);                         \
        a = a + b + m[kB2sSigma[r][2 * i + 1]];          \
        d = b2s_rotr(d ^ a, 8);                          \
        c += d;                                          \
        b = b2s_rotr(b ^ c, 7);                          \
    } while (0)

// h: chaining value; m: 16 message words; t: bytes hashed so far including
// this block; last: final block.
TC_DEV void b2s_compress(uint32_t h[8], const uint32_t m[16], uint64_t t, bool last) {
    uint32_t v[16];
    for (int k = 0; k < 8; ++k) v[k] = h[k];
    for (int k = 0; k < 8; ++k) v[k + 8] = kB2sIv[k];
    v[12] ^= (uint32_t)t;
    v[13] ^= (uint32_t)(t >> 32);
    if (last) v[14] = ~v[14];
    for (int r = 0; r < 10; ++r) {
        TC_B2S_G(r, 0, v[0], v[4], v[8], v[12]);
        TC_B2S_G(r, 1, v[1], v[5], v[9], v[13]);
        TC_B2S_G(r, 2, v[2], v[6], v[10], v[14]);
        TC_B2S_G(r, 3, v[3], v[7], v[11], v[15]);
        TC_B2S_G(r, 4, v[0], v[5], v[10], v[15]);
        TC_B2S_G(r, 5, v[1], v[6], v[11], v[12]);
        TC_B2S_G(r, 6, v[2], v[7], v[8], v[13]);
        TC_B2S_G(r, 7, v[3], v[4], v[9], v[14]);
    }
    for (int k = 0; k < 8; ++k) h[k] ^= v[k] ^ v[k + 8];
}
#undef TC_B2S_G

// Initial chaining value for an unkeyed 32-byte digest.
TC_DEV void b2s_init(uint32_t h[8]) {
    for (int k = 0; k < 8; ++k) h[k] = kB2sIv[k];
    h[0] ^= 0x01010020u;
}

// Digest of two 32-byte children (one 64-byte block). The digest bytes are
// the little-endian words of h, so a node is stored as 8 u32 words.
TC_DEV void b2s_node(const uint32_t l[8], const uint32_t r[8], uint32_t out[8]) {
    uint32_t m[16];
    for (int k = 0; k < 8; ++k) {
        m[k] = l[k];
        m[k + 8] = r[k];
    }
    b2s_init(out);
    b2s_compress(out, m, 64, true);
}

}  // namespace tc
