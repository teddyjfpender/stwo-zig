// SHA-256 for the RV64IM guest (our code). Drop-in for evmone's sha256.cpp
// (symbol evmone::crypto::sha256), used by the SSZ request root, the EIP-7685
// requests hash and the SHA256 precompile.
//
// * Fully unrolled rounds with rotating register names (no state shuffling).
// * A 64-byte message (every SSZ Merkle node) is one data block plus a constant
//   padding block whose message schedule is precomputed into K+W constants.
// * With -DCANDIDATE_SERVICES each compression is the execution-only
//   candidate service 0x0003_0010 (CONTEXT.md), packet = state[8] u32 then the
//   64 message bytes.
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "services.hpp"

namespace {

constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

constexpr uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

constexpr uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
constexpr uint32_t bsig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
constexpr uint32_t bsig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
constexpr uint32_t ssig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
constexpr uint32_t ssig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

// K[i] + W[i] for the padding block of a 64-byte message (0x80, zeros, bit length 512).
struct PadKW {
    uint32_t v[64];
};
constexpr PadKW make_pad_kw() {
    uint32_t w[64] = {};
    w[0] = 0x80000000u;
    w[15] = 512;
    for (int i = 16; i < 64; ++i) w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];
    PadKW r{};
    for (int i = 0; i < 64; ++i) r.v[i] = K[i] + w[i];
    return r;
}
constexpr PadKW kPadKW = make_pad_kw();

inline uint32_t load_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline uint32_t bswap32(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0xff00u) | ((x << 8) & 0xff0000u) | (x << 24);
}

#define SHA_ROUND(a, b, c, d, e, f, g, h, kw)                          \
    do {                                                                \
        const uint32_t t1 = h + bsig1(e) + (g ^ (e & (f ^ g))) + (kw);  \
        const uint32_t t2 = bsig0(a) + ((a & b) | (c & (a | b)));       \
        d += t1;                                                        \
        h = t1 + t2;                                                    \
    } while (0)

#define SHA_8ROUNDS(kw, i)                                   \
    SHA_ROUND(a, b, c, d, e, f, g, h, kw[(i) + 0]);          \
    SHA_ROUND(h, a, b, c, d, e, f, g, kw[(i) + 1]);          \
    SHA_ROUND(g, h, a, b, c, d, e, f, kw[(i) + 2]);          \
    SHA_ROUND(f, g, h, a, b, c, d, e, kw[(i) + 3]);          \
    SHA_ROUND(e, f, g, h, a, b, c, d, kw[(i) + 4]);          \
    SHA_ROUND(d, e, f, g, h, a, b, c, kw[(i) + 5]);          \
    SHA_ROUND(c, d, e, f, g, h, a, b, kw[(i) + 6]);          \
    SHA_ROUND(b, c, d, e, f, g, h, a, kw[(i) + 7])

// Rounds over a precomputed K+W array.
inline void compress_kw(uint32_t st[8], const uint32_t* kw) {
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    SHA_8ROUNDS(kw, 0);
    SHA_8ROUNDS(kw, 8);
    SHA_8ROUNDS(kw, 16);
    SHA_8ROUNDS(kw, 24);
    SHA_8ROUNDS(kw, 32);
    SHA_8ROUNDS(kw, 40);
    SHA_8ROUNDS(kw, 48);
    SHA_8ROUNDS(kw, 56);
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

#if defined(CANDIDATE_SERVICES)
struct alignas(8) ShaPacket {
    uint32_t state[8];
    uint8_t block[64];
};
inline void compress(uint32_t st[8], const uint8_t* block) {
    ShaPacket p;
    std::memcpy(p.state, st, 32);
    std::memcpy(p.block, block, 64);
    stwo::ecall(stwo::kCandSha256, &p);
    std::memcpy(st, p.state, 32);
}
inline void compress_pad64(uint32_t st[8]) {
    static constexpr uint8_t pad[64] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00};
    compress(st, pad);
}
#else
inline void compress(uint32_t st[8], const uint8_t* block) {
    uint32_t w[64];
    if ((reinterpret_cast<uintptr_t>(block) & 3) == 0) {
        const uint32_t* q = reinterpret_cast<const uint32_t*>(block);
        for (int i = 0; i < 16; ++i) w[i] = bswap32(q[i]);
    } else {
        for (int i = 0; i < 16; ++i) w[i] = load_be32(block + 4 * i);
    }
    for (int i = 16; i < 64; ++i) w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];
    for (int i = 0; i < 64; ++i) w[i] += K[i];
    compress_kw(st, w);
}
inline void compress_pad64(uint32_t st[8]) { compress_kw(st, kPadKW.v); }
#endif

inline void store_digest(std::byte* out, const uint32_t st[8]) {
    uint8_t* o = reinterpret_cast<uint8_t*>(out);
    for (int i = 0; i < 8; ++i) {
        o[4 * i] = uint8_t(st[i] >> 24);
        o[4 * i + 1] = uint8_t(st[i] >> 16);
        o[4 * i + 2] = uint8_t(st[i] >> 8);
        o[4 * i + 3] = uint8_t(st[i]);
    }
}

}  // namespace

namespace evmone::crypto {

void sha256(std::byte hash[32], const std::byte* data, size_t size) {
    uint32_t st[8];
    std::memcpy(st, H0, sizeof(st));
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    if (size == 64) {
        compress(st, p);
        compress_pad64(st);
        store_digest(hash, st);
        return;
    }
    size_t n = size;
    while (n >= 64) {
        compress(st, p);
        p += 64;
        n -= 64;
    }
    alignas(8) uint8_t tail[128] = {};
    std::memcpy(tail, p, n);
    tail[n] = 0x80;
    const size_t blocks = n + 9 <= 64 ? 1 : 2;
    const uint64_t bits = uint64_t(size) * 8;
    uint8_t* lenp = tail + blocks * 64 - 8;
    for (int i = 0; i < 8; ++i) lenp[i] = uint8_t(bits >> (56 - 8 * i));
    compress(st, tail);
    if (blocks == 2) compress(st, tail + 64);
    store_digest(hash, st);
}

}  // namespace evmone::crypto
