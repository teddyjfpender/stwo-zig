// Keccak-256 sponge over the admitted Keccak-f[1600] ECALL service (our code).
// Drop-in for evmone's keccak.c: same public symbol ethash_keccak256, so every
// Keccak call site in evmone and ziskethone goes through the service.
// Padding, absorb and squeeze are ordinary RV64IM instructions; the input may
// be unaligned, so words are assembled with aligned loads (funnel shift) and
// never read an aligned word that holds no input byte.
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <evmone_precompiles/keccak.h>

#include "services.hpp"

namespace {
constexpr size_t kRate = 136;
constexpr size_t kRateWords = kRate / 8;

inline uint64_t load_word_aligned(const uint8_t* p) { return *reinterpret_cast<const uint64_t*>(p); }

// XOR `words` LE words of `in` into the state; `in` may be unaligned but all
// words must be fully inside the input.
inline void absorb_words(uint64_t* st, const uint8_t* in, size_t words) {
    const unsigned off = reinterpret_cast<uintptr_t>(in) & 7;
    if (off == 0) {
        for (size_t i = 0; i < words; ++i) st[i] ^= load_word_aligned(in + 8 * i);
        return;
    }
    const unsigned sh = off * 8;
    const unsigned rs = 64 - sh;
    const uint8_t* base = in - off;
    uint64_t cur = load_word_aligned(base);
    for (size_t i = 0; i < words; ++i) {
        // Bytes in+8i .. in+8i+7 lie in aligned words base+8i and base+8i+8.
        const uint64_t nxt = load_word_aligned(base + 8 * i + 8);
        st[i] ^= (cur >> sh) | (nxt << rs);
        cur = nxt;
    }
}
}  // namespace

extern "C" union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size) noexcept {
    alignas(32) uint64_t st[25] = {};
    while (size >= kRate) {
        absorb_words(st, data, kRateWords);
        stwo::keccak_f(st);
        data += kRate;
        size -= kRate;
    }
    // Final block: whole words then the tail bytes, then padding.
    const size_t words = size / 8;
    absorb_words(st, data, words);
    uint8_t* sb = reinterpret_cast<uint8_t*>(st);
    for (size_t i = words * 8; i < size; ++i) sb[i] ^= data[i];
    sb[size] ^= 0x01;
    sb[kRate - 1] ^= 0x80;
    stwo::keccak_f(st);
    union ethash_hash256 out;
    out.word64s[0] = st[0];
    out.word64s[1] = st[1];
    out.word64s[2] = st[2];
    out.word64s[3] = st[3];
    return out;
}

extern "C" union ethash_hash256 ethash_keccak256_32(const uint8_t data[32]) noexcept {
    return ethash_keccak256(data, 32);
}
