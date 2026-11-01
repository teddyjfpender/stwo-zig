// Keccak-256 sponge over the admitted Keccak-f[1600] ECALL service (our code).
// Drop-in for evmone's keccak.c: same public symbol ethash_keccak256, so every
// Keccak call site in evmone and ziskethone goes through the service.
// Padding, absorb and squeeze are ordinary RV64IM instructions. The guest traps
// on misaligned accesses, so words of an unaligned input are assembled from the
// aligned words that hold them (never reading a word with no input byte), and
// the final partial word is one masked word instead of a byte loop.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <evmone_precompiles/keccak.h>

#include "services.hpp"
#if defined(CANDIDATE_KECCAK)
#include "candidate_curves.hpp"
#endif

namespace {
constexpr size_t kRate = 136;
constexpr size_t kRateWords = kRate / 8;

inline uint64_t ldw(const uint8_t* p) { return *reinterpret_cast<const uint64_t*>(p); }

// XOR (or, for the first block, store) `words` LE words of `in` into the
// state; all words lie fully inside the input.
template <bool kStore>
inline void absorb_words(uint64_t* st, const uint8_t* in, size_t words) {
    const unsigned off = reinterpret_cast<uintptr_t>(in) & 7;
    if (off == 0) {
        for (size_t i = 0; i < words; ++i) {
            const uint64_t w = ldw(in + 8 * i);
            st[i] = kStore ? w : st[i] ^ w;
        }
        return;
    }
    const unsigned sh = off * 8;
    const unsigned rs = 64 - sh;
    const uint8_t* base = in - off;
    uint64_t cur = ldw(base);
    for (size_t i = 0; i < words; ++i) {
        // Bytes in+8i .. in+8i+7 lie in aligned words base+8i and base+8i+8.
        const uint64_t nxt = ldw(base + 8 * i + 8);
        const uint64_t w = (cur >> sh) | (nxt << rs);
        st[i] = kStore ? w : st[i] ^ w;
        cur = nxt;
    }
}

// The `n` (1..7) bytes at p as the low bytes of a word (upper bytes zero).
inline uint64_t tail_word(const uint8_t* p, size_t n) {
    const unsigned off = reinterpret_cast<uintptr_t>(p) & 7;
    const uint8_t* a = p - off;
    uint64_t w = ldw(a) >> (off * 8);
    if (off + n > 8) w |= ldw(a + 8) << (64 - off * 8);
    return w & ((uint64_t(1) << (8 * n)) - 1);
}
// Memo of single-block inputs of at most 64 bytes (log topics and
// addresses, mapping keys, trie keys repeat across a block): the key is the
// padded block's first 9 lanes, which determine the input and its length.
// A hit skips the Keccak-f service call, the prover's most expensive item per
// call; the digest is recomputed exactly on a miss.
constexpr size_t kMemoSlots = 4096;
struct MemoEntry {
    uint64_t key[9];
    uint64_t out[4];
};
MemoEntry* g_memo = nullptr;
}  // namespace

extern "C" union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size) noexcept {
    alignas(32) uint64_t st[25];
#if defined(CANDIDATE_KECCAK)
    // Candidate keccak_sponge: absorb, pad and permute in one call. Inputs of
    // at most 64 bytes keep the memoized admitted path below.
    if (size > 64) {
        stwo::cand_keccak256(st, data, size);
        union ethash_hash256 out;
        for (int i = 0; i < 4; ++i) out.word64s[i] = st[i];
        return out;
    }
#endif
    bool first = true;
    while (size >= kRate) {
        if (first) {
            absorb_words<true>(st, data, kRateWords);
            for (size_t i = kRateWords; i < 25; ++i) st[i] = 0;
            first = false;
        } else {
            absorb_words<false>(st, data, kRateWords);
        }
        stwo::keccak_f(st);
        data += kRate;
        size -= kRate;
    }
    // Final block: whole words, the partial word with the 0x01 pad byte, 0x80.
    const size_t words = size / 8;
    const size_t rem = size & 7;
    uint64_t last = uint64_t(0x01) << (8 * rem);
    if (rem) last |= tail_word(data + 8 * words, rem);
    if (first) {
        absorb_words<true>(st, data, words);
        st[words] = last;
        for (size_t i = words + 1; i < 25; ++i) st[i] = 0;
        if (size <= 64) {
            if (!g_memo) g_memo = static_cast<MemoEntry*>(std::calloc(kMemoSlots, sizeof(MemoEntry)));
            uint64_t h = 0;
            for (int i = 0; i < 9; ++i) h = (h ^ st[i]) * 0x9E3779B97F4A7C15ull;
            MemoEntry& m = g_memo[(h >> 52) & (kMemoSlots - 1)];
            uint64_t diff = 0;
            for (int i = 0; i < 9; ++i) diff |= m.key[i] ^ st[i];
            union ethash_hash256 out;
            if (diff == 0 && (m.key[0] | m.key[1] | m.key[8] | m.out[0])) {
                for (int i = 0; i < 4; ++i) out.word64s[i] = m.out[i];
                return out;
            }
            for (int i = 0; i < 9; ++i) m.key[i] = st[i];
            st[kRateWords - 1] ^= uint64_t(0x80) << 56;
            stwo::keccak_f(st);
            for (int i = 0; i < 4; ++i) out.word64s[i] = m.out[i] = st[i];
            return out;
        }
    } else {
        absorb_words<false>(st, data, words);
        st[words] ^= last;
    }
    st[kRateWords - 1] ^= uint64_t(0x80) << 56;
    stwo::keccak_f(st);
    union ethash_hash256 out;
    out.word64s[0] = st[0];
    out.word64s[1] = st[1];
    out.word64s[2] = st[2];
    out.word64s[3] = st[3];
    return out;
}
