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

// st[from..24] = 0 (from in 1..25) as straight-line stores entered at `from`:
// a zeroing loop is turned into a memset call by the compiler.
inline void zero_lanes_from(uint64_t* st, size_t from) {
    switch (from) {
        case 1: st[1] = 0; [[fallthrough]];
        case 2: st[2] = 0; [[fallthrough]];
        case 3: st[3] = 0; [[fallthrough]];
        case 4: st[4] = 0; [[fallthrough]];
        case 5: st[5] = 0; [[fallthrough]];
        case 6: st[6] = 0; [[fallthrough]];
        case 7: st[7] = 0; [[fallthrough]];
        case 8: st[8] = 0; [[fallthrough]];
        case 9: st[9] = 0; [[fallthrough]];
        case 10: st[10] = 0; [[fallthrough]];
        case 11: st[11] = 0; [[fallthrough]];
        case 12: st[12] = 0; [[fallthrough]];
        case 13: st[13] = 0; [[fallthrough]];
        case 14: st[14] = 0; [[fallthrough]];
        case 15: st[15] = 0; [[fallthrough]];
        case 16: st[16] = 0; [[fallthrough]];
        case 17: st[17] = 0; [[fallthrough]];
        case 18: st[18] = 0; [[fallthrough]];
        case 19: st[19] = 0; [[fallthrough]];
        case 20: st[20] = 0; [[fallthrough]];
        case 21: st[21] = 0; [[fallthrough]];
        case 22: st[22] = 0; [[fallthrough]];
        case 23: st[23] = 0; [[fallthrough]];
        case 24: st[24] = 0; [[fallthrough]];
        default: break;
    }
}

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
#if defined(ADMITTED_KECCAK)
    // Admitted Keccak-256 sponge (ethereum_services_v3, tag 0x0003_0130):
    // absorb, pad and permute in the service. Inputs of at most 64 bytes keep
    // the memoized Keccak-f path below. The admitted call takes len < 2^20, so
    // longer inputs absorb whole-block chunks first (no finalize), then the
    // tail with finalize. st and the packet are word-disjoint from the input.
    if (size > 64) {
        constexpr uint64_t kChunk = 7710 * kRate;  // < 2^20, whole blocks
        uint64_t flags = 2;                         // fresh
        while (size > kChunk) {
            alignas(8) uint64_t pk[4] = {reinterpret_cast<uintptr_t>(st), reinterpret_cast<uintptr_t>(data), kChunk, flags};
            stwo::ecall(0x00030130, pk);
            data += kChunk;
            size -= kChunk;
            flags = 0;
        }
        alignas(8) uint64_t pk[4] = {reinterpret_cast<uintptr_t>(st), reinterpret_cast<uintptr_t>(data), size, flags | 1};
        stwo::ecall(0x00030130, pk);
        union ethash_hash256 out;
        for (int i = 0; i < 4; ++i) out.word64s[i] = st[i];
        return out;
    }
#endif
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
            zero_lanes_from(st, kRateWords);
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
        zero_lanes_from(st, words + 1);
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
