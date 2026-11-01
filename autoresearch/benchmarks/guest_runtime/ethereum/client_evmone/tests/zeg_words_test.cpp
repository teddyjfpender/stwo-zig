// Host test for the ZEG_STWO word paths patched into ziskethone (our code):
// zeg::hash_bytes (seeded_hash.hpp) must equal the reference memcpy-to-word
// hash, and zisk_xmemcmp / zisk_xmemcpy (zisk_dma.hpp) must agree with
// memcmp == 0 / memcpy, for every source and destination alignment and for
// keys that differ in a single byte; count_nonzero_bytes (intrinsic_gas.hpp)
// must equal a byte loop for any offset, length and zero density.
//
// Build: python3 -I build.py --out DIR --host --tests  (runs it)
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>

#include "zeg/intrinsic_gas.hpp"
#include "zeg/seeded_hash.hpp"
#include "zeg/zisk_dma.hpp"

namespace {
uint64_t reference_hash(const zeg::HashSeed& s, const uint8_t* p, size_t n) {
    uint64_t h = s.c;
    size_t i = 0;
    for (; i < n / 8; ++i) {
        uint64_t w;
        std::memcpy(&w, p + 8 * i, 8);
        h += s.a[i] * w;
    }
    if (n & 7) {
        uint64_t w = 0;
        std::memcpy(&w, p + 8 * i, n & 7);
        h += s.a[i] * w;
    }
    return h;
}
void fail(const char* what, size_t n, unsigned oa, unsigned ob) {
    std::fprintf(stderr, "FAIL %s size=%zu offsets=%u,%u\n", what, n, oa, ob);
    std::exit(1);
}
template <size_t N>
void check_fixed(std::mt19937_64& rng) {
    alignas(16) uint8_t A[N + 24], B[N + 24], D[N + 24], R[N + 24];
    for (unsigned oa = 0; oa < 8; ++oa)
        for (unsigned ob = 0; ob < 8; ++ob)
            for (int t = 0; t < 40; ++t) {
                for (auto& c : A) c = uint8_t(rng());
                std::memcpy(B, A, sizeof(A));
                if (t & 1) B[ob + rng() % N] ^= uint8_t(1u << (rng() % 8));
                const uint8_t* a = A + ob;  // same bytes at both offsets when t is even
                std::memmove(B + oa, B + ob, N);
                const bool eq = std::memcmp(a, B + oa, N) == 0;
                if ((zeg::zisk::zisk_xmemcmp<N>(a, B + oa) == 0) != eq) fail("xmemcmp", N, oa, ob);
                for (auto& c : D) c = uint8_t(rng());
                std::memcpy(R, D, sizeof(D));
                zeg::zisk::zisk_xmemcpy<N>(D + oa, A + ob);
                std::memcpy(R + oa, A + ob, N);
                if (std::memcmp(D, R, sizeof(D)) != 0) fail("xmemcpy", N, oa, ob);
            }
}
}  // namespace

int main() {
    std::mt19937_64 rng(0x7a6567);
    uint8_t raw[16];
    for (auto& c : raw) c = uint8_t(rng());
    const zeg::HashSeed s = zeg::HashSeed::derive(raw);
    alignas(16) uint8_t buf[96];
    for (int t = 0; t < 20000; ++t) {
        for (auto& c : buf) c = uint8_t(rng());
        const unsigned off = rng() % 8;
        const size_t n = 1 + rng() % 64;
        if (zeg::hash_bytes(s, buf + off, n) != reference_hash(s, buf + off, n)) fail("hash_bytes", n, off, 0);
    }
    for (int t = 0; t < 20000; ++t) {
        const unsigned dens = rng() % 4;  // 0: all zero ... 3: mostly non-zero
        for (auto& c : buf) c = (rng() % 4 < dens) ? uint8_t(rng() | 1) : 0;
        const unsigned off = rng() % 8;
        const size_t n = rng() % (sizeof(buf) - 8);
        size_t ref = 0;
        for (size_t i = 0; i < n; ++i) ref += buf[off + i] != 0;
        if (zeg::count_nonzero_bytes({buf + off, n}) != ref) fail("count_nonzero_bytes", n, off, 0);
    }
    check_fixed<20>(rng);
    check_fixed<32>(rng);
    check_fixed<56>(rng);
    std::printf("zeg_words_test: hash_bytes, count_nonzero_bytes, zisk_xmemcmp/xmemcpy<20,32,56> OK\n");
    return 0;
}
