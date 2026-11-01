// Host test for the ZEG_STWO word paths patched into ziskethone (our code):
// zeg::hash_bytes (seeded_hash.hpp) must equal the reference memcpy-to-word
// hash, and zisk_xmemcmp / zisk_xmemcpy (zisk_dma.hpp) must agree with
// memcmp == 0 / memcpy, for every source and destination alignment and for
// keys that differ in a single byte; count_nonzero_bytes (intrinsic_gas.hpp)
// must equal a byte loop for any offset, length and zero density;
// StwoFlatIndex (the Accounts/Storages row index) must agree with std::map
// through growth, duplicate emplace and absent lookups.
//
// Build: python3 -I build.py --out DIR --host --tests  (runs it)
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "zeg/hash_reserve.hpp"
#include "zeg/intrinsic_gas.hpp"
#include "zeg/seeded_hash.hpp"
#include "zeg/stwo_flat_index.hpp"
#include "zeg/zisk_dma.hpp"

namespace zeg {
[[noreturn]] void fatal(const char* why) {
    std::fprintf(stderr, "FAIL zeg::fatal: %s\n", why);
    std::exit(1);
}
}  // namespace zeg

namespace {
// Same layout as the (private) TKey.
struct alignas(8) TKey {
    evmc::address address;
    uint32_t pad = 0;
    evmc::bytes32 position;
    TKey(const evmc::address& a, const evmc::bytes32& p) : address(a), position(p) {}
};
static_assert(sizeof(TKey) == 56);
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
    {
        // Addresses: clustered (shared prefixes) and random, through several doublings.
        struct AddrHash { const zeg::HashSeed* s_; };
        struct Eq {};
        zeg::StwoFlatIndex<evmc::address, 3> ix(0, AddrHash{&s}, Eq{});
        zeg::hash_reserve_empty(ix, 100);
        std::map<std::string, size_t> ref;
        std::vector<evmc::address> keys;
        for (size_t i = 0; i < 9000; ++i) {
            evmc::address a{};
            for (auto& c : a.bytes) c = uint8_t(rng());
            if (i % 3 == 0 && !keys.empty()) {
                a = keys[rng() % keys.size()];
                a.bytes[19] ^= uint8_t(1 + rng() % 255);
            }
            const std::string k(reinterpret_cast<const char*>(a.bytes), 20);
            if (!ref.count(k)) { ref[k] = i; keys.push_back(a); }
            ix.emplace(a, ref[k] == i ? i : i + 1000000);  // duplicates must not overwrite
            if (i % 7 == 0) {
                evmc::address probe{};
                for (auto& c : probe.bytes) c = uint8_t(rng());
                const std::string pk(reinterpret_cast<const char*>(probe.bytes), 20);
                if ((ix.find(probe) != ix.end()) != (ref.count(pk) != 0)) fail("flat index absent", 20, 0, 0);
            }
        }
        for (const auto& a : keys) {
            const auto* e = ix.find(a);
            const std::string k(reinterpret_cast<const char*>(a.bytes), 20);
            if (e == ix.end() || e->second != ref[k]) fail("flat index address", 20, 0, 0);
        }
        // Storage keys (56-byte aligned Key).
        struct KeyHash { const zeg::HashSeed* s_; };
        zeg::StwoFlatIndex<TKey, 7> sx(0, KeyHash{&s}, Eq{});
        std::vector<TKey> sk;
        for (size_t i = 0; i < 5000; ++i) {
            evmc::address a = keys[rng() % 50];
            evmc::bytes32 p{};
            p.bytes[31] = uint8_t(i);
            p.bytes[30] = uint8_t(i >> 8);
            sk.emplace_back(a, p);
            sx.emplace(sk.back(), i);
        }
        for (size_t i = 0; i < sk.size(); ++i) {
            const auto* e = sx.find(sk[i]);
            if (e == sx.end()) fail("flat index storage key missing", 56, 0, 0);
            // the same (address, position) may repeat: first insert wins
            size_t first = i;
            for (size_t j = 0; j < i; ++j)
                if (std::memcmp(&sk[j], &sk[i], sizeof(sk[i])) == 0) { first = j; break; }
            if (e->second != first) fail("flat index storage key", 56, 0, 0);
        }
    }
    check_fixed<20>(rng);
    check_fixed<32>(rng);
    check_fixed<56>(rng);
    std::printf("zeg_words_test: hash_bytes, count_nonzero_bytes, StwoFlatIndex, zisk_xmemcmp/xmemcpy<20,32,56> OK\n");
    return 0;
}
