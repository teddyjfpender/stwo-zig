// Software emulation of the ECALL services for host (native) builds (our code).
// Keccak-f[1600] reference permutation; secp256k1 RCB projective add/double with
// the exact formulas of the executor (src/frontends/riscv/rv64/ethereum_services/
// secp256k1.zig); candidate services per autoresearch/guest_efficiency/CONTEXT.md.
#include <cstdint>
#include <cstring>

#include <intx/intx.hpp>

#include "services.hpp"

extern "C" [[noreturn]] void stwo_guest_abort(const char* why) noexcept;

namespace {
constexpr uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
constexpr int ROT[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
inline uint64_t rol(uint64_t x, int s) { return s ? (x << s) | (x >> (64 - s)) : x; }
void keccakf(uint64_t a[25]) {
    for (int r = 0; r < 24; ++r) {
        uint64_t c[5], d[5], b[25];
        for (int x = 0; x < 5; ++x) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; ++x) d[x] = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
        for (int i = 0; i < 25; ++i) a[i] ^= d[i % 5];
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y) b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[x + 5 * y], ROT[x + 5 * y]);
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        a[0] ^= RC[r];
    }
}

using intx::uint256;
using intx::uint512;
const uint256 P = intx::from_string<uint256>("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
uint256 ld(const uint64_t* w) { uint256 v; for (int i = 0; i < 4; ++i) v[i] = w[i]; return v; }
void st(uint64_t* w, const uint256& v) { for (int i = 0; i < 4; ++i) w[i] = v[i]; }
uint256 red(const uint256& a) { return a >= P ? a - P : a; }
uint256 mul(const uint256& a, const uint256& b) { return intx::mulmod(a, b, P); }
uint256 add(const uint256& a, const uint256& b) { return intx::addmod(a, b, P); }
uint256 sub(const uint256& a, const uint256& b) { return a >= b ? a - b : P - (b - a); }
uint256 sm(const uint256& a, uint64_t k) { return mul(a, uint256{k}); }

void emu_secp_add(uint64_t* w) {
    const uint256 x = red(ld(w)), y = red(ld(w + 4)), z = red(ld(w + 8));
    const uint256 x2 = red(ld(w + 12)), y2 = red(ld(w + 16)), z2 = red(ld(w + 20));
    const uint256 xx = mul(x, x2), yy = mul(y, y2), zz = mul(z, z2);
    const uint256 xy = sub(sub(mul(add(x, y), add(x2, y2)), xx), yy);
    const uint256 yz = sub(sub(mul(add(y, z), add(y2, z2)), yy), zz);
    const uint256 xz = sub(sub(mul(add(x, z), add(x2, z2)), xx), zz);
    const uint256 bzz3 = sm(zz, 21);
    const uint256 ym = sub(yy, bzz3), yp = add(yy, bzz3);
    const uint256 byz3 = sm(yz, 21), xx3 = sm(xx, 3), bxx9 = sm(xx, 63);
    st(w, sub(mul(xy, ym), mul(byz3, xz)));
    st(w + 4, add(mul(yp, ym), mul(bxx9, xz)));
    st(w + 8, add(mul(yz, yp), mul(xx3, xy)));
}
void emu_secp_double(uint64_t* w) {
    const uint256 x = red(ld(w)), y = red(ld(w + 4)), z = red(ld(w + 8));
    const uint256 yy = mul(y, y), zz = mul(z, z);
    const uint256 xy2 = sm(mul(x, y), 2);
    const uint256 bzz3 = sm(zz, 21), bzz9 = sm(zz, 63);
    const uint256 ym = sub(yy, bzz9), yp = add(yy, bzz3);
    const uint256 t = sm(mul(yy, zz), 168);
    st(w, mul(xy2, ym));
    st(w + 4, add(mul(ym, yp), t));
    st(w + 8, sm(mul(mul(yy, y), z), 8));
}
}  // namespace

namespace stwo {
void host_service(uint64_t tag, void* packet) noexcept {
    uint64_t* w = static_cast<uint64_t*>(packet);
    switch (tag) {
        case kKeccakF: keccakf(w); return;
        case kSecpAddWords: emu_secp_add(w); return;
        case kSecpDoubleWords: emu_secp_double(w); return;
        case kCandMemcpy: std::memmove(reinterpret_cast<void*>(w[0]), reinterpret_cast<void*>(w[1]), w[2]); return;
        case kCandMemset: std::memset(reinterpret_cast<void*>(w[0]), int(w[1] & 0xff), w[2]); return;
        case kCandMemcmp: {
            const int r = std::memcmp(reinterpret_cast<void*>(w[0]), reinterpret_cast<void*>(w[1]), w[2]);
            w[3] = uint64_t(int64_t(r < 0 ? -1 : r > 0 ? 1 : 0));
            return;
        }
        case kCandArith256: {
            const uint512 r = intx::umul(ld(w), ld(w + 4)) + uint512{ld(w + 8)};
            st(w + 12, static_cast<uint256>(r));
            st(w + 16, static_cast<uint256>(r >> 256));
            return;
        }
        case kCandArith256Mod: {
            const uint256 m = ld(w + 12);
            uint256 r = 0;
            if (m != 0) r = static_cast<uint256>((intx::umul(ld(w), ld(w + 4)) + uint512{ld(w + 8)}) % uint512{m});
            st(w + 16, r);
            return;
        }
        default: stwo_guest_abort("unknown service tag");
    }
}
}  // namespace stwo
