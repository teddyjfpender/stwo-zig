// Software emulation of the ECALL services for host (native) builds (our code).
// Keccak-f[1600] reference permutation; secp256k1 RCB projective add/double with
// the exact formulas of the executor (src/frontends/riscv/rv64/ethereum_services/
// secp256k1.zig); candidate services per autoresearch/guest_efficiency/CONTEXT.md.
#include <cstdint>
#include <cstring>

#include <intx/intx.hpp>

#include "candidate_curves.hpp"
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

// Candidate curve, field and sponge services (candidate_curves.hpp).
using u384 = intx::uint<384>;
using u768 = intx::uint<768>;
using u1024 = intx::uint<1024>;
const uint256 PBN = intx::from_string<uint256>("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
const u384 PBLS = intx::from_string<u384>(
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
u384 ld6(const uint64_t* w) { u384 v; for (int i = 0; i < 6; ++i) v[i] = w[i]; return v; }
void st6(uint64_t* w, const u384& v) { for (int i = 0; i < 6; ++i) w[i] = v[i]; }
template <typename U>
struct Fld {
    U p;
    U mul(const U& a, const U& b) const {
        return static_cast<U>(intx::umul(a, b) % intx::uint<2 * U::num_bits>{p});
    }
    U add(const U& a, const U& b) const { return a >= p - b ? a - (p - b) : a + b; }
    U sub(const U& a, const U& b) const { return a >= b ? a - b : p - (b - a); }
    U inv(const U& a) const {  // Fermat, p prime
        U r = 1, x = a, e = p - 2;
        while (e != 0) {
            if (e & 1) r = mul(r, x);
            x = mul(x, x);
            e >>= 1;
        }
        return r;
    }
    void aff_add(U* r, const U* p1, const U* p2) const {
        const U l = mul(sub(p2[1], p1[1]), inv(sub(p2[0], p1[0])));
        const U x3 = sub(sub(mul(l, l), p1[0]), p2[0]);
        r[1] = sub(mul(l, sub(p1[0], x3)), p1[1]);
        r[0] = x3;
    }
    void aff_dbl(U* r, const U* p1) const {
        const U xx = mul(p1[0], p1[0]);
        const U l = mul(add(add(xx, xx), xx), inv(add(p1[1], p1[1])));
        const U x3 = sub(mul(l, l), add(p1[0], p1[0]));
        r[1] = sub(mul(l, sub(p1[0], x3)), p1[1]);
        r[0] = x3;
    }
    void fp2(U* r, const U* a, const U* b) const {
        const U c0 = sub(mul(a[0], b[0]), mul(a[1], b[1]));
        r[1] = add(mul(a[0], b[1]), mul(a[1], b[0]));
        r[0] = c0;
    }
};
// a*b*2^-384 mod odd m via REDC on 1024-bit intermediates.
u384 mont384(u384 a, u384 b, const u384& m) {
    if (m == 1) return 0;
    a %= m;
    b %= m;
    u384 ninv = 1;  // m^-1 mod 2^384 by Newton iteration
    for (int i = 0; i < 9; ++i) ninv *= u384{2} - m * ninv;
    const u768 t = intx::umul(a, b);
    const u384 q = static_cast<u384>(t) * (u384{0} - ninv);
    const u1024 s = u1024{t} + u1024{intx::umul(q, m)};
    u384 r = static_cast<u384>(s >> 384);
    if (r >= m) r -= m;
    return r;
}
uint64_t* at(uint64_t v) { return reinterpret_cast<uint64_t*>(v); }
}  // namespace
// Calls per candidate curve tag (low byte), so host tests can assert that a hook is live.
extern "C" { uint64_t stwo_host_curve_calls[256]; }
namespace {
void emu_candidate_curve(uint64_t tag, uint64_t* w) {
    ++stwo_host_curve_calls[tag & 0xff];
    const Fld<uint256> bn{PBN};
    const Fld<u384> bls{PBLS};
    switch (tag) {
        case stwo::kCandBn254G1Add: {
            uint256 p[2] = {ld(at(w[1])), ld(at(w[1]) + 4)}, q[2] = {ld(at(w[2])), ld(at(w[2]) + 4)}, r[2];
            if (p[0] == q[0] || p[0] >= PBN || p[1] >= PBN || q[0] >= PBN || q[1] >= PBN)
                stwo_guest_abort("bn254_g1_add precondition");
            bn.aff_add(r, p, q);
            st(at(w[0]), r[0]);
            st(at(w[0]) + 4, r[1]);
            return;
        }
        case stwo::kCandBn254G1Double: {
            uint256 p[2] = {ld(at(w[1])), ld(at(w[1]) + 4)}, r[2];
            if (p[1] == 0 || p[0] >= PBN || p[1] >= PBN) stwo_guest_abort("bn254_g1_double precondition");
            bn.aff_dbl(r, p);
            st(at(w[0]), r[0]);
            st(at(w[0]) + 4, r[1]);
            return;
        }
        case stwo::kCandBn254Fp2Mul: {
            uint256 a[2] = {ld(at(w[1])) % PBN, ld(at(w[1]) + 4) % PBN}, b[2] = {ld(at(w[2])) % PBN, ld(at(w[2]) + 4) % PBN}, r[2];
            bn.fp2(r, a, b);
            st(at(w[0]), r[0]);
            st(at(w[0]) + 4, r[1]);
            return;
        }
        case stwo::kCandBls12381Fp2Mul: {
            u384 a[2] = {ld6(at(w[1])) % PBLS, ld6(at(w[1]) + 6) % PBLS}, b[2] = {ld6(at(w[2])) % PBLS, ld6(at(w[2]) + 6) % PBLS};
            // Montgomery: (a0 b0 - a1 b1) R^-1, (a0 b1 + a1 b0) R^-1 = REDC of each product combination.
            const u384 r0 = bls.sub(mont384(a[0], b[0], PBLS), mont384(a[1], b[1], PBLS));
            const u384 r1 = bls.add(mont384(a[0], b[1], PBLS), mont384(a[1], b[0], PBLS));
            st6(at(w[0]), r0);
            st6(at(w[0]) + 6, r1);
            return;
        }
        case stwo::kCandArith384Mont: {
            const u384 m = ld6(at(w[2]));
            if ((m[0] & 1) == 0) stwo_guest_abort("arith384_mont even modulus");
            st6(at(w[3]), mont384(ld6(at(w[0])), ld6(at(w[1])), m));
            return;
        }
        case stwo::kCandArith384Mod: {
            const u384 m = ld6(at(w[3]));
            u384 r = 0;
            if (m != 0) r = static_cast<u384>((intx::umul(ld6(at(w[0])), ld6(at(w[1]))) + u768{ld6(at(w[2]))}) % u768{m});
            st6(at(w[4]), r);
            return;
        }
        case stwo::kCandKeccakSponge: {
            uint64_t* s = at(w[0]);
            const uint8_t* in = reinterpret_cast<const uint8_t*>(w[1]);
            const uint64_t len = w[2], flags = w[3];
            const bool fin = flags & stwo::kSpongeFinalize;
            if ((flags & ~uint64_t(3)) || (!fin && len % 136)) stwo_guest_abort("keccak_sponge flags/length");
            uint64_t a[25] = {};
            if (!(flags & stwo::kSpongeFresh)) std::memcpy(a, s, 200);
            uint64_t off = 0;
            uint8_t block[136];
            for (; len - off >= 136; off += 136) {
                std::memcpy(block, in + off, 136);
                for (int i = 0; i < 17; ++i) { uint64_t v; std::memcpy(&v, block + 8 * i, 8); a[i] ^= v; }
                keccakf(a);
            }
            if (fin) {
                std::memset(block, 0, 136);
                std::memcpy(block, in + off, len - off);
                block[len - off] ^= 0x01;
                block[135] ^= 0x80;
                for (int i = 0; i < 17; ++i) { uint64_t v; std::memcpy(&v, block + 8 * i, 8); a[i] ^= v; }
                keccakf(a);
            }
            std::memcpy(s, a, 200);
            return;
        }
        default: stwo_guest_abort("candidate curve service not emulated on the host");
    }
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
        case kJumpdestBitmap: {
            const auto* code = reinterpret_cast<const uint8_t*>(w[0]);
            auto* out = reinterpret_cast<uint64_t*>(w[2]);
            const uint64_t n = w[1];
            std::memset(out, 0, (n + 63) / 64 * 8);
            for (uint64_t i = 0; i < n;) {
                const uint8_t op = code[i];
                if (op >= 0x60 && op <= 0x7f) { i += op - 0x5e; continue; }
                if (op == 0x5b) out[i / 64] |= uint64_t{1} << (i % 64);
                ++i;
            }
            return;
        }
        default:
            if ((tag & 0xffffff00) == 0x00030100) return emu_candidate_curve(tag, w);
            stwo_guest_abort("unknown service tag");
    }
}
}  // namespace stwo
