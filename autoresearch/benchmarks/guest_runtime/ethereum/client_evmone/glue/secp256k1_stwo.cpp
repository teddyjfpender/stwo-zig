// secp256k1 ECDSA public-key recovery on the admitted stwo services (our code).
//
// Replaces evmone's software recover for every signer derivation in the guest
// (transaction senders, EIP-7702 authorities and the ECRECOVER precompile):
//   * the C ABI `secp256k1_ecdsa_recover` ziskethone calls (zeg/zisk_crypto.hpp);
//   * evmone::crypto::secp256k1::{ecrecover, secp256k1_ecdsa_recover, to_address}
//     used by evmone's precompile dispatch.
//
// Point arithmetic: projective (X:Y:Z) add/double through ECALL 0x0002_0011 /
// 0x0002_0012, which compute the complete Renes-Costello-Batina formulas of
// k256 (identity (0:1:0) and P+P included). Field and scalar arithmetic that
// has no service (square root, the two inversions, scalar products) runs as
// RV64IM code: 4x64-bit limbs, MUL/MULHU products, special-form reduction.
//
// Recovery (SEC 1, 4.1.6): R = (r, y) with y = sqrt(r^3 + 7) of the requested
// parity, u1 = -z/r, u2 = s/r (mod n), Q = u1*G + u2*R by interleaved 4-bit
// windows (Straus) over tables of 1..15 multiples of G (built once) and R.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

#include <evmc/evmc.hpp>

#include "services.hpp"

extern "C" union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size) noexcept;

namespace {

using u64 = uint64_t;
using u128 = unsigned __int128;

struct U256 {
    u64 v[4];
};

constexpr U256 P = {{0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}};
constexpr U256 N = {{0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL}};
// 2^256 - N
constexpr u64 NC[3] = {0x402DA1732FC9BEBFULL, 0x4551231950B75FC4ULL, 0x1ULL};
constexpr u64 PC = 0x1000003D1ULL;  // 2^256 - P

inline bool is_zero(const U256& a) { return (a.v[0] | a.v[1] | a.v[2] | a.v[3]) == 0; }
inline bool eq(const U256& a, const U256& b) {
    return ((a.v[0] ^ b.v[0]) | (a.v[1] ^ b.v[1]) | (a.v[2] ^ b.v[2]) | (a.v[3] ^ b.v[3])) == 0;
}
inline bool geq(const U256& a, const U256& b) {
    for (int i = 3; i >= 0; --i) {
        if (a.v[i] != b.v[i]) return a.v[i] > b.v[i];
    }
    return true;
}
// a - b, returns borrow.
inline u64 sub_to(U256& r, const U256& a, const U256& b) {
    u64 borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const u64 d = a.v[i] - b.v[i];
        const u64 b1 = a.v[i] < b.v[i];
        r.v[i] = d - borrow;
        borrow = b1 | (d < borrow);
    }
    return borrow;
}
inline u64 add_to(U256& r, const U256& a, const U256& b) {
    u64 carry = 0;
    for (int i = 0; i < 4; ++i) {
        const u64 s = a.v[i] + b.v[i];
        const u64 c1 = s < a.v[i];
        r.v[i] = s + carry;
        carry = c1 | (r.v[i] < s);
    }
    return carry;
}

// 512-bit product.
inline void mul_wide(u64 t[8], const U256& a, const U256& b) {
    for (int i = 0; i < 8; ++i) t[i] = 0;
    for (int i = 0; i < 4; ++i) {
        u64 carry = 0;
        for (int j = 0; j < 4; ++j) {
            const u128 p = (u128)a.v[i] * b.v[j] + t[i + j] + carry;
            t[i + j] = (u64)p;
            carry = (u64)(p >> 64);
        }
        t[i + 4] = carry;
    }
}

// ---- field mod P ----
U256 fe_reduce_wide(const u64 t[8]) {
    // t = hi*2^256 + lo == lo + hi*PC (mod P)
    u64 r[5];
    u64 carry = 0;
    for (int i = 0; i < 4; ++i) {
        const u128 p = (u128)t[4 + i] * PC + t[i] + carry;
        r[i] = (u64)p;
        carry = (u64)(p >> 64);
    }
    r[4] = carry;  // < 2^34
    // Fold r[4] once more.
    u128 p = (u128)r[4] * PC + r[0];
    U256 out;
    out.v[0] = (u64)p;
    u64 c = (u64)(p >> 64);
    for (int i = 1; i < 4; ++i) {
        const u128 s = (u128)r[i] + c;
        out.v[i] = (u64)s;
        c = (u64)(s >> 64);
    }
    if (c) {
        // Wrapped past 2^256: add PC again (cannot wrap twice).
        u128 s = (u128)out.v[0] + PC;
        out.v[0] = (u64)s;
        u64 cc = (u64)(s >> 64);
        for (int i = 1; i < 4 && cc; ++i) {
            out.v[i] += cc;
            cc = out.v[i] == 0;
        }
    }
    if (geq(out, P)) sub_to(out, out, P);
    return out;
}
inline U256 fe_mul(const U256& a, const U256& b) {
    u64 t[8];
    mul_wide(t, a, b);
    return fe_reduce_wide(t);
}
inline U256 fe_sqr(const U256& a) { return fe_mul(a, a); }
inline U256 fe_sqr_n(U256 a, int n) {
    while (n--) a = fe_sqr(a);
    return a;
}
inline U256 fe_add(const U256& a, const U256& b) {
    U256 r;
    const u64 c = add_to(r, a, b);
    if (c || geq(r, P)) sub_to(r, r, P);
    return r;
}

// a^((P+1)/4); caller checks the square.
U256 fe_sqrt_candidate(const U256& a) {
    const U256 x2 = fe_mul(fe_sqr(a), a);
    const U256 x3 = fe_mul(fe_sqr(x2), a);
    const U256 x6 = fe_mul(fe_sqr_n(x3, 3), x3);
    const U256 x9 = fe_mul(fe_sqr_n(x6, 3), x3);
    const U256 x11 = fe_mul(fe_sqr_n(x9, 2), x2);
    const U256 x22 = fe_mul(fe_sqr_n(x11, 11), x11);
    const U256 x44 = fe_mul(fe_sqr_n(x22, 22), x22);
    const U256 x88 = fe_mul(fe_sqr_n(x44, 44), x44);
    const U256 x176 = fe_mul(fe_sqr_n(x88, 88), x88);
    const U256 x220 = fe_mul(fe_sqr_n(x176, 44), x44);
    const U256 x223 = fe_mul(fe_sqr_n(x220, 3), x3);
    U256 t = fe_mul(fe_sqr_n(x223, 23), x22);
    t = fe_mul(fe_sqr_n(t, 6), x2);
    return fe_sqr_n(t, 2);
}

// ---- generic modular inverse by binary extended Euclid (public inputs) ----
// a in [1, m-1], m odd. Variable time is fine: all inputs are public.
inline void shr1(U256& a, u64 top) {
    a.v[0] = (a.v[0] >> 1) | (a.v[1] << 63);
    a.v[1] = (a.v[1] >> 1) | (a.v[2] << 63);
    a.v[2] = (a.v[2] >> 1) | (a.v[3] << 63);
    a.v[3] = (a.v[3] >> 1) | (top << 63);
}
inline void half_mod(U256& x, const U256& m) {
    if (x.v[0] & 1) {
        const u64 c = add_to(x, x, m);
        shr1(x, c);
    } else {
        shr1(x, 0);
    }
}
inline void sub_mod(U256& x, const U256& y, const U256& m) {
    if (sub_to(x, x, y)) add_to(x, x, m);
}
U256 inv_mod(const U256& a, const U256& m) {
    U256 u = a, v = m;
    U256 x1 = {{1, 0, 0, 0}}, x2 = {{0, 0, 0, 0}};
    const U256 one = {{1, 0, 0, 0}};
    while (!eq(u, one) && !eq(v, one)) {
        while ((u.v[0] & 1) == 0) { shr1(u, 0); half_mod(x1, m); }
        while ((v.v[0] & 1) == 0) { shr1(v, 0); half_mod(x2, m); }
        if (geq(u, v)) {
            sub_to(u, u, v);
            sub_mod(x1, x2, m);
        } else {
            sub_to(v, v, u);
            sub_mod(x2, x1, m);
        }
    }
    return eq(u, one) ? x1 : x2;
}

// ---- scalars mod N ----
U256 sc_reduce_wide(const u64 t_in[8]) {
    // Fold hi*2^256 == hi*NC until the value fits in 256 bits + small carry.
    u64 t[8];
    std::memcpy(t, t_in, sizeof(t));
    for (int round = 0; round < 4; ++round) {
        bool hi_zero = (t[4] | t[5] | t[6] | t[7]) == 0;
        if (hi_zero) break;
        u64 r[8] = {t[0], t[1], t[2], t[3], 0, 0, 0, 0};
        for (int i = 0; i < 4; ++i) {
            if (!t[4 + i]) continue;
            u64 carry = 0;
            for (int j = 0; j < 3; ++j) {
                const u128 p = (u128)t[4 + i] * NC[j] + r[i + j] + carry;
                r[i + j] = (u64)p;
                carry = (u64)(p >> 64);
            }
            for (int k = i + 3; k < 8 && carry; ++k) {
                const u128 s = (u128)r[k] + carry;
                r[k] = (u64)s;
                carry = (u64)(s >> 64);
            }
        }
        std::memcpy(t, r, sizeof(t));
    }
    U256 out = {{t[0], t[1], t[2], t[3]}};
    while (geq(out, N)) sub_to(out, out, N);
    return out;
}
inline U256 sc_mul(const U256& a, const U256& b) {
    u64 t[8];
    mul_wide(t, a, b);
    return sc_reduce_wide(t);
}

// ---- points via services ----
struct Proj {
    U256 x, y, z;
};

alignas(32) stwo::SecpAddPacket g_acc;  // accumulator in w[0..12], operand in w[12..24]

inline void acc_set(const Proj& p) {
    std::memcpy(&g_acc.w[0], p.x.v, 32);
    std::memcpy(&g_acc.w[4], p.y.v, 32);
    std::memcpy(&g_acc.w[8], p.z.v, 32);
}
inline Proj acc_get() {
    Proj p;
    std::memcpy(p.x.v, &g_acc.w[0], 32);
    std::memcpy(p.y.v, &g_acc.w[4], 32);
    std::memcpy(p.z.v, &g_acc.w[8], 32);
    return p;
}
inline void acc_double() {
    // DOUBLE reads/writes only the first 12 words of the packet.
    stwo::ecall(stwo::kSecpDoubleWords, g_acc.w);
}
inline void acc_add(const Proj& q) {
    std::memcpy(&g_acc.w[12], q.x.v, 32);
    std::memcpy(&g_acc.w[16], q.y.v, 32);
    std::memcpy(&g_acc.w[20], q.z.v, 32);
    stwo::ecall(stwo::kSecpAddWords, g_acc.w);
}

// table[i] = (i+1) * P for i in 0..14
void build_table(Proj table[15], const Proj& p) {
    table[0] = p;
    acc_set(p);
    acc_double();
    table[1] = acc_get();
    for (int i = 2; i < 15; ++i) {
        acc_set(table[i - 1]);
        acc_add(p);
        table[i] = acc_get();
    }
}

const Proj kG = {
    {{0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL}},
    {{0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL}},
    {{1, 0, 0, 0}},
};
Proj g_gtable[15];
bool g_gtable_ready = false;

inline unsigned nibble_at(const U256& k, int i) {  // i-th 4-bit window from the bottom
    return unsigned(k.v[i >> 4] >> ((i & 15) * 4)) & 15;
}

// Q = u1*G + u2*R; returns false if Q is the point at infinity.
bool double_mul(const U256& u1, const U256& u2, const Proj& r, U256& qx, U256& qy) {
    if (!g_gtable_ready) {
        build_table(g_gtable, kG);
        g_gtable_ready = true;
    }
    Proj rt[15];
    build_table(rt, r);
    Proj acc = {{{0, 0, 0, 0}}, {{1, 0, 0, 0}}, {{0, 0, 0, 0}}};  // identity
    acc_set(acc);
    bool started = false;
    for (int i = 63; i >= 0; --i) {
        if (started) {
            acc_double(); acc_double(); acc_double(); acc_double();
        }
        const unsigned a = nibble_at(u1, i), b = nibble_at(u2, i);
        if (a) { acc_add(g_gtable[a - 1]); started = true; }
        if (b) { acc_add(rt[b - 1]); started = true; }
    }
    const Proj q = acc_get();
    if (is_zero(q.z)) return false;
    const U256 zi = inv_mod(q.z, P);
    qx = fe_mul(q.x, zi);
    qy = fe_mul(q.y, zi);
    return true;
}

inline U256 from_be(const uint8_t* b) {
    U256 r;
    for (int i = 0; i < 4; ++i) {
        u64 w = 0;
        for (int j = 0; j < 8; ++j) w = (w << 8) | b[(3 - i) * 8 + j];
        r.v[i] = w;
    }
    return r;
}
inline void to_be(const U256& a, uint8_t* b) {
    for (int i = 0; i < 4; ++i) {
        const u64 w = a.v[3 - i];
        for (int j = 0; j < 8; ++j) b[i * 8 + j] = uint8_t(w >> (8 * (7 - j)));
    }
}

// Core recover on LE limbs. Returns 0 on success.
int recover(const U256& z_in, const U256& r, const U256& s, unsigned recid, U256& qx, U256& qy) {
    if (recid > 1) return 1;
    if (is_zero(r) || geq(r, N) || is_zero(s) || geq(s, N)) return 1;
    // R.x = r (r < N < P); y^2 = r^3 + 7.
    const U256 seven = {{7, 0, 0, 0}};
    const U256 rhs = fe_add(fe_mul(fe_sqr(r), r), seven);
    U256 y = fe_sqrt_candidate(rhs);
    if (!eq(fe_sqr(y), rhs)) return 1;
    if ((y.v[0] & 1) != recid) sub_to(y, P, y);  // y != 0 since rhs is a nonzero square
    // z mod N (z is a 256-bit hash).
    U256 z = z_in;
    if (geq(z, N)) sub_to(z, z, N);
    const U256 rinv = inv_mod(r, N);
    U256 u1 = sc_mul(z, rinv);
    if (!is_zero(u1)) sub_to(u1, N, u1);  // -z/r
    const U256 u2 = sc_mul(s, rinv);
    const Proj R = {r, y, {{1, 0, 0, 0}}};
    return double_mul(u1, u2, R, qx, qy) ? 0 : 1;
}

}  // namespace

extern "C" int secp256k1_ecdsa_recover(const uint64_t* z, const uint64_t* r, const uint64_t* s, unsigned recid,
                                       uint64_t* pubkey) {
    U256 zz, rr, ss, qx, qy;
    std::memcpy(zz.v, z, 32);
    std::memcpy(rr.v, r, 32);
    std::memcpy(ss.v, s, 32);
    if (recover(zz, rr, ss, recid, qx, qy) != 0) return 1;
    std::memcpy(pubkey, qx.v, 32);
    std::memcpy(pubkey + 4, qy.v, 32);
    return 0;
}

// ---- evmone API (ECRECOVER precompile) ----
#include <evmone_precompiles/secp256k1.hpp>

namespace evmone::crypto::secp256k1 {

evmc::address to_address(std::span<const uint8_t, 64> pubkey) noexcept {
    const auto h = ethash_keccak256(pubkey.data(), 64);
    evmc::address a;
    std::memcpy(a.bytes, h.bytes + 12, 20);
    return a;
}

std::optional<evmc::address> ecrecover(std::span<const uint8_t, 32> hash, std::span<const uint8_t, 32> r_bytes,
                                       std::span<const uint8_t, 32> s_bytes, bool parity,
                                       RecoveryMode mode) noexcept {
    const U256 z = from_be(hash.data()), r = from_be(r_bytes.data()), s = from_be(s_bytes.data());
    if (mode == RecoveryMode::strict) {
        // s <= N/2
        U256 half = N;
        shr1(half, 0);
        if (!geq(half, s)) return std::nullopt;
    }
    U256 qx, qy;
    if (recover(z, r, s, parity ? 1u : 0u, qx, qy) != 0) return std::nullopt;
    uint8_t pk[64];
    to_be(qx, pk);
    to_be(qy, pk + 32);
    return to_address(std::span<const uint8_t, 64>{pk, 64});
}

}  // namespace evmone::crypto::secp256k1
