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
// k256 (identity (0:1:0) and P+P included). Square root, inversions and (without
// the v3 arith256_mod service, see fe_mul/sc_mul) the field and scalar products run
// as RV64IM code: 4x64-bit limbs, MUL/MULHU products, special-form reduction.
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

#include <evmone_precompiles/keccak.h>

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
#if defined(ADMITTED_ARITH)
// Admitted v3 arith256_mod service (0x0003_0021): one ECALL returns the canonical
// r = (a*b + c) mod m for ANY 256-bit a, b, c and m != 0 (the truth AIR proves
// a*b + c = q*m + r with q < 2^512 and r < m; design/riscv-proving-stack/rv64-arith256-service.md).
// The software reductions below also return the canonical residue of a*b for any 256-bit
// inputs, so both paths give identical results (tests/secp_differential.cpp runs the
// recover differential with this path on the host service emulation).
// One packet per modulus: c = 0 and m are written once here; the service writes only r,
// so they stay intact across calls. 32-byte aligned as the admitted ABI requires.
struct alignas(32) ModMulPacket {
    u64 w[20];
};
ModMulPacket g_fe_mul_packet = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, P.v[0], P.v[1], P.v[2], P.v[3], 0, 0, 0, 0}};
ModMulPacket g_sc_mul_packet = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, N.v[0], N.v[1], N.v[2], N.v[3], 0, 0, 0, 0}};
inline U256 svc_mul_mod(ModMulPacket& pk, const U256& a, const U256& b) {
    for (int i = 0; i < 4; ++i) {
        pk.w[i] = a.v[i];
        pk.w[4 + i] = b.v[i];
    }
    stwo::ecall(stwo::kV3Arith256Mod, pk.w);
    return U256{{pk.w[16], pk.w[17], pk.w[18], pk.w[19]}};
}
#endif

inline U256 fe_mul(const U256& a, const U256& b) {
#if defined(ADMITTED_ARITH)
    return svc_mul_mod(g_fe_mul_packet, a, b);
#else
    u64 t[8];
    mul_wide(t, a, b);
    return fe_reduce_wide(t);
#endif
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
#if defined(ADMITTED_ARITH)
    return svc_mul_mod(g_sc_mul_packet, a, b);
#else
    u64 t[8];
    mul_wide(t, a, b);
    return sc_reduce_wide(t);
#endif
}

// ---- points via services ----
struct Proj {
    U256 x, y, z;
    Proj() = default;
    constexpr Proj(const U256& a, const U256& b, const U256& c) : x(a), y(b), z(c) {}
    // 96-byte copies would be memcpy calls on RV64 (12 words exceed LLVM's
    // inline-store limit); force the 12 aligned word moves inline.
    Proj(const Proj& o) noexcept { __builtin_memcpy_inline(this, &o, sizeof(Proj)); }
    Proj& operator=(const Proj& o) noexcept {
        __builtin_memcpy_inline(this, &o, sizeof(Proj));
        return *this;
    }
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

struct Table {
    Proj p[15];  // (i+1) * P
};

void build_table(Table& t, const Proj& p) {
    t.p[0] = p;
    acc_set(p);
    acc_double();
    t.p[1] = acc_get();
    for (int i = 2; i < 15; ++i) {
        acc_set(t.p[i - 1]);
        acc_add(p);
        t.p[i] = acc_get();
    }
}

// GLV endomorphism: lambda * (x, y) = (beta * x, y).
constexpr U256 LAMBDA = {{0xDF02967C1B23BD72ULL, 0x122E22EA20816678ULL, 0xA5261C028812645AULL, 0x5363AD4CC05C30E0ULL}};
constexpr U256 BETA = {{0xC1396C28719501EEULL, 0x9CF0497512F58995ULL, 0x6E64479EAC3434E9ULL, 0x7AE96A2B657C0710ULL}};
constexpr U256 MINUS_B1 = {{0x6F547FA90ABFE4C3ULL, 0xE4437ED6010E8828ULL, 0, 0}};
constexpr U256 MINUS_B2 = {{0xD765CDA83DB1562CULL, 0x8A280AC50774346DULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL}};
constexpr U256 G1 = {{0xE893209A45DBB031ULL, 0x3DAA8A1471E8CA7FULL, 0xE86C90E49284EB15ULL, 0x3086D221A7D46BCDULL}};
constexpr U256 G2 = {{0x1571B4AE8AC47F71ULL, 0x221208AC9DF506C6ULL, 0x6F547FA90ABFE4C4ULL, 0xE4437ED6010E8828ULL}};

// round(k * g / 2^384)
U256 mul_shift_384(const U256& k, const U256& g) {
    u64 t[8];
    mul_wide(t, k, g);
    U256 r = {{t[6], t[7], 0, 0}};
    if (t[5] >> 63) {
        if (++r.v[0] == 0) ++r.v[1];
    }
    return r;
}

inline U256 sc_add(const U256& a, const U256& b) {
    U256 r;
    const u64 c = add_to(r, a, b);
    if (c || geq(r, N)) sub_to(r, r, N);
    return r;
}
inline U256 sc_neg(const U256& a) {
    if (is_zero(a)) return a;
    U256 r;
    sub_to(r, N, a);
    return r;
}
inline bool fits128(const U256& a) { return (a.v[2] | a.v[3]) == 0; }

// k = k1 + k2 * lambda (mod N) with |k1|, |k2| < 2^128; signs returned separately.
bool split_lambda(const U256& k, U256& k1, bool& neg1, U256& k2, bool& neg2) {
    const U256 c1 = sc_mul(mul_shift_384(k, G1), MINUS_B1);
    const U256 c2 = sc_mul(mul_shift_384(k, G2), MINUS_B2);
    U256 r2 = sc_add(c1, c2);
    U256 r1 = sc_add(k, sc_neg(sc_mul(r2, LAMBDA)));
    neg1 = !fits128(r1);
    if (neg1) r1 = sc_neg(r1);
    neg2 = !fits128(r2);
    if (neg2) r2 = sc_neg(r2);
    k1 = r1;
    k2 = r2;
    return fits128(r1) && fits128(r2);
}

inline Proj neg_point(const Proj& p) {
    Proj q = p;
    if (!is_zero(q.y)) sub_to(q.y, P, p.y);
    return q;
}
inline Proj endo(const Proj& p) {
    Proj q = p;
    q.x = fe_mul(p.x, BETA);
    return q;
}

const Proj kG = {
    {{0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL}},
    {{0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL}},
    {{1, 0, 0, 0}},
};
Table g_tg, g_tlg, g_tg_neg, g_tlg_neg;
bool g_tables_ready = false;

void make_neg(Table& out, const Table& in) {
    for (int i = 0; i < 15; ++i) out.p[i] = neg_point(in.p[i]);
}

inline unsigned nibble_at(const U256& k, int i) {  // i-th 4-bit window from the bottom
    return unsigned(k.v[i >> 4] >> ((i & 15) * 4)) & 15;
}

// Plain 4-bit Straus over 256-bit scalars (fallback if a GLV split fails).
Proj double_mul_plain(const U256& u1, const U256& u2, const Table& tq) {
    acc_set(Proj{{{0, 0, 0, 0}}, {{1, 0, 0, 0}}, {{0, 0, 0, 0}}});
    bool started = false;
    for (int i = 63; i >= 0; --i) {
        if (started) { acc_double(); acc_double(); acc_double(); acc_double(); }
        const unsigned a = nibble_at(u1, i), b = nibble_at(u2, i);
        if (a) { acc_add(g_tg.p[a - 1]); started = true; }
        if (b) { acc_add(tq.p[b - 1]); started = true; }
    }
    return acc_get();
}

// Q = u1*G + u2*P in projective coordinates (Z = 0 for infinity).
Proj double_mul(const U256& u1, const U256& u2, const Proj& p) {
    if (!g_tables_ready) {
        build_table(g_tg, kG);
        for (int i = 0; i < 15; ++i) g_tlg.p[i] = endo(g_tg.p[i]);
        make_neg(g_tg_neg, g_tg);
        make_neg(g_tlg_neg, g_tlg);
        g_tables_ready = true;
    }
    Table tp;
    build_table(tp, p);
    U256 a1, a2, b1, b2;
    bool na1, na2, nb1, nb2;
    if (!split_lambda(u1, a1, na1, a2, na2) || !split_lambda(u2, b1, nb1, b2, nb2)) {
        return double_mul_plain(u1, u2, tp);
    }
    Table tlp;
    for (int i = 0; i < 15; ++i) tlp.p[i] = endo(tp.p[i]);
    if (nb1) for (auto& q : tp.p) q = neg_point(q);
    if (nb2) for (auto& q : tlp.p) q = neg_point(q);
    const Table& ta = na1 ? g_tg_neg : g_tg;
    const Table& tla = na2 ? g_tlg_neg : g_tlg;
    acc_set(Proj{{{0, 0, 0, 0}}, {{1, 0, 0, 0}}, {{0, 0, 0, 0}}});
    bool started = false;
    for (int i = 31; i >= 0; --i) {
        if (started) { acc_double(); acc_double(); acc_double(); acc_double(); }
        unsigned d;
        if ((d = nibble_at(a1, i))) { acc_add(ta.p[d - 1]); started = true; }
        if ((d = nibble_at(a2, i))) { acc_add(tla.p[d - 1]); started = true; }
        if ((d = nibble_at(b1, i))) { acc_add(tp.p[d - 1]); started = true; }
        if ((d = nibble_at(b2, i))) { acc_add(tlp.p[d - 1]); started = true; }
    }
    return acc_get();
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

// ---- recovery hints (input adapter) ----
// The untrusted adapter may supply, per recovery it observed on the host, the
// recovered key Q, the y of R = (r, y) and w = s^-1 mod N. A hint is used only
// after checking s*w = 1, y^2 = r^3 + 7 with parity recid, Q on the curve and
// (z w) G + (r w) Q = R projectively; that pins Q to the recovery result
// without a square root or an inversion. Otherwise the full recovery runs.
struct Hint {
    U256 z, r, s, qx, qy, ry, w;
    u64 recid;
};
const Hint* g_hints = nullptr;
size_t g_hint_n = 0;

bool on_curve(const U256& x, const U256& y) {
    const U256 seven = {{7, 0, 0, 0}};
    return !geq(x, P) && !geq(y, P) && eq(fe_sqr(y), fe_add(fe_mul(fe_sqr(x), x), seven));
}

Proj double_mul(const U256& u1, const U256& u2, const Proj& p);

bool recover_hinted(const U256& z, const U256& r, const U256& s, unsigned recid, U256& qx, U256& qy) {
    for (size_t i = 0; i < g_hint_n; ++i) {
        const Hint& h = g_hints[i];
        if (!eq(h.z, z) || !eq(h.r, r) || !eq(h.s, s) || h.recid != recid) continue;
        const U256 one = {{1, 0, 0, 0}};
        if (geq(h.w, N) || !eq(sc_mul(s, h.w), one)) return false;
        if ((h.ry.v[0] & 1) != recid || !on_curve(r, h.ry) || !on_curve(h.qx, h.qy)) return false;
        const Proj rp = double_mul(sc_mul(z, h.w), sc_mul(r, h.w), Proj{h.qx, h.qy, one});
        if (is_zero(rp.z) || !eq(fe_mul(r, rp.z), rp.x) || !eq(fe_mul(h.ry, rp.z), rp.y)) return false;
        qx = h.qx;
        qy = h.qy;
        return true;
    }
    return false;
}

#if defined(STWO_HOST)
void record_hint(const U256& z, const U256& r, const U256& s, unsigned recid, const U256& qx, const U256& qy,
                 const U256& ry, const U256& w);
#endif

// Core recover on LE limbs. Returns 0 on success.
int recover(const U256& z_in, const U256& r, const U256& s, unsigned recid, U256& qx, U256& qy) {
    if (recid > 1) return 1;
    if (is_zero(r) || geq(r, N) || is_zero(s) || geq(s, N)) return 1;
    {
        U256 zr = z_in;
        if (geq(zr, N)) sub_to(zr, zr, N);
        if (g_hint_n && recover_hinted(zr, r, s, recid, qx, qy)) return 0;
    }
    // R.x = r (r < N < P); y^2 = r^3 + 7.
    const U256 seven = {{7, 0, 0, 0}};
    const U256 rhs = fe_add(fe_mul(fe_sqr(r), r), seven);
    U256 y = fe_sqrt_candidate(rhs);
    if (!eq(fe_sqr(y), rhs)) return 1;
    if ((y.v[0] & 1) != recid) sub_to(y, P, y);  // y != 0 since rhs is a nonzero square
    U256 z = z_in;
    if (geq(z, N)) sub_to(z, z, N);
    const U256 rinv = inv_mod(r, N);
    const U256 u1 = sc_neg(sc_mul(z, rinv));  // -z/r
    const U256 u2 = sc_mul(s, rinv);
    const Proj q = double_mul(u1, u2, Proj{r, y, {{1, 0, 0, 0}}});
    if (is_zero(q.z)) return 1;
    const U256 zi = inv_mod(q.z, P);
    qx = fe_mul(q.x, zi);
    qy = fe_mul(q.y, zi);
#if defined(STWO_HOST)
    record_hint(z, r, s, recid, qx, qy, y, inv_mod(s, N));
#endif
    return 0;
}

// ---- deferred verification of hinted signers (transaction senders) ----
// The canonical input carries each transaction's 65-byte public key. The
// sender is derived from it immediately and the signature is checked later,
// in one batch: R' = (z/s) G + (r/s) Q must have x(R') = r and the y parity
// `recid`. That pins R' to the unique point recovery would use, so Q is
// exactly the recovered key (and a non-recoverable signature fails).
struct Pending {
    U256 z, r, s;
    Proj q;
    unsigned recid;
};
Pending* g_pending = nullptr;
size_t g_pending_n = 0, g_pending_cap = 0;

}  // namespace

extern "C" [[noreturn]] void stwo_guest_abort(const char* why) noexcept;

// Returns false if the hint is not a valid curve point (caller then recovers).
extern "C" bool stwo_secp_hint_sender(const uint8_t z_be[32], const uint8_t r_be[32], const uint8_t s_be[32],
                                      unsigned recid, const uint8_t pubkey65[65], uint8_t addr_out[20]) {
    if (pubkey65[0] != 0x04 || recid > 1) return false;
    const U256 x = from_be(pubkey65 + 1), y = from_be(pubkey65 + 33);
    if (geq(x, P) || geq(y, P)) return false;
    const U256 seven = {{7, 0, 0, 0}};
    if (!eq(fe_sqr(y), fe_add(fe_mul(fe_sqr(x), x), seven))) return false;
    const U256 r = from_be(r_be), s = from_be(s_be);
    if (is_zero(r) || geq(r, N) || is_zero(s) || geq(s, N)) return false;
    if (g_pending_n == g_pending_cap) {
        const size_t cap = g_pending_cap ? 2 * g_pending_cap : 256;
        Pending* np = new Pending[cap];
        for (size_t i = 0; i < g_pending_n; ++i) np[i] = g_pending[i];
        delete[] g_pending;
        g_pending = np;
        g_pending_cap = cap;
    }
    U256 z = from_be(z_be);
    if (geq(z, N)) sub_to(z, z, N);
    g_pending[g_pending_n++] = Pending{z, r, s, Proj{x, y, {{1, 0, 0, 0}}}, recid};
    const auto h = ethash_keccak256(pubkey65 + 1, 64);
    std::memcpy(addr_out, h.bytes + 12, 20);
    return true;
}

// Recovery hints from the adapted input (copied; 8 x 32-byte LE values + recid each).
extern "C" void stwo_secp_set_hints(const uint8_t* p, size_t count) {
    Hint* h = new Hint[count];
    for (size_t i = 0; i < count; ++i) {
        const uint8_t* q = p + i * 232;
        U256* f[7] = {&h[i].z, &h[i].r, &h[i].s, &h[i].qx, &h[i].qy, &h[i].ry, &h[i].w};
        for (int k = 0; k < 7; ++k)
            for (int j = 0; j < 4; ++j) {
                u64 v = 0;
                for (int b = 7; b >= 0; --b) v = (v << 8) | q[32 * k + 8 * j + b];
                f[k]->v[j] = v;
            }
        h[i].recid = q[224];
    }
    g_hints = h;
    g_hint_n = count;
}

// Test hook: drop deferred signatures (the guest itself aborts on failure).
extern "C" void stwo_secp_reset_pending() { g_pending_n = 0; }

// Verifies every deferred signature; aborts the guest on any failure.
extern "C" void stwo_secp_verify_pending() {
    const size_t n = g_pending_n;
    if (n == 0) return;
    // Batch inverse of every s (mod N).
    U256* pre = new U256[n];
    pre[0] = g_pending[0].s;
    for (size_t i = 1; i < n; ++i) pre[i] = sc_mul(pre[i - 1], g_pending[i].s);
    U256 inv = inv_mod(pre[n - 1], N);
    U256* sinv = new U256[n];
    for (size_t i = n; i-- > 1;) {
        sinv[i] = sc_mul(inv, pre[i - 1]);
        inv = sc_mul(inv, g_pending[i].s);
    }
    sinv[0] = inv;
    // R'_i projective; check x = r without inverting.
    Proj* rp = new Proj[n];
    for (size_t i = 0; i < n; ++i) {
        const Pending& p = g_pending[i];
        rp[i] = double_mul(sc_mul(p.z, sinv[i]), sc_mul(p.r, sinv[i]), p.q);
        if (is_zero(rp[i].z)) stwo_guest_abort("signature: R is infinity");
        if (!eq(fe_mul(p.r, rp[i].z), rp[i].x)) stwo_guest_abort("signature: x(R) != r");
    }
    // Batch inverse of every Z (mod P) for the y parity.
    pre[0] = rp[0].z;
    for (size_t i = 1; i < n; ++i) pre[i] = fe_mul(pre[i - 1], rp[i].z);
    inv = inv_mod(pre[n - 1], P);
    for (size_t i = n; i-- > 0;) {
        const U256 zi = i ? fe_mul(inv, pre[i - 1]) : inv;
        if (i) inv = fe_mul(inv, rp[i].z);
        const U256 y = fe_mul(rp[i].y, zi);
        if ((y.v[0] & 1) != g_pending[i].recid) stwo_guest_abort("signature: y parity");
    }
    delete[] pre;
    delete[] sinv;
    delete[] rp;
    g_pending_n = 0;
}

namespace {
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
// (Omitted by the host differential test, which links evmone's reference.)
#if !defined(STWO_SECP_NO_EVMONE_API)
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
#endif  // STWO_SECP_NO_EVMONE_API

#if defined(STWO_HOST)
// Host only: record each successful full recovery for the input adapter
// (STWO_SECP_HINTS_OUT=<file>; 232-byte records, see stwo_secp_set_hints).
#include <cstdio>
#include <cstdlib>
namespace {
void record_hint(const U256& z, const U256& r, const U256& s, unsigned recid, const U256& qx, const U256& qy,
                 const U256& ry, const U256& w) {
    static FILE* f = [] { const char* p = std::getenv("STWO_SECP_HINTS_OUT"); return p ? std::fopen(p, "ab") : nullptr; }();
    if (!f) return;
    uint8_t rec[232] = {};
    const U256* v[7] = {&z, &r, &s, &qx, &qy, &ry, &w};
    for (int k = 0; k < 7; ++k)
        for (int j = 0; j < 4; ++j)
            for (int b = 0; b < 8; ++b) rec[32 * k + 8 * j + b] = uint8_t(v[k]->v[j] >> (8 * b));
    rec[224] = uint8_t(recid);
    std::fwrite(rec, 1, sizeof rec, f);
    std::fflush(f);
}
}  // namespace
#endif
