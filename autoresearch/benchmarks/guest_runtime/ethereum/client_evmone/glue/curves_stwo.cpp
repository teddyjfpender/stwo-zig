// BN254 and BLS12-381 glue over the curve/field services (our code). Compiled
// into every build; each part is active only with its group: the execution-
// only candidates (build.py --candidate-set ...,bn / ...,bls; pointer packets)
// or the ADMITTED ethereum_services_v3 services (build.py --profile v3
// --v3-set ...,bn / ...,bls; inline 32-byte aligned packets, outputs over the
// leading operands, design/riscv-proving-stack/rv64-curve-services.md). The
// same algorithms run on either backend; only the packet transport differs.
//
// BN254 (CANDIDATE_BN): evmone's ecAdd/ecMul call stwo_bn254_g1_add/_mul
// (patch 0020), its pairing tower's Fq2 products call stwo_bn254_fp2_mul.
// BLS12-381 (CANDIDATE_BLS): blst's 384-bit Montgomery products and Fp2
// products call stwo_arith384_mont / stwo_bls12_381_fp2_mul (patch 0021).
#include <cstdint>

#include "candidate_curves.hpp"

#if defined(ADMITTED_BN) || defined(ADMITTED_BLS)
#if !defined(ADMITTED_V3)
#error "admitted curve groups are ethereum_services_v3 groups"
#endif
namespace stwo {
inline constexpr uint64_t kV3Bn254G1Add = 0x00030100;
inline constexpr uint64_t kV3Bn254G1Double = 0x00030101;
inline constexpr uint64_t kV3Bn254Fp2Mul = 0x00030102;
inline constexpr uint64_t kV3Bls12381Fp2Mul = 0x00030112;
inline constexpr uint64_t kV3Arith384Mont = 0x00030121;
// Inline packet of `W` words (W multiple of 4): the Word16 bridge binds whole
// 32-byte coordinates at a0, so the packet is 32-byte aligned.
template <int W>
struct alignas(32) Inline {
    static_assert(W % 4 == 0);
    uint64_t w[W];
};
template <int N>
inline void put(uint64_t* dst, const uint64_t* src) noexcept {
    for (int i = 0; i < N; ++i) dst[i] = src[i];
}
// [x1 y1 x2 y2] -> [x3 y3 ..]; [x y] -> [x3 y3]; [a0 a1 b0 b1] -> [c0 c1 ..].
inline void v3_bn_add(uint64_t r[8], const uint64_t p[8], const uint64_t q[8]) noexcept {
    Inline<16> pk;
    put<8>(pk.w, p);
    put<8>(pk.w + 8, q);
    ecall(kV3Bn254G1Add, pk.w);
    put<8>(r, pk.w);
}
inline void v3_bn_dbl(uint64_t r[8], const uint64_t p[8]) noexcept {
    Inline<8> pk;
    put<8>(pk.w, p);
    ecall(kV3Bn254G1Double, pk.w);
    put<8>(r, pk.w);
}
inline void v3_bn_fp2(uint64_t r[8], const uint64_t a[8], const uint64_t b[8]) noexcept {
    Inline<16> pk;
    put<8>(pk.w, a);
    put<8>(pk.w + 8, b);
    ecall(kV3Bn254Fp2Mul, pk.w);
    put<8>(r, pk.w);
}
// [a0 a1 b0 b1] (6 limbs each) -> [c0 c1 ..]; [a b m pad16] -> [r ..].
inline void v3_bls_fp2(uint64_t r[12], const uint64_t a[12], const uint64_t b[12]) noexcept {
    Inline<24> pk;
    put<12>(pk.w, a);
    put<12>(pk.w + 12, b);
    ecall(kV3Bls12381Fp2Mul, pk.w);
    put<12>(r, pk.w);
}
inline void v3_mont384(uint64_t r[6], const uint64_t a[6], const uint64_t b[6], const uint64_t m[6]) noexcept {
    Inline<20> pk;
    put<6>(pk.w, a);
    put<6>(pk.w + 6, b);
    put<6>(pk.w + 12, m);
    pk.w[18] = 0;
    pk.w[19] = 0;
    ecall(kV3Arith384Mont, pk.w);
    put<6>(r, pk.w);
}
}  // namespace stwo
#endif

#if defined(CANDIDATE_BN) || defined(ADMITTED_BN)
namespace {
// BN254 G1 group order r (little-endian limbs). G1 has cofactor 1.
constexpr uint64_t kOrder[4] = {0x43e1f593f0000001ull, 0x2833e84879b97091ull, 0xb85045b68181585dull,
                                0x30644e72e131a029ull};

struct alignas(8) Pt {
    uint64_t w[8];  // x limbs 0..3, y limbs 4..7, plain canonical form
};

inline bool eq4(const uint64_t* a, const uint64_t* b) {
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0;
}

#if defined(ADMITTED_BN)
inline void dbl(Pt& r, const Pt& p) { stwo::v3_bn_dbl(r.w, p.w); }
inline void add(Pt& r, const Pt& p, const Pt& q) { stwo::v3_bn_add(r.w, p.w, q.w); }
#else
inline void dbl(Pt& r, const Pt& p) { stwo::cand2(stwo::kCandBn254G1Double, r.w, p.w); }
inline void add(Pt& r, const Pt& p, const Pt& q) { stwo::cand3(stwo::kCandBn254G1Add, r.w, p.w, q.w); }
#endif

// acc += t for points of the prime-order group; the services need x_acc != x_t
// (add) and y != 0 (double, always true here: no point of order two exists).
inline void accumulate(Pt& acc, bool& inf, const Pt& t) {
    if (inf) {
        acc = t;
        inf = false;
    } else if (eq4(acc.w, t.w)) {
        if (eq4(acc.w + 4, t.w + 4))
            dbl(acc, acc);
        else
            inf = true;  // acc = -t
    } else {
        add(acc, acc, t);
    }
}

// k >= r is reduced (k*P = (k mod r)*P on the group); k < 2^256 < 6r.
inline void reduce_scalar(uint64_t k[4]) {
    for (;;) {
        bool ge = true;
        for (int i = 3; i >= 0; --i) {
            if (k[i] != kOrder[i]) {
                ge = k[i] > kOrder[i];
                break;
            }
        }
        if (!ge) return;
        uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            const uint64_t d = k[i] - kOrder[i];
            const uint64_t b1 = k[i] < kOrder[i];
            k[i] = d - borrow;
            borrow = b1 | (d < borrow);
        }
    }
}
}  // namespace

// r = k*p for a validated finite point p; *inf = 1 when the result is infinity.
extern "C" void stwo_bn254_g1_mul(const uint64_t p[8], const uint64_t k_in[4], uint64_t r[8], int* inf) noexcept {
    uint64_t k[4] = {k_in[0], k_in[1], k_in[2], k_in[3]};
    reduce_scalar(k);
    // Fixed 4-bit window, table T[i] = i*p (i < 16 < r, so no special cases).
    Pt t[16];
    for (int i = 0; i < 8; ++i) t[1].w[i] = p[i];
    dbl(t[2], t[1]);
    for (int i = 3; i < 16; ++i) add(t[i], t[i - 1], t[1]);
    Pt acc;
    bool acc_inf = true;
    for (int n = 63; n >= 0; --n) {
        const unsigned w = unsigned(k[n >> 4] >> ((n & 15) * 4)) & 15;
        if (!acc_inf)
            for (int d = 0; d < 4; ++d) dbl(acc, acc);
        if (w) accumulate(acc, acc_inf, t[w]);
    }
    *inf = acc_inf;
    if (!acc_inf)
        for (int i = 0; i < 8; ++i) r[i] = acc.w[i];
}

// r = p + q for validated finite points.
extern "C" void stwo_bn254_g1_add(const uint64_t p[8], const uint64_t q[8], uint64_t r[8], int* inf) noexcept {
    Pt acc, t;
    for (int i = 0; i < 8; ++i) {
        acc.w[i] = p[i];
        t.w[i] = q[i];
    }
    bool acc_inf = false;
    accumulate(acc, acc_inf, t);
    *inf = acc_inf;
    if (!acc_inf)
        for (int i = 0; i < 8; ++i) r[i] = acc.w[i];
}

extern "C" void stwo_bn254_fp2_mul(uint64_t r[8], const uint64_t a[8], const uint64_t b[8]) noexcept {
#if defined(ADMITTED_BN)
    stwo::v3_bn_fp2(r, a, b);
#else
    stwo::cand3(stwo::kCandBn254Fp2Mul, r, a, b);
#endif
}
#endif  // CANDIDATE_BN || ADMITTED_BN

#if defined(CANDIDATE_BLS) || defined(ADMITTED_BLS)
extern "C" void stwo_arith384_mont(uint64_t ret[6], const uint64_t a[6], const uint64_t b[6],
                                   const uint64_t p[6]) noexcept {
#if defined(ADMITTED_BLS)
    stwo::v3_mont384(ret, a, b, p);
#else
    stwo::cand4(stwo::kCandArith384Mont, a, b, p, ret);
#endif
}

extern "C" void stwo_bls12_381_fp2_mul(uint64_t ret[12], const uint64_t a[12], const uint64_t b[12]) noexcept {
#if defined(ADMITTED_BLS)
    stwo::v3_bls_fp2(ret, a, b);
#else
    stwo::cand3(stwo::kCandBls12381Fp2Mul, ret, a, b);
#endif
}
#endif  // CANDIDATE_BLS || ADMITTED_BLS
