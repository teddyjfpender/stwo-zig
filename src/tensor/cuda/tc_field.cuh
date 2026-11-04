// M31 / CM31 / QM31 arithmetic for the tensor CUDA kernels, with delayed
// ("lazy") reduction.
//
// p = 2^31 - 1. QM31 = CM31[u] / (u^2 - (2 + i)), CM31 = M31[i] / (i^2 + 1);
// a QM31 is four canonical limbs (a, b, c, d) = (a + b i) + (c + d i) u, the
// same order as field.zig `limbs()` and the Metal `Qm31Value`.
//
// Lazy reduction (the idea of FlashProve's prover/field/lazy_gl64.cuh, after
// Dumas-Giorgi-Pernet, mapped from Goldilocks to M31): a product of two
// canonical limbs is < 2^62, so up to four products (and a few small terms)
// sum in a u64 without overflow and are reduced ONCE with the Mersenne fold
// x = (x & p) + (x >> 31). qm_mul does 16 limb products with 6 reductions
// instead of 12; the accumulators below add 2^32 canonical QM31 values (or
// keep a running partial fold for products) before a single final reduce.
// Every function returns canonical limbs, so results are bit-identical to the
// Zig field code (field arithmetic is exact: any reduction schedule that
// yields the canonical residue gives the same bits).
#pragma once
#include "tc_prelude.cuh"

namespace tc {

static constexpr uint32_t P = 0x7fffffffu;

struct qm {
    uint32_t a, b, c, d;
};

// --- M31 -------------------------------------------------------------------

// Canonical residue of any x < 2^64.
TC_HD uint32_t m31_reduce64(uint64_t x) {
    uint64_t r = (x & P) + (x >> 31);       // < 2^34
    r = (r & P) + (r >> 31);                // < 2^31 + 8
    uint32_t v = (uint32_t)r;
    return v >= P ? v - P : v;
}
TC_HD uint32_t m31_add(uint32_t x, uint32_t y) {
    uint32_t s = x + y;
    return s >= P ? s - P : s;
}
TC_HD uint32_t m31_sub(uint32_t x, uint32_t y) { return m31_add(x, P - y); }
TC_HD uint32_t m31_neg(uint32_t x) { return x == 0 ? 0 : P - x; }
TC_HD uint32_t m31_mul(uint32_t x, uint32_t y) { return m31_reduce64((uint64_t)x * y); }

// Canonical residue of any int32 (INT32_MIN -> p - 1, INT32_MAX = p -> 0),
// as field.zig fromI32 / Metal tm_from_i32.
TC_HD uint32_t m31_from_i32(int32_t x) {
    int64_t r = x;
    if (r < 0) r += P;
    if (r < 0) r += P;
    if (r >= (int64_t)P) r -= P;
    return (uint32_t)r;
}
// Canonical residue of a signed accumulator (any int64).
TC_HD uint32_t m31_from_i64(int64_t x) {
    int64_t r = x % (int64_t)P;
    if (r < 0) r += P;
    return (uint32_t)r;
}

// --- QM31 ------------------------------------------------------------------

TC_HD qm qm_zero() { return qm{0, 0, 0, 0}; }
TC_HD qm qm_one() { return qm{1, 0, 0, 0}; }
TC_HD bool qm_is_one(qm x) { return x.a == 1 && x.b == 0 && x.c == 0 && x.d == 0; }
TC_HD qm qm_add(qm x, qm y) {
    return qm{m31_add(x.a, y.a), m31_add(x.b, y.b), m31_add(x.c, y.c), m31_add(x.d, y.d)};
}
TC_HD qm qm_sub(qm x, qm y) {
    return qm{m31_sub(x.a, y.a), m31_sub(x.b, y.b), m31_sub(x.c, y.c), m31_sub(x.d, y.d)};
}
TC_HD qm qm_mul_base(qm x, uint32_t s) {
    return qm{m31_mul(x.a, s), m31_mul(x.b, s), m31_mul(x.c, s), m31_mul(x.d, s)};
}

// (x0 + x1 u)(y0 + y1 u) = x0 y0 + (2 + i) x1 y1 + (x0 y1 + x1 y0) u.
TC_HD qm qm_mul(qm x, qm y) {
    typedef uint64_t W;
    // x1 y1 = e + g i (reduced: it is multiplied by 2 + i next)
    const uint32_t e = m31_reduce64((W)x.c * y.c + (W)x.d * (P - y.d));
    const uint32_t g = m31_reduce64((W)x.c * y.d + (W)x.d * y.c);
    // (2 + i)(e + g i) = (2e - g) + (e + 2g) i, folded into x0 y0
    const uint32_t o0 = m31_reduce64((W)x.a * y.a + (W)x.b * (P - y.b) + 2 * (W)e + (W)(P - g));
    const uint32_t o1 = m31_reduce64((W)x.a * y.b + (W)x.b * y.a + (W)e + 2 * (W)g);
    // x0 y1 + x1 y0: four products < 4 (2^31 - 1)^2 < 2^64
    const uint32_t o2 = m31_reduce64((W)x.a * y.c + (W)x.b * (P - y.d) + (W)x.c * y.a + (W)x.d * (P - y.b));
    const uint32_t o3 = m31_reduce64((W)x.a * y.d + (W)x.b * y.c + (W)x.c * y.b + (W)x.d * y.a);
    return qm{o0, o1, o2, o3};
}

// --- lazy accumulators -------------------------------------------------------

// Sum of canonical QM31 values: each limb < 2^31, so 2^33 additions fit.
struct qacc {
    uint64_t v[4];
};
TC_HD qacc qacc_zero() { return qacc{{0, 0, 0, 0}}; }
TC_HD void qacc_add(qacc &s, qm x) {
    s.v[0] += x.a;
    s.v[1] += x.b;
    s.v[2] += x.c;
    s.v[3] += x.d;
}
TC_HD qm qacc_get(const qacc &s) {
    return qm{m31_reduce64(s.v[0]), m31_reduce64(s.v[1]), m31_reduce64(s.v[2]), m31_reduce64(s.v[3])};
}

// Sum of (canonical M31) x (canonical QM31) products: the running value is
// partially folded before each add, so it stays < 2^62 + 2^34 for any count.
struct pacc {
    uint64_t v[4];
};
TC_HD pacc pacc_zero() { return pacc{{0, 0, 0, 0}}; }
TC_HD uint64_t tc_fold(uint64_t x) { return (x & P) + (x >> 31); }
TC_HD void pacc_mac(pacc &s, uint32_t m, qm x) {
    s.v[0] = tc_fold(s.v[0]) + (uint64_t)m * x.a;
    s.v[1] = tc_fold(s.v[1]) + (uint64_t)m * x.b;
    s.v[2] = tc_fold(s.v[2]) + (uint64_t)m * x.c;
    s.v[3] = tc_fold(s.v[3]) + (uint64_t)m * x.d;
}
TC_HD qm pacc_get(const pacc &s) {
    return qm{m31_reduce64(s.v[0]), m31_reduce64(s.v[1]), m31_reduce64(s.v[2]), m31_reduce64(s.v[3])};
}

// Signed integer x QM31 sums (FlashProve's IAcc idea, lazy_signed.cuh): with
// |m| <= 2^7 (int8) each product is < 2^38 in magnitude, so 2^25 of them sum
// exactly in int64 and are reduced once. Callers bound the count.
struct iacc {
    int64_t v[4];
};
TC_HD iacc iacc_zero() { return iacc{{0, 0, 0, 0}}; }
TC_HD void iacc_mac(iacc &s, int32_t m, qm x) {
    s.v[0] += (int64_t)m * x.a;
    s.v[1] += (int64_t)m * x.b;
    s.v[2] += (int64_t)m * x.c;
    s.v[3] += (int64_t)m * x.d;
}
TC_HD qm iacc_get(const iacc &s) {
    return qm{m31_from_i64(s.v[0]), m31_from_i64(s.v[1]), m31_from_i64(s.v[2]), m31_from_i64(s.v[3])};
}

TC_HD qm qm_load(const uint32_t *f, uint64_t i) {
    const uint32_t *p = f + 4 * i;
    return qm{p[0], p[1], p[2], p[3]};
}
TC_HD void qm_store(uint32_t *f, uint64_t i, qm x) {
    uint32_t *p = f + 4 * i;
    p[0] = x.a;
    p[1] = x.b;
    p[2] = x.c;
    p[3] = x.d;
}

}  // namespace tc
