#pragma once

#include "fields_support.h"

struct StwoMetalQm31 {
    uint a;
    uint b;
    uint c;
    uint d;
};

struct StwoMetalCm31 {
    uint a;
    uint b;
};

static inline StwoMetalCm31 stwo_metal_cm31(uint a, uint b) {
    return StwoMetalCm31 { a, b };
}

static inline StwoMetalCm31 stwo_metal_cm31_add(StwoMetalCm31 lhs, StwoMetalCm31 rhs) {
    return StwoMetalCm31 {
        stwo_metal_m31_add(lhs.a, rhs.a),
        stwo_metal_m31_add(lhs.b, rhs.b),
    };
}

static inline StwoMetalCm31 stwo_metal_cm31_sub(StwoMetalCm31 lhs, StwoMetalCm31 rhs) {
    return StwoMetalCm31 {
        stwo_metal_m31_sub(lhs.a, rhs.a),
        stwo_metal_m31_sub(lhs.b, rhs.b),
    };
}

static inline StwoMetalCm31 stwo_metal_cm31_neg(StwoMetalCm31 value) {
    return StwoMetalCm31 {
        stwo_metal_m31_neg(value.a),
        stwo_metal_m31_neg(value.b),
    };
}

static inline StwoMetalCm31 stwo_metal_cm31_mul_base(StwoMetalCm31 value, uint scalar) {
    return StwoMetalCm31 {
        stwo_metal_m31_mul(value.a, scalar),
        stwo_metal_m31_mul(value.b, scalar),
    };
}

static inline StwoMetalCm31 stwo_metal_cm31_mul(StwoMetalCm31 lhs, StwoMetalCm31 rhs) {
    return StwoMetalCm31 {
        stwo_metal_m31_sub(stwo_metal_m31_mul(lhs.a, rhs.a), stwo_metal_m31_mul(lhs.b, rhs.b)),
        stwo_metal_m31_add(stwo_metal_m31_mul(lhs.a, rhs.b), stwo_metal_m31_mul(lhs.b, rhs.a)),
    };
}

static inline StwoMetalCm31 stwo_metal_cm31_inverse(StwoMetalCm31 value) {
    uint denom_inverse = stwo_metal_m31_inv(
        stwo_metal_m31_add(
            stwo_metal_m31_square(value.a),
            stwo_metal_m31_square(value.b)
        )
    );
    return stwo_metal_cm31_mul_base(
        StwoMetalCm31 { value.a, stwo_metal_m31_neg(value.b) },
        denom_inverse
    );
}

static inline StwoMetalQm31 stwo_metal_qm31_from_base(uint value) {
    return StwoMetalQm31 { value, 0u, 0u, 0u };
}

static inline StwoMetalQm31 stwo_metal_qm31_add(StwoMetalQm31 lhs, StwoMetalQm31 rhs) {
    return StwoMetalQm31 {
        stwo_metal_m31_add(lhs.a, rhs.a),
        stwo_metal_m31_add(lhs.b, rhs.b),
        stwo_metal_m31_add(lhs.c, rhs.c),
        stwo_metal_m31_add(lhs.d, rhs.d),
    };
}

static inline StwoMetalQm31 stwo_metal_qm31_sub(StwoMetalQm31 lhs, StwoMetalQm31 rhs) {
    return StwoMetalQm31 {
        stwo_metal_m31_sub(lhs.a, rhs.a),
        stwo_metal_m31_sub(lhs.b, rhs.b),
        stwo_metal_m31_sub(lhs.c, rhs.c),
        stwo_metal_m31_sub(lhs.d, rhs.d),
    };
}

static inline StwoMetalQm31 stwo_metal_qm31_mul_base(StwoMetalQm31 value, uint scalar) {
    return StwoMetalQm31 {
        stwo_metal_m31_mul(value.a, scalar),
        stwo_metal_m31_mul(value.b, scalar),
        stwo_metal_m31_mul(value.c, scalar),
        stwo_metal_m31_mul(value.d, scalar),
    };
}

static inline StwoMetalQm31 stwo_metal_qm31_double(StwoMetalQm31 value) {
    return stwo_metal_qm31_add(value, value);
}

static inline StwoMetalQm31 stwo_metal_qm31_mul(StwoMetalQm31 lhs, StwoMetalQm31 rhs) {
    uint a0 = lhs.a;
    uint a1 = lhs.b;
    uint a2 = lhs.c;
    uint a3 = lhs.d;
    uint b0 = rhs.a;
    uint b1 = rhs.b;
    uint b2 = rhs.c;
    uint b3 = rhs.d;

    uint x0 = stwo_metal_m31_sub(stwo_metal_m31_mul(a0, b0), stwo_metal_m31_mul(a1, b1));
    uint x1 = stwo_metal_m31_add(stwo_metal_m31_mul(a0, b1), stwo_metal_m31_mul(a1, b0));
    uint y0 = stwo_metal_m31_sub(stwo_metal_m31_mul(a2, b2), stwo_metal_m31_mul(a3, b3));
    uint y1 = stwo_metal_m31_add(stwo_metal_m31_mul(a2, b3), stwo_metal_m31_mul(a3, b2));

    uint cross0 = stwo_metal_m31_sub(stwo_metal_m31_mul(a0, b2), stwo_metal_m31_mul(a1, b3));
    uint cross1 = stwo_metal_m31_add(stwo_metal_m31_mul(a0, b3), stwo_metal_m31_mul(a1, b2));
    uint cross2 = stwo_metal_m31_sub(stwo_metal_m31_mul(a2, b0), stwo_metal_m31_mul(a3, b1));
    uint cross3 = stwo_metal_m31_add(stwo_metal_m31_mul(a2, b1), stwo_metal_m31_mul(a3, b0));

    uint r_y0 = stwo_metal_m31_sub(stwo_metal_m31_mul(2u, y0), y1);
    uint r_y1 = stwo_metal_m31_add(y0, stwo_metal_m31_mul(2u, y1));

    return StwoMetalQm31 {
        stwo_metal_m31_add(x0, r_y0),
        stwo_metal_m31_add(x1, r_y1),
        stwo_metal_m31_add(cross0, cross2),
        stwo_metal_m31_add(cross1, cross3),
    };
}

static inline StwoMetalQm31 stwo_metal_qm31_neg(StwoMetalQm31 value) {
    return StwoMetalQm31 {
        stwo_metal_m31_neg(value.a),
        stwo_metal_m31_neg(value.b),
        stwo_metal_m31_neg(value.c),
        stwo_metal_m31_neg(value.d),
    };
}

/// QM31 inverse: q = (a, b) in CM31 x CM31, where QM31 = CM31[u] / (u^2 - (2+i)).
/// inv(q) = conj(q) / norm(q), where conj(a,b) = (a,-b) and
/// norm(q) = a^2 - (2+i)*b^2  (in CM31).
static inline StwoMetalQm31 stwo_metal_qm31_inverse(StwoMetalQm31 value) {
    StwoMetalCm31 a = { value.a, value.b };
    StwoMetalCm31 b = { value.c, value.d };
    // (2+i) in CM31 = { 2, 1 }
    StwoMetalCm31 two_plus_i = { 2u, 1u };
    // norm = a*a - (2+i)*b*b
    StwoMetalCm31 a_sq = stwo_metal_cm31_mul(a, a);
    StwoMetalCm31 b_sq = stwo_metal_cm31_mul(b, b);
    StwoMetalCm31 norm = stwo_metal_cm31_sub(a_sq, stwo_metal_cm31_mul(two_plus_i, b_sq));
    StwoMetalCm31 norm_inv = stwo_metal_cm31_inverse(norm);
    // conj(q) = (a, -b)
    StwoMetalCm31 neg_b = stwo_metal_cm31_neg(b);
    // result = conj * norm_inv
    StwoMetalCm31 r_a = stwo_metal_cm31_mul(a, norm_inv);
    StwoMetalCm31 r_b = stwo_metal_cm31_mul(neg_b, norm_inv);
    return StwoMetalQm31 { r_a.a, r_a.b, r_b.a, r_b.b };
}

static inline StwoMetalQm31 stwo_metal_qm31_mul_cm31(StwoMetalQm31 lhs, StwoMetalCm31 rhs) {
    StwoMetalCm31 lo = stwo_metal_cm31_mul(StwoMetalCm31 { lhs.a, lhs.b }, rhs);
    StwoMetalCm31 hi = stwo_metal_cm31_mul(StwoMetalCm31 { lhs.c, lhs.d }, rhs);
    return StwoMetalQm31 { lo.a, lo.b, hi.a, hi.b };
}

static inline StwoMetalQm31 stwo_metal_load_qm31(device const uint *values, uint index) {
    uint base = index * 4u;
    return StwoMetalQm31 {
        values[base + 0u],
        values[base + 1u],
        values[base + 2u],
        values[base + 3u],
    };
}

static inline void stwo_metal_store_qm31(device uint *values, uint index, StwoMetalQm31 value) {
    uint base = index * 4u;
    values[base + 0u] = value.a;
    values[base + 1u] = value.b;
    values[base + 2u] = value.c;
    values[base + 3u] = value.d;
}

static inline StwoMetalQm31 stwo_metal_fri_fold_pair(
    StwoMetalQm31 f_p,
    StwoMetalQm31 f_neg_p,
    uint inverse_factor,
    StwoMetalQm31 alpha
) {
    StwoMetalQm31 f0 = stwo_metal_qm31_add(f_p, f_neg_p);
    StwoMetalQm31 f1 =
        stwo_metal_qm31_mul_base(stwo_metal_qm31_sub(f_p, f_neg_p), inverse_factor);
    return stwo_metal_qm31_add(f0, stwo_metal_qm31_mul(alpha, f1));
}

static inline StwoMetalQm31 stwo_metal_fold_base_mle_pair(
    uint lhs,
    uint rhs,
    StwoMetalQm31 assignment
) {
    uint delta = stwo_metal_m31_sub(rhs, lhs);
    return stwo_metal_qm31_add(
        stwo_metal_qm31_from_base(lhs),
        stwo_metal_qm31_mul_base(assignment, delta)
    );
}

static inline StwoMetalQm31 stwo_metal_fold_secure_mle_pair(
    StwoMetalQm31 lhs,
    StwoMetalQm31 rhs,
    StwoMetalQm31 assignment
) {
    return stwo_metal_qm31_add(
        lhs,
        stwo_metal_qm31_mul(assignment, stwo_metal_qm31_sub(rhs, lhs))
    );
}
