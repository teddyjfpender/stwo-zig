#pragma once

#include <metal_stdlib>

using namespace metal;

constant uint STWO_METAL_M31_P = 2147483647u;

struct StwoMetalCirclePointM31 {
    uint x;
    uint y;
};

static inline uint stwo_metal_bit_reverse_index(uint index, uint log_len) {
    uint reversed = 0;
    for (uint bit = 0; bit < log_len; ++bit) {
        reversed = (reversed << 1) | ((index >> bit) & 1u);
    }
    return reversed;
}

static inline uint stwo_metal_m31_add(uint lhs, uint rhs) {
    uint sum = lhs + rhs;
    return sum >= STWO_METAL_M31_P ? sum - STWO_METAL_M31_P : sum;
}

static inline uint stwo_metal_m31_sub(uint lhs, uint rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_METAL_M31_P - rhs;
}

static inline uint stwo_metal_m31_neg(uint value) {
    uint negated = STWO_METAL_M31_P - value;
    return negated == STWO_METAL_M31_P ? 0u : negated;
}

static inline uint stwo_metal_m31_mul(uint lhs, uint rhs) {
    ulong product = (ulong)lhs * (ulong)rhs;
    ulong reduced =
        (((((product >> 31u) + product + 1u) >> 31u) + product) & (ulong)STWO_METAL_M31_P);
    return (uint)reduced;
}

static inline uint stwo_metal_m31_square(uint value) {
    return stwo_metal_m31_mul(value, value);
}

static inline uint stwo_metal_m31_pow_to_power_of_two(uint squarings, uint value) {
    uint result = value;
    for (uint i = 0; i < squarings; ++i) {
        result = stwo_metal_m31_square(result);
    }
    return result;
}

static inline uint stwo_metal_m31_inv(uint value) {
    uint t0 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(2u, value), value);
    uint t1 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(1u, t0), t0);
    uint t2 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(3u, t1), t0);
    uint t3 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(1u, t2), t0);
    uint t4 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(8u, t3), t3);
    uint t5 = stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(8u, t4), t3);
    return stwo_metal_m31_mul(stwo_metal_m31_pow_to_power_of_two(7u, t5), t2);
}

static inline StwoMetalCirclePointM31 stwo_metal_circle_point_mul(
    StwoMetalCirclePointM31 lhs,
    StwoMetalCirclePointM31 rhs
) {
    return StwoMetalCirclePointM31 {
        stwo_metal_m31_sub(
            stwo_metal_m31_mul(lhs.x, rhs.x),
            stwo_metal_m31_mul(lhs.y, rhs.y)
        ),
        stwo_metal_m31_add(
            stwo_metal_m31_mul(lhs.x, rhs.y),
            stwo_metal_m31_mul(lhs.y, rhs.x)
        ),
    };
}

static inline StwoMetalCirclePointM31 stwo_metal_circle_point_square(StwoMetalCirclePointM31 value) {
    return stwo_metal_circle_point_mul(value, value);
}

static inline StwoMetalCirclePointM31 stwo_metal_circle_point_pow(
    StwoMetalCirclePointM31 base,
    uint exponent
) {
    StwoMetalCirclePointM31 result = StwoMetalCirclePointM31 { 1u, 0u };
    while (exponent > 0u) {
        if ((exponent & 1u) != 0u) {
            result = stwo_metal_circle_point_mul(base, result);
        }
        base = stwo_metal_circle_point_square(base);
        exponent >>= 1u;
    }
    return result;
}
