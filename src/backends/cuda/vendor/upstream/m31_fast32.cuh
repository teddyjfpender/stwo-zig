#ifndef STWO_M31_FAST32_H
#define STWO_M31_FAST32_H

#include "fields.cuh"

// Candidate-only arithmetic for the fixed-width N2B final interval. Qualified
// inputs are canonical M31 words; the P alias is normalized defensively. The
// product for 0 <= a,b <= P is below 2^62, so
// `hi << 1` cannot overflow and `(hi << 1) | (lo >> 31)` is exactly
// floor(a*b / 2^31). Two Mersenne folds then land in [0,P], where P maps to 0.
__device__ __forceinline__ m31 stwo_m31_mul_fast32(m31 a, m31 b) {
    constexpr uint32_t modulus = 0x7fffffffu;
    const uint32_t lo = a * b;
    const uint32_t hi = __umulhi(a, b);
    const uint32_t quotient = (hi << 1) | (lo >> 31);
    uint32_t reduced = (lo & modulus) + quotient;
    reduced = (reduced & modulus) + (reduced >> 31);
    return reduced == modulus ? 0u : reduced;
}

// Canonical inputs sum to at most 2P-2 (<2^32); one fold plus P->0 is exact.
__device__ __forceinline__ m31 stwo_m31_add_fast32(m31 a, m31 b) {
    constexpr uint32_t modulus = 0x7fffffffu;
    const uint32_t sum = a + b;
    const uint32_t reduced = (sum & modulus) + (sum >> 31);
    return reduced == modulus ? 0u : reduced;
}

// Canonical inputs make both branches ordinary 32-bit arithmetic without
// overflow: a+P-b <= 2P-2 < 2^32.
__device__ __forceinline__ m31 stwo_m31_sub_fast32(m31 a, m31 b) {
    constexpr uint32_t modulus = 0x7fffffffu;
    const uint32_t difference = a >= b ? a - b : a + modulus - b;
    return difference == modulus ? 0u : difference;
}

#endif
