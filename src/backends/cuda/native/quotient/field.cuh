#pragma once

#include "types.cuh"

#include <cstdint>

namespace stwo::cuda::quotient {

using oods::add;
using oods::inverse;
using oods::mul;
using oods::neg;
using oods::one;
using oods::point_pow;
using oods::square;
using oods::sub;
using oods::zero;

__host__ __device__ __forceinline__ QM31 mul_scalar(
    QM31 value,
    M31 scalar) {
    return mul(scalar, value);
}

__host__ __device__ __forceinline__ QM31 power(
    QM31 value,
    std::uint32_t exponent) {
    QM31 result = one();
    while (exponent != 0) {
        if ((exponent & 1u) != 0) result = mul(result, value);
        value = square(value);
        exponent >>= 1;
    }
    return result;
}

__host__ __device__ __forceinline__ SecureCirclePoint add_base_offset(
    SecureCirclePoint value,
    CirclePoint offset) {
    return {
        sub(mul_scalar(value.x, offset.x), mul_scalar(value.y, offset.y)),
        add(mul_scalar(value.x, offset.y), mul_scalar(value.y, offset.x)),
    };
}

__host__ __device__ __forceinline__ void conjugate_line_coefficients(
    SecureCirclePoint point,
    QM31 value,
    QM31 alpha,
    QM31 *a,
    QM31 *b,
    QM31 *c) {
    const QM31 value_difference = sub(
        QM31{value.a, neg(value.b)},
        value);
    const QM31 point_difference = sub(
        QM31{point.y.a, neg(point.y.b)},
        point.y);
    const QM31 constant = sub(
        mul(value, point_difference),
        mul(value_difference, point.y));
    *a = mul(alpha, value_difference);
    *b = mul(alpha, constant);
    *c = mul(alpha, point_difference);
}

__device__ __forceinline__ std::uint32_t bit_reverse(
    std::uint32_t value,
    std::uint32_t bits) {
    return __brev(value) >> (32u - bits);
}

__device__ __forceinline__ CirclePoint domain_at_index(
    std::uint32_t initial,
    std::uint32_t step,
    std::uint32_t index,
    std::uint32_t domain_size) {
    constexpr std::uint64_t kCircleOrder = 1ull << 31;
    constexpr std::uint64_t kCircleMask = kCircleOrder - 1;
    const std::uint32_t half = domain_size >> 1;
    const std::uint64_t offset =
        static_cast<std::uint64_t>(step) *
        static_cast<std::uint64_t>(index < half ? index : index - half);
    const std::uint64_t forward =
        static_cast<std::uint64_t>(initial) + offset;
    const std::uint64_t exponent =
        index < half ? forward : kCircleOrder - forward;
    return point_pow(
        oods::kCircleGenerator,
        static_cast<std::uint32_t>(exponent & kCircleMask));
}

__device__ __forceinline__ CM31 denominator(
    SecureCirclePoint sample,
    CirclePoint domain) {
    const CM31 real_x = sample.x.a;
    const CM31 real_y = sample.y.a;
    const CM31 imaginary_x = sample.x.b;
    const CM31 imaginary_y = sample.y.b;
    return sub(
        mul(CM31{sub(real_x.a, domain.x), real_x.b}, imaginary_y),
        mul(CM31{sub(real_y.a, domain.y), real_y.b}, imaginary_x));
}

}  // namespace stwo::cuda::quotient
