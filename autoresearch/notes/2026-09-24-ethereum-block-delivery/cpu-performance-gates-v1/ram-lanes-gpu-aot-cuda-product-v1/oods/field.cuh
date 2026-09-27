#pragma once

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::oods {

using M31 = std::uint32_t;

struct CM31 {
    M31 a;
    M31 b;
};

struct QM31 {
    CM31 a;
    CM31 b;
};

struct CirclePoint {
    M31 x;
    M31 y;
};

// ABI order is x.a.a, x.a.b, x.b.a, x.b.b, then the four y words.
struct SecureCirclePoint {
    QM31 x;
    QM31 y;
};

static_assert(sizeof(QM31) == 4 * sizeof(std::uint32_t));
static_assert(sizeof(SecureCirclePoint) == 8 * sizeof(std::uint32_t));
static_assert(alignof(CM31) == alignof(std::uint32_t));
static_assert(alignof(QM31) == alignof(std::uint32_t));
static_assert(alignof(CirclePoint) == alignof(std::uint32_t));
static_assert(alignof(SecureCirclePoint) == alignof(std::uint32_t));
static_assert(offsetof(CM31, a) == 0);
static_assert(offsetof(CM31, b) == sizeof(std::uint32_t));
static_assert(offsetof(QM31, a) == 0);
static_assert(offsetof(QM31, b) == 2 * sizeof(std::uint32_t));
static_assert(offsetof(CirclePoint, x) == 0);
static_assert(offsetof(CirclePoint, y) == sizeof(std::uint32_t));
static_assert(offsetof(SecureCirclePoint, x) == 0);
static_assert(offsetof(SecureCirclePoint, y) == 4 * sizeof(std::uint32_t));

constexpr M31 kPrime = 2147483647u;
constexpr CM31 kExtensionR{2u, 1u};
constexpr CirclePoint kCircleGenerator{2u, 1268011823u};

__host__ __device__ __forceinline__ M31 add(M31 lhs, M31 rhs) {
    const std::uint64_t sum =
        static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs);
    return static_cast<M31>(sum < kPrime ? sum : sum - kPrime);
}

__host__ __device__ __forceinline__ M31 sub(M31 lhs, M31 rhs) {
    return add(lhs, kPrime - rhs);
}

__host__ __device__ __forceinline__ M31 neg(M31 value) {
    return value == 0 ? 0 : kPrime - value;
}

__host__ __device__ __forceinline__ M31 mul(M31 lhs, M31 rhs) {
    const std::uint64_t value =
        static_cast<std::uint64_t>(lhs) * static_cast<std::uint64_t>(rhs);
    const std::uint64_t first = value + (value >> 31);
    const std::uint64_t second = value + (first >> 31);
    return static_cast<M31>(second & kPrime);
}

__host__ __device__ __forceinline__ M31 square(M31 value) {
    return mul(value, value);
}

__host__ __device__ __forceinline__ M31 pow2(M31 value, int exponent) {
    for (int index = 0; index < exponent; ++index) {
        value = square(value);
    }
    return value;
}

__host__ __device__ __forceinline__ M31 inverse(M31 value) {
    const M31 t0 = mul(pow2(value, 2), value);
    const M31 t1 = mul(pow2(t0, 1), t0);
    const M31 t2 = mul(pow2(t1, 3), t0);
    const M31 t3 = mul(pow2(t2, 1), t0);
    const M31 t4 = mul(pow2(t3, 8), t3);
    const M31 t5 = mul(pow2(t4, 8), t3);
    return mul(pow2(t5, 7), t2);
}

__host__ __device__ __forceinline__ CM31 add(CM31 lhs, CM31 rhs) {
    return {add(lhs.a, rhs.a), add(lhs.b, rhs.b)};
}

__host__ __device__ __forceinline__ CM31 sub(CM31 lhs, CM31 rhs) {
    return {sub(lhs.a, rhs.a), sub(lhs.b, rhs.b)};
}

__host__ __device__ __forceinline__ CM31 neg(CM31 value) {
    return {neg(value.a), neg(value.b)};
}

__host__ __device__ __forceinline__ CM31 mul(CM31 lhs, CM31 rhs) {
    return {
        sub(mul(lhs.a, rhs.a), mul(lhs.b, rhs.b)),
        add(mul(lhs.a, rhs.b), mul(lhs.b, rhs.a)),
    };
}

__host__ __device__ __forceinline__ CM31 mul(M31 lhs, CM31 rhs) {
    return {mul(lhs, rhs.a), mul(lhs, rhs.b)};
}

__host__ __device__ __forceinline__ CM31 inverse(CM31 value) {
    const M31 factor =
        inverse(add(mul(value.a, value.a), mul(value.b, value.b)));
    return {mul(value.a, factor), mul(neg(value.b), factor)};
}

__host__ __device__ __forceinline__ QM31 zero() {
    return {{0u, 0u}, {0u, 0u}};
}

__host__ __device__ __forceinline__ QM31 one() {
    return {{1u, 0u}, {0u, 0u}};
}

__host__ __device__ __forceinline__ QM31 add(QM31 lhs, QM31 rhs) {
    return {add(lhs.a, rhs.a), add(lhs.b, rhs.b)};
}

__host__ __device__ __forceinline__ QM31 add(M31 lhs, QM31 rhs) {
    return {{add(lhs, rhs.a.a), rhs.a.b}, rhs.b};
}

__host__ __device__ __forceinline__ QM31 sub(QM31 lhs, QM31 rhs) {
    return {sub(lhs.a, rhs.a), sub(lhs.b, rhs.b)};
}

__host__ __device__ __forceinline__ QM31 mul(QM31 lhs, QM31 rhs) {
    const CM31 v0 = mul(lhs.a, rhs.a);
    const CM31 v1 = mul(lhs.b, rhs.b);
    const CM31 v2 = mul(add(lhs.a, lhs.b), add(rhs.a, rhs.b));
    return {add(v0, mul(kExtensionR, v1)), sub(v2, add(v0, v1))};
}

__host__ __device__ __forceinline__ QM31 mul(M31 lhs, QM31 rhs) {
    return {mul(lhs, rhs.a), mul(lhs, rhs.b)};
}

__host__ __device__ __forceinline__ QM31 square(QM31 value) {
    return mul(value, value);
}

__host__ __device__ __forceinline__ QM31 inverse(QM31 value) {
    const CM31 b_squared = mul(value.b, value.b);
    const CM31 rotated{neg(b_squared.b), b_squared.a};
    const CM31 denominator =
        sub(mul(value.a, value.a), add(add(b_squared, b_squared), rotated));
    const CM31 denominator_inverse = inverse(denominator);
    return {
        mul(value.a, denominator_inverse),
        neg(mul(value.b, denominator_inverse)),
    };
}

__host__ __device__ __forceinline__ SecureCirclePoint add_base(
    SecureCirclePoint lhs,
    CirclePoint rhs) {
    return {
        sub(mul(rhs.x, lhs.x), mul(rhs.y, lhs.y)),
        add(mul(rhs.y, lhs.x), mul(rhs.x, lhs.y)),
    };
}

__host__ __device__ __forceinline__ SecureCirclePoint double_point(
    SecureCirclePoint value) {
    return {
        sub(square(value.x), square(value.y)),
        add(mul(value.x, value.y), mul(value.x, value.y)),
    };
}

__host__ __device__ __forceinline__ CirclePoint point_mul(
    CirclePoint lhs,
    CirclePoint rhs) {
    return {
        sub(mul(lhs.x, rhs.x), mul(lhs.y, rhs.y)),
        add(mul(lhs.x, rhs.y), mul(lhs.y, rhs.x)),
    };
}

__host__ __device__ __forceinline__ CirclePoint point_pow(
    CirclePoint value,
    std::uint32_t exponent) {
    CirclePoint result{1u, 0u};
    while (exponent != 0) {
        if ((exponent & 1u) != 0) result = point_mul(value, result);
        value = point_mul(value, value);
        exponent >>= 1;
    }
    return result;
}

__host__ __device__ constexpr bool is_power_of_two(std::uint32_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
}

}  // namespace stwo::cuda::oods
