#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace oods_reference {

using M31 = std::uint32_t;
struct CM31 { M31 a; M31 b; };
struct QM31 { CM31 a; CM31 b; };
struct CirclePoint { M31 x; M31 y; };
struct SecureCirclePoint { QM31 x; QM31 y; };

constexpr M31 prime = 2147483647u;
constexpr CM31 extension_r{2u, 1u};
constexpr CirclePoint circle_generator{2u, 1268011823u};

inline M31 add(M31 lhs, M31 rhs) {
    const std::uint64_t sum =
        static_cast<std::uint64_t>(lhs) + static_cast<std::uint64_t>(rhs);
    return static_cast<M31>(sum < prime ? sum : sum - prime);
}

inline M31 sub(M31 lhs, M31 rhs) { return add(lhs, prime - rhs); }
inline M31 neg(M31 value) { return value == 0 ? 0 : prime - value; }

inline M31 mul(M31 lhs, M31 rhs) {
    const std::uint64_t value =
        static_cast<std::uint64_t>(lhs) * static_cast<std::uint64_t>(rhs);
    const std::uint64_t first = value + (value >> 31);
    return static_cast<M31>((value + (first >> 31)) & prime);
}

inline M31 square(M31 value) { return mul(value, value); }

inline M31 pow2(M31 value, int count) {
    while (count-- > 0) value = square(value);
    return value;
}

inline M31 inverse(M31 value) {
    const M31 t0 = mul(pow2(value, 2), value);
    const M31 t1 = mul(pow2(t0, 1), t0);
    const M31 t2 = mul(pow2(t1, 3), t0);
    const M31 t3 = mul(pow2(t2, 1), t0);
    const M31 t4 = mul(pow2(t3, 8), t3);
    const M31 t5 = mul(pow2(t4, 8), t3);
    return mul(pow2(t5, 7), t2);
}

inline CM31 add(CM31 lhs, CM31 rhs) {
    return {add(lhs.a, rhs.a), add(lhs.b, rhs.b)};
}
inline CM31 sub(CM31 lhs, CM31 rhs) {
    return {sub(lhs.a, rhs.a), sub(lhs.b, rhs.b)};
}
inline CM31 neg(CM31 value) { return {neg(value.a), neg(value.b)}; }
inline CM31 mul(CM31 lhs, CM31 rhs) {
    return {
        sub(mul(lhs.a, rhs.a), mul(lhs.b, rhs.b)),
        add(mul(lhs.a, rhs.b), mul(lhs.b, rhs.a)),
    };
}
inline CM31 mul(M31 lhs, CM31 rhs) {
    return {mul(lhs, rhs.a), mul(lhs, rhs.b)};
}
inline CM31 inverse(CM31 value) {
    const M31 factor =
        inverse(add(mul(value.a, value.a), mul(value.b, value.b)));
    return {mul(value.a, factor), mul(neg(value.b), factor)};
}

inline QM31 zero() { return {{0u, 0u}, {0u, 0u}}; }
inline QM31 one() { return {{1u, 0u}, {0u, 0u}}; }
inline QM31 add(QM31 lhs, QM31 rhs) {
    return {add(lhs.a, rhs.a), add(lhs.b, rhs.b)};
}
inline QM31 add(M31 lhs, QM31 rhs) {
    return {{add(lhs, rhs.a.a), rhs.a.b}, rhs.b};
}
inline QM31 sub(QM31 lhs, QM31 rhs) {
    return {sub(lhs.a, rhs.a), sub(lhs.b, rhs.b)};
}
inline QM31 mul(QM31 lhs, QM31 rhs) {
    const CM31 v0 = mul(lhs.a, rhs.a);
    const CM31 v1 = mul(lhs.b, rhs.b);
    const CM31 v2 = mul(add(lhs.a, lhs.b), add(rhs.a, rhs.b));
    return {add(v0, mul(extension_r, v1)), sub(v2, add(v0, v1))};
}
inline QM31 mul(M31 lhs, QM31 rhs) {
    return {mul(lhs, rhs.a), mul(lhs, rhs.b)};
}
inline QM31 square(QM31 value) { return mul(value, value); }
inline QM31 inverse(QM31 value) {
    const CM31 b_squared = mul(value.b, value.b);
    const CM31 rotated{neg(b_squared.b), b_squared.a};
    const CM31 denominator =
        sub(mul(value.a, value.a), add(add(b_squared, b_squared), rotated));
    const CM31 factor = inverse(denominator);
    return {mul(value.a, factor), neg(mul(value.b, factor))};
}

inline bool equal(QM31 lhs, QM31 rhs) {
    return lhs.a.a == rhs.a.a && lhs.a.b == rhs.a.b &&
           lhs.b.a == rhs.b.a && lhs.b.b == rhs.b.b;
}

inline bool equal(SecureCirclePoint lhs, SecureCirclePoint rhs) {
    return equal(lhs.x, rhs.x) && equal(lhs.y, rhs.y);
}

inline SecureCirclePoint add_base(
    SecureCirclePoint lhs,
    CirclePoint rhs) {
    return {
        sub(mul(rhs.x, lhs.x), mul(rhs.y, lhs.y)),
        add(mul(rhs.y, lhs.x), mul(rhs.x, lhs.y)),
    };
}

inline SecureCirclePoint double_point(SecureCirclePoint value) {
    return {
        sub(square(value.x), square(value.y)),
        add(mul(value.x, value.y), mul(value.x, value.y)),
    };
}

inline CirclePoint point_mul(CirclePoint lhs, CirclePoint rhs) {
    return {
        sub(mul(lhs.x, rhs.x), mul(lhs.y, rhs.y)),
        add(mul(lhs.x, rhs.y), mul(lhs.y, rhs.x)),
    };
}

inline CirclePoint point_pow(CirclePoint value, std::uint32_t exponent) {
    CirclePoint result{1u, 0u};
    while (exponent != 0) {
        if ((exponent & 1u) != 0) result = point_mul(value, result);
        value = point_mul(value, value);
        exponent >>= 1;
    }
    return result;
}

inline std::uint32_t bit_reverse(
    std::uint32_t value,
    std::uint32_t bits) {
    std::uint32_t result = 0;
    for (std::uint32_t index = 0; index < bits; ++index) {
        result = (result << 1) | ((value >> index) & 1u);
    }
    return result;
}

inline CirclePoint domain_at_index(
    std::uint32_t initial,
    std::uint32_t step,
    std::uint32_t index,
    std::uint32_t size) {
    constexpr std::uint64_t order = 1ull << 31;
    const std::uint32_t half = size >> 1;
    std::uint64_t global;
    if (index < half) {
        global = static_cast<std::uint64_t>(initial) +
                 static_cast<std::uint64_t>(step) * index;
    } else {
        global = order -
                 (static_cast<std::uint64_t>(initial) +
                  static_cast<std::uint64_t>(step) * (index - half));
    }
    return point_pow(
        circle_generator,
        static_cast<std::uint32_t>(global & (order - 1)));
}

inline SecureCirclePoint derive_point(QM31 parameter, CirclePoint offset) {
    const QM31 parameter_squared = square(parameter);
    const QM31 denominator_inverse =
        inverse(add(one(), parameter_squared));
    return add_base(
        {
            mul(sub(one(), parameter_squared), denominator_inverse),
            mul(add(parameter, parameter), denominator_inverse),
        },
        offset);
}

inline std::vector<QM31> folding_factors(
    SecureCirclePoint point,
    std::uint32_t log_size) {
    std::vector<QM31> factors(log_size);
    factors[log_size - 1] = point.y;
    QM31 x = point.x;
    for (int index = static_cast<int>(log_size) - 2; index >= 0; --index) {
        factors[index] = x;
        x = sub(add(square(x), square(x)), one());
    }
    return factors;
}

inline QM31 evaluate(
    const std::vector<M31> &coefficients,
    const std::vector<QM31> &factors) {
    std::vector<QM31> level;
    level.reserve(coefficients.size());
    for (M31 coefficient : coefficients) level.push_back(add(coefficient, zero()));
    int factor = static_cast<int>(factors.size()) - 1;
    while (level.size() > 1) {
        std::vector<QM31> next(level.size() / 2);
        for (std::size_t index = 0; index < next.size(); ++index) {
            next[index] = add(
                level[2 * index],
                mul(level[2 * index + 1], factors[factor]));
        }
        level = std::move(next);
        --factor;
    }
    return level[0];
}

}  // namespace oods_reference
