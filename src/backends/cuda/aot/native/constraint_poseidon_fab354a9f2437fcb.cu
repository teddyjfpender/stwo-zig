// Exact Poseidon transition and eight-column LogUp composition.
//
// The caller owns resident memory, transcript state, and synchronization.

#include <cstdint>

using u64 = unsigned long long;

constexpr std::uint32_t kPrime = 2147483647u;
constexpr std::uint32_t kState = 16u;
constexpr std::uint32_t kRepetitions = 8u;
constexpr std::uint32_t kHalfRounds = 4u;
constexpr std::uint32_t kPartialRounds = 14u;
constexpr std::uint32_t kColumnsPerRep = 158u;
constexpr std::uint32_t kMainColumns = 1264u;
constexpr std::uint32_t kInteractionColumns = 32u;
constexpr std::uint32_t kSourceColumns = 1296u;
constexpr std::uint32_t kConstraints = 1144u;

struct Cm31 {
    std::uint32_t a;
    std::uint32_t b;
};

struct Qm31 {
    Cm31 a;
    Cm31 b;
};

__device__ __forceinline__ std::uint32_t add_m31(
    std::uint32_t lhs,
    std::uint32_t rhs) {
    const u64 sum = static_cast<u64>(lhs) + rhs;
    return static_cast<std::uint32_t>(
        sum < kPrime ? sum : sum - kPrime);
}

__device__ __forceinline__ std::uint32_t sub_m31(
    std::uint32_t lhs,
    std::uint32_t rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + kPrime - rhs;
}

__device__ __forceinline__ std::uint32_t mul_m31(
    std::uint32_t lhs,
    std::uint32_t rhs) {
    const u64 value = static_cast<u64>(lhs) * rhs;
    const u64 first = value + (value >> 31u);
    const u64 second = value + (first >> 31u);
    return static_cast<std::uint32_t>(second & kPrime);
}

__device__ __forceinline__ Cm31 add_cm31(Cm31 lhs, Cm31 rhs) {
    return {add_m31(lhs.a, rhs.a), add_m31(lhs.b, rhs.b)};
}

__device__ __forceinline__ Cm31 sub_cm31(Cm31 lhs, Cm31 rhs) {
    return {sub_m31(lhs.a, rhs.a), sub_m31(lhs.b, rhs.b)};
}

__device__ __forceinline__ Cm31 mul_cm31(Cm31 lhs, Cm31 rhs) {
    return {
        sub_m31(mul_m31(lhs.a, rhs.a), mul_m31(lhs.b, rhs.b)),
        add_m31(mul_m31(lhs.a, rhs.b), mul_m31(lhs.b, rhs.a)),
    };
}

__device__ __forceinline__ Qm31 zero_qm31() {
    return {{0u, 0u}, {0u, 0u}};
}

__device__ __forceinline__ Qm31 one_qm31() {
    return {{1u, 0u}, {0u, 0u}};
}

__device__ __forceinline__ Qm31 from_base(std::uint32_t value) {
    return {{value, 0u}, {0u, 0u}};
}

__device__ __forceinline__ Qm31 add_qm31(Qm31 lhs, Qm31 rhs) {
    return {add_cm31(lhs.a, rhs.a), add_cm31(lhs.b, rhs.b)};
}

__device__ __forceinline__ Qm31 sub_qm31(Qm31 lhs, Qm31 rhs) {
    return {sub_cm31(lhs.a, rhs.a), sub_cm31(lhs.b, rhs.b)};
}

__device__ __forceinline__ Qm31 mul_qm31(Qm31 lhs, Qm31 rhs) {
    const Cm31 v0 = mul_cm31(lhs.a, rhs.a);
    const Cm31 v1 = mul_cm31(lhs.b, rhs.b);
    const Cm31 v2 = mul_cm31(
        add_cm31(lhs.a, lhs.b),
        add_cm31(rhs.a, rhs.b));
    const Cm31 extension_v1 = {
        sub_m31(mul_m31(2u, v1.a), v1.b),
        add_m31(v1.a, mul_m31(2u, v1.b)),
    };
    return {
        add_cm31(v0, extension_v1),
        sub_cm31(v2, add_cm31(v0, v1)),
    };
}

__device__ __forceinline__ Qm31 mul_base(
    Qm31 value,
    std::uint32_t scalar) {
    return {
        {mul_m31(value.a.a, scalar), mul_m31(value.a.b, scalar)},
        {mul_m31(value.b.a, scalar), mul_m31(value.b.b, scalar)},
    };
}

__device__ __forceinline__ Qm31 pow5(Qm31 value) {
    const Qm31 square = mul_qm31(value, value);
    return mul_qm31(mul_qm31(square, square), value);
}

__device__ __forceinline__ Qm31 load_qm31(
    const std::uint32_t *words,
    u64 index) {
    const u64 base = 4ull * index;
    return {
        {words[base], words[base + 1ull]},
        {words[base + 2ull], words[base + 3ull]},
    };
}

__device__ __forceinline__ std::uint32_t load_source(
    const std::uint32_t *slab,
    u64 stride,
    std::uint32_t column,
    std::uint32_t row) {
    return slab[static_cast<u64>(column) * stride + row];
}

__device__ __forceinline__ Qm31 load_secure_source(
    const std::uint32_t *slab,
    u64 stride,
    std::uint32_t column,
    std::uint32_t row) {
    return {
        {
            load_source(slab, stride, column, row),
            load_source(slab, stride, column + 1u, row),
        },
        {
            load_source(slab, stride, column + 2u, row),
            load_source(slab, stride, column + 3u, row),
        },
    };
}

__device__ __forceinline__ void m4(Qm31 *x) {
    const Qm31 t0 = add_qm31(x[0], x[1]);
    const Qm31 t02 = add_qm31(t0, t0);
    const Qm31 t1 = add_qm31(x[2], x[3]);
    const Qm31 t12 = add_qm31(t1, t1);
    const Qm31 t2 = add_qm31(add_qm31(x[1], x[1]), t1);
    const Qm31 t3 = add_qm31(add_qm31(x[3], x[3]), t0);
    const Qm31 t4 = add_qm31(add_qm31(t12, t12), t3);
    const Qm31 t5 = add_qm31(add_qm31(t02, t02), t2);
    x[0] = add_qm31(t3, t5);
    x[1] = t5;
    x[2] = add_qm31(t2, t4);
    x[3] = t4;
}

__device__ __forceinline__ void external_matrix(Qm31 *state) {
    for (std::uint32_t group = 0u; group < 4u; ++group) {
        m4(state + group * 4u);
    }
    for (std::uint32_t lane = 0u; lane < 4u; ++lane) {
        Qm31 sum = state[lane];
        sum = add_qm31(sum, state[lane + 4u]);
        sum = add_qm31(sum, state[lane + 8u]);
        sum = add_qm31(sum, state[lane + 12u]);
        for (std::uint32_t group = 0u; group < 4u; ++group) {
            const std::uint32_t index = group * 4u + lane;
            state[index] = add_qm31(state[index], sum);
        }
    }
}

__device__ __forceinline__ void external_round(Qm31 *state) {
    for (std::uint32_t lane = 0u; lane < kState; ++lane) {
        state[lane] = add_qm31(state[lane], from_base(1234u));
    }
    external_matrix(state);
    for (std::uint32_t lane = 0u; lane < kState; ++lane) {
        state[lane] = pow5(state[lane]);
    }
}

__device__ __forceinline__ void internal_matrix(Qm31 *state) {
    Qm31 sum = state[0];
    for (std::uint32_t lane = 1u; lane < kState; ++lane) {
        sum = add_qm31(sum, state[lane]);
    }
    std::uint32_t coefficient = 2u;
    for (std::uint32_t lane = 0u; lane < kState; ++lane) {
        state[lane] = add_qm31(mul_base(state[lane], coefficient), sum);
        coefficient = add_m31(coefficient, coefficient);
    }
}

__device__ __forceinline__ Qm31 combine_lookup(
    const Qm31 *state,
    Qm31 z,
    Qm31 alpha) {
    Qm31 result = sub_qm31(zero_qm31(), z);
    Qm31 power = one_qm31();
    for (std::uint32_t lane = 0u; lane < kState; ++lane) {
        result = add_qm31(result, mul_qm31(power, state[lane]));
        power = mul_qm31(power, alpha);
    }
    return result;
}

__device__ __forceinline__ std::uint32_t reverse_bits(
    std::uint32_t value,
    std::uint32_t bits) {
    return bits == 0u ? value : __brev(value) >> (32u - bits);
}

__device__ __forceinline__ std::uint32_t previous_storage_row(
    std::uint32_t row,
    std::uint32_t evaluation_log_size) {
    const std::uint32_t half = 1u << (evaluation_log_size - 1u);
    std::uint32_t natural = reverse_bits(row, evaluation_log_size);
    if (natural < half) {
        natural = natural == 0u ? half - 1u : natural - 1u;
    } else {
        const std::uint32_t offset = natural - half;
        natural = half + (offset + 1u == half ? 0u : offset + 1u);
    }
    return reverse_bits(natural, evaluation_log_size);
}

__device__ __forceinline__ void add_constraint(
    Qm31 *combined,
    const std::uint32_t *powers,
    std::uint32_t index,
    Qm31 constraint) {
    *combined = add_qm31(
        *combined,
        mul_qm31(
            load_qm31(powers, kConstraints - 1u - index),
            constraint));
}

extern "C" __global__ void __launch_bounds__(64)
stwo_native_constraint_poseidon_slab_v1_2e0242737cfd5d1c(
    const std::uint32_t *source_slab,
    u64 source_slab_words,
    u64 source_stride_words,
    const std::uint32_t *random_powers,
    u64 random_power_words,
    const std::uint32_t *denominator_inverses,
    u64 denominator_words,
    const std::uint32_t *lookup_elements,
    u64 lookup_words,
    const std::uint32_t *claimed_sum_words,
    u64 claimed_sum_word_count,
    std::uint32_t *coordinate_slab,
    u64 coordinate_slab_words,
    u64 coordinate_stride_words,
    std::uint32_t row_count,
    std::uint32_t trace_log_size,
    std::uint32_t inverse_rows) {
    const std::uint32_t row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) return;
    if (source_slab == nullptr || random_powers == nullptr ||
        denominator_inverses == nullptr || lookup_elements == nullptr ||
        claimed_sum_words == nullptr || coordinate_slab == nullptr ||
        trace_log_size >= 29u) {
        return;
    }

    const u64 expected_rows = 1ull << (trace_log_size + 2u);
    const u64 required_source_words =
        (kSourceColumns - 1ull) * source_stride_words + expected_rows;
    const u64 required_coordinate_words =
        3ull * coordinate_stride_words + expected_rows;
    const std::uint32_t expected_inverse_rows =
        trace_log_size == 0u ? 1u : 1u << (31u - trace_log_size);
    if (static_cast<u64>(row_count) != expected_rows ||
        source_stride_words < expected_rows ||
        required_source_words > source_slab_words ||
        random_power_words != 4ull * kConstraints ||
        denominator_words != 4ull || lookup_words != 8ull ||
        claimed_sum_word_count != 4ull ||
        coordinate_stride_words < expected_rows ||
        required_coordinate_words > coordinate_slab_words ||
        inverse_rows != expected_inverse_rows) {
        return;
    }

    const Qm31 z = load_qm31(lookup_elements, 0u);
    const Qm31 alpha = load_qm31(lookup_elements, 1u);
    const Qm31 shift =
        mul_base(load_qm31(claimed_sum_words, 0u), inverse_rows);
    Qm31 combined = zero_qm31();
    Qm31 previous_column = zero_qm31();
    std::uint32_t constraint = 0u;
    std::uint32_t column = 0u;

    for (std::uint32_t rep = 0u; rep < kRepetitions; ++rep) {
        Qm31 state[kState];
        Qm31 initial[kState];
        for (std::uint32_t lane = 0u; lane < kState; ++lane) {
            state[lane] = from_base(load_source(
                source_slab, source_stride_words, column++, row));
            initial[lane] = state[lane];
        }
        for (std::uint32_t round = 0u; round < kHalfRounds; ++round) {
            external_round(state);
            for (std::uint32_t lane = 0u; lane < kState; ++lane) {
                const Qm31 stored = from_base(load_source(
                    source_slab, source_stride_words, column++, row));
                add_constraint(
                    &combined,
                    random_powers,
                    constraint++,
                    sub_qm31(state[lane], stored));
                state[lane] = stored;
            }
        }
        for (std::uint32_t round = 0u; round < kPartialRounds; ++round) {
            state[0] = add_qm31(state[0], from_base(1234u));
            internal_matrix(state);
            state[0] = pow5(state[0]);
            const Qm31 stored = from_base(load_source(
                source_slab, source_stride_words, column++, row));
            add_constraint(
                &combined,
                random_powers,
                constraint++,
                sub_qm31(state[0], stored));
            state[0] = stored;
        }
        for (std::uint32_t round = 0u; round < kHalfRounds; ++round) {
            external_round(state);
            for (std::uint32_t lane = 0u; lane < kState; ++lane) {
                const Qm31 stored = from_base(load_source(
                    source_slab, source_stride_words, column++, row));
                add_constraint(
                    &combined,
                    random_powers,
                    constraint++,
                    sub_qm31(state[lane], stored));
                state[lane] = stored;
            }
        }

        const Qm31 initial_denominator =
            combine_lookup(initial, z, alpha);
        const Qm31 final_denominator =
            combine_lookup(state, z, alpha);
        const Qm31 numerator =
            sub_qm31(final_denominator, initial_denominator);
        const Qm31 denominator =
            mul_qm31(initial_denominator, final_denominator);
        const Qm31 current = load_secure_source(
            source_slab,
            source_stride_words,
            kMainColumns + rep * 4u,
            row);
        Qm31 diff = sub_qm31(current, previous_column);
        if (rep + 1u == kRepetitions) {
            const std::uint32_t previous_row =
                previous_storage_row(row, trace_log_size + 2u);
            const Qm31 previous = load_secure_source(
                source_slab,
                source_stride_words,
                kMainColumns + rep * 4u,
                previous_row);
            diff = add_qm31(
                sub_qm31(sub_qm31(current, previous), previous_column),
                shift);
        }
        add_constraint(
            &combined,
            random_powers,
            constraint++,
            sub_qm31(mul_qm31(diff, denominator), numerator));
        previous_column = current;
    }

    if (column != kMainColumns || constraint != kConstraints) return;
    combined = mul_base(
        combined,
        denominator_inverses[row >> trace_log_size]);
    coordinate_slab[row] =
        add_m31(coordinate_slab[row], combined.a.a);
    coordinate_slab[coordinate_stride_words + row] = add_m31(
        coordinate_slab[coordinate_stride_words + row],
        combined.a.b);
    coordinate_slab[2ull * coordinate_stride_words + row] = add_m31(
        coordinate_slab[2ull * coordinate_stride_words + row],
        combined.b.a);
    coordinate_slab[3ull * coordinate_stride_words + row] = add_m31(
        coordinate_slab[3ull * coordinate_stride_words + row],
        combined.b.b);
}
