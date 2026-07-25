// Exact Plonk algebraic and two-column LogUp composition over one resident slab.
//
// The caller owns all memory, synchronization, and transcript state. This
// kernel evaluates the three canonical constraints without allocation,
// transfer, host callbacks, or fallback.

#include <cstdint>

using u64 = unsigned long long;

constexpr std::uint32_t kM31Prime = 2147483647u;

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
    const u64 sum = static_cast<u64>(lhs) + static_cast<u64>(rhs);
    return static_cast<std::uint32_t>(
        sum < kM31Prime ? sum : sum - kM31Prime);
}

__device__ __forceinline__ std::uint32_t sub_m31(
    std::uint32_t lhs,
    std::uint32_t rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + kM31Prime - rhs;
}

__device__ __forceinline__ std::uint32_t mul_m31(
    std::uint32_t lhs,
    std::uint32_t rhs) {
    const u64 value = static_cast<u64>(lhs) * static_cast<u64>(rhs);
    const u64 first = value + (value >> 31u);
    const u64 second = value + (first >> 31u);
    return static_cast<std::uint32_t>(second & kM31Prime);
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
    std::uint32_t first_column,
    std::uint32_t row) {
    return {
        {
            load_source(slab, stride, first_column, row),
            load_source(slab, stride, first_column + 1u, row),
        },
        {
            load_source(slab, stride, first_column + 2u, row),
            load_source(slab, stride, first_column + 3u, row),
        },
    };
}

__device__ __forceinline__ Qm31 combine_lookup(
    Qm31 z,
    Qm31 alpha,
    std::uint32_t wire,
    std::uint32_t value) {
    return sub_qm31(
        add_qm31(from_base(wire), mul_base(alpha, value)),
        z);
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

extern "C" __global__ void __launch_bounds__(128)
stwo_native_constraint_plonk_logup_slab_v1_1aeccc54c43f17c3(
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
        trace_log_size >= 30u) {
        return;
    }

    const u64 expected_rows = 1ull << (trace_log_size + 1u);
    const u64 required_source_words =
        15ull * source_stride_words + expected_rows;
    const u64 required_coordinate_words =
        3ull * coordinate_stride_words + expected_rows;
    const std::uint32_t expected_inverse_rows =
        trace_log_size == 0u ? 1u : 1u << (31u - trace_log_size);
    if (static_cast<u64>(row_count) != expected_rows ||
        source_stride_words < expected_rows ||
        required_source_words > source_slab_words ||
        random_power_words != 12ull ||
        denominator_words != 2ull ||
        lookup_words != 8ull ||
        claimed_sum_word_count != 4ull ||
        coordinate_stride_words < expected_rows ||
        required_coordinate_words > coordinate_slab_words ||
        inverse_rows != expected_inverse_rows) {
        return;
    }

    const std::uint32_t a_wire =
        load_source(source_slab, source_stride_words, 0u, row);
    const std::uint32_t b_wire =
        load_source(source_slab, source_stride_words, 1u, row);
    const std::uint32_t c_wire =
        load_source(source_slab, source_stride_words, 2u, row);
    const std::uint32_t op =
        load_source(source_slab, source_stride_words, 3u, row);
    const std::uint32_t multiplicity =
        load_source(source_slab, source_stride_words, 4u, row);
    const std::uint32_t a_value =
        load_source(source_slab, source_stride_words, 5u, row);
    const std::uint32_t b_value =
        load_source(source_slab, source_stride_words, 6u, row);
    const std::uint32_t c_value =
        load_source(source_slab, source_stride_words, 7u, row);

    const std::uint32_t algebraic = add_m31(
        sub_m31(
            c_value,
            mul_m31(op, add_m31(a_value, b_value))),
        mul_m31(
            sub_m31(1u, op),
            mul_m31(a_value, b_value)));

    const Qm31 z = load_qm31(lookup_elements, 0u);
    const Qm31 lookup_alpha = load_qm31(lookup_elements, 1u);
    const Qm31 q0 = combine_lookup(z, lookup_alpha, a_wire, a_value);
    const Qm31 q1 = combine_lookup(z, lookup_alpha, b_wire, b_value);
    const Qm31 first_sum =
        load_secure_source(source_slab, source_stride_words, 8u, row);
    const Qm31 first_logup = sub_qm31(
        mul_qm31(mul_qm31(first_sum, q0), q1),
        add_qm31(q0, q1));

    const Qm31 q2 = combine_lookup(z, lookup_alpha, c_wire, c_value);
    const Qm31 current =
        load_secure_source(source_slab, source_stride_words, 12u, row);
    const std::uint32_t previous_row =
        previous_storage_row(row, trace_log_size + 1u);
    const Qm31 previous = load_secure_source(
        source_slab,
        source_stride_words,
        12u,
        previous_row);
    const Qm31 shift =
        mul_base(load_qm31(claimed_sum_words, 0u), inverse_rows);
    const Qm31 final_logup = add_qm31(
        mul_qm31(
            add_qm31(
                sub_qm31(sub_qm31(current, previous), first_sum),
                shift),
            q2),
        from_base(multiplicity));

    Qm31 combined = mul_base(load_qm31(random_powers, 2u), algebraic);
    combined = add_qm31(
        combined,
        mul_qm31(load_qm31(random_powers, 1u), first_logup));
    combined = add_qm31(
        combined,
        mul_qm31(load_qm31(random_powers, 0u), final_logup));
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
