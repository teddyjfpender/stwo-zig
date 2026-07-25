// Exact mixed-height Blake scheduler, round, and XOR LogUp composition.
//
// The caller owns resident memory, transcript state, and synchronization.

#include <cstdint>

using u64 = unsigned long long;

constexpr std::uint32_t kPrime = 2147483647u;
constexpr std::uint32_t kComponents = 8u;
constexpr std::uint32_t kConstraints = 417u;
constexpr std::uint32_t kRelations = 14u;
constexpr std::uint32_t kClaims = 8u;
constexpr std::uint32_t kRounds = 10u;
constexpr std::uint32_t kRoundSources = 644u;
constexpr std::uint32_t kRoundMain = 384u;
constexpr std::uint32_t kInv16 = 1u << 15u;

struct Cm31 {
    std::uint32_t a;
    std::uint32_t b;
};

struct Qm31 {
    Cm31 a;
    Cm31 b;
};

struct Fu32 {
    Qm31 low;
    Qm31 high;
};

struct RelationEntry {
    Qm31 multiplicity;
    Qm31 denominator;
};

struct RelationBatch {
    Qm31 numerator;
    Qm31 denominator;
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

__device__ __forceinline__ Qm31 neg_qm31(Qm31 value) {
    return sub_qm31(zero_qm31(), value);
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

__device__ __forceinline__ void relation_append(
    Qm31 *result,
    Qm31 *power,
    Qm31 alpha,
    Qm31 value) {
    *result = add_qm31(*result, mul_qm31(*power, value));
    *power = mul_qm31(*power, alpha);
}

__device__ __forceinline__ Qm31 relation_three(
    const std::uint32_t *relations,
    std::uint32_t relation_index,
    Qm31 first,
    Qm31 second,
    Qm31 third) {
    const Qm31 z = load_qm31(relations, 2u * relation_index);
    const Qm31 alpha = load_qm31(relations, 2u * relation_index + 1u);
    Qm31 result = neg_qm31(z);
    Qm31 power = one_qm31();
    relation_append(&result, &power, alpha, first);
    relation_append(&result, &power, alpha, second);
    relation_append(&result, &power, alpha, third);
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

__device__ __forceinline__ RelationBatch pair_entries(
    RelationEntry first,
    RelationEntry second) {
    return {
        add_qm31(
            mul_qm31(first.multiplicity, second.denominator),
            mul_qm31(second.multiplicity, first.denominator)),
        mul_qm31(first.denominator, second.denominator),
    };
}

__device__ __forceinline__ RelationBatch single_entry(
    RelationEntry entry) {
    return {entry.multiplicity, entry.denominator};
}

__device__ __forceinline__ void add_weighted(
    Qm31 *combined,
    const std::uint32_t *powers,
    std::uint32_t power_start,
    std::uint32_t constraint_count,
    std::uint32_t constraint_index,
    Qm31 constraint) {
    const std::uint32_t power_index =
        power_start + constraint_count - 1u - constraint_index;
    *combined = add_qm31(
        *combined,
        mul_qm31(load_qm31(powers, power_index), constraint));
}

__device__ __forceinline__ Qm31 logup_constraint(
    RelationBatch batch,
    Qm31 current,
    Qm31 previous_column,
    Qm31 previous_row_last,
    Qm31 claimed_sum,
    std::uint32_t inverse_rows,
    bool last) {
    Qm31 difference = sub_qm31(current, previous_column);
    if (last) {
        difference = add_qm31(
            sub_qm31(difference, previous_row_last),
            mul_base(claimed_sum, inverse_rows));
    }
    return sub_qm31(
        mul_qm31(difference, batch.denominator),
        batch.numerator);
}

constexpr std::uint8_t kSigma[kRounds][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

__device__ __forceinline__ Qm31 scheduler_round_relation(
    const std::uint32_t *source,
    u64 stride,
    std::uint32_t row,
    const std::uint32_t *relations,
    std::uint32_t round) {
    const Qm31 z = load_qm31(relations, 2u);
    const Qm31 alpha = load_qm31(relations, 3u);
    Qm31 result = neg_qm31(z);
    Qm31 power = one_qm31();
    const std::uint32_t state_start = 32u + round * 32u;
    for (std::uint32_t column = 0u; column < 64u; ++column) {
        relation_append(
            &result,
            &power,
            alpha,
            from_base(load_source(
                source, stride, state_start + column, row)));
    }
    for (std::uint32_t word = 0u; word < 16u; ++word) {
        const std::uint32_t message = kSigma[round][word];
        relation_append(
            &result,
            &power,
            alpha,
            from_base(load_source(
                source, stride, 2u * message, row)));
        relation_append(
            &result,
            &power,
            alpha,
            from_base(load_source(
                source, stride, 2u * message + 1u, row)));
    }
    return result;
}

__device__ __forceinline__ Qm31 scheduler_blake_relation(
    const std::uint32_t *source,
    u64 stride,
    std::uint32_t row,
    const std::uint32_t *relations) {
    const Qm31 z = load_qm31(relations, 0u);
    const Qm31 alpha = load_qm31(relations, 1u);
    Qm31 result = neg_qm31(z);
    Qm31 power = one_qm31();
    for (std::uint32_t column = 32u; column < 64u; ++column) {
        relation_append(
            &result,
            &power,
            alpha,
            from_base(load_source(source, stride, column, row)));
    }
    for (std::uint32_t column = 352u; column < 384u; ++column) {
        relation_append(
            &result,
            &power,
            alpha,
            from_base(load_source(source, stride, column, row)));
    }
    for (std::uint32_t column = 0u; column < 32u; ++column) {
        relation_append(
            &result,
            &power,
            alpha,
            from_base(load_source(source, stride, column, row)));
    }
    return result;
}

__device__ __forceinline__ Qm31 evaluate_scheduler(
    const std::uint32_t *source,
    u64 stride,
    std::uint32_t row,
    std::uint32_t previous_row,
    const std::uint32_t *powers,
    const std::uint32_t *relations,
    const std::uint32_t *claims,
    std::uint32_t inverse_rows) {
    Qm31 combined = zero_qm31();
    Qm31 previous_column = zero_qm31();
    const Qm31 previous_row_last =
        load_secure_source(source, stride, 384u + 4u * 5u, previous_row);
    const Qm31 claim = load_qm31(claims, 0u);
    for (std::uint32_t batch = 0u; batch < 5u; ++batch) {
        const RelationEntry first = {
            one_qm31(),
            scheduler_round_relation(
                source, stride, row, relations, 2u * batch),
        };
        const RelationEntry second = {
            one_qm31(),
            scheduler_round_relation(
                source, stride, row, relations, 2u * batch + 1u),
        };
        const Qm31 current =
            load_secure_source(source, stride, 384u + 4u * batch, row);
        add_weighted(
            &combined,
            powers,
            411u,
            6u,
            batch,
            logup_constraint(
                pair_entries(first, second),
                current,
                previous_column,
                previous_row_last,
                claim,
                inverse_rows,
                false));
        previous_column = current;
    }
    const RelationBatch final_batch = single_entry({
        zero_qm31(),
        scheduler_blake_relation(source, stride, row, relations),
    });
    const Qm31 final_current =
        load_secure_source(source, stride, 384u + 4u * 5u, row);
    add_weighted(
        &combined,
        powers,
        411u,
        6u,
        5u,
        logup_constraint(
            final_batch,
            final_current,
            previous_column,
            previous_row_last,
            claim,
            inverse_rows,
            true));
    return combined;
}

struct RoundReader {
    const std::uint32_t *source;
    u64 stride;
    std::uint32_t row;
    const std::uint32_t *relations;
    const std::uint32_t *powers;
    std::uint32_t power_start;
    std::uint32_t main_index;
    std::uint32_t algebraic_index;
    std::uint32_t entry_count;
    RelationEntry pending;
    Qm31 previous_column;
    Qm31 previous_row_last;
    Qm31 claim;
    std::uint32_t inverse_rows;
    Qm31 combined;

    __device__ __forceinline__ Qm31 next() {
        return from_base(load_source(
            source, stride, main_index++, row));
    }

    __device__ __forceinline__ Fu32 next_u32() {
        return {next(), next()};
    }

    __device__ __forceinline__ void constraint(Qm31 value) {
        add_weighted(
            &combined,
            powers,
            power_start,
            129u,
            algebraic_index++,
            value);
    }

    __device__ __forceinline__ void emit_batch(
        RelationBatch batch,
        std::uint32_t batch_index,
        bool last) {
        const Qm31 current = load_secure_source(
            source, stride, kRoundMain + 4u * batch_index, row);
        add_weighted(
            &combined,
            powers,
            power_start,
            129u,
            64u + batch_index,
            logup_constraint(
                batch,
                current,
                previous_column,
                previous_row_last,
                claim,
                inverse_rows,
                last));
        previous_column = current;
    }

    __device__ __forceinline__ void entry(RelationEntry value) {
        if ((entry_count & 1u) == 0u) {
            pending = value;
        } else {
            emit_batch(
                pair_entries(pending, value),
                entry_count >> 1u,
                false);
        }
        ++entry_count;
    }

    __device__ __forceinline__ void flush_last_entry() {
        emit_batch(single_entry(pending), entry_count >> 1u, true);
    }

    __device__ __forceinline__ Fu32 add2(Fu32 lhs, Fu32 rhs) {
        const Qm31 low = next();
        const Qm31 high = next();
        const Qm31 carry_low = mul_base(
            sub_qm31(add_qm31(lhs.low, rhs.low), low),
            kInv16);
        constraint(mul_qm31(
            carry_low,
            sub_qm31(carry_low, one_qm31())));
        const Qm31 carry_high = mul_base(
            sub_qm31(
                add_qm31(add_qm31(lhs.high, rhs.high), carry_low),
                high),
            kInv16);
        constraint(mul_qm31(
            carry_high,
            sub_qm31(carry_high, one_qm31())));
        return {low, high};
    }

    __device__ __forceinline__ Fu32 add3(
        Fu32 lhs,
        Fu32 rhs,
        Fu32 third) {
        const Qm31 low = next();
        const Qm31 high = next();
        const Qm31 carry_low = mul_base(
            sub_qm31(
                add_qm31(add_qm31(lhs.low, rhs.low), third.low),
                low),
            kInv16);
        constraint(mul_qm31(
            mul_qm31(
                carry_low,
                sub_qm31(carry_low, one_qm31())),
            sub_qm31(carry_low, from_base(2u))));
        const Qm31 carry_high = mul_base(
            sub_qm31(
                add_qm31(
                    add_qm31(
                        add_qm31(lhs.high, rhs.high),
                        third.high),
                    carry_low),
                high),
            kInv16);
        constraint(mul_qm31(
            mul_qm31(
                carry_high,
                sub_qm31(carry_high, one_qm31())),
            sub_qm31(carry_high, from_base(2u))));
        return {low, high};
    }

    __device__ __forceinline__ void split(
        Qm31 value,
        std::uint32_t width,
        Qm31 *low,
        Qm31 *high) {
        *high = next();
        *low = sub_qm31(
            value,
            mul_base(*high, 1u << width));
    }

    __device__ __forceinline__ void xor2(
        std::uint32_t width,
        Qm31 a0,
        Qm31 a1,
        Qm31 b0,
        Qm31 b1,
        Qm31 *r0,
        Qm31 *r1) {
        *r0 = next();
        *r1 = next();
        const std::uint32_t relation_index =
            width == 12u ? 2u :
            width == 9u ? 3u :
            width == 8u ? 4u :
            width == 7u ? 5u : 6u;
        entry({
            one_qm31(),
            relation_three(relations, relation_index, a0, b0, *r0),
        });
        entry({
            one_qm31(),
            relation_three(relations, relation_index, a1, b1, *r1),
        });
    }

    __device__ __forceinline__ Fu32 xor_rotate(
        Fu32 lhs,
        Fu32 rhs,
        std::uint32_t width) {
        Qm31 al0, al1, ah0, ah1, bl0, bl1, bh0, bh1;
        split(lhs.low, width, &al0, &al1);
        split(lhs.high, width, &ah0, &ah1);
        split(rhs.low, width, &bl0, &bl1);
        split(rhs.high, width, &bh0, &bh1);
        Qm31 low0, low1, high0, high1;
        xor2(width, al0, ah0, bl0, bh0, &low0, &low1);
        const std::uint32_t high_width = 16u - width;
        xor2(high_width, al1, ah1, bl1, bh1, &high0, &high1);
        const std::uint32_t factor = 1u << high_width;
        return {
            add_qm31(mul_base(low1, factor), high0),
            add_qm31(mul_base(low0, factor), high1),
        };
    }

    __device__ __forceinline__ Fu32 xor_rotate16(
        Fu32 lhs,
        Fu32 rhs) {
        Qm31 al0, al1, ah0, ah1, bl0, bl1, bh0, bh1;
        split(lhs.low, 8u, &al0, &al1);
        split(lhs.high, 8u, &ah0, &ah1);
        split(rhs.low, 8u, &bl0, &bl1);
        split(rhs.high, 8u, &bh0, &bh1);
        Qm31 low0, low1, high0, high1;
        xor2(8u, al0, ah0, bl0, bh0, &low0, &low1);
        xor2(8u, al1, ah1, bl1, bh1, &high0, &high1);
        return {
            add_qm31(mul_base(high1, 256u), low1),
            add_qm31(mul_base(high0, 256u), low0),
        };
    }

    __device__ __forceinline__ void g(
        Fu32 *a,
        Fu32 *b,
        Fu32 *c,
        Fu32 *d,
        Fu32 message0,
        Fu32 message1) {
        *a = add3(*a, *b, message0);
        *d = xor_rotate16(*a, *d);
        *c = add2(*c, *d);
        *b = xor_rotate(*b, *c, 12u);
        *a = add3(*a, *b, message1);
        *d = xor_rotate(*a, *d, 8u);
        *c = add2(*c, *d);
        *b = xor_rotate(*b, *c, 7u);
    }
};

__device__ __forceinline__ Fu32 load_fu32_source(
    const std::uint32_t *source,
    u64 stride,
    std::uint32_t column,
    std::uint32_t row) {
    return {
        from_base(load_source(source, stride, column, row)),
        from_base(load_source(source, stride, column + 1u, row)),
    };
}

__device__ __forceinline__ void relation_append_word(
    Qm31 *result,
    Qm31 *power,
    Qm31 alpha,
    Fu32 word) {
    relation_append(result, power, alpha, word.low);
    relation_append(result, power, alpha, word.high);
}

__device__ __forceinline__ Qm31 evaluate_round(
    const std::uint32_t *source,
    u64 stride,
    std::uint32_t row,
    std::uint32_t previous_row,
    const std::uint32_t *powers,
    std::uint32_t power_start,
    const std::uint32_t *relations,
    const std::uint32_t *claims,
    std::uint32_t claim_index,
    std::uint32_t inverse_rows) {
    RoundReader reader = {
        source,
        stride,
        row,
        relations,
        powers,
        power_start,
        0u,
        0u,
        0u,
        {},
        zero_qm31(),
        load_secure_source(
            source, stride, kRoundMain + 4u * 64u, previous_row),
        load_qm31(claims, claim_index),
        inverse_rows,
        zero_qm31(),
    };
    Fu32 v0 = reader.next_u32();
    Fu32 v1 = reader.next_u32();
    Fu32 v2 = reader.next_u32();
    Fu32 v3 = reader.next_u32();
    Fu32 v4 = reader.next_u32();
    Fu32 v5 = reader.next_u32();
    Fu32 v6 = reader.next_u32();
    Fu32 v7 = reader.next_u32();
    Fu32 v8 = reader.next_u32();
    Fu32 v9 = reader.next_u32();
    Fu32 v10 = reader.next_u32();
    Fu32 v11 = reader.next_u32();
    Fu32 v12 = reader.next_u32();
    Fu32 v13 = reader.next_u32();
    Fu32 v14 = reader.next_u32();
    Fu32 v15 = reader.next_u32();
    reader.main_index = 64u;

    reader.g(
        &v0, &v4, &v8, &v12,
        load_fu32_source(source, stride, 32u, row),
        load_fu32_source(source, stride, 34u, row));
    reader.g(
        &v1, &v5, &v9, &v13,
        load_fu32_source(source, stride, 36u, row),
        load_fu32_source(source, stride, 38u, row));
    reader.g(
        &v2, &v6, &v10, &v14,
        load_fu32_source(source, stride, 40u, row),
        load_fu32_source(source, stride, 42u, row));
    reader.g(
        &v3, &v7, &v11, &v15,
        load_fu32_source(source, stride, 44u, row),
        load_fu32_source(source, stride, 46u, row));
    reader.g(
        &v0, &v5, &v10, &v15,
        load_fu32_source(source, stride, 48u, row),
        load_fu32_source(source, stride, 50u, row));
    reader.g(
        &v1, &v6, &v11, &v12,
        load_fu32_source(source, stride, 52u, row),
        load_fu32_source(source, stride, 54u, row));
    reader.g(
        &v2, &v7, &v8, &v13,
        load_fu32_source(source, stride, 56u, row),
        load_fu32_source(source, stride, 58u, row));
    reader.g(
        &v3, &v4, &v9, &v14,
        load_fu32_source(source, stride, 60u, row),
        load_fu32_source(source, stride, 62u, row));

    const Qm31 round_z = load_qm31(relations, 2u);
    const Qm31 round_alpha = load_qm31(relations, 3u);
    Qm31 round_relation = neg_qm31(round_z);
    Qm31 round_power = one_qm31();
    for (std::uint32_t column = 0u; column < 32u; column += 2u) {
        relation_append_word(
            &round_relation,
            &round_power,
            round_alpha,
            load_fu32_source(source, stride, column, row));
    }
    relation_append_word(&round_relation, &round_power, round_alpha, v0);
    relation_append_word(&round_relation, &round_power, round_alpha, v1);
    relation_append_word(&round_relation, &round_power, round_alpha, v2);
    relation_append_word(&round_relation, &round_power, round_alpha, v3);
    relation_append_word(&round_relation, &round_power, round_alpha, v4);
    relation_append_word(&round_relation, &round_power, round_alpha, v5);
    relation_append_word(&round_relation, &round_power, round_alpha, v6);
    relation_append_word(&round_relation, &round_power, round_alpha, v7);
    relation_append_word(&round_relation, &round_power, round_alpha, v8);
    relation_append_word(&round_relation, &round_power, round_alpha, v9);
    relation_append_word(&round_relation, &round_power, round_alpha, v10);
    relation_append_word(&round_relation, &round_power, round_alpha, v11);
    relation_append_word(&round_relation, &round_power, round_alpha, v12);
    relation_append_word(&round_relation, &round_power, round_alpha, v13);
    relation_append_word(&round_relation, &round_power, round_alpha, v14);
    relation_append_word(&round_relation, &round_power, round_alpha, v15);
    for (std::uint32_t column = 32u; column < 64u; column += 2u) {
        relation_append_word(
            &round_relation,
            &round_power,
            round_alpha,
            load_fu32_source(source, stride, column, row));
    }
    reader.entry({
        neg_qm31(one_qm31()),
        round_relation,
    });
    reader.flush_last_entry();
    return reader.combined;
}

__device__ __forceinline__ Qm31 evaluate_xor(
    const std::uint32_t *source,
    u64 stride,
    std::uint32_t row,
    std::uint32_t previous_row,
    const std::uint32_t *powers,
    const std::uint32_t *relations,
    const std::uint32_t *claims,
    std::uint32_t table_index,
    std::uint32_t inverse_rows) {
    constexpr std::uint32_t multiplicities[5] = {256u, 16u, 16u, 16u, 1u};
    constexpr std::uint32_t secure_columns[5] = {128u, 8u, 8u, 8u, 1u};
    constexpr std::uint32_t limb_bits[5] = {8u, 7u, 6u, 5u, 4u};
    constexpr std::uint32_t expand_bits[5] = {4u, 2u, 2u, 2u, 0u};
    constexpr std::uint32_t power_start[5] = {25u, 17u, 9u, 1u, 0u};
    const std::uint32_t count = multiplicities[table_index];
    const std::uint32_t batches_count = secure_columns[table_index];
    RelationEntry pending = {};
    Qm31 combined = zero_qm31();
    Qm31 previous_column = zero_qm31();
    const std::uint32_t interaction_start = 3u + count;
    const Qm31 previous_row_last = load_secure_source(
        source,
        stride,
        interaction_start + 4u * (batches_count - 1u),
        previous_row);
    const Qm31 claim = load_qm31(claims, 1u + table_index);
    for (std::uint32_t column = 0u; column < count; ++column) {
        const std::uint32_t expand = expand_bits[table_index];
        const std::uint32_t ah = column >> expand;
        const std::uint32_t bh =
            column & ((1u << expand) - 1u);
        const std::uint32_t shift = limb_bits[table_index];
        const RelationEntry entry = {
            neg_qm31(from_base(
                load_source(source, stride, 3u + column, row))),
            relation_three(
                relations,
                2u + table_index,
                add_qm31(
                    from_base(load_source(source, stride, 0u, row)),
                    from_base(ah << shift)),
                add_qm31(
                    from_base(load_source(source, stride, 1u, row)),
                    from_base(bh << shift)),
                add_qm31(
                    from_base(load_source(source, stride, 2u, row)),
                    from_base((ah ^ bh) << shift))),
        };
        if ((column & 1u) == 0u) {
            pending = entry;
        } else {
            const std::uint32_t batch = column >> 1u;
            const Qm31 current = load_secure_source(
                source, stride, interaction_start + 4u * batch, row);
            add_weighted(
                &combined,
                powers,
                power_start[table_index],
                batches_count,
                batch,
                logup_constraint(
                    pair_entries(pending, entry),
                    current,
                    previous_column,
                    previous_row_last,
                    claim,
                    inverse_rows,
                    batch + 1u == batches_count));
            previous_column = current;
        }
    }
    if ((count & 1u) != 0u) {
        const std::uint32_t batch = batches_count - 1u;
        const Qm31 current = load_secure_source(
            source, stride, interaction_start + 4u * batch, row);
        add_weighted(
            &combined,
            powers,
            power_start[table_index],
            batches_count,
            batch,
            logup_constraint(
                single_entry(pending),
                current,
                previous_column,
                previous_row_last,
                claim,
                inverse_rows,
                true));
        previous_column = current;
    }
    return combined;
}

__device__ __forceinline__ void store_lifted(
    std::uint32_t *coordinates,
    u64 stride,
    std::uint32_t local_row,
    std::uint32_t evaluation_log,
    std::uint32_t maximum_log,
    Qm31 value,
    bool initialize) {
    const std::uint32_t shift = maximum_log - evaluation_log;
    const std::uint32_t factor = 1u << shift;
    const std::uint32_t group = local_row >> 1u;
    const std::uint32_t parity = local_row & 1u;
    const std::uint32_t values[4] = {
        value.a.a, value.a.b, value.b.a, value.b.b,
    };
    for (std::uint32_t repeat = 0u; repeat < factor; ++repeat) {
        const std::uint32_t target =
            2u * (group * factor + repeat) + parity;
        for (std::uint32_t coordinate = 0u; coordinate < 4u; ++coordinate) {
            std::uint32_t *destination =
                coordinates + static_cast<u64>(coordinate) * stride + target;
            *destination = initialize
                ? values[coordinate]
                : add_m31(*destination, values[coordinate]);
        }
    }
}

extern "C" __global__ void __launch_bounds__(64)
stwo_native_constraint_blake_component_v1_64a336ee32f09d7e(
    const std::uint32_t *source_slab,
    u64 source_slab_words,
    u64 source_stride_words,
    const std::uint32_t *random_powers,
    u64 random_power_words,
    const std::uint32_t *denominator_inverses,
    u64 denominator_words,
    const std::uint32_t *relation_elements,
    u64 relation_words,
    const std::uint32_t *claimed_sums,
    u64 claimed_sum_words,
    std::uint32_t *coordinate_slab,
    u64 coordinate_slab_words,
    u64 coordinate_stride_words,
    std::uint32_t local_row_count,
    std::uint32_t trace_log_size,
    std::uint32_t evaluation_log_size,
    std::uint32_t maximum_evaluation_log_size,
    std::uint32_t component_index,
    std::uint32_t initialize_output) {
    const std::uint32_t row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= local_row_count ||
        component_index >= kComponents ||
        evaluation_log_size != trace_log_size + 1u ||
        evaluation_log_size > maximum_evaluation_log_size ||
        local_row_count != (1u << evaluation_log_size) ||
        source_stride_words != local_row_count ||
        random_power_words != 4ull * kConstraints ||
        denominator_words != 2ull ||
        relation_words != 4ull * kRelations ||
        claimed_sum_words != 4ull * kClaims ||
        coordinate_stride_words !=
            (1ull << maximum_evaluation_log_size) ||
        coordinate_slab_words != 4ull * coordinate_stride_words ||
        initialize_output != (component_index == 0u ? 1u : 0u)) {
        return;
    }

    constexpr std::uint32_t source_columns[8] = {
        408u, 644u, 644u, 771u, 51u, 51u, 51u, 8u,
    };
    if (source_slab_words !=
        source_stride_words * source_columns[component_index]) {
        return;
    }
    const std::uint32_t previous_row =
        previous_storage_row(row, evaluation_log_size);
    const std::uint32_t inverse_rows =
        1u << (31u - trace_log_size);
    Qm31 combined;
    if (component_index == 0u) {
        combined = evaluate_scheduler(
            source_slab,
            source_stride_words,
            row,
            previous_row,
            random_powers,
            relation_elements,
            claimed_sums,
            inverse_rows);
    } else if (component_index < 3u) {
        combined = evaluate_round(
            source_slab,
            source_stride_words,
            row,
            previous_row,
            random_powers,
            component_index == 1u ? 282u : 153u,
            relation_elements,
            claimed_sums,
            component_index == 1u ? 6u : 7u,
            inverse_rows);
    } else {
        combined = evaluate_xor(
            source_slab,
            source_stride_words,
            row,
            previous_row,
            random_powers,
            relation_elements,
            claimed_sums,
            component_index - 3u,
            inverse_rows);
    }
    combined = mul_base(
        combined,
        denominator_inverses[
            row >> trace_log_size]);
    store_lifted(
        coordinate_slab,
        coordinate_stride_words,
        row,
        evaluation_log_size,
        maximum_evaluation_log_size,
        combined,
        initialize_output != 0u);
}
