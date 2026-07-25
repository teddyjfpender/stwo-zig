// Exact mixed-height Blake paired LogUp fractions.
//
// This AOT authority writes only canonical paired numerators and denominators.
// The resident relation fraction-chain and circle-order tail own inversion,
// cumulative columns, claimed sums, shifting, and the final prefix scan.

#include "constraint_blake_3b9fbc925d6d3336.cu"

namespace {

constexpr std::uint32_t kInteractionBlock = 128u;
constexpr std::uint32_t kMainColumns[8] = {
    384u, 384u, 384u, 256u, 16u, 16u, 16u, 1u,
};
constexpr std::uint32_t kSecureColumns[8] = {
    6u, 65u, 65u, 128u, 8u, 8u, 8u, 1u,
};
constexpr std::uint32_t kFixedLogs[5] = {16u, 14u, 12u, 10u, 8u};

struct BaseFu32 {
  std::uint32_t low;
  std::uint32_t high;
};

__device__ __forceinline__ void store_fraction(
    std::uint32_t *output, Qm31 *denominators, u64 stride,
    std::uint32_t batch, std::uint32_t row, RelationBatch value) {
  const u64 output_column = 4ull * batch;
  output[(output_column + 0ull) * stride + row] = value.numerator.a.a;
  output[(output_column + 1ull) * stride + row] = value.numerator.a.b;
  output[(output_column + 2ull) * stride + row] = value.numerator.b.a;
  output[(output_column + 3ull) * stride + row] = value.numerator.b.b;
  denominators[static_cast<u64>(batch) * stride + row] = value.denominator;
}

__device__ __forceinline__ void generate_scheduler_fractions(
    const std::uint32_t *source, u64 stride, std::uint32_t row,
    const std::uint32_t *relations, std::uint32_t *output,
    Qm31 *denominators) {
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
    store_fraction(
        output, denominators, stride, batch, row,
        pair_entries(first, second));
  }
  store_fraction(
      output, denominators, stride, 5u, row,
      single_entry({
          zero_qm31(),
          scheduler_blake_relation(source, stride, row, relations),
      }));
}

struct InteractionRoundReader {
  const std::uint32_t *source;
  u64 stride;
  std::uint32_t row;
  const std::uint32_t *relations;
  std::uint32_t *output;
  Qm31 *denominators;
  std::uint32_t main_index;
  std::uint32_t batch_index;

  __device__ __forceinline__ BaseFu32 next_u32() {
    const std::uint32_t low =
        load_source(source, stride, main_index++, row);
    const std::uint32_t high =
        load_source(source, stride, main_index++, row);
    return {low, high};
  }

  __device__ __forceinline__ BaseFu32 add2() {
    return next_u32();
  }

  __device__ __forceinline__ BaseFu32 add3() {
    return next_u32();
  }

  __device__ __forceinline__ void split(
      std::uint32_t value, std::uint32_t width, std::uint32_t *low,
      std::uint32_t *high) {
    *high = load_source(source, stride, main_index++, row);
    *low = sub_m31(value, mul_m31(*high, 1u << width));
  }

  __device__ __forceinline__ void xor2(
      std::uint32_t width, std::uint32_t a0, std::uint32_t a1,
      std::uint32_t b0, std::uint32_t b1, std::uint32_t *r0,
      std::uint32_t *r1) {
    *r0 = load_source(source, stride, main_index++, row);
    *r1 = load_source(source, stride, main_index++, row);
    const std::uint32_t relation_index =
        width == 12u ? 2u :
        width == 9u ? 3u :
        width == 8u ? 4u :
        width == 7u ? 5u : 6u;
    store_fraction(
        output, denominators, stride, batch_index++, row,
        pair_entries(
            {
                one_qm31(),
                relation_three(
                    relations, relation_index, from_base(a0),
                    from_base(b0), from_base(*r0)),
            },
            {
                one_qm31(),
                relation_three(
                    relations, relation_index, from_base(a1),
                    from_base(b1), from_base(*r1)),
            }));
  }

  __device__ __forceinline__ BaseFu32 xor_rotate(
      BaseFu32 lhs, BaseFu32 rhs, std::uint32_t width) {
    std::uint32_t al0, al1, ah0, ah1, bl0, bl1, bh0, bh1;
    split(lhs.low, width, &al0, &al1);
    split(lhs.high, width, &ah0, &ah1);
    split(rhs.low, width, &bl0, &bl1);
    split(rhs.high, width, &bh0, &bh1);
    std::uint32_t low0, low1, high0, high1;
    xor2(width, al0, ah0, bl0, bh0, &low0, &low1);
    const std::uint32_t high_width = 16u - width;
    xor2(high_width, al1, ah1, bl1, bh1, &high0, &high1);
    const std::uint32_t factor = 1u << high_width;
    return {
        add_m31(mul_m31(low1, factor), high0),
        add_m31(mul_m31(low0, factor), high1),
    };
  }

  __device__ __forceinline__ BaseFu32 xor_rotate16(
      BaseFu32 lhs, BaseFu32 rhs) {
    std::uint32_t al0, al1, ah0, ah1, bl0, bl1, bh0, bh1;
    split(lhs.low, 8u, &al0, &al1);
    split(lhs.high, 8u, &ah0, &ah1);
    split(rhs.low, 8u, &bl0, &bl1);
    split(rhs.high, 8u, &bh0, &bh1);
    std::uint32_t low0, low1, high0, high1;
    xor2(8u, al0, ah0, bl0, bh0, &low0, &low1);
    xor2(8u, al1, ah1, bl1, bh1, &high0, &high1);
    return {
        add_m31(mul_m31(high1, 256u), low1),
        add_m31(mul_m31(high0, 256u), low0),
    };
  }

  __device__ __forceinline__ void g(
      BaseFu32 *a, BaseFu32 *b, BaseFu32 *c, BaseFu32 *d) {
    *a = add3();
    *d = xor_rotate16(*a, *d);
    *c = add2();
    *b = xor_rotate(*b, *c, 12u);
    *a = add3();
    *d = xor_rotate(*a, *d, 8u);
    *c = add2();
    *b = xor_rotate(*b, *c, 7u);
  }
};

__device__ __forceinline__ BaseFu32 load_base_fu32(
    const std::uint32_t *source, u64 stride, std::uint32_t first_column,
    std::uint32_t row) {
  return {
      load_source(source, stride, first_column, row),
      load_source(source, stride, first_column + 1u, row),
  };
}

__device__ __forceinline__ void generate_round_fractions(
    const std::uint32_t *source, u64 stride, std::uint32_t row,
    const std::uint32_t *relations, std::uint32_t *output,
    Qm31 *denominators) {
  InteractionRoundReader reader = {
      source, stride, row, relations, output, denominators, 64u, 0u,
  };
  BaseFu32 v0 = load_base_fu32(source, stride, 0u, row);
  BaseFu32 v1 = load_base_fu32(source, stride, 2u, row);
  BaseFu32 v2 = load_base_fu32(source, stride, 4u, row);
  BaseFu32 v3 = load_base_fu32(source, stride, 6u, row);
  BaseFu32 v4 = load_base_fu32(source, stride, 8u, row);
  BaseFu32 v5 = load_base_fu32(source, stride, 10u, row);
  BaseFu32 v6 = load_base_fu32(source, stride, 12u, row);
  BaseFu32 v7 = load_base_fu32(source, stride, 14u, row);
  BaseFu32 v8 = load_base_fu32(source, stride, 16u, row);
  BaseFu32 v9 = load_base_fu32(source, stride, 18u, row);
  BaseFu32 v10 = load_base_fu32(source, stride, 20u, row);
  BaseFu32 v11 = load_base_fu32(source, stride, 22u, row);
  BaseFu32 v12 = load_base_fu32(source, stride, 24u, row);
  BaseFu32 v13 = load_base_fu32(source, stride, 26u, row);
  BaseFu32 v14 = load_base_fu32(source, stride, 28u, row);
  BaseFu32 v15 = load_base_fu32(source, stride, 30u, row);
  reader.g(&v0, &v4, &v8, &v12);
  reader.g(&v1, &v5, &v9, &v13);
  reader.g(&v2, &v6, &v10, &v14);
  reader.g(&v3, &v7, &v11, &v15);
  reader.g(&v0, &v5, &v10, &v15);
  reader.g(&v1, &v6, &v11, &v12);
  reader.g(&v2, &v7, &v8, &v13);
  reader.g(&v3, &v4, &v9, &v14);

  const Qm31 z = load_qm31(relations, 2u);
  const Qm31 alpha = load_qm31(relations, 3u);
  Qm31 round_relation = neg_qm31(z);
  Qm31 power = one_qm31();
  for (std::uint32_t column = 0u; column < 32u; ++column) {
    relation_append(
        &round_relation, &power, alpha,
        from_base(load_source(source, stride, column, row)));
  }
  relation_append(
      &round_relation, &power, alpha, from_base(v0.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v0.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v1.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v1.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v2.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v2.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v3.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v3.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v4.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v4.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v5.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v5.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v6.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v6.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v7.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v7.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v8.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v8.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v9.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v9.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v10.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v10.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v11.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v11.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v12.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v12.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v13.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v13.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v14.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v14.high));
  relation_append(
      &round_relation, &power, alpha, from_base(v15.low));
  relation_append(
      &round_relation, &power, alpha, from_base(v15.high));
  for (std::uint32_t column = 32u; column < 64u; ++column) {
    relation_append(
        &round_relation, &power, alpha,
        from_base(load_source(source, stride, column, row)));
  }
  store_fraction(
      output, denominators, stride, reader.batch_index++, row,
      single_entry({
          neg_qm31(one_qm31()),
          round_relation,
      }));
}

__device__ __forceinline__ void generate_xor_fractions(
    const std::uint32_t *preprocessed, const std::uint32_t *main,
    u64 stride, std::uint32_t row, const std::uint32_t *relations,
    std::uint32_t *output, Qm31 *denominators,
    std::uint32_t table_index) {
  constexpr std::uint32_t multiplicities[5] = {
      256u, 16u, 16u, 16u, 1u,
  };
  constexpr std::uint32_t limb_bits[5] = {8u, 7u, 6u, 5u, 4u};
  constexpr std::uint32_t expand_bits[5] = {4u, 2u, 2u, 2u, 0u};
  const std::uint32_t count = multiplicities[table_index];
  RelationEntry pending = {};
  for (std::uint32_t column = 0u; column < count; ++column) {
    const std::uint32_t expand = expand_bits[table_index];
    const std::uint32_t ah = column >> expand;
    const std::uint32_t bh = column & ((1u << expand) - 1u);
    const std::uint32_t shift = limb_bits[table_index];
    const Qm31 first = add_qm31(
        from_base(load_source(preprocessed, stride, 0u, row)),
        from_base(ah << shift));
    const Qm31 second = add_qm31(
        from_base(load_source(preprocessed, stride, 1u, row)),
        from_base(bh << shift));
    const Qm31 third = add_qm31(
        from_base(load_source(preprocessed, stride, 2u, row)),
        from_base((ah ^ bh) << shift));
    const RelationEntry entry = {
        neg_qm31(from_base(load_source(main, stride, column, row))),
        relation_three(
            relations, 2u + table_index, first, second, third),
    };
    if ((column & 1u) == 0u) {
      pending = entry;
    } else {
      store_fraction(
          output, denominators, stride, column >> 1u, row,
          pair_entries(pending, entry));
    }
  }
  if ((count & 1u) != 0u) {
    store_fraction(
        output, denominators, stride, count >> 1u, row,
        single_entry(pending));
  }
}

__global__ void __launch_bounds__(kInteractionBlock)
stwo_native_interaction_blake_exact_pairs_v1(
    const std::uint32_t *main_source, u64 main_words,
    const std::uint32_t *preprocessed_source, u64 preprocessed_words,
    const std::uint32_t *relations, u64 relation_words,
    std::uint32_t *output, u64 output_words,
    std::uint32_t *denominator_words, u64 denominator_word_count,
    std::uint32_t component_index, std::uint32_t log_n_rows) {
  if (main_source == nullptr || relations == nullptr || output == nullptr ||
      denominator_words == nullptr || component_index >= 8u ||
      log_n_rows < 4u || log_n_rows > 13u || relation_words != 56ull) {
    return;
  }
  const std::uint32_t component_log =
      component_index == 0u ? log_n_rows :
      component_index == 1u ? log_n_rows + 3u :
      component_index == 2u ? log_n_rows + 1u :
      kFixedLogs[component_index - 3u];
  const u64 rows = 1ull << component_log;
  const bool is_xor = component_index >= 3u;
  if (main_words != rows * kMainColumns[component_index] ||
      output_words != rows * 4ull * kSecureColumns[component_index] ||
      denominator_word_count !=
          rows * 4ull * kSecureColumns[component_index] ||
      (is_xor && (preprocessed_source == nullptr ||
                  preprocessed_words != rows * 3ull)) ||
      (!is_xor && preprocessed_words != 0ull)) {
    return;
  }
  const std::uint32_t row =
      blockIdx.x * blockDim.x + threadIdx.x;
  if (row >= rows) return;
  Qm31 *denominators = reinterpret_cast<Qm31 *>(denominator_words);
  if (component_index == 0u) {
    generate_scheduler_fractions(
        main_source, rows, row, relations, output, denominators);
  } else if (component_index < 3u) {
    generate_round_fractions(
        main_source, rows, row, relations, output, denominators);
  } else {
    generate_xor_fractions(
        preprocessed_source, main_source, rows, row, relations, output,
        denominators, component_index - 3u);
  }
}

}  // namespace
