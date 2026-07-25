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

__device__ __forceinline__ Qm31 relation_value(
    const std::uint32_t *relations, std::uint32_t relation_index,
    const Qm31 *values, std::uint32_t count) {
  const Qm31 z = load_qm31(relations, 2u * relation_index);
  const Qm31 alpha = load_qm31(relations, 2u * relation_index + 1u);
  Qm31 result = neg_qm31(z);
  Qm31 power = one_qm31();
  for (std::uint32_t index = 0u; index < count; ++index) {
    relation_append(&result, &power, alpha, values[index]);
  }
  return result;
}

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

  __device__ __forceinline__ Qm31 next() {
    return from_base(load_source(source, stride, main_index++, row));
  }

  __device__ __forceinline__ Fu32 next_u32() {
    return {next(), next()};
  }

  __device__ __forceinline__ Fu32 add2(Fu32, Fu32) {
    return next_u32();
  }

  __device__ __forceinline__ Fu32 add3(Fu32, Fu32, Fu32) {
    return next_u32();
  }

  __device__ __forceinline__ void split(
      Qm31 value, std::uint32_t width, Qm31 *low, Qm31 *high) {
    *high = next();
    *low = sub_qm31(value, mul_base(*high, 1u << width));
  }

  __device__ __forceinline__ void xor2(
      std::uint32_t width, Qm31 a0, Qm31 a1, Qm31 b0, Qm31 b1,
      Qm31 *r0, Qm31 *r1) {
    *r0 = next();
    *r1 = next();
    const std::uint32_t relation_index =
        width == 12u ? 2u :
        width == 9u ? 3u :
        width == 8u ? 4u :
        width == 7u ? 5u : 6u;
    Qm31 first_values[3] = {a0, b0, *r0};
    Qm31 second_values[3] = {a1, b1, *r1};
    store_fraction(
        output, denominators, stride, batch_index++, row,
        pair_entries(
            {
                one_qm31(),
                relation_value(relations, relation_index, first_values, 3u),
            },
            {
                one_qm31(),
                relation_value(relations, relation_index, second_values, 3u),
            }));
  }

  __device__ __forceinline__ Fu32 xor_rotate(
      Fu32 lhs, Fu32 rhs, std::uint32_t width) {
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

  __device__ __forceinline__ Fu32 xor_rotate16(Fu32 lhs, Fu32 rhs) {
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
      Fu32 *state, std::uint32_t a, std::uint32_t b, std::uint32_t c,
      std::uint32_t d, Fu32 message0, Fu32 message1) {
    state[a] = add3(state[a], state[b], message0);
    state[d] = xor_rotate16(state[a], state[d]);
    state[c] = add2(state[c], state[d]);
    state[b] = xor_rotate(state[b], state[c], 12u);
    state[a] = add3(state[a], state[b], message1);
    state[d] = xor_rotate(state[a], state[d], 8u);
    state[c] = add2(state[c], state[d]);
    state[b] = xor_rotate(state[b], state[c], 7u);
  }
};

__device__ __forceinline__ void generate_round_fractions(
    const std::uint32_t *source, u64 stride, std::uint32_t row,
    const std::uint32_t *relations, std::uint32_t *output,
    Qm31 *denominators) {
  InteractionRoundReader reader = {
      source, stride, row, relations, output, denominators, 0u, 0u,
  };
  Fu32 state[16];
  Fu32 input_state[16];
  Fu32 message[16];
  for (std::uint32_t index = 0u; index < 16u; ++index) {
    state[index] = reader.next_u32();
    input_state[index] = state[index];
  }
  for (std::uint32_t index = 0u; index < 16u; ++index) {
    message[index] = reader.next_u32();
  }
  reader.g(state, 0, 4, 8, 12, message[0], message[1]);
  reader.g(state, 1, 5, 9, 13, message[2], message[3]);
  reader.g(state, 2, 6, 10, 14, message[4], message[5]);
  reader.g(state, 3, 7, 11, 15, message[6], message[7]);
  reader.g(state, 0, 5, 10, 15, message[8], message[9]);
  reader.g(state, 1, 6, 11, 12, message[10], message[11]);
  reader.g(state, 2, 7, 8, 13, message[12], message[13]);
  reader.g(state, 3, 4, 9, 14, message[14], message[15]);

  Qm31 tuple[96];
  std::uint32_t tuple_index = 0u;
  for (std::uint32_t index = 0u; index < 16u; ++index) {
    tuple[tuple_index++] = input_state[index].low;
    tuple[tuple_index++] = input_state[index].high;
  }
  for (std::uint32_t index = 0u; index < 16u; ++index) {
    tuple[tuple_index++] = state[index].low;
    tuple[tuple_index++] = state[index].high;
  }
  for (std::uint32_t index = 0u; index < 16u; ++index) {
    tuple[tuple_index++] = message[index].low;
    tuple[tuple_index++] = message[index].high;
  }
  store_fraction(
      output, denominators, stride, reader.batch_index++, row,
      single_entry({
          neg_qm31(one_qm31()),
          relation_value(relations, 1u, tuple, tuple_index),
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
    Qm31 tuple[3] = {
        add_qm31(
            from_base(load_source(preprocessed, stride, 0u, row)),
            from_base(ah << shift)),
        add_qm31(
            from_base(load_source(preprocessed, stride, 1u, row)),
            from_base(bh << shift)),
        add_qm31(
            from_base(load_source(preprocessed, stride, 2u, row)),
            from_base((ah ^ bh) << shift)),
    };
    const RelationEntry entry = {
        neg_qm31(from_base(load_source(main, stride, column, row))),
        relation_value(relations, 2u + table_index, tuple, 3u),
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
