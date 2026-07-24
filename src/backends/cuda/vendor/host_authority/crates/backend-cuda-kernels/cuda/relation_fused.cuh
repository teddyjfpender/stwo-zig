// Shared device helpers for the generated CommonLookupElements engine.
//
// Both relation lanes — the 3-stage pipeline in relation_graph.cu
// (pairs -> ragged batch inverse -> global fraction chain) and the fused
// single-kernel pipeline in relation_fused.cu — compute every tuple word,
// combine, multiplicity and per-column fraction through these exact
// functions, so the two lanes cannot drift. Do not fork these bodies.
//
// Geometry: both lanes dispatch off the same immutable 11-word per-instance
// geometry records documented in batch_inverse.cuh ([pair_first, pair_blocks,
// inverse_first, inverse_blocks, row_first, row_blocks, rows, columns,
// n_real, source_offset_rows, inverse_rows]). The fused kernel deliberately
// reuses the RELATION_ROW_FIRST/RELATION_ROW_BLOCKS row-tile dispatch of
// fraction_chain_global_kernel instead of defining a leaner table: the
// records are already resident, proven and shared with the tail kernels.

#ifndef RELATION_FUSED_CUH
#define RELATION_FUSED_CUH

#include <cstdint>

#include "batch_inverse.cuh"

constexpr uint32_t RELATION_LAUNCH_BLOCK = 256;
constexpr uint32_t RELATION_DESC_WORDS = 16;
constexpr uint32_t RELATION_USE_WORDS = 7;
constexpr uint32_t RELATION_LARGE_MEMORY_VALUE_ID_BASE = 0x40000000u;
constexpr uint32_t RELATION_XOR12_LIMB_BITS = 10;
constexpr uint32_t RELATION_XOR12_EXPAND_BITS = 2;
constexpr uint32_t RELATION_FUSED_NARROW_MAX_TUPLE_WORDS = 32;
// The one-read lane pads each bounded row tile to one 512-leaf Montgomery tree.
// Its shared SoA is numerator[512] + denominator[512] + tree[511].
constexpr uint32_t RELATION_FUSED_ONE_READ_FRACTIONS = 512;
constexpr uint32_t RELATION_FUSED_ONE_READ_TREE_NODES =
    RELATION_FUSED_ONE_READ_FRACTIONS - 1u;
constexpr uint32_t RELATION_FUSED_ONE_READ_SHARED_WORDS =
    4u * (RELATION_FUSED_ONE_READ_FRACTIONS * 2u +
          RELATION_FUSED_ONE_READ_TREE_NODES);
constexpr uint32_t RELATION_FUSED_ONE_READ_SHARED_BYTES =
    RELATION_FUSED_ONE_READ_SHARED_WORDS * sizeof(uint32_t);
static_assert(RELATION_FUSED_ONE_READ_FRACTIONS ==
                  2u * RELATION_LAUNCH_BLOCK,
              "one-read leaf initialization assumes two leaves/thread");
static_assert(RELATION_FUSED_ONE_READ_SHARED_BYTES == 24560u,
              "one-read shared-memory budget changed without resource review");

// Static per-instance eligibility for the fused lane, passed BY VALUE as a
// kernel parameter: 256 bits cover 256 instances without an arena slot, and
// the bits are baked into (captured) launch parameters, so the mask is
// capture-safe by construction. Hosts with more instances must fail closed
// to the 3-stage lane before launching.
constexpr uint32_t RELATION_FUSED_MASK_WORDS = 8;
constexpr uint32_t RELATION_FUSED_MAX_INSTANCES = RELATION_FUSED_MASK_WORDS * 32u;

struct relation_fused_mask {
  uint32_t bits[RELATION_FUSED_MASK_WORDS];
};

__device__ __forceinline__ bool relation_fused_mask_test(
    const relation_fused_mask &mask, uint32_t instance) {
  return ((mask.bits[(instance >> 5u) & (RELATION_FUSED_MASK_WORDS - 1u)] >>
           (instance & 31u)) &
          1u) != 0u;
}

__device__ __forceinline__ m31 relation_tuple_word(
    const uint32_t *const *sources, uint32_t n_rows, uint32_t row,
    uint32_t source_offset_rows, const uint32_t *use, uint32_t word) {
  uint32_t kind = use[0];
  uint32_t arg = use[1];
  if (word == 0) {
    return use[3];
  }
  if (kind == 0u) { // LookupWords.
    return sources[0][(arg + word) * n_rows + row];
  }
  if (kind == 7u) { // ProjectedColumns; relation id is descriptor word 3.
    return sources[arg + word - 1u][row];
  }
  if (kind == 8u) { // ProjectedColumnsNoId.
    return sources[arg + word][row];
  }
  if (kind == 1u) { // MemoryAddressChunk.
    if (word == 1) {
      return row + 1u + arg * n_rows;
    }
    return sources[arg * 2u][row];
  }
  if (kind == 2u || kind == 4u) { // Memory big/small limb pair.
    return sources[arg + word - 1u][row];
  }
  if (kind == 3u) { // Full big memory value.
    if (word == 1) {
      return (row + source_offset_rows) | RELATION_LARGE_MEMORY_VALUE_ID_BASE;
    }
    return sources[word - 2u][row];
  }
  if (kind == 5u) { // Full small memory value.
    if (word == 1) {
      return row + source_offset_rows;
    }
    return sources[word - 2u][row];
  }
  // BitwiseXor12: multiplicity-column index encodes high parts of a,b;
  // row encodes their two low 10-bit limbs.
  uint32_t ah = arg >> RELATION_XOR12_EXPAND_BITS;
  uint32_t bh = arg & ((1u << RELATION_XOR12_EXPAND_BITS) - 1u);
  uint32_t a = (ah << RELATION_XOR12_LIMB_BITS) | (row >> RELATION_XOR12_LIMB_BITS);
  uint32_t b = (bh << RELATION_XOR12_LIMB_BITS) |
               (row & ((1u << RELATION_XOR12_LIMB_BITS) - 1u));
  return word == 1 ? a : (word == 2 ? b : (a ^ b));
}

__device__ __forceinline__ qm31 relation_combine_use(
    const uint32_t *const *sources, uint32_t n_rows, uint32_t row,
    uint32_t source_offset_rows, const uint32_t *use, const qm31 *alphas,
    qm31 z) {
  qm31 zero = {{0, 0}, {0, 0}};
  qm31 acc = sub(zero, z);
  for (uint32_t word = 0; word < use[2]; ++word) {
    acc = add(acc, mul(relation_tuple_word(sources, n_rows, row,
                                           source_offset_rows, use, word),
                       alphas[word]));
  }
  return acc;
}

__device__ __forceinline__ m31 relation_multiplicity(
    const uint32_t *const *sources, uint32_t n_rows, uint32_t row,
    uint32_t n_real, const uint32_t *use) {
  uint32_t kind = use[4];
  uint32_t arg = use[5];
  m31 value;
  if (kind == 0u) {
    value = 1u;
  } else if (kind == 1u) {
    value = row < n_real ? 1u : 0u;
  } else if (kind == 2u) {
    value = sources[0][arg * n_rows + row];
  } else if (kind == 3u) {
    value = sources[arg * 2u + 1u][row];
  } else {
    // Big/small multiplicity and XOR12 all carry their source-column index.
    value = sources[arg][row];
  }
  return use[6] != 0u && value != 0u ? P - value : value;
}

// One column's fraction (numerator, denominator) at one row, including the
// arity-2 fold `(m_b*d_a + m_a*d_b) / (d_a*d_b)`. This is the single source
// of truth for both the pairs kernel (which materializes both values) and
// the fused kernel (which keeps them in registers).
__device__ __forceinline__ void relation_column_fraction(
    const uint32_t *const *sources, uint32_t n_rows, uint32_t row,
    uint32_t n_real, uint32_t source_offset_rows, const uint32_t *descriptor,
    const qm31 *alphas, qm31 z, qm31 *numerator, qm31 *denominator) {
  const uint32_t *use_a = descriptor + 1;
  qm31 denominator_a = relation_combine_use(sources, n_rows, row,
                                            source_offset_rows, use_a, alphas, z);
  m31 mult_a = relation_multiplicity(sources, n_rows, row, n_real, use_a);
  if (descriptor[0] == 2u) {
    const uint32_t *use_b = descriptor + 1 + RELATION_USE_WORDS;
    qm31 denominator_b = relation_combine_use(
        sources, n_rows, row, source_offset_rows, use_b, alphas, z);
    m31 mult_b = relation_multiplicity(sources, n_rows, row, n_real, use_b);
    *numerator = add(mul(mult_b, denominator_a), mul(mult_a, denominator_b));
    *denominator = mul(denominator_a, denominator_b);
  } else {
    *numerator = qm31{{mult_a, 0}, {0, 0}};
    *denominator = denominator_a;
  }
}

// Denominator-only variant for the fused kernel's second pass, which reloads
// its staged numerators from the committed output columns and therefore must
// not pay the multiplicity-column reads again.
__device__ __forceinline__ qm31 relation_column_denominator(
    const uint32_t *const *sources, uint32_t n_rows, uint32_t row,
    uint32_t source_offset_rows, const uint32_t *descriptor,
    const qm31 *alphas, qm31 z) {
  const uint32_t *use_a = descriptor + 1;
  qm31 denominator = relation_combine_use(sources, n_rows, row,
                                          source_offset_rows, use_a, alphas, z);
  if (descriptor[0] == 2u) {
    const uint32_t *use_b = descriptor + 1 + RELATION_USE_WORDS;
    denominator = mul(denominator,
                      relation_combine_use(sources, n_rows, row,
                                           source_offset_rows, use_b, alphas, z));
  }
  return denominator;
}

// Resolve `(instance, local_block)` from a proof-wide block index by binary
// search over the per-instance geometry records.
__device__ __forceinline__ uint32_t relation_instance_for_block(
    const uint32_t *geometry, uint32_t n_instances, uint32_t global_block,
    uint32_t first_word, uint32_t count_word, uint32_t *local_block) {
  uint32_t lo = 0u;
  uint32_t hi = n_instances;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2u;
    const uint32_t *g = geometry + mid * RELATION_GEOMETRY_WORDS;
    if (g[first_word] <= global_block) {
      lo = mid + 1u;
    } else {
      hi = mid;
    }
  }
  if (lo == 0u) {
    return n_instances;
  }
  uint32_t instance = lo - 1u;
  const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
  *local_block = global_block - g[first_word];
  return *local_block < g[count_word] ? instance : n_instances;
}

#endif // RELATION_FUSED_CUH
