#include "custody.cuh"
#include "deep_lazy.cuh"
#include "om31.cuh"
#include <cstdlib>
#include <cstring>
#include "samples.h"
namespace stwo::cuda::rv64 {
constexpr uint32_t sample_threads = 128, sample_tile = 1024, factor_stride = 28;
__device__ void sample_put(uint32_t *words, OM31 value) {
  for (uint32_t i = 0; i < 8; ++i)
    words[i] = coordinate(value, i);
}
__global__ void sample_base(StwoRv64SamplePoints j) {
  *j.ready = 0;
  sample_put(j.points, zero());
  sample_put(j.points + 8, zero());
  const OM31 t = from_words(j.parameter);
  if (!canonical(t)) {
    atomicOr(j.status, 2u);
    return;
  }
  if (atomicOr(j.status, 0u))
    return;
  const OM31 t2 = mul(t, t), denominator = add(one(), t2);
  if (is_zero(denominator)) {
    atomicOr(j.status, 4u);
    return;
  }
  const OM31 reciprocal = inverse_nonzero(denominator);
  sample_put(j.points, mul(sub(one(), t2), reciprocal));
  sample_put(j.points + 8, mul(add(t, t), reciprocal));
  *j.ready = 1;
}
__global__ void sample_base_from_point(StwoRv64SamplePoints j) {
  *j.ready = 0;
  sample_put(j.points, zero());
  sample_put(j.points + 8, zero());
  const OM31 x = from_words(j.parameter), y = from_words(j.parameter + 8);
  if (!canonical(x) || !canonical(y)) {
    atomicOr(j.status, 2u);
    return;
  }
  if (atomicOr(j.status, 0u))
    return;
  if (!is_zero(sub(add(mul(x, x), mul(y, y)), one()))) {
    atomicOr(j.status, 4u);
    return;
  }
  sample_put(j.points, x);
  sample_put(j.points + 8, y);
  *j.ready = 1;
}
__global__ void sample_points(StwoRv64SamplePoints j) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= j.count)
    return;
  j.ready[i + 1] = 0;
  uint32_t *output = j.points + uint64_t(i + 1) * 16;
  sample_put(output, zero());
  sample_put(output + 8, zero());
  for (uint32_t k = 0; k < factor_stride; ++k)
    sample_put(j.factors + (uint64_t(i) * factor_stride + k) * 8, zero());
  if (!j.ready[0])
    return;
  const auto recipe = j.recipes[i];
  if (recipe.offset_x >= q::kPrime || recipe.offset_y >= q::kPrime ||
      !recipe.coefficient_log || recipe.coefficient_log > 28 ||
      recipe.folds > 28) {
    atomicOr(j.status, 2u);
    return;
  }
  if (q::add(q::mul(recipe.offset_x, recipe.offset_x),
             q::mul(recipe.offset_y, recipe.offset_y)) != 1) {
    atomicOr(j.status, 4u);
    return;
  }
  const OM31 bx = from_words(j.points), by = from_words(j.points + 8);
  OM31 x = sub(scale(bx, recipe.offset_x), scale(by, recipe.offset_y));
  OM31 y = add(scale(bx, recipe.offset_y), scale(by, recipe.offset_x));
  sample_put(output, x);
  sample_put(output + 8, y);
  for (uint32_t k = 0; k < recipe.folds; ++k) {
    const OM31 xy = mul(x, y);
    const OM31 square = mul(x, x);
    x = sub(add(square, square), one());
    y = add(xy, xy);
  }
  uint32_t *factors = j.factors + uint64_t(i) * factor_stride * 8;
  sample_put(factors, y);
  for (uint32_t k = 1; k < recipe.coefficient_log; ++k) {
    sample_put(factors + k * 8, x);
    const OM31 square = mul(x, x);
    x = sub(add(square, square), one());
  }
  j.ready[i + 1] = 1;
}
__global__ void sample_validate(StwoRv64SampleEvaluation j) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= j.count)
    return;
  j.valid[i] = 0;
  sample_put(j.values + uint64_t(j.first + i) * 8, zero());
  const auto term = j.terms[j.first + i];
  if (term.reserved || term.source >= j.source_count ||
      term.group >= j.group_count) {
    atomicOr(j.status, 1u);
    return;
  }
  const auto source = j.sources[term.source];
  const uint64_t n = uint64_t(1) << j.coefficient_log;
  if (source.tree >= 4 || source.coefficient_log != j.coefficient_log ||
      source.offset > j.tree_words[source.tree] ||
      n > j.tree_words[source.tree] - source.offset ||
      j.recipes[term.group].coefficient_log != j.coefficient_log) {
    atomicOr(j.status, 1u);
    return;
  }
  if (j.point_ready[0] != 1 || j.point_ready[term.group + 1] != 1) {
    atomicOr(j.status, 4u);
    return;
  }
  for (uint32_t k = 0; k < j.coefficient_log; ++k)
    if (!canonical(from_words(
            j.factors + (uint64_t(term.group) * factor_stride + k) * 8))) {
      atomicOr(j.status, 2u);
      return;
    }
  j.valid[i] = 1;
}
__device__ OM31 sample_tile_value(const uint32_t *source, uint32_t base_index,
                                  uint32_t count, const uint32_t *factors,
                                  uint32_t *status) {
  uint32_t v[8];
#pragma unroll
  for (uint32_t i = 0; i < 8; ++i) {
    v[i] = base_index + i < count ? source[base_index + i] : 0;
    if (v[i] >= q::kPrime) {
      atomicOr(status, 2u);
      v[i] = 0;
    }
  }
  const OM31 y = from_words(factors), x = from_words(factors + 8),
             xx = from_words(factors + 16);
  const OM31 a = add(base(v[0]), scale(y, v[1])),
             b = add(base(v[2]), scale(y, v[3]));
  const OM31 c = add(base(v[4]), scale(y, v[5])),
             d = add(base(v[6]), scale(y, v[7]));
  return add(add(a, mul(b, x)), mul(add(c, mul(d, x)), xx));
}
__global__ void sample_first(StwoRv64SampleEvaluation j, uint32_t blocks) {
  __shared__ OM31 shared[sample_threads];
  const uint32_t sample = blockIdx.y, lane = threadIdx.x;
  const uint32_t n = 1u << j.coefficient_log,
                 start = blockIdx.x * sample_tile + lane * 8;
  if (!j.valid[sample]) {
    if (!lane)
      sample_put(j.scratch_a + (uint64_t(sample) * blocks + blockIdx.x) * 8,
                 zero());
    return;
  }
  const auto term = j.terms[j.first + sample];
  const auto source = j.sources[term.source];
  const uint32_t *factors =
      j.factors + uint64_t(term.group) * factor_stride * 8;
  const uint32_t active = min(sample_threads, max(1u, n / 8));
  shared[lane] = lane < active
                     ? sample_tile_value(j.trees[source.tree] + source.offset,
                                         start, n, factors, j.status)
                     : zero();
  uint32_t consumed = 3;
  for (uint32_t width = active / 2; width; width >>= 1, ++consumed) {
    __syncthreads();
    OM31 left = zero(), right = zero();
    if (lane < width) {
      left = shared[lane * 2];
      right = shared[lane * 2 + 1];
    }
    __syncthreads();
    if (lane < width)
      shared[lane] = add(left, mul(right, from_words(factors + consumed * 8)));
  }
  if (!lane)
    sample_put(j.scratch_a + (uint64_t(sample) * blocks + blockIdx.x) * 8,
               shared[0]);
}
__global__ void sample_reduce(StwoRv64SampleEvaluation j, const uint32_t *input,
                              uint32_t input_count, uint32_t consumed,
                              uint32_t *output, uint32_t output_count) {
  __shared__ OM31 shared[sample_threads * 2];
  const uint32_t sample = blockIdx.y, lane = threadIdx.x;
  const uint32_t start = blockIdx.x * sample_threads * 2;
  // Invalid samples were zeroed by sample_first. Do not dereference their
  // descriptors at later levels, including on the zero-only reduction path.
  const bool valid = j.valid[sample];
  const uint32_t group = valid ? j.terms[j.first + sample].group : 0;
  const uint32_t *factors = j.factors + uint64_t(group) * factor_stride * 8;
  const uint32_t *in = input + uint64_t(sample) * input_count * 8;
  shared[lane] = start + lane < input_count
                     ? from_words(in + uint64_t(start + lane) * 8)
                     : zero();
  shared[lane + sample_threads] =
      start + lane + sample_threads < input_count
          ? from_words(in + uint64_t(start + lane + sample_threads) * 8)
          : zero();
  __syncthreads();
  for (uint32_t width = min(input_count, sample_threads * 2) / 2; width;
       width >>= 1, ++consumed) {
    OM31 left = zero(), right = zero();
    if (lane < width) {
      left = shared[lane * 2];
      right = shared[lane * 2 + 1];
    }
    __syncthreads();
    if (lane < width)
      shared[lane] =
          valid ? add(left, mul(right, from_words(factors + consumed * 8)))
                : zero();
    __syncthreads();
  }
  if (!lane)
    sample_put(output + (uint64_t(sample) * output_count + blockIdx.x) * 8,
               shared[0]);
}
__global__ void sample_store(StwoRv64SampleEvaluation j,
                             const uint32_t *input) {
  const uint32_t sample = blockIdx.x * blockDim.x + threadIdx.x;
  if (sample >= j.count)
    return;
  sample_put(j.values + uint64_t(j.first + sample) * 8,
             j.valid[sample] ? from_words(input + uint64_t(sample) * 8)
                             : zero());
}
// ---------------------------------------------------------------------------
// M8 T3: sample_first as a dot product against a shared tile basis.
// sample_first evaluates sum_j c_j prod_{k<10, bit k of j} f_k over each
// 1024-coefficient tile with a per-sample OM31 tree. The tile basis
// L_j = prod_{k<10, bit k of j} f_k depends only on the group's factors, so
// it is built once per launch (sample_basis, into scratch_b, which the
// reduction does not touch until sample_first has finished) and every sample
// becomes 8 lazily-reduced base x OM31 products per coefficient. The tile
// partial is the same field element, so scratch_a, the reduction and the
// sample values are bit-identical. A sample whose group differs from the
// basis group (never produced by the PCS planner, still legal in the ABI)
// recomputes its weights from its own factors.
// Samples per CTA (the basis registers are reused that many times).
// [M] A/B (deep_t3_parity_bench, 5090, 7 reps, median ms; chunk 4/8/16/32):
//   2^22 x 72: 1.119 / 0.990 / 0.912 / 0.848
//   2^18 x 72: 0.094 / 0.084 / 0.079 / 0.085
//   2^14 x 200: 0.040 / 0.040 / 0.042 / 0.048
// => 32 from 1024 tiles (2^20 coefficients) up, 16 below.
constexpr uint32_t sample_chunk_small = 16, sample_chunk_large = 32,
                   sample_chunk_large_tiles = 1024;
constexpr uint32_t sample_fast_threads = 256, sample_fast_slots = 4,
                   sample_basis_words = sample_tile * 8,
                   sample_basis_none = 0xffffffffu;
static_assert(sample_fast_threads * sample_fast_slots == sample_tile,
              "tile basis covers one sample_first tile");
__device__ __forceinline__ uint32_t sample_basis_bits(uint32_t coefficient_log) {
  return min(10u, coefficient_log);
}
__global__ __launch_bounds__(512) void sample_basis(StwoRv64SampleEvaluation j,
                                                    uint32_t *basis) {
  __shared__ OM31 table[sample_tile];
  __shared__ uint32_t group;
  const uint32_t lane = threadIdx.x;
  if (!lane) {
    group = sample_basis_none;
    for (uint32_t i = 0; i < j.count; ++i)
      if (j.valid[i]) {
        group = j.terms[j.first + i].group;
        break;
      }
    basis[sample_basis_words] = group;
  }
  __syncthreads();
  if (group == sample_basis_none) return;
  const uint32_t *factors = j.factors + uint64_t(group) * factor_stride * 8;
  const uint32_t bits = sample_basis_bits(j.coefficient_log);
  if (!lane) table[0] = one();
  for (uint32_t k = 0; k < bits; ++k) {
    __syncthreads();
    const OM31 f = from_words(factors + k * 8);
    for (uint32_t i = lane; i < (1u << k); i += blockDim.x)
      table[i + (1u << k)] = mul(table[i], f);
  }
  __syncthreads();
  for (uint32_t i = lane; i < (1u << bits) * 8; i += blockDim.x)
    basis[i] = coordinate(table[i / 8], i % 8);
}
__device__ OM31 sample_weight(const uint32_t *factors, uint32_t index,
                              uint32_t bits) {
  OM31 w = one();
  for (uint32_t k = 0; k < bits; ++k)
    if (index >> k & 1u) w = mul(w, from_words(factors + k * 8));
  return w;
}
// Eight canonical coordinates per lane -> warp sum. Butterfly transpose:
// 4+2+1 exchanges split the coordinates, 2 more finish the sum. Lane l ends
// with coordinate ((l>>4)&1)*4 + ((l>>3)&1)*2 + ((l>>2)&1).
__device__ __forceinline__ uint32_t sample_warp_sum8(const uint32_t (&v)[8],
                                                     uint32_t lane) {
  const bool h16 = lane & 16u, h8 = lane & 8u, h4 = lane & 4u;
  uint32_t w4[4], w2[2];
#pragma unroll
  for (uint32_t i = 0; i < 4; ++i) {
    const uint32_t send = h16 ? v[i] : v[i + 4], keep = h16 ? v[i + 4] : v[i];
    w4[i] = q::add(keep, __shfl_xor_sync(0xffffffffu, send, 16));
  }
#pragma unroll
  for (uint32_t i = 0; i < 2; ++i) {
    const uint32_t send = h8 ? w4[i] : w4[i + 2], keep = h8 ? w4[i + 2] : w4[i];
    w2[i] = q::add(keep, __shfl_xor_sync(0xffffffffu, send, 8));
  }
  const uint32_t send = h4 ? w2[0] : w2[1], keep = h4 ? w2[1] : w2[0];
  uint32_t w = q::add(keep, __shfl_xor_sync(0xffffffffu, send, 4));
  w = q::add(w, __shfl_xor_sync(0xffffffffu, w, 2));
  return q::add(w, __shfl_xor_sync(0xffffffffu, w, 1));
}
// [M] A/B (deep_t3_parity_bench, 5090, 2^22 coefficients x 72 samples, 7
// reps, median): min blocks 1 (140 regs) 1.460 ms, 2 (128 regs) 0.914 ms.
// Legacy sample_first tree: 3.102 ms.
#ifndef STWO_RV64_SAMPLE_MIN_BLOCKS
#define STWO_RV64_SAMPLE_MIN_BLOCKS 2
#endif
template <uint32_t sample_fast_chunk>
__global__ __launch_bounds__(sample_fast_threads, STWO_RV64_SAMPLE_MIN_BLOCKS) void sample_first_basis(
    StwoRv64SampleEvaluation j, uint32_t blocks, const uint32_t *basis) {
  constexpr uint32_t warps = sample_fast_threads / 32;
  __shared__ uint32_t partial[sample_fast_chunk][warps][8];
  const uint32_t lane = threadIdx.x, tile = blockIdx.x,
                 first_sample = blockIdx.y * sample_fast_chunk;
  const uint32_t n = 1u << j.coefficient_log, bits = sample_basis_bits(j.coefficient_log);
  const uint32_t limit = min(n, sample_tile), base_index = tile * sample_tile;
  const uint32_t basis_group = basis[sample_basis_words];
  uint32_t weights[sample_fast_slots][8];
#pragma unroll
  for (uint32_t r = 0; r < sample_fast_slots; ++r) {
    const uint32_t index = lane + r * sample_fast_threads;
#pragma unroll
    for (uint32_t k = 0; k < 8; ++k)
      weights[r][k] = basis_group != sample_basis_none && index < limit
                          ? basis[index * 8 + k]
                          : 0u;
  }
  bool bad = false;
  const uint32_t chunk = min(sample_fast_chunk, j.count - first_sample);
  for (uint32_t s = 0; s < chunk; ++s) {
    const uint32_t sample = first_sample + s;
    // Invalid samples were zeroed by sample_validate; never dereference
    // their descriptors (sample_first writes their tile partial as zero).
    if (!j.valid[sample]) continue;
    const auto term = j.terms[j.first + sample];
    const auto source = j.sources[term.source];
    const uint32_t *column = j.trees[source.tree] + source.offset + base_index;
    uint64_t acc[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    if (term.group == basis_group) {
#pragma unroll
      for (uint32_t r = 0; r < sample_fast_slots; ++r) {
        const uint32_t index = lane + r * sample_fast_threads;
        uint32_t c = index < limit ? column[index] : 0u;
        if (c >= q::kPrime) {
          bad = true;
          c = 0;
        }
#pragma unroll
        for (uint32_t k = 0; k < 8; ++k) acc[k] = lazy::mac(acc[k], weights[r][k], c);
      }
    } else {
      const uint32_t *factors =
          j.factors + uint64_t(term.group) * factor_stride * 8;
      for (uint32_t r = 0; r < sample_fast_slots; ++r) {
        const uint32_t index = lane + r * sample_fast_threads;
        if (index >= limit) continue;
        uint32_t c = column[index];
        if (c >= q::kPrime) {
          bad = true;
          c = 0;
        }
        const OM31 w = sample_weight(factors, index, bits);
        for (uint32_t k = 0; k < 8; ++k)
          acc[k] = lazy::mac(acc[k], coordinate(w, k), c);
      }
    }
    // Four products below 2^62 each: acc < 2^64.
    uint32_t v[8];
#pragma unroll
    for (uint32_t k = 0; k < 8; ++k) v[k] = lazy::reduce64(acc[k]);
    const uint32_t sum = sample_warp_sum8(v, lane & 31u);
    if (!(lane & 3u))
      partial[s][lane / 32][((lane >> 4) & 1u) * 4 + ((lane >> 3) & 1u) * 2 +
                            ((lane >> 2) & 1u)] = sum;
  }
  if (bad) atomicOr(j.status, 2u);
  __syncthreads();
  for (uint32_t i = lane; i < chunk * 8; i += blockDim.x) {
    const uint32_t s = i / 8, k = i % 8, sample = first_sample + s;
    uint32_t value = 0;
    if (j.valid[sample])
      for (uint32_t w = 0; w < warps; ++w) value = q::add(value, partial[s][w][k]);
    j.scratch_a[(uint64_t(sample) * blocks + tile) * 8 + k] = value;
  }
}
} // namespace stwo::cuda::rv64
static int sample_points_dispatch(void *ctx, uint32_t lane,
                                  const StwoRv64SamplePoints *input,
                                  bool from_point) {
  using namespace stwo::cuda::rv64;
  if (!input || input->reserved || !input->count || input->count > 1024)
    return int(cudaErrorInvalidValue);
  const auto j = *input;
  RangeCustody<8> c(ctx, lane);
  if (!c.range(j.parameter, from_point ? 16 : 8, false) ||
      !c.range(reinterpret_cast<const uint32_t *>(j.recipes),
               uint64_t(j.count) * 4, false) ||
      !c.range(j.points, uint64_t(j.count + 1) * 16, true) ||
      !c.range(j.factors, uint64_t(j.count) * factor_stride * 8, true) ||
      !c.range(j.ready, j.count + 1, true) || !c.range(j.status, 1, true))
    return c.status;
  if (from_point)
    sample_base_from_point<<<1, 1, 0, c.stream>>>(j);
  else
    sample_base<<<1, 1, 0, c.stream>>>(j);
  sample_points<<<(j.count + 127) / 128, 128, 0, c.stream>>>(j);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_sample_points_on(void *ctx, uint32_t lane,
                                          const StwoRv64SamplePoints *input) {
  return sample_points_dispatch(ctx, lane, input, false);
}
extern "C" int
stwo_rv64_sample_points_from_point_on(void *ctx, uint32_t lane,
                                      const StwoRv64SamplePoints *input) {
  return sample_points_dispatch(ctx, lane, input, true);
}
extern "C" int
stwo_rv64_sample_evaluate_on(void *ctx, uint32_t lane,
                             const StwoRv64SampleEvaluation *input) {
  using namespace stwo::cuda::rv64;
  if (!input || !input->count || input->count > 65535 || !input->source_count ||
      input->source_count > 65536 || !input->group_count ||
      input->group_count > 1024 || !input->coefficient_log ||
      input->coefficient_log > 28 || input->term_capacity > 65536 ||
      input->first > input->term_capacity ||
      input->count > input->term_capacity - input->first ||
      input->value_words < uint64_t(input->term_capacity) * 8)
    return int(cudaErrorInvalidValue);
  if (reinterpret_cast<uintptr_t>(input->sources) % alignof(StwoRv64DeepSource))
    return int(cudaErrorInvalidValue);
  const auto j = *input;
  const uint32_t n = 1u << j.coefficient_log,
                 blocks = (n + sample_tile - 1) / sample_tile;
  const uint64_t scratch_words = uint64_t(blocks) * j.count * 8;
  if (j.scratch_words < scratch_words)
    return int(cudaErrorInvalidValue);
  RangeCustody<20> c(ctx, lane);
  for (uint32_t i = 0; i < 4; ++i) {
    if (j.tree_words[i]) {
      if (!c.range(j.trees[i], j.tree_words[i], false))
        return c.status;
    } else if (j.trees[i])
      return int(cudaErrorInvalidValue);
  }
  if (!c.range(reinterpret_cast<const uint32_t *>(j.sources),
               uint64_t(j.source_count) * 4, false) ||
      !c.range(reinterpret_cast<const uint32_t *>(j.terms),
               uint64_t(j.term_capacity) * 4, false) ||
      !c.range(reinterpret_cast<const uint32_t *>(j.recipes),
               uint64_t(j.group_count) * 4, false) ||
      !c.range(j.factors, uint64_t(j.group_count) * factor_stride * 8, false) ||
      !c.range(j.point_ready, j.group_count + 1, false) ||
      !c.range(j.scratch_a, scratch_words, true) ||
      !c.range(j.scratch_b, scratch_words, true) ||
      !c.range(j.values, j.value_words, true) ||
      !c.range(j.valid, j.count, true) || !c.range(j.status, 1, true))
    return c.status;
  sample_validate<<<(j.count + 127) / 128, 128, 0, c.stream>>>(j);
  // The basis lives in scratch_b, so it needs a custody-checked bank of at
  // least one tile basis plus its group word; smaller launches (and
  // STWO_RV64_M8_SAMPLE_LEGACY=1) keep the per-sample tree kernel.
  const char *legacy_env = std::getenv("STWO_RV64_M8_SAMPLE_LEGACY");
  const bool legacy = legacy_env && std::strcmp(legacy_env, "1") == 0;
  if (!legacy && scratch_words > sample_basis_words) {
    sample_basis<<<1, 512, 0, c.stream>>>(j, j.scratch_b);
    if (blocks >= sample_chunk_large_tiles)
      sample_first_basis<sample_chunk_large>
          <<<dim3(blocks, (j.count + sample_chunk_large - 1) / sample_chunk_large),
             sample_fast_threads, 0, c.stream>>>(j, blocks, j.scratch_b);
    else
      sample_first_basis<sample_chunk_small>
          <<<dim3(blocks, (j.count + sample_chunk_small - 1) / sample_chunk_small),
             sample_fast_threads, 0, c.stream>>>(j, blocks, j.scratch_b);
  } else {
    sample_first<<<dim3(blocks, j.count), 128, 0, c.stream>>>(j, blocks);
  }
  uint32_t count = blocks, consumed = 10;
  uint32_t *in = j.scratch_a, *out = j.scratch_b;
  while (count > 1) {
    const uint32_t next = (count + 255) / 256;
    sample_reduce<<<dim3(next, j.count), 128, 0, c.stream>>>(
        j, in, count, consumed, out, next);
    consumed += min(8u, 31u - uint32_t(__builtin_clz(count)));
    count = next;
    uint32_t *tmp = in;
    in = out;
    out = tmp;
  }
  sample_store<<<(j.count + 127) / 128, 128, 0, c.stream>>>(j, in);
  return int(cudaPeekAtLastError());
}
