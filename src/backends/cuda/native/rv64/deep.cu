#include "custody.cuh"
#include "deep.h"
#include "deep_lazy.cuh"
#include "om31.cuh"
#include <cstdio>
#include <cstdlib>
#include <cstring>
namespace stwo::cuda::rv64 {
// Diagnostic-only timing. Event destruction is safe after a partial create
// or failed enqueue; no events/synchronization exist on the default path.
struct DeepTimings {
  cudaEvent_t events[4]{};
  ~DeepTimings() {
    for (auto event : events) if (event) cudaEventDestroy(event);
  }
  int create() {
    for (auto &event : events) {
      const int status = int(cudaEventCreate(&event));
      if (status) return status;
    }
    return 0;
  }
};
__device__ OM31 deep_power(OM31 x, uint32_t exponent) {
  OM31 result = one();
  while (exponent) {
    if (exponent & 1)
      result = mul(result, x);
    x = mul(x, x);
    exponent >>= 1;
  }
  return result;
}
__device__ bool inner_zero(q::QM31 x) {
  return !(x.a.a | x.a.b | x.b.a | x.b.b);
}
__device__ OM31 conjugate(OM31 x) { return {x.c0, q::sub(q::zero(), x.c1)}; }
__device__ bool deep_layout(const StwoRv64DeepGroup *groups, uint32_t count,
                            uint64_t coefficient_words,
                            uint64_t evaluation_words, uint32_t output_log) {
  uint64_t coefficient_end = 0, evaluation_end = 0;
  for (uint32_t i = 0; i < count; ++i) {
    const auto g = groups[i];
    if (g.coefficient_log < 1 || g.evaluation_log < g.coefficient_log ||
        g.evaluation_log > 28 || g.evaluation_log > output_log ||
        g.coefficient_offset != coefficient_end ||
        g.evaluation_offset != evaluation_end)
      return false;
    coefficient_end += uint64_t(8) << g.coefficient_log;
    evaluation_end += uint64_t(8) << g.evaluation_log;
    if (coefficient_end > coefficient_words ||
        evaluation_end > evaluation_words)
      return false;
  }
  return true;
}
__global__ void deep_validate(StwoRv64DeepPrepare j) {
  *j.valid = 0;
  j.valid[1] = 0;
  // Evaluation offsets are checked here for contiguity; allocation size is
  // checked again at combine, before any metadata-dependent read.
  if (atomicOr(j.status, 0u) ||
      !deep_layout(j.groups, j.group_count, j.coefficient_words, UINT64_MAX,
                   28)) {
    atomicOr(j.status, 1u);
    return;
  }
  const OM31 alpha = from_words(j.alpha);
  if (!canonical(alpha)) {
    atomicOr(j.status, 2u);
    return;
  }
  uint32_t previous = 0;
  for (uint32_t group = 0; group < j.group_count; ++group) {
    const auto g = j.groups[group];
    if (g.begin != previous || g.end <= g.begin || g.end > j.term_count) {
      atomicOr(j.status, 1u);
      return;
    }
    previous = g.end;
    const OM31 x = from_words(j.points + 16 * group);
    const OM31 y = from_words(j.points + 16 * group + 8);
    if (!canonical(x) || !canonical(y)) {
      atomicOr(j.status, 2u);
      return;
    }
    if (!is_zero(sub(add(mul(x, x), mul(y, y)), one())) || inner_zero(y.c1)) {
      atomicOr(j.status, 4u);
      return;
    }
    for (uint32_t t = g.begin; t < g.end; ++t) {
      const auto term = j.terms[t];
      if (term.reserved || term.group != group ||
          term.source >= j.source_count || term.exponent >= j.term_count) {
        atomicOr(j.status, 1u);
        return;
      }
      const auto source = j.sources[term.source];
      const uint64_t n = uint64_t(1) << g.coefficient_log;
      if (source.tree >= 4 || source.coefficient_log != g.coefficient_log ||
          source.offset > j.tree_words[source.tree] ||
          n > j.tree_words[source.tree] - source.offset) {
        atomicOr(j.status, 1u);
        return;
      }
      if (!canonical(from_words(j.values + uint64_t(t) * 8))) {
        atomicOr(j.status, 2u);
        return;
      }
    }
  }
  if (previous != j.term_count) {
    atomicOr(j.status, 1u);
    return;
  }
  *j.valid = 1;
}
__global__ void deep_lines(StwoRv64DeepPrepare j) {
  const uint32_t group = blockIdx.x, lane = threadIdx.x;
  if (group >= j.group_count)
    return;
  // One group can contain thousands of terms even for a tiny row domain.
  // Weights are term-independent; reduce their two field sums within a CTA
  // rather than serializing the entire group onto one GPU thread.
  __shared__ OM31 a_partial[128], b_partial[128];
  OM31 a_sum = zero(), b_sum = zero();
  if (*j.valid) {
    const auto g = j.groups[group];
    const OM31 y = from_words(j.points + 16 * group + 8);
    const OM31 c = sub(conjugate(y), y);
    const OM31 alpha = from_words(j.alpha);
    for (uint32_t t = g.begin + lane; t < g.end; t += blockDim.x) {
      const OM31 value = from_words(j.values + uint64_t(t) * 8);
      const OM31 power = deep_power(alpha, j.terms[t].exponent);
      const OM31 a = mul(power, sub(conjugate(value), value));
      const OM31 b = sub(mul(mul(power, value), c), mul(a, y));
      a_sum = add(a_sum, a);
      b_sum = add(b_sum, b);
      const OM31 weight = mul(power, c);
      for (uint32_t k = 0; k < 8; ++k)
        j.weights[uint64_t(t) * 8 + k] = coordinate(weight, k);
    }
  }
  a_partial[lane] = a_sum;
  b_partial[lane] = b_sum;
  __syncthreads();
  for (uint32_t width = blockDim.x / 2; width; width >>= 1) {
    if (lane < width) {
      a_partial[lane] = add(a_partial[lane], a_partial[lane + width]);
      b_partial[lane] = add(b_partial[lane], b_partial[lane + width]);
    }
    __syncthreads();
  }
  if (lane) return;
  for (uint32_t k = 0; k < 8; ++k) {
    j.linear[uint64_t(group) * 16 + k] = coordinate(a_partial[0], k);
    j.linear[uint64_t(group) * 16 + 8 + k] = coordinate(b_partial[0], k);
  }
}
__global__ void deep_aggregate(StwoRv64DeepPrepare j) {
  if (!*j.valid)
    return;
  const uint32_t group = blockIdx.y;
  const auto g = j.groups[group];
  const uint32_t n = 1u << g.coefficient_log;
  for (uint32_t row = blockIdx.x * blockDim.x + threadIdx.x; row < n;
       row += gridDim.x * blockDim.x) {
    OM31 result = zero();
    for (uint32_t t = g.begin; t < g.end; ++t) {
      const auto source = j.sources[j.terms[t].source];
      uint32_t coefficient = j.trees[source.tree][source.offset + row];
      if (coefficient >= q::kPrime) {
        atomicOr(j.status, 2u);
        coefficient = 0;
      }
      result = add(result,
                   scale(from_words(j.weights + uint64_t(t) * 8), coefficient));
    }
    store(j.coefficients + g.coefficient_offset, n, row, result);
  }
}
// Scalar-coordinate layout: a warp owns adjacent coefficient rows,
// eight warps compute the eight independent extension-field coordinates.
// Each coordinate visits terms in the identical order as deep_aggregate.
__global__ void deep_aggregate_coordinates(StwoRv64DeepPrepare j) {
  if (!*j.valid) return;
  const auto g = j.groups[blockIdx.y];
  const uint32_t n = 1u << g.coefficient_log;
  const uint32_t coordinate = threadIdx.y;
  for (uint32_t row = blockIdx.x * blockDim.x + threadIdx.x; row < n;
       row += gridDim.x * blockDim.x) {
    uint32_t result = 0;
    for (uint32_t t = g.begin; t < g.end; ++t) {
      const auto source = j.sources[j.terms[t].source];
      uint32_t coefficient = j.trees[source.tree][source.offset + row];
      if (coefficient >= q::kPrime) {
        atomicOr(j.status, 2u);
        coefficient = 0;
      }
      result = q::add(result, q::mul(j.weights[uint64_t(t) * 8 + coordinate],
                                    coefficient));
    }
    j.coefficients[g.coefficient_offset + uint64_t(coordinate) * n + row] = result;
  }
}
// Row-major aggregation (kernels stream, M4): one thread owns two coefficient
// rows and all eight coordinates. Each source coefficient is loaded once
// (coalesced along the row axis; the lane->row axis is never permuted) instead
// of once per coordinate warp, and the term -> source -> tree chain is
// resolved once per CTA into shared memory instead of once per thread and
// term. Weights are canonical (deep_lines), so every product w*c < p^2 < 2^62;
// products accumulate lazily in 64 bits and fold below 2^34 every two terms.
// Field addition is exact, so the canonical result is bit-identical to
// deep_aggregate_coordinates for every term order.
constexpr uint32_t kDeepRowThreads = 256;
constexpr uint32_t kDeepRowsPerThread = 2;
constexpr uint32_t kDeepTermChunk = 128;
__device__ __forceinline__ uint64_t deep_fold(uint64_t x) {
  return (x & q::kPrime) + (x >> 31);
}
__device__ __forceinline__ uint32_t deep_canonical(uint64_t x) {
  // x < 2^34 after a fold; a second fold leaves x < p + 8.
  const uint32_t folded = uint32_t(deep_fold(x));
  return folded >= q::kPrime ? folded - q::kPrime : folded;
}
__global__ __launch_bounds__(kDeepRowThreads) void deep_aggregate_rows(
    StwoRv64DeepPrepare j) {
  if (!*j.valid) return;
  const auto g = j.groups[blockIdx.y];
  const uint32_t n = 1u << g.coefficient_log;
  __shared__ const uint32_t *columns[kDeepTermChunk];
  __shared__ uint4 weights[kDeepTermChunk][2];
  constexpr uint32_t tile = kDeepRowThreads * kDeepRowsPerThread;
  for (uint32_t row0 = blockIdx.x * tile; row0 < n; row0 += gridDim.x * tile) {
    uint64_t acc[kDeepRowsPerThread][8];
#pragma unroll
    for (uint32_t r = 0; r < kDeepRowsPerThread; ++r)
#pragma unroll
      for (uint32_t k = 0; k < 8; ++k) acc[r][k] = 0;
    bool bad = false;
    for (uint32_t base = g.begin; base < g.end; base += kDeepTermChunk) {
      const uint32_t count = min(kDeepTermChunk, g.end - base);
      __syncthreads();
      for (uint32_t i = threadIdx.x; i < count; i += blockDim.x) {
        const auto source = j.sources[j.terms[base + i].source];
        const uint32_t *tree = source.tree == 0   ? j.trees[0]
                               : source.tree == 1 ? j.trees[1]
                               : source.tree == 2 ? j.trees[2]
                                                  : j.trees[3];
        columns[i] = tree + source.offset;
        const uint32_t *w = j.weights + uint64_t(base + i) * 8;
        weights[i][0] = make_uint4(w[0], w[1], w[2], w[3]);
        weights[i][1] = make_uint4(w[4], w[5], w[6], w[7]);
      }
      __syncthreads();
      if (row0 + threadIdx.x < n) {
        for (uint32_t i = 0; i < count; ++i) {
          uint32_t c[kDeepRowsPerThread];
#pragma unroll
          for (uint32_t r = 0; r < kDeepRowsPerThread; ++r) {
            const uint32_t row = row0 + threadIdx.x + r * kDeepRowThreads;
            c[r] = row < n ? columns[i][row] : 0u;
            if (c[r] >= q::kPrime) {
              bad = true;
              c[r] = 0;
            }
          }
          const uint4 w0 = weights[i][0], w1 = weights[i][1];
          const uint32_t w[8] = {w0.x, w0.y, w0.z, w0.w,
                                 w1.x, w1.y, w1.z, w1.w};
#pragma unroll
          for (uint32_t r = 0; r < kDeepRowsPerThread; ++r)
#pragma unroll
            for (uint32_t k = 0; k < 8; ++k)
              acc[r][k] += uint64_t(w[k]) * c[r];
          // acc < 2^34 before each pair of products, < 2^63 + 2^34 after.
          if ((i & 1u) || i + 1u == count) {
#pragma unroll
            for (uint32_t r = 0; r < kDeepRowsPerThread; ++r)
#pragma unroll
              for (uint32_t k = 0; k < 8; ++k)
                acc[r][k] = deep_fold(acc[r][k]);
          }
        }
      }
    }
    if (bad) atomicOr(j.status, 2u);
#pragma unroll
    for (uint32_t r = 0; r < kDeepRowsPerThread; ++r) {
      const uint32_t row = row0 + threadIdx.x + r * kDeepRowThreads;
      if (row >= n) continue;
#pragma unroll
      for (uint32_t k = 0; k < 8; ++k)
        j.coefficients[g.coefficient_offset + uint64_t(k) * n + row] =
            deep_canonical(acc[r][k]);
    }
  }
}
__global__ void deep_combine_validate(StwoRv64DeepCombine j, uint32_t *ok) {
  *ok = *j.valid && !atomicOr(j.status, 0u) &&
        deep_layout(j.groups, j.group_count, UINT64_MAX, j.evaluation_words,
                    j.output_log);
  if (*ok) {
    for (uint32_t group = 0; group < j.group_count; ++group) {
      const OM31 x = from_words(j.points + uint64_t(group) * 16);
      const OM31 y = from_words(j.points + uint64_t(group) * 16 + 8);
      if (!canonical(x) || !canonical(y)) {
        *ok = 0;
        atomicOr(j.status, 2u);
        break;
      }
      if (!is_zero(sub(add(mul(x, x), mul(y, y)), one())) || inner_zero(y.c1)) {
        *ok = 0;
        atomicOr(j.status, 4u);
        break;
      }
    }
  }
  if (!*ok)
    atomicOr(j.status, 1u);
}
__global__ void deep_combine(StwoRv64DeepCombine j) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t n = 1u << j.output_log;
  if (row >= n)
    return;
  store(j.output.words, j.output.stride, row, zero());
  // Metadata is validated by a preceding kernel; status may be written by
  // other rows, so it must never be used as a non-atomic per-row guard.
  if (!j.valid[1])
    return;
  const uint32_t x = j.domain_xy[uint64_t(row) * 2],
                 y = j.domain_xy[uint64_t(row) * 2 + 1];
  if (x >= q::kPrime || y >= q::kPrime) {
    atomicOr(j.status, 2u);
    return;
  }
  if (q::add(q::mul(x, x), q::mul(y, y)) != 1) {
    atomicOr(j.status, 4u);
    return;
  }
  OM31 result = zero();
  bool bad = false;
  // Eight independent denominators, one QM31 inversion per row and chunk.
  for (uint32_t first = 0; first < j.group_count; first += 8) {
    q::QM31 ds[8], prefixes[8];
    OM31 numerators[8];
    q::QM31 product = q::one();
    const uint32_t count = min(8u, j.group_count - first);
    // Constant indices keep the batched inverse tile in registers.
#pragma unroll
    for (uint32_t k = 0; k < 8; ++k) {
      if (k >= count)
        continue;
      const uint32_t id = first + k;
      const auto g = j.groups[id];
      const OM31 sx = from_words(j.points + uint64_t(id) * 16);
      const OM31 sy = from_words(j.points + uint64_t(id) * 16 + 8);
      q::QM31 rx = sx.c0, ry = sy.c0;
      rx.a.a = q::sub(rx.a.a, x);
      ry.a.a = q::sub(ry.a.a, y);
      ds[k] = q::sub(q::mul(rx, sy.c1), q::mul(ry, sx.c1));
      if (inner_zero(ds[k])) {
        atomicOr(j.status, 8u);
        ds[k] = q::one();
        bad = true;
      }
      prefixes[k] = product;
      product = q::mul(product, ds[k]);
      const uint32_t diff = j.output_log - g.evaluation_log;
      const uint32_t index = ((row >> (diff + 1)) << 1) + (row & 1u);
      const OM31 value = load(j.evaluations + g.evaluation_offset,
                              1u << g.evaluation_log, index);
      const OM31 a = from_words(j.linear + uint64_t(id) * 16);
      const OM31 b = from_words(j.linear + uint64_t(id) * 16 + 8);
      if (!canonical(value) || !canonical(a) || !canonical(b)) {
        atomicOr(j.status, 2u);
        bad = true;
      }
      numerators[k] = sub(sub(value, scale(a, y)), b);
    }
    q::QM31 reciprocal = q::inverse(product);

#pragma unroll
    for (int k = 7; k >= 0; --k) {
      if (uint32_t(k) >= count)
        continue;
      const auto inv = q::mul(reciprocal, prefixes[k]);
      reciprocal = q::mul(reciprocal, ds[k]);
      result = add(result, {q::mul(numerators[k].c0, inv),
                            q::mul(numerators[k].c1, inv)});
    }
  }
  if (!bad)
    store(j.output.words, j.output.stride, row, result);
}
// ---------------------------------------------------------------------------
// M8 T3 kernels. Same ABI, same status bits, bit-identical outputs; the
// legacy kernels above stay selectable with STWO_RV64_M8_DEEP_LEGACY=1.
// ---------------------------------------------------------------------------
// deep_validate with the serial scan order preserved: the first failing check
// in (group, header, points, term order) wins, exactly as in deep_validate.
// Terms of one group are checked by the whole CTA and the earliest failing
// term is selected with a shared atomicMin over key = 2*(t-begin)+check.
constexpr uint32_t kDeepValidateThreads = 256;
__global__ __launch_bounds__(kDeepValidateThreads) void deep_validate_parallel(
    StwoRv64DeepPrepare j) {
  __shared__ uint32_t verdict, best;
  const uint32_t lane = threadIdx.x;
  if (!lane) {
    *j.valid = 0;
    j.valid[1] = 0;
    verdict = 0;
    if (atomicOr(j.status, 0u) ||
        !deep_layout(j.groups, j.group_count, j.coefficient_words, UINT64_MAX,
                     28))
      verdict = 1;
    else if (!canonical(from_words(j.alpha)))
      verdict = 2;
  }
  __syncthreads();
  if (verdict) {
    if (!lane) atomicOr(j.status, verdict);
    return;
  }
  uint32_t previous = 0;
  for (uint32_t group = 0; group < j.group_count; ++group) {
    // Every branch below is CTA-uniform: all threads read the same words.
    const auto g = j.groups[group];
    if (g.begin != previous || g.end <= g.begin || g.end > j.term_count) {
      if (!lane) atomicOr(j.status, 1u);
      return;
    }
    previous = g.end;
    const OM31 x = from_words(j.points + 16 * group);
    const OM31 y = from_words(j.points + 16 * group + 8);
    if (!canonical(x) || !canonical(y)) {
      if (!lane) atomicOr(j.status, 2u);
      return;
    }
    if (!is_zero(sub(add(mul(x, x), mul(y, y)), one())) || inner_zero(y.c1)) {
      if (!lane) atomicOr(j.status, 4u);
      return;
    }
    if (!lane) best = UINT32_MAX;
    __syncthreads();
    const uint64_t n = uint64_t(1) << g.coefficient_log;
    for (uint32_t t = g.begin + lane; t < g.end; t += blockDim.x) {
      const auto term = j.terms[t];
      uint32_t key = UINT32_MAX;
      if (term.reserved || term.group != group ||
          term.source >= j.source_count || term.exponent >= j.term_count) {
        key = 2 * (t - g.begin);
      } else {
        const auto source = j.sources[term.source];
        if (source.tree >= 4 || source.coefficient_log != g.coefficient_log ||
            source.offset > j.tree_words[source.tree] ||
            n > j.tree_words[source.tree] - source.offset)
          key = 2 * (t - g.begin);
        else if (!canonical(from_words(j.values + uint64_t(t) * 8)))
          key = 2 * (t - g.begin) + 1;
      }
      if (key != UINT32_MAX) {
        atomicMin(&best, key);
        break; // later terms of this thread have larger keys
      }
    }
    __syncthreads();
    const uint32_t found = best;
    if (found != UINT32_MAX) {
      if (!lane) atomicOr(j.status, (found & 1u) ? 2u : 1u);
      return;
    }
    __syncthreads(); // best is reset for the next group only after all reads
  }
  if (previous != j.term_count) {
    if (!lane) atomicOr(j.status, 1u);
    return;
  }
  if (!lane) *j.valid = 1;
}
// deep_combine over point classes. Groups whose sample points are equal
// (word-identical, e.g. the OODS point at every height) share one denominator
//   d(x, y) = (sx.c0 - x) sy.c1 - (sy.c0 - y) sx.c1 = P - x sy.c1 + y sx.c1,
// P = sx.c0 sy.c1 - sy.c0 sx.c1, so their numerators are summed first:
//   sum_g (v_g - a_g y - b_g) = sum_g v_g - A y - B.
// The class fractions accumulate as N/D (N = N d + n D, D = D d) and the row
// does ONE QM31 inversion instead of one per eight groups. All arithmetic is
// exact over the field, so the canonical row value equals deep_combine's
// sum_g n_g / d_g bit for bit. Status bits: domain (2/4) per row as before;
// a zero class denominator sets 8 exactly when every group of that class
// would; non-canonical a/b (2) is decided once per CTA and raised by every
// row that reaches the group loop, as deep_combine does.
constexpr uint32_t kDeepCombineThreads = 256, kDeepCombineGroups = 128;
struct DeepClass {
  uint32_t p[4], ns1[4], s2[4], na[8], nb[8];
};
// [M] A/B (deep_t3_parity_bench, 5090, 2^22 rows x 68 groups, 7 reps,
// median): min blocks 1 (93 regs) 4.46 ms, 3 (80 regs) 4.43 ms: flat, the
// kernel is ALU-issue bound, not latency bound. Legacy deep_combine: 11.0 ms.
#ifndef STWO_RV64_DEEP_COMBINE_MIN_BLOCKS
#define STWO_RV64_DEEP_COMBINE_MIN_BLOCKS 1
#endif
__global__ __launch_bounds__(kDeepCombineThreads, STWO_RV64_DEEP_COMBINE_MIN_BLOCKS) void deep_combine_classes(
    StwoRv64DeepCombine j) {
  __shared__ DeepClass classes[kDeepCombineGroups];
  __shared__ const uint32_t *member_words[kDeepCombineGroups];
  __shared__ uint32_t member_log[kDeepCombineGroups];
  __shared__ uint32_t class_end[kDeepCombineGroups];
  __shared__ uint32_t rep[kDeepCombineGroups], class_of[kDeepCombineGroups];
  __shared__ uint32_t class_count, lin_bad, enabled;
  const uint32_t n = 1u << j.output_log, lane = threadIdx.x;
  const uint32_t stride = gridDim.x * blockDim.x;
  if (!lane) {
    enabled = j.valid[1];
    lin_bad = 0;
  }
  __syncthreads();
  if (!enabled) {
    for (uint32_t row = blockIdx.x * blockDim.x + lane; row < n; row += stride)
      store(j.output.words, j.output.stride, row, zero());
    return;
  }
  const uint32_t gc = j.group_count;
  // Class representative: the first group with a word-identical point.
  for (uint32_t g = lane; g < gc; g += blockDim.x) {
    const uint32_t *pg = j.points + uint64_t(g) * 16;
    uint32_t r = g;
    for (uint32_t h = 0; h < g; ++h) {
      const uint32_t *ph = j.points + uint64_t(h) * 16;
      bool same = true;
#pragma unroll
      for (uint32_t k = 0; k < 16; ++k) same = same && pg[k] == ph[k];
      if (same) {
        r = h;
        break;
      }
    }
    rep[g] = r;
  }
  __syncthreads();
  if (!lane) {
    uint32_t count = 0;
    for (uint32_t g = 0; g < gc; ++g)
      class_of[g] = rep[g] == g ? count++ : class_of[rep[g]];
    class_count = count;
    // Counting sort of groups by class (stable in group order).
    for (uint32_t c = 0; c < count; ++c) class_end[c] = 0;
    for (uint32_t g = 0; g < gc; ++g) ++class_end[class_of[g]];
    uint32_t running = 0;
    for (uint32_t c = 0; c < count; ++c) {
      running += class_end[c];
      class_end[c] = running - class_end[c]; // temporarily: begin
    }
    for (uint32_t g = 0; g < gc; ++g) {
      const auto group = j.groups[g];
      const uint32_t slot = class_end[class_of[g]]++;
      member_words[slot] = j.evaluations + group.evaluation_offset;
      member_log[slot] = group.evaluation_log;
    }
    // class_end[c] is now the end of class c's member range.
  }
  __syncthreads();
  for (uint32_t c = lane; c < class_count; c += blockDim.x) {
    uint32_t r = 0, seen = 0;
    OM31 a_sum = zero(), b_sum = zero();
    bool bad = false;
    for (uint32_t g = 0; g < gc; ++g) {
      if (class_of[g] != c) continue;
      if (!seen++) r = g;
      const OM31 a = from_words(j.linear + uint64_t(g) * 16);
      const OM31 b = from_words(j.linear + uint64_t(g) * 16 + 8);
      bad = bad || !canonical(a) || !canonical(b);
      a_sum = add(a_sum, a);
      b_sum = add(b_sum, b);
    }
    if (bad) lin_bad = 1;
    const OM31 sx = from_words(j.points + uint64_t(r) * 16);
    const OM31 sy = from_words(j.points + uint64_t(r) * 16 + 8);
    const q::QM31 p = q::sub(q::mul(sx.c0, sy.c1), q::mul(sy.c0, sx.c1));
    auto &out = classes[c];
    out.p[0] = p.a.a, out.p[1] = p.a.b, out.p[2] = p.b.a, out.p[3] = p.b.b;
    out.ns1[0] = lazy::P - sy.c1.a.a, out.ns1[1] = lazy::P - sy.c1.a.b;
    out.ns1[2] = lazy::P - sy.c1.b.a, out.ns1[3] = lazy::P - sy.c1.b.b;
    out.s2[0] = sx.c1.a.a, out.s2[1] = sx.c1.a.b, out.s2[2] = sx.c1.b.a,
    out.s2[3] = sx.c1.b.b;
    for (uint32_t k = 0; k < 8; ++k) {
      out.na[k] = lazy::P - coordinate(a_sum, k);
      out.nb[k] = lazy::P - coordinate(b_sum, k);
    }
  }
  __syncthreads();
  const uint32_t count = class_count;
  const bool linear_bad = lin_bad;
  for (uint32_t row = blockIdx.x * blockDim.x + lane; row < n; row += stride) {
    const uint32_t x = j.domain_xy[uint64_t(row) * 2],
                   y = j.domain_xy[uint64_t(row) * 2 + 1];
    if (x >= q::kPrime || y >= q::kPrime) {
      store(j.output.words, j.output.stride, row, zero());
      atomicOr(j.status, 2u);
      continue;
    }
    if (q::add(q::mul(x, x), q::mul(y, y)) != 1) {
      store(j.output.words, j.output.stride, row, zero());
      atomicOr(j.status, 4u);
      continue;
    }
    bool bad = linear_bad, bad_value = false;
    if (linear_bad) atomicOr(j.status, 2u);
    OM31 numerator = zero();
    q::QM31 denominator = q::one();
    uint32_t member = 0;
    for (uint32_t c = 0; c < count; ++c) {
      const DeepClass &k = classes[c];
      q::QM31 d;
      d.a.a = lazy::reduce64(lazy::mac(lazy::mac(k.p[0], x, k.ns1[0]), y, k.s2[0]));
      d.a.b = lazy::reduce64(lazy::mac(lazy::mac(k.p[1], x, k.ns1[1]), y, k.s2[1]));
      d.b.a = lazy::reduce64(lazy::mac(lazy::mac(k.p[2], x, k.ns1[2]), y, k.s2[2]));
      d.b.b = lazy::reduce64(lazy::mac(lazy::mac(k.p[3], x, k.ns1[3]), y, k.s2[3]));
      if (inner_zero(d)) {
        atomicOr(j.status, 8u);
        d = q::one();
        bad = true;
      }
      uint64_t acc[8];
#pragma unroll
      for (uint32_t i = 0; i < 8; ++i) acc[i] = lazy::mac(k.nb[i], y, k.na[i]);
      for (const uint32_t end = class_end[c]; member < end; ++member) {
        const uint32_t log = member_log[member];
        const uint32_t diff = j.output_log - log;
        const uint32_t index = ((row >> (diff + 1)) << 1) + (row & 1u);
        const uint32_t *words = member_words[member] + index;
#pragma unroll
        for (uint32_t i = 0; i < 8; ++i) {
          const uint32_t v = words[uint64_t(i) << log];
          bad_value = bad_value || v >= q::kPrime;
          acc[i] += v;
        }
      }
      OM31 value;
      value.c0 = {{lazy::reduce64(acc[0]), lazy::reduce64(acc[1])},
                  {lazy::reduce64(acc[2]), lazy::reduce64(acc[3])}};
      value.c1 = {{lazy::reduce64(acc[4]), lazy::reduce64(acc[5])},
                  {lazy::reduce64(acc[6]), lazy::reduce64(acc[7])}};
      if (!c) {
        numerator = value;
        denominator = d;
      } else {
        const lazy::QB dp = lazy::prepare(d), Dp = lazy::prepare(denominator);
        numerator.c0 = lazy::qmul_add(numerator.c0, dp, value.c0, Dp);
        numerator.c1 = lazy::qmul_add(numerator.c1, dp, value.c1, Dp);
        denominator = lazy::qmul(denominator, dp);
      }
    }
    if (bad_value) {
      atomicOr(j.status, 2u);
      bad = true;
    }
    const lazy::QB inv = lazy::prepare(q::inverse(denominator));
    const OM31 result{lazy::qmul(numerator.c0, inv),
                      lazy::qmul(numerator.c1, inv)};
    store(j.output.words, j.output.stride, row, bad ? zero() : result);
  }
}
// STWO_RV64_M8_DEEP_LEGACY=1 restores the pre-M8 deep_validate/deep_combine
// kernels (A/B and parity only); any other value or unset selects the M8 ones.
inline bool deep_legacy() {
  return m8_env_is_one("STWO_RV64_M8_DEEP_LEGACY");
}
// Persistent grid for deep_combine_classes: the per-CTA class prologue is
// paid once per resident CTA, not once per 256 rows.
inline uint32_t deep_combine_grid(uint32_t rows) {
  static const uint32_t resident = [] {
    int device = 0, sms = 0, per_sm = 0;
    if (cudaGetDevice(&device) ||
        cudaDeviceGetAttribute(&sms, cudaDevAttrMultiProcessorCount, device) ||
        cudaOccupancyMaxActiveBlocksPerMultiprocessor(
            &per_sm, deep_combine_classes, kDeepCombineThreads, 0) ||
        sms <= 0 || per_sm <= 0) {
      cudaGetLastError();
      return 0u;
    }
    return uint32_t(sms) * uint32_t(per_sm);
  }();
  const uint32_t needed = (rows + kDeepCombineThreads - 1) / kDeepCombineThreads;
  return resident && resident < needed ? resident : needed;
}
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_deep_prepare_on(void *ctx, uint32_t lane,
                                         const StwoRv64DeepPrepare *input) {
  using namespace stwo::cuda::rv64;
  if (!input || input->reserved || !input->source_count ||
      input->source_count > 65536 || !input->term_count ||
      input->term_count > 65536 || !input->group_count ||
      input->group_count > 1024)
    return int(cudaErrorInvalidValue);
  if (reinterpret_cast<uintptr_t>(input->sources) %
          alignof(StwoRv64DeepSource) ||
      reinterpret_cast<uintptr_t>(input->groups) % alignof(StwoRv64DeepGroup))
    return int(cudaErrorInvalidValue);
  const auto j = *input;
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
               uint64_t(j.term_count) * 4, false) ||
      !c.range(reinterpret_cast<const uint32_t *>(j.groups),
               uint64_t(j.group_count) * 8, false) ||
      !c.range(j.points, uint64_t(j.group_count) * 16, false) ||
      !c.range(j.values, uint64_t(j.term_count) * 8, false) ||
      !c.range(j.alpha, 8, false) ||
      !c.range(j.weights, uint64_t(j.term_count) * 8, true) ||
      !c.range(j.linear, uint64_t(j.group_count) * 16, true) ||
      !c.range(j.coefficients, j.coefficient_words, true) ||
      !c.range(j.valid, 2, true) || !c.range(j.status, 1, true))
    return c.status;
  int cleared = int(
      cudaMemsetAsync(j.coefficients, 0, j.coefficient_words * 4, c.stream));
  if (cleared)
    return cleared;
  const char *timing_env = nullptr;
  const bool timing = timing_env && std::strcmp(timing_env, "1") == 0;
  DeepTimings spans;
  if (timing) {
    int status = spans.create();
    if (!status) status = int(cudaEventRecord(spans.events[0], c.stream));
    if (status) return status;
  }
  const bool legacy = deep_legacy();
  // [M] M8 T3 A/B (deep_t3_parity_bench, 5090, 68 groups x 60 terms, 7 reps,
  // median): whole prepare 1.656 ms (serial <<<1,1>>> validate) -> 0.227 ms.
  if (legacy)
    deep_validate<<<1, 1, 0, c.stream>>>(j);
  else
    deep_validate_parallel<<<1, kDeepValidateThreads, 0, c.stream>>>(j);
  if (timing) {
    const int status = int(cudaEventRecord(spans.events[1], c.stream));
    if (status) return status;
  }
  deep_lines<<<j.group_count, 128, 0, c.stream>>>(j);
  if (timing) {
    const int status = int(cudaEventRecord(spans.events[2], c.stream));
    if (status) return status;
  }
  // Launch geometry is independent of device metadata. Grid-stride rows
  // preserve parallelism for large compact groups without host feedback.
  // STWO_RV64_DEEP_COORDINATES selects the aggregation kernel for A/B runs:
  // unset or "2" = row-major (default), "1" = per-coordinate warps (M3),
  // "0" = OM31 per-thread. All three produce identical coefficients.
  const char *coordinate_env = nullptr;
  if (coordinate_env && std::strcmp(coordinate_env, "0") != 0 &&
      std::strcmp(coordinate_env, "1") != 0 &&
      std::strcmp(coordinate_env, "2") != 0)
    return int(cudaErrorInvalidValue);
  const char aggregation = coordinate_env ? coordinate_env[0] : '2';
  if (aggregation == '2') {
    // 1024 CTAs per group: ~6 resident CTAs per SM on a 170-SM part for the
    // large groups; small groups exit their grid-stride loop immediately.
    deep_aggregate_rows<<<dim3(1024, j.group_count), kDeepRowThreads, 0,
                          c.stream>>>(j);
  } else if (aggregation == '1') {
    deep_aggregate_coordinates<<<dim3(256, j.group_count), dim3(32, 8), 0,
                                 c.stream>>>(j);
  } else {
    deep_aggregate<<<dim3(64, j.group_count), 128, 0, c.stream>>>(j);
  }
  if (timing) {
    int status = int(cudaEventRecord(spans.events[3], c.stream));
    if (!status) status = int(cudaEventSynchronize(spans.events[3]));
    if (status) return status;
    float milliseconds[3]{};
    for (uint32_t i = 0; i < 3; ++i) {
      status = int(cudaEventElapsedTime(&milliseconds[i], spans.events[i],
                                         spans.events[i + 1]));
      if (status) return status;
    }
    std::fprintf(stderr, "GPU_DEEP_DIAGNOSTIC validate_ms=%.6f lines_ms=%.6f "
                 "aggregate_ms=%.6f groups=%u terms=%u sources=%u "
                 "profile_only_end_sync=1\n", milliseconds[0], milliseconds[1],
                 milliseconds[2], j.group_count, j.term_count, j.source_count);
  }
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_deep_combine_on(void *ctx, uint32_t lane,
                                         const StwoRv64DeepCombine *input) {
  using namespace stwo::cuda::rv64;
  if (!input || input->reserved[0] || input->reserved[1] ||
      !input->group_count || input->group_count > 1024 || !input->output_log ||
      input->output_log > 28)
    return int(cudaErrorInvalidValue);
  if (reinterpret_cast<uintptr_t>(input->groups) % alignof(StwoRv64DeepGroup))
    return int(cudaErrorInvalidValue);
  const auto j = *input;
  RangeCustody<12> c(ctx, lane);
  if (!c.range(reinterpret_cast<const uint32_t *>(j.groups),
               uint64_t(j.group_count) * 8, false) ||
      !c.range(j.points, uint64_t(j.group_count) * 16, false) ||
      !c.range(j.linear, uint64_t(j.group_count) * 16, false) ||
      !c.range(j.evaluations, j.evaluation_words, false) ||
      !c.range(j.domain_xy, uint64_t(2) << j.output_log, false) ||
      !c.range(j.valid, 2, true) ||
      !c.plane(j.output, 1u << j.output_log, 8, true) ||
      !c.range(j.status, 1, true))
    return c.status;
  deep_combine_validate<<<1, 1, 0, c.stream>>>(
      j, const_cast<uint32_t *>(j.valid) + 1);
  if (deep_legacy() || j.group_count > kDeepCombineGroups)
    deep_combine<<<((1u << j.output_log) + 127) / 128, 128, 0, c.stream>>>(j);
  else
    deep_combine_classes<<<deep_combine_grid(1u << j.output_log),
                           kDeepCombineThreads, 0, c.stream>>>(j);
  return int(cudaPeekAtLastError());
}
