#include "custody.cuh"
#include "deep.h"
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
  const char *timing_env = std::getenv("STWO_RV64_DEEP_TIMING");
  const bool timing = timing_env && std::strcmp(timing_env, "1") == 0;
  DeepTimings spans;
  if (timing) {
    int status = spans.create();
    if (!status) status = int(cudaEventRecord(spans.events[0], c.stream));
    if (status) return status;
  }
  deep_validate<<<1, 1, 0, c.stream>>>(j);
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
  const char *coordinate_env = std::getenv("STWO_RV64_DEEP_COORDINATES");
  if (coordinate_env && std::strcmp(coordinate_env, "0") != 0 &&
      std::strcmp(coordinate_env, "1") != 0)
    return int(cudaErrorInvalidValue);
  const bool scalar_coordinates = !coordinate_env ||
      std::strcmp(coordinate_env, "1") == 0;
  if (scalar_coordinates)
    deep_aggregate_coordinates<<<dim3(256, j.group_count), dim3(32, 8), 0,
                                 c.stream>>>(j);
  else
    deep_aggregate<<<dim3(64, j.group_count), 128, 0, c.stream>>>(j);
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
  deep_combine<<<((1u << j.output_log) + 127) / 128, 128, 0, c.stream>>>(j);
  return int(cudaPeekAtLastError());
}
