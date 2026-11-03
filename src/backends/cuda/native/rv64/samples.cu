#include "custody.cuh"
#include "om31.cuh"
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
  sample_first<<<dim3(blocks, j.count), 128, 0, c.stream>>>(j, blocks);
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
