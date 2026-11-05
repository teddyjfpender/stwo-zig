#include "binding.h"
#include "custody.cuh"
#include "eq_tile.cuh"
#include "om31.cuh"
namespace stwo::cuda::rv64 {
constexpr uint32_t scan_width = 128;
__device__ uint32_t physical(uint32_t logical, uint32_t log) {
  const uint32_t n = 1u << log;
  const uint32_t circle =
      (logical & 1u) ? n - (logical + 1u) / 2u : logical / 2u;
  return __brev(circle) >> (32u - log);
}
__global__ void binding_eq_seed(const uint32_t *point, uint32_t log,
                                StwoRv64Plane output, uint32_t *status) {
  for (uint32_t i = 0; i < log; ++i) {
    const OM31 value = from_words(point + i * 8);
    if (!canonical(value))
      atomicOr(status, 2u);
    else if (is_zero(value) || is_zero(sub(value, one())))
      atomicOr(status, 4u);
  }
  store(output.words, output.stride, 0, atomicOr(status, 0u) ? zero() : one());
}
template <uint32_t Levels>
__global__ void binding_eq_expand(const uint32_t *point, uint32_t first,
                                  uint32_t half, StwoRv64Plane output,
                                  uint32_t *status) {
  __shared__ uint32_t valid;
  if (!threadIdx.x)
    valid = atomicOr(status, 0u) == 0;
  __syncthreads();
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= half)
    return;
  if (valid)
    expand_eq_tile<Levels>(load(output.words, output.stride, i), point, first,
                           output.words, output.stride, i, half);
  else
    for (uint32_t j = 0; j < (1u << Levels); ++j)
      store(output.words, output.stride, i + uint64_t(j) * half, zero());
}
template <bool BaseNumerator, bool Deferred = false>
__global__ void project_binding(StwoRv64BindingProjection job) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t rows = 1u << job.row_log;
  if (row >= rows)
    return;
  store(job.prefix.words, job.prefix.stride, row, zero());
  const OM31 eta = from_words(job.metadata + 8 * 256);
  const OM31 target = Deferred ? zero() : from_words(job.metadata + 8 * 257);
  const OM31 eq = Deferred ? one() : load(job.eq.words, job.eq.stride, row);
  if (!canonical(eta) || !canonical(target) || !canonical(eq)) {
    atomicOr(job.status, 2u);
    return;
  }
  const uint32_t lanes = 1u << job.lane_log;
  OM31 projection_n = zero(), projection_d = zero();
  for (uint32_t lane = 0; lane < lanes; ++lane) {
    const uint32_t i = row * lanes + lane;
    const OM31 weight = from_words(job.metadata + 8 * lane);
    const OM31 denominator = load(job.d.words, job.d.stride, i);
    if (!canonical(weight) || !canonical(denominator)) {
      atomicOr(job.status, 2u);
      return;
    }
    if constexpr (BaseNumerator) {
      const uint32_t numerator = job.n.words[i];
      if (numerator >= q::kPrime) {
        atomicOr(job.status, 2u);
        return;
      }
      projection_n = add(projection_n, scale(weight, numerator));
    } else {
      const OM31 numerator = load(job.n.words, job.n.stride, i);
      if (!canonical(numerator)) {
        atomicOr(job.status, 2u);
        return;
      }
      projection_n = add(projection_n, mul(weight, numerator));
    }
    projection_d = add(projection_d, mul(weight, denominator));
  }
  const OM31 projected = add(projection_n, mul(eta, projection_d));
  if constexpr (Deferred)
    store(job.prefix.words, job.prefix.stride, row, projected);
  else
    store(job.prefix.words, job.prefix.stride, row, sub(mul(eq, projected), target));
}
__global__ void finalize_binding(StwoRv64BindingFinalize job) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  if (row >= (1u << job.row_log)) return;
  const OM31 eq = load(job.eq.words, job.eq.stride, row);
  const OM31 projection = load(job.projection.words, job.projection.stride, row);
  const OM31 target = from_words(job.metadata + 8 * 257);
  if (!canonical(eq) || !canonical(projection) || !canonical(target)) {
    atomicOr(job.status, 2u);
    store(job.output.words, job.output.stride, row, zero());
    return;
  }
  store(job.output.words, job.output.stride, row, sub(mul(eq, projection), target));
}
__global__ void scan_chunks(uint32_t *data, uint64_t stride, uint32_t count,
                            uint32_t *totals, uint32_t blocks, uint32_t log,
                            uint32_t *status) {
  __shared__ uint32_t warp_sums[4];
  const uint32_t coordinate = blockIdx.y;
  const uint32_t logical = blockIdx.x * scan_width + threadIdx.x;
  const uint32_t index =
      log ? physical(logical < count ? logical : 0, log) : logical;
  const uint64_t offset = uint64_t(coordinate) * stride + index;
  uint32_t value = logical < count ? data[offset] : 0;
  if (value >= q::kPrime) {
    atomicOr(status, 2u);
    value = 0;
  }
  const uint32_t lane = threadIdx.x & 31u, warp = threadIdx.x / 32u;
  for (uint32_t shift = 1; shift < 32; shift <<= 1) {
    const uint32_t other = __shfl_up_sync(0xffffffffu, value, shift);
    if (lane >= shift)
      value = q::add(value, other);
  }
  if (lane == 31)
    warp_sums[warp] = value;
  __syncthreads();
  if (warp == 0) {
    uint32_t total = lane < 4 ? warp_sums[lane] : 0;
    for (uint32_t shift = 1; shift < 32; shift <<= 1) {
      const uint32_t other = __shfl_up_sync(0xffffffffu, total, shift);
      if (lane >= shift)
        total = q::add(total, other);
    }
    if (lane < 4)
      warp_sums[lane] = total;
  }
  __syncthreads();
  if (warp)
    value = q::add(value, warp_sums[warp - 1]);
  if (logical < count)
    data[offset] = value;
  if (threadIdx.x == scan_width - 1)
    totals[uint64_t(coordinate) * blocks + blockIdx.x] = value;
}
__global__ void scan_carries(uint32_t *data, uint64_t stride, uint32_t count,
                             const uint32_t *parent, uint32_t parent_stride,
                             uint32_t log, const uint32_t *total,
                             uint32_t center) {
  const uint32_t logical = blockIdx.x * scan_width + threadIdx.x;
  if (logical >= count)
    return;
  const uint32_t coordinate = blockIdx.y;
  const uint32_t index = log ? physical(logical, log) : logical;
  const uint64_t offset = uint64_t(coordinate) * stride + index;
  const uint32_t chunk = logical / scan_width;
  uint32_t value = data[offset];
  if (chunk)
    value =
        q::add(value, parent[uint64_t(coordinate) * parent_stride + chunk - 1]);
  if (center)
    value = q::sub(value, total[coordinate]);
  data[offset] = value;
}
__global__ void scan_claim(const uint32_t *total, uint32_t *claim,
                           uint32_t *status, uint32_t center) {
  const uint32_t c = threadIdx.x;
  if (c < 8) {
    claim[c] = total[c];
    if (!center && total[c])
      atomicOr(status, 8u);
  }
}
} // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_binding_eq_on(void *ctx, uint32_t lane,
                                       const uint32_t *point, uint32_t log,
                                       StwoRv64Plane output, uint32_t *status) {
  if (!log || log > 27)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(point, log * 8, false) || !c.plane(output, 1u << log, 8, true) ||
      !c.range(status, 1, true))
    return c.status;
  binding_eq_seed<<<1, 1, 0, c.stream>>>(point, log, output, status);
  uint32_t remaining = log, half = 1;
  while (remaining) {
    const uint32_t levels = remaining < 4 ? remaining : 4;
    const uint32_t first = remaining - levels, blocks = (half + 127) / 128;
    switch (levels) {
    case 4:
      binding_eq_expand<4>
          <<<blocks, 128, 0, c.stream>>>(point, first, half, output, status);
      break;
    case 3:
      binding_eq_expand<3>
          <<<blocks, 128, 0, c.stream>>>(point, first, half, output, status);
      break;
    case 2:
      binding_eq_expand<2>
          <<<blocks, 128, 0, c.stream>>>(point, first, half, output, status);
      break;
    default:
      binding_eq_expand<1>
          <<<blocks, 128, 0, c.stream>>>(point, first, half, output, status);
      break;
    }
    remaining -= levels;
    half <<= levels;
  }
  return int(cudaPeekAtLastError());
}
extern "C" int
stwo_rv64_binding_project_on(void *ctx, uint32_t lane,
                             const StwoRv64BindingProjection *input) {
  if (!input || input->reserved[0] || input->reserved[1] || !input->row_log ||
      input->row_log > 22 || input->lane_log > 8 ||
      input->row_log + input->lane_log > 28)
    return int(cudaErrorInvalidValue);
  const auto job = *input;
  const uint32_t rows = 1u << job.row_log, facts = rows << job.lane_log;
  Custody c(ctx, lane);
  if (!c.numerator(job.n, facts) || !c.plane(job.d, facts, 8, false) ||
      !c.plane(job.eq, rows, 8, false) || !c.plane(job.prefix, rows, 8, true) ||
      !c.range(job.metadata, 260 * 8, false) || !c.range(job.status, 1, true))
    return c.status;
  if (job.n.coordinates == 1)
    project_binding<true><<<(rows + 127) / 128, 128, 0, c.stream>>>(job);
  else
    project_binding<false><<<(rows + 127) / 128, 128, 0, c.stream>>>(job);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_binding_deferred_on(
    void *ctx, uint32_t lane, const StwoRv64BindingDeferred *input) {
  using namespace stwo::cuda::rv64;
  if (!input || input->reserved[0] || input->reserved[1] || !input->row_log ||
      input->row_log > 22 || input->lane_log > 8 ||
      input->row_log + input->lane_log > 28) return int(cudaErrorInvalidValue);
  const auto job = *input;
  const uint32_t rows = 1u << job.row_log, facts = rows << job.lane_log;
  Custody c(ctx, lane);
  if (!c.numerator(job.n, facts) || !c.plane(job.d, facts, 8, false) ||
      !c.plane(job.output, rows, 8, true) ||
      !c.range(job.metadata, 260 * 8, false) || !c.range(job.status, 1, true))
    return c.status;
  const StwoRv64BindingProjection projected{job.n, job.d, {}, job.output,
      job.metadata, job.status, job.row_log, job.lane_log, {0, 0}};
  if (job.n.coordinates == 1)
    project_binding<true, true><<<(rows + 127) / 128, 128, 0, c.stream>>>(projected);
  else
    project_binding<false, true><<<(rows + 127) / 128, 128, 0, c.stream>>>(projected);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_binding_finalize_on(
    void *ctx, uint32_t lane, const StwoRv64BindingFinalize *input) {
  using namespace stwo::cuda::rv64;
  if (!input || input->reserved[0] || input->reserved[1] || input->reserved[2] ||
      !input->row_log || input->row_log > 27) return int(cudaErrorInvalidValue);
  const auto job = *input;
  const uint32_t rows = 1u << job.row_log;
  Custody c(ctx, lane);
  if (!c.plane(job.projection, rows, 8, false) ||
      !c.plane(job.eq, rows, 8, false) || !c.plane(job.output, rows, 8, true) ||
      !c.range(job.metadata, 260 * 8, false) || !c.range(job.status, 1, true))
    return c.status;
  finalize_binding<<<(rows + 127) / 128, 128, 0, c.stream>>>(job);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_prefix_scan_on(void *ctx, uint32_t lane,
                                        const StwoRv64PrefixScan *input) {
  if (!input || input->reserved[0] || input->reserved[1] || !input->row_log ||
      input->row_log > 27 || input->center > 1)
    return int(cudaErrorInvalidValue);
  const auto job = *input;
  const uint32_t rows = 1u << job.row_log;
  uint32_t counts[8]{}, offsets[8]{}, levels = 0, n = rows;
  uint64_t words = 0;
  while (n > 1) {
    const uint32_t blocks = (n + scan_width - 1) / scan_width;
    counts[levels] = blocks;
    offsets[levels++] = uint32_t(words);
    words += uint64_t(blocks) * 8;
    n = blocks;
  }
  if (!levels || levels > 8 || job.scratch_words < words)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.plane(job.data, rows, 8, true) || !c.range(job.scratch, words, true) ||
      !c.range(job.claim, 8, true) || !c.range(job.status, 1, true))
    return c.status;
  uint32_t *data = job.data.words;
  uint64_t stride = job.data.stride;
  uint32_t count = rows;
  for (uint32_t level = 0; level < levels; ++level) {
    uint32_t *next = job.scratch + offsets[level];
    scan_chunks<<<dim3(counts[level], 8), 128, 0, c.stream>>>(
        data, stride, count, next, counts[level], level == 0 ? job.row_log : 0,
        job.status);
    data = next;
    stride = count = counts[level];
  }
  const uint32_t *total = job.scratch + offsets[levels - 1];
  for (int level = int(levels) - 2; level >= 0; --level) {
    uint32_t *destination =
        level == 0 ? job.data.words : job.scratch + offsets[level - 1];
    const uint32_t size = level == 0 ? rows : counts[level - 1];
    const uint64_t dest_stride = level == 0 ? job.data.stride : size;
    scan_carries<<<dim3((size + 127) / 128, 8), 128, 0, c.stream>>>(
        destination, dest_stride, size, job.scratch + offsets[level],
        counts[level], level == 0 ? job.row_log : 0, total,
        level == 0 ? job.center : 0);
  }
  // A one-chunk scan needs no carries, but classic prefixes still center.
  if (levels == 1 && job.center)
    scan_carries<<<dim3(1, 8), 128, 0, c.stream>>>(
        job.data.words, job.data.stride, rows, total, 1, job.row_log, total, 1);
  scan_claim<<<1, 8, 0, c.stream>>>(total, job.claim, job.status, job.center);
  return int(cudaPeekAtLastError());
}
