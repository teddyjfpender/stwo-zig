#include "binding.h"
#include "custody.cuh"
#include "eq_tile.cuh"
#include "logup_t8.h"
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
// ---- T8 (STWO_RV64_M8_LOGUP_BLOCK_INVERSE=1): coalesced level 0 ----------
// Level 0 scans logical coset order but data sits in circle order, so the
// original scan_chunks/scan_carries gather one 4-byte word per 32-byte sector
// (0.85 ms per pass at 2^22 x 8 coordinates [M], ~300 GB/s). View the plane as
// 64 rows x M columns, M = n/64: physical = brev6(low6(circle)) * M +
// brev(high(circle)). Logical chunk c (128 values) is then exactly two columns,
// brev(c) (its even logicals) and M-1-brev(c) (its odd logicals), so a block of
// columns [r0, r0+32) plus the mirror [M-r0-32, M-r0) holds 32 whole chunks and
// every global access is a 128-byte row segment. Two passes (chunk sums; then
// local scan + carry + centring) replace scan_chunks + scan_carries at level
// 0 with the same launch count and bit-identical data, totals and claim.
constexpr uint32_t tile_cols = 32, tile_rows = 64, tile_pitch = tile_cols + 1;
// One block covers tile_cols column pairs x tile_rows rows = 2^tile_min_log
// values, so the level-0 grid is rows >> tile_min_log blocks (M/64 >= 1).
constexpr uint32_t tile_min_log = 12;
static_assert((1u << tile_min_log) == 2 * tile_cols * tile_rows, "tile geometry");
__device__ __forceinline__ uint32_t brev_bits(uint32_t v, uint32_t bits) {
  return bits ? __brev(v) >> (32u - bits) : 0u;
}
// Chunk owning lo column r0+e of the block (its mirror is hi index 31-e).
__device__ __forceinline__ uint32_t tile_chunk(uint32_t column, uint32_t log) {
  const uint32_t high_bits = log - 6, high = brev_bits(column, high_bits);
  const uint32_t half = 1u << (high_bits - 1);
  return high < half ? high : (2u * half - 1u - high);
}
// Tile row holding logical value t (0..127) of a chunk, within its even (t
// even) or odd (t odd) column.
__device__ __forceinline__ uint32_t tile_slot(uint32_t t) {
  return t & 1u ? brev_bits(63u - (t >> 1), 6) : brev_bits(t >> 1, 6);
}
__device__ __forceinline__ uint32_t tile_load(const uint32_t *p, uint32_t *status) {
  uint32_t v = *p;
  if (v >= q::kPrime) {
    atomicOr(status, 2u);
    v = 0;
  }
  return v;
}
// Pass 1: chunk sums into totals (the values scan_chunks writes at level 0).
__global__ void __launch_bounds__(256) scan_tile_sums(const uint32_t *data, uint64_t stride, uint32_t log,
                               uint32_t *totals, uint32_t chunks, uint32_t *status) {
  __shared__ uint32_t partial[2][8][tile_cols];
  const uint32_t columns = 1u << (log - 6), r0 = blockIdx.x * tile_cols;
  const uint32_t col = threadIdx.x & 31u, group = threadIdx.x >> 5;
  const uint32_t *plane = data + uint64_t(blockIdx.y) * stride;
  uint32_t lo = 0, hi = 0;
#pragma unroll
  for (uint32_t i = 0; i < tile_rows / 8; ++i) {
    const uint64_t row = uint64_t(group + 8 * i) * columns;
    lo = q::add(lo, tile_load(plane + row + r0 + col, status));
    hi = q::add(hi, tile_load(plane + row + columns - r0 - tile_cols + col, status));
  }
  partial[0][group][col] = lo;
  partial[1][group][col] = hi;
  __syncthreads();
  if (threadIdx.x < tile_cols) {
    const uint32_t e = threadIdx.x;
    uint32_t total = 0;
    for (uint32_t g = 0; g < 8; ++g)
      total = q::add(q::add(total, partial[0][g][e]), partial[1][g][31 - e]);
    totals[uint64_t(blockIdx.y) * chunks + tile_chunk(r0 + e, log)] = total;
  }
}
// Pass 2: per-chunk inclusive scan in logical order + parent carry (+ centre).
__global__ void __launch_bounds__(256) scan_tile_apply(uint32_t *data, uint64_t stride, uint32_t log,
                                const uint32_t *parent, uint32_t chunks,
                                const uint32_t *total, uint32_t center,
                                uint32_t *status) {
  __shared__ uint32_t tile[2][tile_rows][tile_pitch];
  const uint32_t columns = 1u << (log - 6), r0 = blockIdx.x * tile_cols;
  const uint32_t coordinate = blockIdx.y;
  uint32_t *plane = data + uint64_t(coordinate) * stride;
  {
    const uint32_t col = threadIdx.x & 31u, group = threadIdx.x >> 5;
#pragma unroll
    for (uint32_t i = 0; i < tile_rows / 8; ++i) {
      const uint32_t s = group + 8 * i;
      const uint64_t row = uint64_t(s) * columns;
      tile[0][s][col] = tile_load(plane + row + r0 + col, status);
      tile[1][s][col] = tile_load(plane + row + columns - r0 - tile_cols + col, status);
    }
  }
  __syncthreads();
  // Thread = (chunk e, segment g of 16 logical values); a chunk's 8 segments
  // are 8 consecutive lanes. lo column e holds the chunk's even logicals iff e
  // is even (r0 is a multiple of 32, and brev(r) < M/2 iff r is even).
  const uint32_t lane = threadIdx.x & 31u, e = (threadIdx.x >> 5) * 4 + (lane >> 3),
                 g = lane & 7u;
  uint32_t *even = e & 1u ? &tile[1][0][31 - e] : &tile[0][0][e];
  uint32_t *odd = e & 1u ? &tile[0][0][e] : &tile[1][0][31 - e];
  uint32_t values[16], run = 0;
#pragma unroll
  for (uint32_t i = 0; i < 16; ++i) {
    const uint32_t t = 16 * g + i;
    run = q::add(run, (t & 1u ? odd : even)[tile_slot(t) * tile_pitch]);
    values[i] = run;
  }
  uint32_t carry = run;
#pragma unroll
  for (uint32_t shift = 1; shift < 8; shift <<= 1) {
    const uint32_t other = __shfl_up_sync(0xffffffffu, carry, shift, 8);
    if (g >= shift)
      carry = q::add(carry, other);
  }
  carry = __shfl_up_sync(0xffffffffu, carry, 1, 8);
  carry = g ? carry : 0u;
  const uint32_t chunk = tile_chunk(r0 + e, log);
  if (chunk)
    carry = q::add(carry, parent[uint64_t(coordinate) * chunks + chunk - 1]);
  if (center)
    carry = q::sub(carry, total[coordinate]);
#pragma unroll
  for (uint32_t i = 0; i < 16; ++i) {
    const uint32_t t = 16 * g + i;
    (t & 1u ? odd : even)[tile_slot(t) * tile_pitch] = q::add(values[i], carry);
  }
  __syncthreads();
  {
    const uint32_t col = threadIdx.x & 31u, group = threadIdx.x >> 5;
#pragma unroll
    for (uint32_t i = 0; i < tile_rows / 8; ++i) {
      const uint32_t s = group + 8 * i;
      const uint64_t row = uint64_t(s) * columns;
      plane[row + r0 + col] = tile[0][s][col];
      plane[row + columns - r0 - tile_cols + col] = tile[1][s][col];
    }
  }
}
// Tiled level 0 needs M/2 >= 32 columns (2^tile_min_log rows). The tile grid
// is rows/4096 blocks, so small scans under-fill the GPU while the gather is
// still cache resident: scanbench median old -> tiled [M, 7-9 reps, 5090]:
// 2^12 0.0107 -> 0.0159 ms, 2^13 0.0128 -> 0.0162, 2^14 0.0135 -> 0.0154,
// 2^15 0.0238 -> 0.0196, 2^16 0.0340 -> 0.0196, 2^18 0.109 -> 0.024,
// 2^22 1.685 -> 0.279. Below 2^15 the original kernels stay.
#ifndef STWO_T8_SCAN_TILE_MIN_LOG
#define STWO_T8_SCAN_TILE_MIN_LOG 15
#endif
constexpr uint32_t tile_use_log = STWO_T8_SCAN_TILE_MIN_LOG;
static_assert(tile_use_log >= tile_min_log, "tile geometry needs 2^12 rows");
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
int stwo::cuda::rv64::t8::prefix_scan(void *ctx, uint32_t lane,
                                      const StwoRv64PrefixScan *input,
                                      int mode) {
  if (mode != 0 && mode != 1)
    return int(cudaErrorInvalidValue);
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
  // levels >= 2 whenever row_log >= 12 (128-wide chunks).
  const bool tiled = mode == 1 && job.row_log >= tile_use_log;
  uint32_t *data = job.data.words;
  uint64_t stride = job.data.stride;
  uint32_t count = rows;
  for (uint32_t level = 0; level < levels; ++level) {
    uint32_t *next = job.scratch + offsets[level];
    if (tiled && level == 0)
      scan_tile_sums<<<dim3(rows >> tile_min_log, 8), 256, 0, c.stream>>>(
          data, stride, job.row_log, next, counts[0], job.status);
    else
      scan_chunks<<<dim3(counts[level], 8), 128, 0, c.stream>>>(
          data, stride, count, next, counts[level],
          level == 0 ? job.row_log : 0, job.status);
    data = next;
    stride = count = counts[level];
  }
  const uint32_t *total = job.scratch + offsets[levels - 1];
  for (int level = int(levels) - 2; level >= 0; --level) {
    if (tiled && level == 0) {
      scan_tile_apply<<<dim3(rows >> tile_min_log, 8), 256, 0, c.stream>>>(
          job.data.words, job.data.stride, job.row_log, job.scratch + offsets[0],
          counts[0], total, job.center, job.status);
      continue;
    }
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
extern "C" int stwo_rv64_prefix_scan_on(void *ctx, uint32_t lane,
                                        const StwoRv64PrefixScan *input) {
  return t8::prefix_scan(ctx, lane, input, t8::mode());
}
