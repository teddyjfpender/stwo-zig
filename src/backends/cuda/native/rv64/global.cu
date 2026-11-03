#include "custody.cuh"
#include "global.h"
#include "om31.cuh"
namespace stwo::cuda::rv64 {
__device__ OM31 warp_up(OM31 value, uint32_t delta) {
  uint32_t words[8];
#pragma unroll
  for (uint32_t i = 0; i < 8; ++i)
    words[i] = __shfl_up_sync(0xffffffffu, coordinate(value, i), delta);
  return from_words(words);
}
__device__ OM31 warp_down(OM31 value, uint32_t delta) {
  uint32_t words[8];
#pragma unroll
  for (uint32_t i = 0; i < 8; ++i)
    words[i] = __shfl_down_sync(0xffffffffu, coordinate(value, i), delta);
  return from_words(words);
}
__device__ OM31 warp_at(OM31 value, uint32_t lane) {
  uint32_t words[8];
#pragma unroll
  for (uint32_t i = 0; i < 8; ++i)
    words[i] = __shfl_sync(0xffffffffu, coordinate(value, i), lane);
  return from_words(words);
}
__global__ void global_inverse_contribute(StwoRv64GlobalPairs j) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  if (row >= (1u << j.row_log))
    return;
  const uint64_t pair_offset = uint64_t(blockIdx.y) * 8 * j.stride;
  OM31 d = load(j.output + pair_offset, j.stride, row);
  OM31 n = load(j.contributions + pair_offset, j.stride, row);
  if (!canonical(d) || !canonical(n)) {
    atomicOr(j.status, 2u);
    d = one();
    n = zero();
  }
  if (is_zero(d)) {
    atomicOr(j.status, 4u);
    d = one();
    n = zero();
  }
  OM31 prefix = d, suffix = d;
  const uint32_t lane = threadIdx.x & 31u;
  // Every active warp has exactly32 rows (row_log>=5). No block barrier or
  // cross-block ordering is required; there is one inversion per warp/pair.
#pragma unroll
  for (uint32_t delta = 1; delta < 32; delta <<= 1) {
    const OM31 before = warp_up(prefix, delta),
               after = warp_down(suffix, delta);
    if (lane >= delta)
      prefix = mul(prefix, before);
    if (lane + delta < 32)
      suffix = mul(suffix, after);
  }
  const OM31 total = warp_at(prefix, 31);
  const OM31 inv_total =
      warp_at(lane == 0 ? inverse_nonzero(total) : zero(), 0);
  const OM31 previous = warp_up(prefix, 1), next = warp_down(suffix, 1);
  const OM31 inverse =
      mul(inv_total, mul(lane ? previous : one(), lane < 31 ? next : one()));
  store(j.output + pair_offset, j.stride, row, inverse);
  store(j.contributions + pair_offset, j.stride, row, mul(n, inverse));
}
__global__ void global_row_sum(StwoRv64GlobalPairs j) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  if (row >= (1u << j.row_log))
    return;
  OM31 sum = zero();
  for (uint32_t pair = 0; pair < j.pairs; ++pair)
    sum = add(sum, load(j.contributions + uint64_t(pair) * 8 * j.stride,
                        j.stride, row));
  store(j.output + uint64_t(j.pairs) * 8 * j.stride, j.stride, row, sum);
}
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_global_pairs_on(void *ctx, uint32_t lane,
                                         const StwoRv64GlobalPairs *input) {
  using namespace stwo::cuda::rv64;
  if (!input || input->reserved[0] || input->reserved[1] ||
      input->row_log < 5 || input->row_log > 22 || !input->pairs ||
      input->pairs > 640 || input->stride < (1u << input->row_log) ||
      input->stride > SIZE_MAX / (8 * uint64_t(input->pairs + 1)))
    return int(cudaErrorInvalidValue);
  const auto j = *input;
  const uint32_t rows = 1u << j.row_log;
  uint64_t need_scan = 0;
  for (uint32_t count = rows; count > 1;) {
    count = (count + 127) / 128;
    need_scan += uint64_t(count) * 8;
  }
  if (j.scan_words < need_scan)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(j.output, uint64_t(j.pairs + 1) * 8 * j.stride, true) ||
      !c.range(j.contributions, uint64_t(j.pairs) * 8 * j.stride, true) ||
      !c.range(j.scan_scratch, need_scan, true) || !c.range(j.claim, 8, true) ||
      !c.range(j.status, 1, true))
    return c.status;
  global_inverse_contribute<<<dim3((rows + 127) / 128, j.pairs), 128, 0,
                              c.stream>>>(j);
  global_row_sum<<<(rows + 127) / 128, 128, 0, c.stream>>>(j);
  const int dispatched = int(cudaPeekAtLastError());
  if (dispatched)
    return dispatched;
  StwoRv64PrefixScan scan{
      {j.output + uint64_t(j.pairs) * 8 * j.stride, j.stride, 8, 0},
      j.scan_scratch,
      need_scan,
      j.claim,
      j.status,
      j.row_log,
      1,
      {0, 0}};
  return stwo_rv64_prefix_scan_on(ctx, lane, &scan);
}
