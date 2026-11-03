#include "custody.cuh"
#include "global.h"
#include "om31.cuh"
namespace stwo::cuda::rv64 {
__device__ OM31 warp_up(OM31 value, uint32_t delta, uint32_t mask) {
  uint32_t words[8];
#pragma unroll
  for (uint32_t i = 0; i < 8; ++i)
    words[i] = __shfl_up_sync(mask, coordinate(value, i), delta);
  return from_words(words);
}
__device__ OM31 warp_down(OM31 value, uint32_t delta, uint32_t mask) {
  uint32_t words[8];
#pragma unroll
  for (uint32_t i = 0; i < 8; ++i)
    words[i] = __shfl_down_sync(mask, coordinate(value, i), delta);
  return from_words(words);
}
__device__ OM31 warp_at(OM31 value, uint32_t lane, uint32_t mask) {
  uint32_t words[8];
#pragma unroll
  for (uint32_t i = 0; i < 8; ++i)
    words[i] = __shfl_sync(mask, coordinate(value, i), lane);
  return from_words(words);
}
__global__ void global_inverse_contribute(StwoRv64GlobalPairs j) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t mask = __ballot_sync(0xffffffffu,row < (1u << j.row_log));
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
  // The circuit minimum is16 rows; higher powers of two fill every warp.
  // Freeze the participating mask before the lane-zero inverse branch.
  // Prefix scan padding still runs complete128-thread blocks with zero tails.
  const uint32_t active_rows = (1u << j.row_log) < 32 ? (1u << j.row_log) : 32;
#pragma unroll
  for (uint32_t delta = 1; delta < active_rows; delta <<= 1) {
    const OM31 before = warp_up(prefix, delta, mask),
               after = warp_down(suffix, delta, mask);
    if (lane >= delta)
      prefix = mul(prefix, before);
    if (lane + delta < active_rows)
      suffix = mul(suffix, after);
  }
  const OM31 total = warp_at(prefix, active_rows - 1, mask);
  const OM31 inv_total =
      warp_at(lane == 0 ? inverse_nonzero(total) : zero(), 0, mask);
  const OM31 previous = warp_up(prefix, 1, mask), next = warp_down(suffix, 1, mask);
  const OM31 inverse =
      mul(inv_total, mul(lane ? previous : one(), lane + 1 < active_rows ? next : one()));
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
      input->row_log < 4 || input->row_log > 27 || !input->pairs ||
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

namespace stwo::cuda::rv64 {
__global__ void global_cumulative(StwoRv64GlobalCumulative j) {
  const uint32_t row=blockIdx.x*blockDim.x+threadIdx.x;
  if(row>=(1u<<j.row_log))return;
  OM31 sum=load(j.output+uint64_t(j.pairs)*8*j.stride,j.stride,row);
  for(uint32_t i=j.pairs;i>0;--i){
    const uint64_t offset=uint64_t(i-1)*8*j.stride;
    store(j.output+offset,j.stride,row,sum);
    sum=sub(sum,load(j.contributions+offset,j.stride,row));
  }
}
}
extern "C" __attribute__((visibility("default"))) int stwo_rv64_global_cumulative_on(void*ctx,uint32_t lane,const StwoRv64GlobalCumulative*input){
  using namespace stwo::cuda::rv64;
  if(!input||input->row_log<4||input->row_log>27||!input->pairs||input->pairs>640||input->stride<(1u<<input->row_log)||input->stride>SIZE_MAX/(8*uint64_t(input->pairs+1)))return int(cudaErrorInvalidValue);
  const auto j=*input;Custody c(ctx,lane);
  if(!c.range(j.output,uint64_t(j.pairs+1)*8*j.stride,true)||!c.range(j.contributions,uint64_t(j.pairs)*8*j.stride,false))return c.status;
  global_cumulative<<<((1u<<j.row_log)+127)/128,128,0,c.stream>>>(j);return int(cudaPeekAtLastError());
}
