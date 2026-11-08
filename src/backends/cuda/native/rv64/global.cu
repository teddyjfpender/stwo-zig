#include "custody.cuh"
#include "global.h"
#include "logup_t8.h"
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
// ---- T8 (STWO_RV64_M8_LOGUP_BLOCK_INVERSE=1) --------------------------------
// The original kernel spends 13 OM31 multiplications per row on a warp
// prefix/suffix scan (~690 M31 muls/row-pair incl. n*inv) and is compute bound
// (11.4 ms at 2^22 x 13 pairs [M], ~610 GB/s). An OM31 inverse by norm descent
// is ~88 M31 muls plus one M31 inverse; batching the M31 inverses over K rows
// per thread (Montgomery, 3 muls/row + 37/K) gives ~150 M31 muls/row-pair, so
// the pass becomes HBM bound. Inverses are unique, so outputs are unchanged.
namespace t8k {
struct Tower {
  q::QM31 n; // a.c0^2 - u a.c1^2         (OM31 -> QM31 norm)
  q::CM31 d; // n.a^2 - (2+i) n.b^2        (QM31 -> CM31 norm, as q::inverse)
  uint32_t m; // d.a^2 + d.b^2              (CM31 -> M31 norm)
};
__device__ __forceinline__ Tower descend(const OM31 &a) {
  Tower t;
  t.n = q::sub(q::square(a.c0), mul_u(q::square(a.c1)));
  const q::CM31 b2 = q::mul(t.n.b, t.n.b);
  const q::CM31 rotated{q::neg(b2.b), b2.a};
  t.d = q::sub(q::mul(t.n.a, t.n.a), q::add(q::add(b2, b2), rotated));
  t.m = q::add(q::mul(t.d.a, t.d.a), q::mul(t.d.b, t.d.b));
  return t;
}
__device__ __forceinline__ OM31 ascend(const OM31 &a, const Tower &t,
                                       uint32_t m_inv) {
  const q::CM31 d_inv{q::mul(t.d.a, m_inv), q::mul(q::neg(t.d.b), m_inv)};
  const q::QM31 n_inv{q::mul(t.n.a, d_inv), q::neg(q::mul(t.n.b, d_inv))};
  return {q::mul(a.c0, n_inv), q::mul(q::sub(q::zero(), a.c1), n_inv)};
}
// In place: m[k] <- m[k]^-1 for K nonzero canonical M31 values.
template <uint32_t K> __device__ __forceinline__ void batch_inverse(uint32_t (&m)[K]) {
  uint32_t prefix[K], acc = 1;
#pragma unroll
  for (uint32_t k = 0; k < K; ++k) {
    prefix[k] = acc;
    acc = q::mul(acc, m[k]);
  }
  uint32_t inv = q::inverse(acc);
#pragma unroll
  for (int k = int(K) - 1; k >= 0; --k) {
    const uint32_t mk = m[k];
    m[k] = q::mul(inv, prefix[k]);
    inv = q::mul(inv, mk);
  }
}
// One pair plane over K rows per thread (rows base + k*blockDim + tid).
// Same substitution and status bits as global_inverse_contribute. Padding rows
// (past 2^row_log) use d = 1 and are neither loaded nor stored.
template <uint32_t K, bool Sum>
__device__ __forceinline__ void invert_pair(const StwoRv64GlobalPairs &j,
                                            uint64_t pair_offset, uint32_t base,
                                            OM31 (&sum)[K]) {
  const uint32_t rows = 1u << j.row_log;
  OM31 d[K];
  Tower t[K];
  uint32_t m[K], invalid = 0;
#pragma unroll
  for (uint32_t k = 0; k < K; ++k) {
    const uint32_t row = base + k * blockDim.x;
    d[k] = one();
    if (row < rows) {
      d[k] = load(j.output + pair_offset, j.stride, row);
      const OM31 n = load(j.contributions + pair_offset, j.stride, row);
      if (!canonical(d[k]) || !canonical(n)) {
        atomicOr(j.status, 2u);
        d[k] = one();
        invalid |= 1u << k;
      }
      if (is_zero(d[k])) {
        atomicOr(j.status, 4u);
        d[k] = one();
        invalid |= 1u << k;
      }
    }
    t[k] = descend(d[k]);
    m[k] = t[k].m;
  }
  batch_inverse<K>(m);
#pragma unroll
  for (uint32_t k = 0; k < K; ++k) {
    const uint32_t row = base + k * blockDim.x;
    if (row >= rows)
      continue;
    const OM31 inverse = ascend(d[k], t[k], m[k]);
    // n is re-read (L1/L2 hit) instead of held across the inversion: it keeps
    // 8 registers per row free. Invalid rows use n = 0, as the original.
    const OM31 n = (invalid >> k) & 1u
                       ? zero()
                       : load(j.contributions + pair_offset, j.stride, row);
    const OM31 c = mul(n, inverse);
    store(j.output + pair_offset, j.stride, row, inverse);
    store(j.contributions + pair_offset, j.stride, row, c);
    if constexpr (Sum)
      sum[k] = add(sum[k], c);
  }
}
// 2-D grid (row blocks, pairs); the row sum stays in global_row_sum.
template <uint32_t K>
__global__ void __launch_bounds__(128) inverse_contribute(StwoRv64GlobalPairs j) {
  OM31 unused[K];
  invert_pair<K, false>(j, uint64_t(blockIdx.y) * 8 * j.stride,
                        blockIdx.x * K * blockDim.x + threadIdx.x, unused);
}
// 1-D grid over rows; every pair plane, then the row sum (global_row_sum's
// plane j.pairs) from registers: one HBM pass instead of two.
template <uint32_t K>
__global__ void __launch_bounds__(128) inverse_contribute_sum(StwoRv64GlobalPairs j) {
  const uint32_t base = blockIdx.x * K * blockDim.x + threadIdx.x,
                 rows = 1u << j.row_log;
  OM31 sum[K];
#pragma unroll
  for (uint32_t k = 0; k < K; ++k)
    sum[k] = zero();
  for (uint32_t pair = 0; pair < j.pairs; ++pair)
    invert_pair<K, true>(j, uint64_t(pair) * 8 * j.stride, base, sum);
#pragma unroll
  for (uint32_t k = 0; k < K; ++k)
    if (base + k * blockDim.x < rows)
      store(j.output + uint64_t(j.pairs) * 8 * j.stride, j.stride,
            base + k * blockDim.x, sum[k]);
}
} // namespace t8k
} // namespace stwo::cuda::rv64
// Rows per thread K. Whole global_pairs launcher, CUDA events, median of 7
// [M, 5090], K=1/2/4: 2^20x13 1.439/1.400/1.394 ms, 2^23x2 2.351/2.282/2.247,
// 2^18x13 0.346/0.344/0.366 (old 3.517, 7.389, 0.903). K=2: never worst.
// Fused (1-D, row sum in registers) iff >= STWO_T8_FUSED_MIN_BLOCKS blocks of
// K*128 rows; 2-D + global_row_sum below. fused vs 2-D [M]: 2^16x13 0.077 vs
// 0.065 ms, 2^17x13 0.137 vs 0.116, 2^18x13 0.339 vs 0.368, 2^19x13 0.708 vs
// 0.786, 2^20x13 1.398 vs 1.568, 2^22x2 1.163 vs 1.289 (2^20x2 0.245 vs
// 0.233 is the one loss). 1024 blocks = fused from 2^18 rows.
#ifndef STWO_T8_ROWS_PER_THREAD
#define STWO_T8_ROWS_PER_THREAD 2
#endif
#ifndef STWO_T8_FUSED_MIN_BLOCKS
#define STWO_T8_FUSED_MIN_BLOCKS 1024
#endif
int stwo::cuda::rv64::t8::global_pairs(void *ctx, uint32_t lane,
                                       const StwoRv64GlobalPairs *input,
                                       int mode) {
  using namespace stwo::cuda::rv64;
  if (mode != 0 && mode != 1)
    return int(cudaErrorInvalidValue);
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
  constexpr uint32_t K = STWO_T8_ROWS_PER_THREAD;
  const uint32_t t8_blocks = (rows + K * 128 - 1) / (K * 128);
  if (mode == 1 && t8_blocks >= STWO_T8_FUSED_MIN_BLOCKS) {
    t8k::inverse_contribute_sum<K><<<t8_blocks, 128, 0, c.stream>>>(j);
  } else {
    if (mode == 1)
      t8k::inverse_contribute<K><<<dim3(t8_blocks, j.pairs), 128, 0, c.stream>>>(j);
    else
      global_inverse_contribute<<<dim3((rows + 127) / 128, j.pairs), 128, 0,
                                  c.stream>>>(j);
    global_row_sum<<<(rows + 127) / 128, 128, 0, c.stream>>>(j);
  }
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
  return t8::prefix_scan(ctx, lane, &scan, mode);
}
extern "C" int stwo_rv64_global_pairs_on(void *ctx, uint32_t lane,
                                         const StwoRv64GlobalPairs *input) {
  return stwo::cuda::rv64::t8::global_pairs(ctx, lane, input,
                                            stwo::cuda::rv64::t8::mode());
}

extern "C" int stwo_rv64_global_contributions_scan_v1_on(void *ctx,uint32_t lane,const StwoRv64GlobalPairs *input) {
  using namespace stwo::cuda::rv64;
  if(!input||input->reserved[0]||input->reserved[1]||input->contributions!=input->output||
     input->row_log<4||input->row_log>27||!input->pairs||input->pairs>13||
     input->stride<(1u<<input->row_log)||input->stride>SIZE_MAX/(8*uint64_t(input->pairs+1)))return int(cudaErrorInvalidValue);
  const auto j=*input;const uint32_t rows=1u<<j.row_log;uint64_t need_scan=0;
  for(uint32_t count=rows;count>1;){count=(count+127)/128;need_scan+=uint64_t(count)*8;}
  if(j.scan_words<need_scan)return int(cudaErrorInvalidValue);
  Custody c(ctx,lane);
  if(!c.range(j.output,uint64_t(j.pairs+1)*8*j.stride,true)||
     !c.range(j.scan_scratch,need_scan,true)||!c.range(j.claim,8,true)||!c.range(j.status,1,true))return c.status;
  global_row_sum<<<(rows+127)/128,128,0,c.stream>>>(j);
  const int dispatched=int(cudaPeekAtLastError());if(dispatched)return dispatched;
  StwoRv64PrefixScan scan{{j.output+uint64_t(j.pairs)*8*j.stride,j.stride,8,0},j.scan_scratch,need_scan,j.claim,j.status,j.row_log,1,{0,0}};
  return stwo_rv64_prefix_scan_on(ctx,lane,&scan);
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
