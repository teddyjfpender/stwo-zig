#include "composition_finalize.h"
#include "custody.cuh"
extern "C" int
stwo_ntt_b2n_om31_composition_split_on(uint32_t *, size_t, uint32_t *, size_t,
                                       uint32_t, uint32_t, const uint32_t *,
                                       uint32_t, void *, uint32_t *);
extern "C" int
stwo_rv64_composition_finalize_on(void *ctx, uint32_t lane, uint32_t *input,
                                  uint32_t *output, uint32_t log,
                                  uint32_t depth, const uint32_t *twiddles,
                                  uint32_t twiddle_words, uint32_t *launches) {
  using namespace stwo::cuda::rv64;
  if (launches)
    *launches = 0;
  if (!launches || log < 3 || log > 28 || depth < 1 || depth > 2 ||
      log <= depth + 1 || twiddle_words < (1u << (log - 1)))
    return int(cudaErrorInvalidValue);
  const uint64_t words = uint64_t(8) << log;
  Custody c(ctx, lane);
  if (!c.range(input, words, true) || !c.range(output, words, true) ||
      !c.range(twiddles, twiddle_words, false))
    return c.status;
  return stwo_ntt_b2n_om31_composition_split_on(
      input, words, output, words, log, depth, twiddles, twiddle_words,
      c.stream, launches);
}

#include "om31.cuh"
namespace {
__global__ void lift_add(const uint32_t *input, uint32_t *output,
                         uint32_t source_log, uint32_t target_log) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t rows = 1u << target_log;
  if (row >= rows) return;
  const uint32_t shift = target_log - source_log;
  const uint32_t source = ((row >> (shift + 1)) << 1) | (row & 1);
  for (uint32_t c = 0; c < 8; ++c) {
    const uint64_t dst = uint64_t(c) * rows + row;
    const uint64_t src = (uint64_t(c) << source_log) + source;
    output[dst] = stwo::cuda::rv64::q::add(output[dst], input[src]);
  }
}
}
extern "C" int stwo_rv64_composition_lift_add_on(
    void *ctx, uint32_t lane, const uint32_t *input, uint32_t source_log,
    uint32_t *output, uint32_t target_log, uint32_t *launches) {
  using namespace stwo::cuda::rv64;
  if (launches) *launches = 0;
  if (!launches || source_log < 3 || target_log < source_log || target_log > 28)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(input, uint64_t(8) << source_log, false) ||
      !c.range(output, uint64_t(8) << target_log, true)) return c.status;
  lift_add<<<((1u << target_log) + 127) / 128, 128, 0, c.stream>>>(
      input, output, source_log, target_log);
  const int status = int(cudaGetLastError());
  if (!status) *launches = 1;
  return status;
}
extern "C" int stwo_rv64_composition_finish_on(
    void *ctx, uint32_t lane, const StwoRv64CompositionBucket *buckets,
    uint32_t count, uint32_t *accumulator, uint32_t *coefficients,
    uint32_t log, uint32_t depth, const uint32_t *twiddles,
    uint32_t twiddle_words, uint32_t *launches) {
  using namespace stwo::cuda::rv64;
  if (launches) *launches = 0;
  if (!launches || !buckets || !count || count > 49 || log < 3 || log > 28 ||
      depth < 1 || depth > 2 || log <= depth + 1 ||
      twiddle_words < (1u << (log - 1))) return int(cudaErrorInvalidValue);
  RangeCustody<64> c(ctx, lane);
  const uint64_t words = uint64_t(8) << log;
  for (uint32_t i = 0; i < count; ++i) {
    if (buckets[i].reserved || buckets[i].log < 3 || buckets[i].log > log)
      return int(cudaErrorInvalidValue);
    if (!c.range(buckets[i].words, uint64_t(8) << buckets[i].log, false)) return c.status;
  }
  if (!c.range(accumulator, words, true) || !c.range(coefficients, words, true) ||
      !c.range(twiddles, twiddle_words, false)) return c.status;
  int status = int(cudaMemsetAsync(accumulator, 0, words * sizeof(uint32_t), c.stream));
  if (status) return status;
  for (uint32_t i = 0; i < count; ++i) {
    lift_add<<<((1u << log) + 127) / 128, 128, 0, c.stream>>>(
        buckets[i].words, accumulator, buckets[i].log, log);
    status = int(cudaGetLastError());
    if (status) return status;
    ++*launches;
  }
  uint32_t split_launches = 0;
  status = stwo_ntt_b2n_om31_composition_split_on(
      accumulator, words, coefficients, words, log, depth, twiddles,
      twiddle_words, c.stream, &split_launches);
  *launches += split_launches;
  return status;
}
namespace {
__global__ void fill_auxiliary(const uint32_t *hc, uint32_t *out, uint32_t log) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x, n = 1u << log;
  if (row >= n) return;
  const uint32_t half = row & 1, bits = half ? row : (n - 1) ^ row;
  // Exactly public_aux.zig carryIndex: these bits are always odd/nonzero.
  const uint32_t carry = __clz(bits) - (32 - log);
  out[row] = row == 0;
  out[uint64_t(n) + row] = row + 1 == n;
  for (uint32_t c = 0; c < 8; ++c)
    out[uint64_t(c + 2) * n + row] = hc[(half * log + carry) * 8 + c];
}
}
extern "C" int stwo_rv64_composition_auxiliary_on(
    void *ctx, uint32_t lane, const uint32_t *hc, uint32_t *output,
    uint32_t log, uint32_t *launches) {
  using namespace stwo::cuda::rv64;
  if (launches) *launches = 0;
  if (!launches || log < 3 || log > 27) return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(hc, 16 * log, false) || !c.range(output, uint64_t(10) << log, true)) return c.status;
  fill_auxiliary<<<((1u << log) + 127) / 128, 128, 0, c.stream>>>(hc, output, log);
  const int status = int(cudaGetLastError());
  if (!status) *launches = 1;
  return status;
}
