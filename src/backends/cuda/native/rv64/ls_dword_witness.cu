#include "custody.cuh"
#include "ls_dword_witness.h"
namespace stwo::cuda::rv64 {
__global__ void ls_dword_witness(const uint32_t *events, uint32_t count,
                                 uint32_t log, uint32_t *main,
                                 uint32_t *status) {
  const uint32_t physical = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t n = 1u << log;
  if (physical >= n)
    return;
  // Write adjacent physical rows in each warp. The compact logical-event
  // reads fit in the cache; scattering all 39 output stores would not.
  const uint32_t circle = __brev(physical) >> (32 - log);
  const uint32_t logical =
      circle < n / 2 ? 2 * circle : 2 * (n - 1 - circle) + 1;
  uint32_t values[79]{};
  if (logical < count) {
    const auto *e = events + uint64_t(logical) * 14;
    const uint64_t a = uint64_t(e[0]) | (uint64_t(e[1]) << 32);
    const uint64_t imm = uint64_t(e[2]) | (uint64_t(e[3]) << 32);
    const uint64_t b = uint64_t(e[4]) | (uint64_t(e[5]) << 32);
    const uint64_t before = uint64_t(e[6]) | (uint64_t(e[7]) << 32);
    const uint64_t ea = a + imm;
    const uint32_t old_epoch = e[8], epoch = e[9], old_tick = e[10],
                   tick = e[11], rights = e[12], store = e[13];
    const bool same = old_epoch == epoch;
    const bool valid =
        old_epoch <= 65535 && epoch <= 65535 && old_epoch <= epoch &&
        old_tick < (1u << 24) && tick < (1u << 24) && tick &&
        (!same || old_tick < tick) && rights <= 3 && store <= 1 &&
        (rights & (store ? 2u : 1u)) && (!store ? b == 0 : true) && !(ea & 7);
    if (!valid)
      atomicOr(status, 1u);
    else {
      const uint64_t after = store ? b : before;
      values[0] = 1;
      values[1] = store;
      values[2] = same;
      values[8] = old_epoch;
      values[9] = epoch;
      values[10] = old_tick & 65535;
      values[11] = old_tick >> 16;
      values[12] = tick & 65535;
      values[13] = tick >> 16;
      values[22] = rights & 1;
      values[23] = rights >> 1;
      if (same) {
        const uint32_t gap = tick - old_tick - 1;
        values[25] = gap & 65535;
        values[26] = gap >> 16;
        values[27] = ((old_tick & 65535) + (gap & 65535) + 1) >> 16;
      } else
        values[24] = epoch - old_epoch - 1;
      values[68] = (ea & 65535) / 8;
      uint32_t carry = 0;
#pragma unroll
      for (uint32_t i = 0; i < 4; ++i) {
        const uint32_t av = (a >> (16 * i)) & 65535;
        const uint32_t iv = (imm >> (16 * i)) & 65535;
        values[4 + i] = (ea >> (16 * i)) & 65535;
        values[14 + i] = (before >> (16 * i)) & 65535;
        values[18 + i] = (after >> (16 * i)) & 65535;
        values[28 + i] = av;
        values[36 + i] = (b >> (16 * i)) & 65535;
        carry = (av + iv + carry) >> 16;
        values[75 + i] = carry;
      }
    }
  }
  constexpr uint32_t stored[] = {0,  1,  2,  5,  6,  7,  8,  9,  10, 11,
                                 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                                 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                                 36, 37, 38, 39, 68, 75, 76, 77, 78};
#pragma unroll
  for (uint32_t c = 0; c < 39; ++c)
    main[uint64_t(c) * n + physical] = values[stored[c]];
}
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_ls_dword_witness_on(void *ctx, uint32_t lane,
                                             const uint32_t *events,
                                             uint32_t count, uint32_t log,
                                             uint32_t *main, uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (log < 5 || log > 22 || count >= (1u << log))
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if ((count && !c.range(events, uint64_t(count) * 14, false)) ||
      !c.range(main, uint64_t(39) << log, true) || !c.range(status, 1, true))
    return c.status;
  ls_dword_witness<<<((1u << log) + 127) / 128, 128, 0, c.stream>>>(
      events, count, log, main, status);
  return int(cudaPeekAtLastError());
}
