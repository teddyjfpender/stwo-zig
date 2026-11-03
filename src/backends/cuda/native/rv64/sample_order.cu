#include "custody.cuh"
#include "sample_order.h"
namespace stwo::cuda::rv64 {
__global__ void sample_order(const uint32_t *input, uint32_t sources,
                             const uint32_t *map, uint32_t count,
                             uint32_t *output, uint32_t *status) {
  const uint32_t word = blockIdx.x * blockDim.x + threadIdx.x;
  if (word >= count * 8)
    return;
  const uint32_t index = map[word / 8];
  uint32_t value = 0;
  if (index >= sources)
    atomicOr(status, 1u);
  else {
    value = input[uint64_t(index) * 8 + (word & 7u)];
    if (value >= 0x7fffffffu) {
      value = 0;
      atomicOr(status, 2u);
    }
  }
  output[word] = value;
}
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_sample_order_on(void *ctx, uint32_t lane,
                                         const uint32_t *input,
                                         uint32_t sources, const uint32_t *map,
                                         uint32_t count, uint32_t *output,
                                         uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (!sources || sources > 65536 || !count || count > 65536)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(input, uint64_t(sources) * 8, false) ||
      !c.range(map, count, false) ||
      !c.range(output, uint64_t(count) * 8, true) || !c.range(status, 1, true))
    return c.status;
  sample_order<<<(count * 8 + 127) / 128, 128, 0, c.stream>>>(
      input, sources, map, count, output, status);
  return int(cudaPeekAtLastError());
}
