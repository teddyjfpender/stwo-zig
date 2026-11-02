#include "custody.cuh"
#include "om31.cuh"
#include "parameters.h"
namespace stwo::cuda::rv64 {
constexpr uint32_t slots =
    STWO_RV64_RELATION_COUNT * STWO_RV64_RELATION_SLOT_STRIDE;
struct Map {
  uint32_t source[slots];
  uint32_t count;
};
static_assert(sizeof(Map) < 4096, "bounded immutable parameter metadata");
__global__ void gather(const uint32_t *source, uint32_t *out, Map map,
                       uint32_t *status) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= map.count * 8)
    return;
  const uint32_t value = source[8 * map.source[i / 8] + i % 8];
  if (value >= q::kPrime) {
    atomicOr(status, 1u);
    out[i] = 0;
  } else
    out[i] = value;
}
} // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int
stwo_rv64_parameter_gather_on(void *ctx, uint32_t lane, const uint32_t *source,
                              uint32_t *output, const uint32_t *indices,
                              uint32_t count, uint32_t namespaces,
                              uint32_t *status) {
  if (!indices || !count || count > slots ||
      (namespaces != 9 && namespaces != 10))
    return int(cudaErrorInvalidValue);
  constexpr uint32_t arities[10] = {6, 30, 13, 19, 1, 1, 3, 6, 5, 4};
  Map map{};
  map.count = count;
  for (uint32_t i = 0; i < count; ++i) {
    const uint32_t relation = indices[i] / STWO_RV64_RELATION_SLOT_STRIDE;
    const uint32_t coordinate = indices[i] % STWO_RV64_RELATION_SLOT_STRIDE;
    if (relation >= namespaces || coordinate > arities[relation] ||
        (relation == 5 && coordinate != 0))
      return int(cudaErrorInvalidValue);
    map.source[i] = indices[i];
  }
  Custody c(ctx, lane);
  if (!c.range(source, uint64_t(slots) * 8, false) ||
      !c.range(output, uint64_t(count) * 8, true) || !c.range(status, 1, true))
    return c.status;
  gather<<<(count * 8 + 127) / 128, 128, 0, c.stream>>>(source, output, map,
                                                        status);
  return int(cudaPeekAtLastError());
}
