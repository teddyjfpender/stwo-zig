// M8 native-producers parity helper (addon, enqueue only): count word
// mismatches between two device ranges of the job's exec context. Used by
// the real-block parity harness to compare a job producer's device output
// with the legacy stage's output (copied into the job arena first). Writes
// out[0] = mismatch count, out[1] = first mismatching index (0xffffffff if none).
#include <cstdint>
#include "rv64/custody.cuh"
namespace {
using namespace stwo::cuda::rv64;
__global__ void job_native_compare_init(uint32_t *out) {
  out[0] = 0;
  out[1] = 0xffffffffu;
}
__global__ void job_native_compare(const uint32_t *a, const uint32_t *b, uint64_t words, uint32_t *out) {
  const uint64_t stride = uint64_t(gridDim.x) * blockDim.x;
  for (uint64_t i = uint64_t(blockIdx.x) * blockDim.x + threadIdx.x; i < words; i += stride) {
    if (a[i] != b[i]) {
      atomicAdd(out, 1u);
      atomicMin(out + 1, i < 0xffffffffull ? uint32_t(i) : 0xfffffffeu);
    }
  }
}
} // namespace
extern "C" int stwo_rv64_jobs_native_compare_v1(void *ctx, uint32_t lane, const uint32_t *a,
                                                const uint32_t *b, uint64_t words, uint32_t *out) {
  RangeCustody<4> c(ctx, lane);
  if (words == 0 || !c.range(a, words, false) || !c.range(b, words, false) || !c.range(out, 2, true))
    return c.status;
  job_native_compare_init<<<1, 1, 0, c.stream>>>(out);
  job_native_compare<<<1024, 256, 0, c.stream>>>(a, b, words, out);
  return int(cudaPeekAtLastError());
}
