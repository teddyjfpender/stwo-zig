// Device OODS point + PCS base point. See jobs/oods_points.h. Same arithmetic
// as samples.cu sample_base and the sample_points shift (enqueue only).
#include "rv64/jobs/oods_points.h"
#include "rv64/custody.cuh"
#include "rv64/om31.cuh"
namespace {
using namespace stwo::cuda::rv64;
__device__ void put(uint32_t *words, OM31 value) {
  for (uint32_t i = 0; i < 8; ++i) words[i] = coordinate(value, i);
}
__global__ void job_oods_points(const uint32_t *draw, uint32_t sx, uint32_t sy,
                                uint32_t *out, uint32_t *status) {
  for (uint32_t i = 0; i < 32; ++i) out[i] = 0;
  *status = 0;
  const OM31 t = from_words(draw);
  if (!canonical(t) || sx >= q::kPrime || sy >= q::kPrime) {
    *status = 2u;
    return;
  }
  if (q::add(q::mul(sx, sx), q::mul(sy, sy)) != 1) {
    *status = 4u;
    return;
  }
  const OM31 t2 = mul(t, t), denominator = add(one(), t2);
  if (is_zero(denominator)) {
    *status = 4u;
    return;
  }
  const OM31 reciprocal = inverse_nonzero(denominator);
  const OM31 x = mul(sub(one(), t2), reciprocal), y = mul(add(t, t), reciprocal);
  put(out, x);
  put(out + 8, y);
  put(out + 16, sub(scale(x, sx), scale(y, sy)));
  put(out + 24, add(scale(x, sy), scale(y, sx)));
}
} // namespace
extern "C" int stwo_rv64_job_oods_points_v1(void *ctx, uint32_t lane, const uint32_t *draw,
                                            uint32_t shift_x, uint32_t shift_y,
                                            uint32_t *out, uint32_t *status) {
  RangeCustody<4> c(ctx, lane);
  if (!c.range(draw, 8, false) || !c.range(out, 32, true) || !c.range(status, 1, true))
    return c.status;
  job_oods_points<<<1, 1, 0, c.stream>>>(draw, shift_x, shift_y, out, status);
  return int(cudaPeekAtLastError());
}
