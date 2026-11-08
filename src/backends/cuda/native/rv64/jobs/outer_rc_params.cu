// Outer composition role parameters on the device (M8 outer-job). The legacy
// controller computes them on the host from the drawn z, alpha and the 11
// claims (circuit_cpu/om31/program_lane.zig extensionParameters):
//   constant        -> embed(QM31 constant)            (precomputed: words)
//   lookup_z        -> z
//   alpha^n         -> alpha^n
//   alpha^n * s     -> alpha^n scaled by the M31 s
//   claim * 2^-log  -> claims[component] scaled by the M31 inverse
// Field arithmetic is exact, so the device values are the host values. The
// table is class-static (built in pre-stage); z/alpha/claims never leave the
// device. Enqueue only; one thread per parameter.
#include "rv64/custody.cuh"
#include "rv64/om31.cuh"
#include <stdint.h>

struct StwoRv64OuterRcParam {
  uint32_t kind;      // 0 constant, 1 z, 2 alpha^n, 3 alpha^n * scale, 4 claim * scale
  uint32_t power;     // n for kinds 2, 3
  uint32_t scale;     // canonical M31 for kinds 3, 4
  uint32_t component; // claim index for kind 4
  uint32_t constant[8];
  uint32_t reserved[4];
};
static_assert(sizeof(StwoRv64OuterRcParam) == 64, "outer RC parameter ABI");

namespace stwo::cuda::rv64 {
__global__ void outer_rc_parameters(const StwoRv64OuterRcParam *table, uint32_t count,
                                    const uint32_t *z_alpha, const uint32_t *claims,
                                    uint32_t *out, uint32_t *status) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= count) return;
  const StwoRv64OuterRcParam p = table[i];
  const OM31 z = from_words(z_alpha), alpha = from_words(z_alpha + 8);
  OM31 v = zero();
  bool ok = canonical(z) && canonical(alpha) && p.kind <= 4;
  if (p.kind == 0) {
    v = from_words(p.constant);
    ok = ok && canonical(v);
  } else if (p.kind == 1) {
    v = z;
  } else if (p.kind == 2 || p.kind == 3) {
    OM31 base = alpha, acc = one();
    for (uint32_t e = p.power; e; e >>= 1) {
      if (e & 1u) acc = mul(acc, base);
      base = mul(base, base);
    }
    v = p.kind == 3 ? scale(acc, p.scale) : acc;
    ok = ok && (p.kind == 2 || p.scale < 0x7fffffffu);
  } else if (p.kind == 4) {
    ok = ok && p.component < 11 && p.scale < 0x7fffffffu;
    if (ok) {
      const OM31 claim = from_words(claims + 8 * p.component);
      ok = canonical(claim);
      v = scale(claim, p.scale);
    }
  }
  if (!ok) {
    atomicOr(status, 1u);
    v = zero();
  }
  store(out + 8 * uint64_t(i), 1, 0, v);
}
} // namespace stwo::cuda::rv64

extern "C" int stwo_rv64_outer_rc_parameters_v1_on(void *context, uint32_t lane,
                                                   const StwoRv64OuterRcParam *table,
                                                   uint32_t count, const uint32_t *z_alpha,
                                                   const uint32_t *claims, uint32_t *out,
                                                   uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (!count || count > (1u << 20) || !table) return int(cudaErrorInvalidValue);
  Custody custody(context, lane);
  if (!custody.range(z_alpha, 16, false) || !custody.range(claims, 88, false) ||
      !custody.range(out, uint64_t(count) * 8, true) || !custody.range(status, 1, true) ||
      !custody.range(reinterpret_cast<const uint32_t *>(table), uint64_t(count) * 16, false))
    return custody.status;
  outer_rc_parameters<<<(count + 127) / 128, 128, 0, custody.stream>>>(table, count, z_alpha,
                                                                       claims, out, status);
  return int(cudaPeekAtLastError());
}
