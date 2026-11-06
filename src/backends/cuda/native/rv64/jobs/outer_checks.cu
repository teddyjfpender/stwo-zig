// Device acceptance checks of an outer (leaf / fold / root) node (M8 GPU-native,
// design rv64-m8-gpu-native.md §3.5; recursion range of gpu_native.Check).
//
// lookup_sum (Check 0x0302): the node's LogUp closure, on device, from the
// node's own outer slab section (canonical claims, z, alpha written by the
// node body) and its expected public outputs (staged node region). Host
// reference: circuit_cpu/om31/witness.zig lookupSum, called by
// jobs/outer_job.zig decode():
//
//   sum = sum_c claims[c]
//       + sum_i 1 / combine(GATE, U_VAR_IDX + 1 + i, output_i)
//       + 1 / combine(GATE, U_VAR_IDX, U_VALUE)
//   combine(t) = sum_k alpha^k * t[k] - z        (k < 6 = MAX_TUPLE)
//
// The node is accepted iff every input is canonical, no denominator is zero
// (the host `inv()` fails there) and sum == 0. Field arithmetic is exact
// (om31.cuh is the host basis), so the verdict is the host's verdict. One
// thread; it writes exactly one Verdict word (gpu_native.zig): 0 accepted,
// (0x0302 << 16) | detail rejected, followed by the caller's per-node tag (the
// job slab is not cleared between jobs: finish accepts the verdict only next
// to its own node's tag). Enqueue only, no sync, no readback.
#include "rv64/custody.cuh"
#include "rv64/om31.cuh"
#include <stdint.h>

struct StwoRv64OuterLookupConstants {
  uint32_t relation;    // component_list.GATE_RELATION_ID
  uint32_t u_index;     // witness/trace.zig U_VAR_IDX
  uint32_t u_value[4];  // witness/trace.zig U_VALUE limbs
  uint32_t n_outputs;
  uint32_t n_claims;    // 11 (Plan.n_components)
  uint32_t tag;         // per-node tag echoed next to the verdict (stale-slab guard)
  uint32_t reserved[3];
};
static_assert(sizeof(StwoRv64OuterLookupConstants) == 48, "outer lookup constants ABI");

namespace stwo::cuda::rv64 {
namespace {
constexpr uint32_t kLookupSum = 0x0302u;
enum Detail : uint32_t {
  kNoncanonicalChallenge = 1,
  kNoncanonicalClaim = 2,
  kZeroDenominator = 3,
  kNoncanonicalOutput = 4,
  kNonzeroSum = 5,
  kBadShape = 6,
};
__device__ __forceinline__ uint32_t reduce(uint64_t x) {
  return uint32_t(x % q::kPrime);
}
__device__ __forceinline__ bool term(const OM31 powers[6], OM31 z, uint32_t relation,
                                     uint32_t address, const uint32_t limbs[4], OM31 &sum) {
  const uint32_t tuple[6] = {reduce(relation), reduce(address), limbs[0], limbs[1], limbs[2], limbs[3]};
  OM31 d = zero();
  for (uint32_t k = 0; k < 6; ++k) d = add(d, scale(powers[k], tuple[k]));
  d = sub(d, z);
  if (is_zero(d)) return false;
  sum = add(sum, inverse_nonzero(d));
  return true;
}
}  // namespace

__global__ void outer_lookup_sum_check(const uint32_t *claims, const uint32_t *z_alpha,
                                       const uint32_t *expected,
                                       StwoRv64OuterLookupConstants c, uint32_t *verdict) {
  if (blockIdx.x || threadIdx.x) return;
  uint32_t detail = 0;
  const OM31 z = from_words(z_alpha), alpha = from_words(z_alpha + 8);
  if (!canonical(z) || !canonical(alpha)) detail = kNoncanonicalChallenge;
  OM31 powers[6];
  powers[0] = one();
  for (uint32_t k = 1; k < 6; ++k) powers[k] = mul(powers[k - 1], alpha);
  OM31 sum = zero();
  for (uint32_t i = 0; i < c.n_claims && !detail; ++i) {
    const OM31 claim = from_words(claims + 8 * i);
    if (!canonical(claim)) detail = kNoncanonicalClaim;
    sum = add(sum, claim);
  }
  for (uint32_t k = 0; k < 4 && !detail; ++k)
    if (c.u_value[k] >= q::kPrime) detail = kNoncanonicalOutput;
  for (uint32_t i = 0; i < c.n_outputs && !detail; ++i) {
    const uint32_t *limbs = expected + 4 * uint64_t(i);
    for (uint32_t k = 0; k < 4; ++k)
      if (limbs[k] >= q::kPrime) detail = kNoncanonicalOutput;
    if (!detail && !term(powers, z, c.relation, c.u_index + 1 + i, limbs, sum)) detail = kZeroDenominator;
  }
  if (!detail && !term(powers, z, c.relation, c.u_index, c.u_value, sum)) detail = kZeroDenominator;
  if (!detail && !is_zero(sum)) detail = kNonzeroSum;
  verdict[0] = detail ? ((kLookupSum << 16) | detail) : 0u;
  verdict[1] = c.tag;
}
}  // namespace stwo::cuda::rv64

// claims: n_claims x 8 words; z_alpha: 16 words; expected: n_outputs x 4 words
// (may be absent when n_outputs == 0); verdict: 1 word. All job-arena / slab
// memory of `context` (custody-checked), stream = the lane's exec stream.
extern "C" int stwo_rv64_outer_lookup_sum_check_v1_on(void *context, uint32_t lane,
                                                      const uint32_t *claims,
                                                      const uint32_t *z_alpha,
                                                      const uint32_t *expected,
                                                      const StwoRv64OuterLookupConstants *constants,
                                                      uint32_t *verdict) {
  using namespace stwo::cuda::rv64;
  if (!constants || !constants->n_claims || constants->n_claims > 64 || constants->n_outputs > 4096)
    return int(cudaErrorInvalidValue);
  RangeCustody<4> custody(context, lane);
  if (!custody.range(claims, uint64_t(constants->n_claims) * 8, false) ||
      !custody.range(z_alpha, 16, false) ||
      (constants->n_outputs && !custody.range(expected, uint64_t(constants->n_outputs) * 4, false)) ||
      !custody.range(verdict, 2, true))
    return custody.status;
  outer_lookup_sum_check<<<1, 1, 0, custody.stream>>>(claims, z_alpha, expected, *constants, verdict);
  return int(cudaPeekAtLastError());
}

// Host-side ABI probe (no device): lets the Zig loader refuse a stale addon.
extern "C" uint32_t stwo_rv64_outer_checks_version(void) {
  return 1;
}
