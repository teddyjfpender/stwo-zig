#pragma once
#include "batch_state.cuh"
namespace stwo::cuda::rv64 {
struct BatchJobs {
  StwoRv64BatchOracle oracles[max_oracles];
  uint32_t count, variables;
};
// 128 oracles (batch.h): 3,080 bytes.
static_assert(sizeof(BatchJobs) < 4096, "bounded launch metadata");
// One authority for legacy and persistent mixed-oracle transcript transitions.
__device__ __forceinline__ void advance_batch_round(BatchState *s, const BatchJobs &jobs,
    uint32_t expected, const uint32_t *point, RoundRecord *record) {
  if (!prepare_record(&s->round, jobs.variables, record))
    return;
  if (s->count != jobs.count || expected >= jobs.variables ||
      s->round.next_round != expected) {
    s->round.status = round_order;
    return;
  }
  for (uint32_t i = 0; i < jobs.count; ++i)
    if (s->initial_variables[i] != jobs.oracles[i].variables) {
      s->round.status = round_order;
      return;
    }
  const uint32_t remaining = jobs.variables - expected;
  Pair raw{zero(), zero()};
  OM31 sleeping_constant = zero();
  for (uint32_t i = 0; i < jobs.count; ++i) {
    if (jobs.oracles[i].variables < remaining) {
      sleeping_constant =
          add(sleeping_constant, scale(s->sleeping_claims[i], 1073741824u));
    } else {
      const auto &job = jobs.oracles[i];
      const OM31 a = load(job.raw, job.raw_stride, 0),
                 b = load(job.raw, job.raw_stride, 1);
      if (!canonical(a) || !canonical(b)) {
        s->round.status = round_field;
        return;
      }
      const OM31 weight = mul(s->weights[i], s->corrections[i]);
      raw.at0 = add(raw.at0, mul(weight, a));
      raw.at2 = add(raw.at2, mul(weight, b));
    }
  }
  // Interpolation is linear. Correct the active weighted sum once, add the
  // native half-claim constant for sleeping oracles, then draw ONE challenge.
  // Per-oracle Eq corrections start only when that oracle becomes active.
  s->round.correction = one();
  const OM31 y = from_words(point + 8 * expected);
  if (!advance_round_with_constant(&s->round, expected, raw, y, record,
                                   sleeping_constant))
    return;
  const OM31 eq = add(mul(sub(one(), record->challenge), sub(one(), y)),
                      mul(record->challenge, y));
  for (uint32_t i = 0; i < jobs.count; ++i) {
    if (jobs.oracles[i].variables < remaining)
      s->sleeping_claims[i] = scale(s->sleeping_claims[i], 1073741824u);
    else
      s->corrections[i] = mul(s->corrections[i], eq);
  }
  s->round.correction = one();
}
} // namespace stwo::cuda::rv64
