// Mixed-height native LogUp sumcheck: one polynomial and challenge per round.
#include "batch_state.cuh"
#include "custody.cuh"
#include "round.cuh"
namespace stwo::cuda::rv64 {
struct BatchJobs {
  StwoRv64BatchOracle oracles[max_oracles];
  uint32_t count, variables;
};
static_assert(sizeof(BatchJobs) < 2048, "bounded launch metadata");
__global__ void batch_init(uint32_t *words, const uint32_t *seed,
                           const uint32_t *claims, const uint32_t *alpha_words,
                           BatchJobs jobs) {
  auto *s = reinterpret_cast<BatchState *>(words);
  const OM31 alpha = from_words(alpha_words);
  bool valid = canonical(alpha);
  for (uint32_t i = 0; i < jobs.count; ++i)
    valid = valid && canonical(from_words(claims + 8 * i));
  for (uint32_t i = 0; i < 9; ++i)
    s->initial_seed[i] = seed[i];
  s->initial_alpha = alpha;
  OM31 total = zero(), weight = one();
  for (uint32_t i = 0; i < max_oracles; ++i) {
    s->initial_claims[i] =
        valid && i < jobs.count ? from_words(claims + 8 * i) : zero();
    s->initial_variables[i] = i < jobs.count ? jobs.oracles[i].variables : 0;
    s->weights[i] = s->sleeping_claims[i] = zero();
    s->corrections[i] = one();
    if (valid && i < jobs.count) {
      s->weights[i] = weight;
      s->sleeping_claims[i] =
          scale(mul(weight, from_words(claims + 8 * i)),
                1u << (jobs.variables - jobs.oracles[i].variables));
      total = add(total, s->sleeping_claims[i]);
      weight = mul(weight, alpha);
    }
  }
  initialize_round(&s->round, seed, total, jobs.variables);
  if (!valid)
    s->round.status = round_field;
  if (seed[8] > (1u << 20))
    s->round.status = round_order;
  s->count = jobs.count;
  for (auto &v : s->reserved)
    v = 0;
}
__global__ void batch_round(uint32_t *words, BatchJobs jobs, uint32_t expected,
                            const uint32_t *point, uint32_t *record_words) {
  auto *s = reinterpret_cast<BatchState *>(words);
  auto *record = reinterpret_cast<RoundRecord *>(record_words);
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
__global__ void batch_mask(StwoRv64Plane n, StwoRv64Plane d, uint32_t *output) {
  const uint32_t c = threadIdx.x;
  if (c >= 8)
    return;
  for (uint32_t row = 0; row < 2; ++row) {
    output[8 * row + c] = n.coordinates == 1 ? (c == 0 ? n.words[row] : 0)
                                             : n.words[c * n.stride + row];
    output[16 + 8 * row + c] = d.words[c * d.stride + row];
  }
}
using BatchCustody = RangeCustody<max_oracles + 8>;
inline int jobs_for(BatchCustody &c, const StwoRv64BatchOracle *oracles,
                    uint32_t count, uint32_t variables, BatchJobs *jobs) {
  if (!oracles || !count || count > max_oracles || variables > 27)
    return int(cudaErrorInvalidValue);
  uint32_t largest = 0;
  *jobs = {};
  for (uint32_t i = 0; i < count; ++i) {
    const auto job = oracles[i];
    if (job.reserved || job.variables > variables)
      return int(cudaErrorInvalidValue);
    largest = largest > job.variables ? largest : job.variables;
    if (job.variables == 0) {
      if (job.raw || job.raw_stride)
        return int(cudaErrorInvalidValue);
    } else {
      if (job.raw_stride < 2 || job.raw_stride > UINT64_MAX / 8)
        return int(cudaErrorInvalidValue);
      if (!c.range(job.raw, 8 * job.raw_stride, false))
        return c.status;
    }
    jobs->oracles[i] = job;
  }
  if (largest != variables)
    return int(cudaErrorInvalidValue);
  jobs->count = count;
  jobs->variables = variables;
  return 0;
}
} // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_batch_init_on(void *ctx, uint32_t lane,
                                       uint32_t *state, const uint32_t *seed,
                                       const uint32_t *claims,
                                       const uint32_t *alpha,
                                       const StwoRv64BatchOracle *oracles,
                                       uint32_t count, uint32_t variables) {
  BatchCustody c(ctx, lane);
  BatchJobs jobs;
  if (const int status = jobs_for(c, oracles, count, variables, &jobs))
    return status;
  if (!c.range(state, STWO_RV64_BATCH_STATE_WORDS, true) ||
      !c.range(seed, 9, false) || !c.range(claims, 8ull * count, false) ||
      !c.range(alpha, 8, false))
    return c.status;
  batch_init<<<1, 1, 0, c.stream>>>(state, seed, claims, alpha, jobs);
  return int(cudaPeekAtLastError());
}
extern "C" int
stwo_rv64_batch_round_on(void *ctx, uint32_t lane, uint32_t *state,
                         const StwoRv64BatchOracle *oracles, uint32_t count,
                         uint32_t variables, uint32_t expected,
                         const uint32_t *point, uint32_t *record) {
  if (!variables || expected >= variables)
    return int(cudaErrorInvalidValue);
  BatchCustody c(ctx, lane);
  BatchJobs jobs;
  if (const int status = jobs_for(c, oracles, count, variables, &jobs))
    return status;
  if (!c.range(state, STWO_RV64_BATCH_STATE_WORDS, true) ||
      !c.range(point, 8ull * variables, false) ||
      !c.range(record, round_record_words, true))
    return c.status;
  batch_round<<<1, 1, 0, c.stream>>>(state, jobs, expected, point, record);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_batch_mask_on(void *ctx, uint32_t lane,
                                       StwoRv64Plane n, StwoRv64Plane d,
                                       uint32_t *output) {
  Custody c(ctx, lane);
  if (!c.numerator(n, 2) || !c.plane(d, 2, 8, false) ||
      !c.range(output, 32, true))
    return c.status;
  batch_mask<<<1, 32, 0, c.stream>>>(n, d, output);
  return int(cudaPeekAtLastError());
}
