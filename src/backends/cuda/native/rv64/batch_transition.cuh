#pragma once
#include "batch_state.cuh"
#include "reduce.cuh"
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
// STWO_RV64_M8_GKR_BATCH_PAR: the same transition, cooperatively by one CTA of
// BlockThreads == OracleThreads + 128 threads. Every thread enters; all early
// returns are block-uniform (they follow a barrier on a shared verdict).
// Oracle i is owned by thread i mod OracleThreads: load, canonical check and
// weighted multiply run in parallel, then a warp/smem tree reduce feeds thread
// 0's transcript step. Lane 0 of each of the four helper warps (one per SM
// sub-partition) computes the round prelude (the inversion and every
// raw-independent product) at the same time, then the raw-dependent products,
// so thread 0 runs only additions, the hash and the draw. Field addition and
// multiplication over canonical M31 coordinates are exact, so the reduced sums
// and every record, digest, challenge and claim are bit-identical to the
// serial loop. Status precedence is unchanged: state status, then order
// (count, next round, per-oracle heights), then field, then pole; any failure
// returns before mutating weights, corrections, sleeping claims or the
// transcript.
// Helper-warps-only barrier (warps OracleThreads/32 .. +3); id 0 is __syncthreads.
__device__ __forceinline__ void helper_barrier() { asm volatile("bar.sync 1, 128;" ::: "memory"); }
// Run by every thread of the four helper warps; lane 0 of helper warp h works.
__device__ __forceinline__ void cooperative_prelude(uint32_t h, bool lead, OM31 prefix_in, OM31 y,
                                                    RoundPrelude *out, OM31 *scratch) {
  // scratch: 0 prefix, 1 ymy, 2 den^2, 3 den*ym, 4 a, 5 inverse_cubic, 6 k0, 7 k2,
  // 8 nd, 9 ca, 10 cb, 11 cc, 12 cubic_denominator.
  const OM31 ym = sub(one(), y), denominator = sub(one(), add(y, y)),
             eq2 = sub(scale(y, 3), one());
  if (lead) {
    if (h == 0) scratch[0] = mul(prefix_in, ym);
    else if (h == 1) { const OM31 ymy = mul(ym, y); scratch[1] = ymy; scratch[12] = mul(ymy, eq2); }
    else if (h == 2) scratch[2] = mul(denominator, denominator);
    else scratch[3] = mul(denominator, ym);
  }
  helper_barrier();
  if (lead && h == 0) {
    const OM31 prefix = scratch[0], cubic_denominator = scratch[12];
    out->y = y;
    out->prefix = prefix;
    out->pole = is_zero(prefix) || is_zero(denominator) || is_zero(cubic_denominator);
    out->reserved[0] = out->reserved[1] = out->reserved[2] = 0;
    // One norm-descent inversion, as in advance_round_with_constant (harmless
    // garbage when pole is set; it is never used then).
    const OM31 reciprocal_product = inverse_nonzero(mul(prefix, cubic_denominator));
    scratch[4] = reciprocal_product;
  }
  helper_barrier();
  if (lead) {
    if (h == 0) scratch[5] = mul(scratch[12], scratch[4]);       // a
    else if (h == 1) scratch[6] = mul(scratch[0], scratch[4]);   // inverse_cubic
  }
  helper_barrier();
  if (lead) {
    if (h == 0) scratch[7] = mul(ym, scratch[5]);                // k0
    else if (h == 1) scratch[8] = mul(eq2, scratch[5]);          // k2
    else if (h == 2) scratch[9] = sub(zero(), mul(denominator, scratch[6])); // nd
  }
  helper_barrier();
  if (lead) {
    if (h == 0) scratch[10] = mul(scratch[9], scratch[2]);       // ca
    else if (h == 1) scratch[11] = mul(scratch[9], scratch[3]);  // cb
    else if (h == 2) scratch[13] = mul(scratch[9], scratch[1]);  // cc
  }
  helper_barrier();
  if (lead) {
    const OM31 ca = scratch[10], cb = scratch[11], cc = scratch[13];
    if (h == 0)
      out->p0 = mul(scratch[7], add(sub(ca, add(cb, cb)), scale(scale(cc, 3), 1073741824u)));
    else if (h == 1) out->p2 = mul(scratch[8], scale(cc, 1073741824u));
    else if (h == 2) out->ps = sub(cb, cc);
    else { out->k0 = scratch[7]; out->k2 = scratch[8]; }
  }
}
template <uint32_t OracleThreads, uint32_t BlockThreads>
__device__ __forceinline__ void advance_batch_round_block(BatchState *s, const BatchJobs &jobs,
    uint32_t expected, const uint32_t *point, RoundRecord *record) {
  static_assert(OracleThreads >= 32 && OracleThreads % 32 == 0 &&
                BlockThreads == OracleThreads + 128 && BlockThreads <= 1024, "warp roles");
  __shared__ uint32_t verdict;
  __shared__ RoundPrelude prelude;
  __shared__ OM31 scratch[14], terms[5], challenge_shared, coefficients_shared[4];
  __shared__ uint32_t partial[3][8][OracleThreads / 32];
  const uint32_t t = threadIdx.x;
  const bool helper = t >= OracleThreads, lead = helper && !(t & 31u);
  const uint32_t h = helper ? (t - OracleThreads) >> 5 : 0;
  if (!t) {
    bool ok = prepare_record(&s->round, jobs.variables, record);
    if (ok && (s->count != jobs.count || expected >= jobs.variables ||
               s->round.next_round != expected)) {
      s->round.status = round_order;
      ok = false;
    }
    verdict = ok;
  }
  __syncthreads();
  if (!verdict)
    return;
  bool order = false;
  for (uint32_t i = t; i < jobs.count; i += BlockThreads)
    order = order || s->initial_variables[i] != jobs.oracles[i].variables;
  if (__syncthreads_or(order)) {
    if (!t)
      s->round.status = round_order;
    return;
  }
  const uint32_t remaining = jobs.variables - expected;
  bool field = false;
  if (!helper) {
    OM31 at0 = zero(), at2 = zero(), sleeping_constant = zero();
    for (uint32_t i = t; i < jobs.count; i += OracleThreads) {
      const auto &job = jobs.oracles[i];
      if (job.variables < remaining) {
        sleeping_constant =
            add(sleeping_constant, scale(s->sleeping_claims[i], 1073741824u));
      } else {
        const OM31 a = load(job.raw, job.raw_stride, 0),
                   b = load(job.raw, job.raw_stride, 1);
        if (!canonical(a) || !canonical(b)) {
          field = true;
          continue;
        }
        const OM31 weight = mul(s->weights[i], s->corrections[i]);
        at0 = add(at0, mul(weight, a));
        at2 = add(at2, mul(weight, b));
      }
    }
    at0 = warp_sum(at0);
    at2 = warp_sum(at2);
    sleeping_constant = warp_sum(sleeping_constant);
    if (!(t & 31u))
      for (uint32_t c = 0; c < 8; ++c) {
        partial[0][c][t >> 5] = coordinate(at0, c);
        partial[1][c][t >> 5] = coordinate(at2, c);
        partial[2][c][t >> 5] = coordinate(sleeping_constant, c);
      }
  } else {
    cooperative_prelude(h, lead, s->round.prefix, from_words(point + 8 * expected),
                        &prelude, scratch);
  }
  // One barrier both votes on the field check and publishes partials + prelude.
  if (__syncthreads_or(field)) {
    if (!t)
      s->round.status = round_field;
    return;
  }
  // Every summing thread reduces the warp partials itself (exact, cheap).
  auto reduced = [&](uint32_t k) {
    uint32_t w[8];
    for (uint32_t c = 0; c < 8; ++c) {
      uint32_t v = partial[k][c][0];
      for (uint32_t j = 1; j < OracleThreads / 32; ++j)
        v = q::add(v, partial[k][c][j]);
      w[c] = v;
    }
    return from_words(w);
  };
  // Raw-dependent products, one per helper lane (thread 0 takes the fifth).
  if (lead) {
    if (h == 0) terms[0] = mul(reduced(0), prelude.k0);        // r0
    else if (h == 1) terms[1] = mul(reduced(1), prelude.k2);   // r2
    else if (h == 2) terms[2] = mul(reduced(0), prelude.p0);
    else terms[3] = mul(reduced(1), prelude.p2);
  }
  Pair raw{zero(), zero()};
  OM31 constant = zero();
  if (!t) {
    raw = {reduced(0), reduced(1)};
    constant = reduced(2);
    terms[4] = mul(sub(s->round.claim, scale(constant, 2)), prelude.ps);
  }
  __syncthreads();
  if (!t) {
    // Interpolation is linear (see advance_batch_round).
    s->round.correction = one();
    OM31 coefficients[4];
    const OM31 cubic = add(add(terms[2], terms[3]), terms[4]);
    const bool ok = advance_round_with_terms(&s->round, expected, raw, prelude, terms[0],
                                             terms[1], cubic, record, constant, coefficients);
    if (ok) {
      challenge_shared = record->challenge;
      for (uint32_t i = 0; i < 4; ++i)
        coefficients_shared[i] = coefficients[i];
    }
    verdict = ok;
  }
  __syncthreads();
  if (!verdict)
    return;
  const OM31 challenge = challenge_shared, y = from_words(point + 8 * expected);
  if (lead && h == 0) {
    s->round.claim = eval_poly(coefficients_shared, challenge);
    // advance_round_with_constant multiplies correction by eq; the batch
    // transition then resets it to one().
    s->round.correction = one();
  }
  if (!helper) {
    // (1-x)(1-y) + x y == (1-y) - x (1-2y), one multiplication (exact).
    const OM31 eq = sub(sub(one(), y), mul(challenge, sub(one(), add(y, y))));
    for (uint32_t i = t; i < jobs.count; i += OracleThreads) {
      if (jobs.oracles[i].variables < remaining)
        s->sleeping_claims[i] = scale(s->sleeping_claims[i], 1073741824u);
      else
        s->corrections[i] = mul(s->corrections[i], eq);
    }
  }
}
} // namespace stwo::cuda::rv64
