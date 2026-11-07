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
// BlockThreads >= OracleThreads + 32 threads. Every thread enters; all early
// returns are block-uniform (they follow a barrier on a shared verdict).
// Oracle i is owned by thread i mod OracleThreads: load, canonical check and
// weighted multiply run in parallel, then a warp/smem tree reduce feeds thread
// 0's transcript step. The helper warp (warp OracleThreads/32) computes the
// round prelude (the inversion and every raw-independent product) at the same
// time with 4-lane group multiplications, then the raw-dependent products and
// the next claim, so thread 0 runs only additions, the hash and the draw. Field addition and
// multiplication over canonical M31 coordinates are exact, so the reduced sums
// and every record, digest, challenge and claim are bit-identical to the
// serial loop. Status precedence is unchanged: state status, then order
// (count, next round, per-oracle heights), then field, then pole; any failure
// returns before mutating weights, corrections, sleeping claims or the
// transcript.
// Lanes 4g..4g+3 of a full warp form group g (8 groups). Every lane of a group
// passes the same (a, b) and receives mul(a, b): lane k of the group computes
// one of the four QM31 partial products a0b0, a1b1, a0b1, a1b0, so the
// dependent latency is one QM31 product instead of three plus their sums. The
// result {a0b0 + u a1b1, a0b1 + a1b0} is mul()'s value exactly (its Karatsuba
// cross term equals a0b1 + a1b0 in the field). All 32 lanes must call it.
__device__ __forceinline__ q::QM31 shfl_qm31(q::QM31 v, uint32_t src) {
  return {{__shfl_sync(0xffffffffu, v.a.a, src), __shfl_sync(0xffffffffu, v.a.b, src)},
          {__shfl_sync(0xffffffffu, v.b.a, src), __shfl_sync(0xffffffffu, v.b.b, src)}};
}
__device__ __forceinline__ OM31 shfl_om31(OM31 v, uint32_t src) {
  return {shfl_qm31(v.c0, src), shfl_qm31(v.c1, src)};
}
__device__ __forceinline__ OM31 group_mul(OM31 a, OM31 b) {
  const uint32_t lane = threadIdx.x & 31u, k = lane & 3u, base = lane & ~3u;
  const q::QM31 x = (k == 0 || k == 2) ? a.c0 : a.c1, y = (k == 0 || k == 3) ? b.c0 : b.c1;
  const q::QM31 product = q::mul(x, y);
  const q::QM31 ac = shfl_qm31(product, base), bd = shfl_qm31(product, base + 1),
                ad = shfl_qm31(product, base + 2), bc = shfl_qm31(product, base + 3);
  return {q::add(ac, mul_u(bd)), q::add(ad, bc)};
}
// Product of group g, broadcast to every lane of the warp.
__device__ __forceinline__ OM31 from_group(OM31 v, uint32_t g) { return shfl_om31(v, 4 * g); }
// Run by all 32 lanes of the helper warp; lane 0 publishes. Group g of each
// level computes one product; unused groups compute discarded values.
__device__ __forceinline__ void cooperative_prelude(OM31 prefix_in, OM31 y, RoundPrelude *out) {
  const uint32_t g = (threadIdx.x & 31u) >> 2;
  const OM31 ym = sub(one(), y), denominator = sub(one(), add(y, y)),
             eq2 = sub(scale(y, 3), one());
  // L1: prefix = P (1-y), ymy = (1-y) y, den^2, den (1-y).
  OM31 v = group_mul(g == 0 ? prefix_in : g == 1 ? ym : denominator,
                     g == 0 ? ym : g == 1 ? y : g == 2 ? denominator : ym);
  const OM31 prefix = from_group(v, 0), ymy = from_group(v, 1),
             den2 = from_group(v, 2), dym = from_group(v, 3);
  const OM31 cubic_denominator = from_group(group_mul(ymy, eq2), 0);
  const OM31 product = from_group(group_mul(prefix, cubic_denominator), 0);
  // One norm-descent inversion, as in advance_round_with_constant (harmless
  // garbage when pole is set; it is never used then). Every lane computes it.
  const OM31 reciprocal_product = inverse_nonzero(product);
  // L4: a = cd / (prefix cd) , inverse_cubic = prefix / (prefix cd).
  v = group_mul(g == 0 ? cubic_denominator : prefix, reciprocal_product);
  const OM31 a = from_group(v, 0), inverse_cubic = from_group(v, 1);
  // L5: k0 = (1-y) a, k2 = (3y-1) a, den * inverse_cubic.
  v = group_mul(g == 0 ? ym : g == 1 ? eq2 : denominator, g <= 1 ? a : inverse_cubic);
  const OM31 k0 = from_group(v, 0), k2 = from_group(v, 1),
             nd = sub(zero(), from_group(v, 2));
  // L6: ca = nd den^2, cb = nd den (1-y), cc = nd (1-y) y.
  v = group_mul(nd, g == 0 ? den2 : g == 1 ? dym : ymy);
  const OM31 ca = from_group(v, 0), cb = from_group(v, 1), cc = from_group(v, 2);
  // L7: p0 = k0 (ca - 2cb + 3cc/2), p2 = k2 cc/2.
  v = group_mul(g == 0 ? k0 : k2, g == 0 ? add(sub(ca, add(cb, cb)), scale(scale(cc, 3), 1073741824u))
                                         : scale(cc, 1073741824u));
  const OM31 p0 = from_group(v, 0), p2 = from_group(v, 1);
  if (!(threadIdx.x & 31u)) {
    out->y = y;
    out->prefix = prefix;
    out->k0 = k0;
    out->k2 = k2;
    out->p0 = p0;
    out->p2 = p2;
    out->ps = sub(cb, cc);
    out->pole = is_zero(prefix) || is_zero(denominator) || is_zero(cubic_denominator);
    out->reserved[0] = out->reserved[1] = out->reserved[2] = 0;
  }
}
template <uint32_t OracleThreads, uint32_t BlockThreads>
__device__ __forceinline__ void advance_batch_round_block(BatchState *s, const BatchJobs &jobs,
    uint32_t expected, const uint32_t *point, RoundRecord *record) {
  static_assert(OracleThreads >= 32 && OracleThreads % 32 == 0 &&
                BlockThreads >= OracleThreads + 32 && BlockThreads <= 1024, "warp roles");
  __shared__ uint32_t verdict;
  __shared__ RoundPrelude prelude;
  __shared__ OM31 terms[5], challenge_shared, coefficients_shared[4];
  __shared__ uint32_t partial[3][8][OracleThreads / 32];
  const uint32_t t = threadIdx.x;
  // Warp OracleThreads/32 is the helper; any further warps only join barriers.
  const bool helper = t >= OracleThreads && t < OracleThreads + 32;
  const uint32_t g = (t & 31u) >> 2;
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
  if (t < OracleThreads) {
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
  } else if (helper) {
    cooperative_prelude(s->round.prefix, from_words(point + 8 * expected), &prelude);
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
  // Raw-dependent products: r0, r2, raw0 p0, raw2 p2, (claim - 2 constant) ps.
  if (helper) {
    const OM31 raw0 = reduced(0), raw2 = reduced(1),
               s1 = sub(s->round.claim, scale(reduced(2), 2));
    const OM31 v = group_mul(g == 0 || g == 2 ? raw0 : g == 4 ? s1 : raw2,
                             g == 0 ? prelude.k0 : g == 1 ? prelude.k2 : g == 2 ? prelude.p0
                                                 : g == 3 ? prelude.p2 : prelude.ps);
    if ((t & 3u) == 0 && g < 5)
      terms[g] = v;
  }
  Pair raw{zero(), zero()};
  OM31 constant = zero();
  if (!t) {
    raw = {reduced(0), reduced(1)};
    constant = reduced(2);
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
  if (helper) {
    // eval_poly(coefficients, x) == c0 + c1 x + (c2 + c3 x) x^2 (exact), in
    // two group-multiplication levels.
    const OM31 *c = coefficients_shared;
    const OM31 v = group_mul(g == 0 ? challenge : g == 1 ? c[1] : c[3], challenge);
    const OM31 x2 = from_group(v, 0), c1x = from_group(v, 1), c3x = from_group(v, 2);
    const OM31 tail = from_group(group_mul(add(c[2], c3x), x2), 0);
    if (t == OracleThreads) {
      s->round.claim = add(add(c[0], c1x), tail);
      // advance_round_with_constant multiplies correction by eq; the batch
      // transition then resets it to one().
      s->round.correction = one();
    }
  }
  if (t < OracleThreads) {
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
