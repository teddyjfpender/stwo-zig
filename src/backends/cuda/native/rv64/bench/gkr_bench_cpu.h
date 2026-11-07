#pragma once
// CPU reference prover (fully materialised, textbook) and an independent CPU
// verifier for the bench protocol. The verifier replays Fiat-Shamir from the
// proof log, checks every sumcheck round, every layer reduction against the
// masks and finally the input MLE at the GKR point from the ORIGINAL tuple
// authority (outer_gkr_projector.cuh Source<Kind>::get on the host).
#include "gkr_bench_common.h"
#include <cstdio>
#include <cstring>
#include <vector>
#ifdef _OPENMP
#include <omp.h>
#endif

namespace gb {
struct HostTrace {
  // per component id (0..10): MAIN [base_width x rows], FIXED [pp x rows]
  std::vector<uint32_t> main[11], fixed[11];
  uint32_t rows_log[11]{};
  uint32_t params[56];
  uint32_t status = 0;
};
inline void make_params(uint32_t seed, uint32_t *params) {
  for (int i = 0; i < 56; ++i) params[i] = hash_word((uint64_t(seed) << 32) ^ (0xABCDull << 16) ^ i);
}
inline void host_trace(HostTrace &h, const ClassSpec &cs, uint32_t seed) {
  for (int i = 0; i < cs.n; ++i) {
    const uint32_t k = cs.inst[i].comp, rl = cs.inst[i].row_log;
    if (!h.main[k].empty()) continue;
    const uint64_t rows = 1ull << rl;
    h.rows_log[k] = rl;
    h.main[k].resize(rows * tup::kBaseWidths[k]);
    h.fixed[k].resize(rows * tup::kPpWidths[k]);
    for (uint32_t c = 0; c < tup::kBaseWidths[k]; ++c)
      for (uint64_t r = 0; r < rows; ++r) h.main[k][c * rows + r] = trace_value(seed, k, c, uint32_t(r));
    for (uint32_t c = 0; c < tup::kPpWidths[k]; ++c)
      for (uint64_t r = 0; r < rows; ++r) h.fixed[k][c * rows + r] = trace_value(seed, k, 64 + c, uint32_t(r));
  }
  make_params(seed, h.params);
}
inline StwoCircuitOuterGkrSource host_source(HostTrace &h, const Inst &in) {
  const uint64_t rows = 1ull << in.row_log;
  StwoCircuitOuterGkrSource s{};
  s.fixed = h.fixed[in.comp].empty() ? nullptr : h.fixed[in.comp].data();
  s.main = h.main[in.comp].data();
  s.parameters = h.params;
  s.status = &h.status;
  s.fixed_words = rows * tup::kPpWidths[in.comp];
  s.main_words = rows * tup::kBaseWidths[in.comp];
  s.component = in.comp;
  s.row_log = in.row_log;
  s.lane_first = in.lane_first;
  s.lane_log = in.lane_log;
  return s;
}
inline Fraction host_fact(const StwoCircuitOuterGkrSource &s, uint32_t idx) {
  using namespace stwo::cuda::rv64::outer_gkr;
  switch (s.component) {
    case 2: return Source<2>{s}.get(idx);
    case 3: return Source<3>{s}.get(idx);
    case 4: return Source<4>{s}.get(idx);
    default: return Source<6>{s}.get(idx);
  }
}

// ---------------- reference prover ----------------
inline std::vector<uint32_t> cpu_prove(HostTrace &h, const ClassSpec &cs, uint32_t seed) {
  const uint32_t lmax = class_layers(cs);
  std::vector<std::vector<std::vector<Fraction>>> V(cs.n);
  for (int i = 0; i < cs.n; ++i) {
    const uint32_t L = inst_vars(cs.inst[i]);
    const auto src = host_source(h, cs.inst[i]);
    V[i].resize(L + 1);
    V[i][L].resize(1ull << L);
    for (uint64_t x = 0; x < (1ull << L); ++x) V[i][L][x] = host_fact(src, uint32_t(x));
    for (int m = int(L) - 1; m >= 0; --m) {
      V[i][m].resize(1ull << m);
      for (uint64_t x = 0; x < (1ull << m); ++x) V[i][m][x] = combine(V[i][m + 1][2 * x], V[i][m + 1][2 * x + 1]);
    }
  }
  std::vector<uint32_t> log(1u << 17);
  State s;
  init_state(s, seed);
  for (uint32_t d = 0; d < lmax; ++d) {
    const DepthDesc dd = depth_desc(cs, d);
    OM31 rn[MAXI], rd[MAXI];
    for (int i = 0; i < cs.n; ++i) {
      rn[i] = V[i][0][0].n;
      rd[i] = V[i][0][0].d;
    }
    begin_depth(s, dd, rn, rd, log.data());
    std::vector<std::vector<Fraction>> T(cs.n);
    for (int i = 0; i < cs.n; ++i)
      if (dd.active[i]) T[i] = V[i][dd.v[i] + 1];
    for (uint32_t t = 1; t <= d; ++t) {
      OM31 h0[MAXI], h2[MAXI];
      for (int i = 0; i < cs.n; ++i) {
        if (!dd.active[i] || t <= d - dd.v[i]) continue;
        const uint32_t k = t - (d - dd.v[i]), n_eq = dd.v[i] - k;
        const uint64_t terms = T[i].size() / 4;
        OM31 a0 = zero(), a2 = zero();
        for (uint64_t b = 0; b < terms; ++b) {
          const OM31 e = eq_direct(&s.point[i][k], n_eq, uint32_t(b));
          const Pair p = sum_term(T[i][2 * b], T[i][2 * b + 1], T[i][2 * (terms + b)],
                                  T[i][2 * (terms + b) + 1], e, s.lambda);
          a0 = add(a0, p.at0);
          a2 = add(a2, p.at2);
        }
        h0[i] = a0;
        h2[i] = a2;
      }
      round_step(s, dd, t, h0, h2, log.data());
      const OM31 r = s.r[t - 1];
      for (int i = 0; i < cs.n; ++i) {
        if (!dd.active[i] || t <= d - dd.v[i]) continue;
        const uint64_t half = T[i].size() / 2;
        std::vector<Fraction> nx(half);
        for (uint64_t j = 0; j < half; ++j)
          nx[j] = {fold(T[i][j].n, T[i][j + half].n, r), fold(T[i][j].d, T[i][j + half].d, r)};
        T[i].swap(nx);
      }
    }
    OM31 mask[MAXI][4];
    for (int i = 0; i < cs.n; ++i)
      if (dd.active[i]) {
        mask[i][0] = T[i][0].n;
        mask[i][1] = T[i][0].d;
        mask[i][2] = T[i][1].n;
        mask[i][3] = T[i][1].d;
      }
    close_depth(s, dd, mask, log.data());
  }
  log.resize(s.log_words);
  return log;
}

// ---------------- independent verifier ----------------
struct VerifyResult {
  bool ok;
  const char *why;
  uint32_t depth;
  double terminal_seconds;
};
inline OM31 read_om(const uint32_t *log, uint32_t &at) {
  const OM31 v = from_words(log + at);
  at += 8;
  return v;
}
inline OM31 horner(const OM31 *c, OM31 x) {
  return add(c[0], mul(x, add(c[1], mul(x, add(c[2], mul(x, c[3]))))));
}
// MLE of instance facts at point y (y[0] = top index bit), parallel.
inline Fraction mle_facts(HostTrace &h, const Inst &in, const OM31 *y) {
  const uint32_t L = inst_vars(in);
  const uint32_t lo_bits = L < 13 ? L : 13, hi_bits = L - lo_bits;
  std::vector<OM31> lo(1u << lo_bits), hi(1u << hi_bits);
  for (uint32_t b = 0; b < lo.size(); ++b) lo[b] = eq_direct(y + hi_bits, lo_bits, b);
  for (uint32_t b = 0; b < hi.size(); ++b) hi[b] = eq_direct(y, hi_bits, b);
  const auto src = host_source(h, in);
  const int64_t nhi = int64_t(hi.size());
  std::vector<Fraction> part(nhi);
#pragma omp parallel for schedule(dynamic, 4)
  for (int64_t x = 0; x < nhi; ++x) {
    OM31 an = zero(), ad = zero();
    for (uint32_t b = 0; b < lo.size(); ++b) {
      const Fraction f = host_fact(src, uint32_t((uint64_t(x) << lo_bits) | b));
      an = add(an, mul(lo[b], f.n));
      ad = add(ad, mul(lo[b], f.d));
    }
    part[x] = {mul(hi[x], an), mul(hi[x], ad)};
  }
  Fraction acc{zero(), zero()};
  for (auto &p : part) acc = {add(acc.n, p.n), add(acc.d, p.d)};
  return acc;
}
inline VerifyResult cpu_verify(HostTrace &h, const ClassSpec &cs, uint32_t seed,
                               const uint32_t *log, uint32_t words, bool terminal) {
  const uint32_t lmax = class_layers(cs);
  Chan ch;
  {
    State s;
    init_state(s, seed);
    ch = s.chan;
  }
  OM31 cn[MAXI], cd[MAXI], point[MAXI][MAXV];
  uint32_t at = 0;
  for (uint32_t d = 0; d < lmax; ++d) {
    const DepthDesc dd = depth_desc(cs, d);
    for (int i = 0; i < cs.n; ++i)
      if (dd.active[i] && dd.v[i] == 0) {
        cn[i] = read_om(log, at);
        cd[i] = read_om(log, at);
      }
    for (int i = 0; i < cs.n; ++i)
      if (dd.active[i]) {
        absorb_om(ch, cn[i]);
        absorb_om(ch, cd[i]);
      }
    const OM31 alpha = draw(ch), lambda = draw(ch);
    OM31 apow[MAXI], ap = one(), C = zero();
    for (int i = 0; i < cs.n; ++i)
      if (dd.active[i]) {
        apow[i] = ap;
        OM31 c = add(cn[i], mul(lambda, cd[i]));
        for (uint32_t k = dd.v[i]; k < d; ++k) c = add(c, c);
        C = add(C, mul(ap, c));
        ap = mul(ap, alpha);
      }
    OM31 r[MAXV];
    for (uint32_t t = 1; t <= d; ++t) {
      OM31 S[4];
      for (int j = 0; j < 4; ++j) S[j] = read_om(log, at);
      const OM31 s01 = add(S[0], add(add(S[0], S[1]), add(S[2], S[3])));
      if (!same(s01, C)) return {false, "round sum != claim", d, 0};
      for (int j = 0; j < 4; ++j) absorb_om(ch, S[j]);
      r[t - 1] = draw(ch);
      C = horner(S, r[t - 1]);
    }
    OM31 mask[MAXI][4];
    OM31 expect = zero();
    for (int i = 0; i < cs.n; ++i)
      if (dd.active[i]) {
        for (int j = 0; j < 4; ++j) mask[i][j] = read_om(log, at);
        const Fraction g = combine({mask[i][0], mask[i][1]}, {mask[i][2], mask[i][3]});
        OM31 e = one();
        const uint32_t v = dd.v[i];
        for (uint32_t k = 0; k < v; ++k) e = mul(e, eq1(point[i][k], r[d - v + k]));
        expect = add(expect, mul(apow[i], mul(e, add(g.n, mul(lambda, g.d)))));
      }
    if (!same(expect, C)) return {false, "layer reduction != masks", d, 0};
    for (int i = 0; i < cs.n; ++i)
      if (dd.active[i])
        for (int j = 0; j < 4; ++j) absorb_om(ch, mask[i][j]);
    const OM31 rs = draw(ch);
    for (int i = 0; i < cs.n; ++i)
      if (dd.active[i]) {
        cn[i] = fold(mask[i][0], mask[i][2], rs);
        cd[i] = fold(mask[i][1], mask[i][3], rs);
        const uint32_t v = dd.v[i];
        for (uint32_t k = 0; k < v; ++k) point[i][k] = r[d - v + k];
        point[i][v] = rs;
      }
  }
  if (at != words) return {false, "log length", lmax, 0};
  double secs = 0;
  if (terminal) {
#ifdef _OPENMP
    const double t0 = omp_get_wtime();
#endif
    for (int i = 0; i < cs.n; ++i) {
      const Fraction f = mle_facts(h, cs.inst[i], point[i]);
      if (!same(f.n, cn[i]) || !same(f.d, cd[i])) return {false, "terminal input MLE", uint32_t(i), 0};
    }
#ifdef _OPENMP
    secs = omp_get_wtime() - t0;
#endif
    if (h.status) return {false, "source status (pole/noncanonical)", 0, secs};
  }
  return {true, "ok", lmax, secs};
}
}  // namespace gb
