#pragma once
// M9 outer-GKR kernel benchmark: protocol shared by the CPU reference prover,
// the CPU verifier and both GPU routes (host+device). STWO_RV64_M9_GKR_BENCH.
//
// Protocol = batched LogUp-GKR exactly as the resident CUDA route runs it
// (gkr_loop.cu / gkr.zig): instances aligned at the INPUT layer, top-down
// depths, half-split (top-bit-first) sumcheck rounds whose raw evaluations
// are the native evalLogupSumRange at0/at2 (om31.cuh sum_term), fixed-variable
// Eq factor (Gruen) kept outside the table, adjacent-pair gate children.
// Lane-major fact index = lane * 2^row_log + row (outer_gkr_projector.cuh).
//
// NOT production: the Fiat-Shamir channel below is an ARX stand-in for the
// Blake2s device channel (same call pattern: absorb per round, one draw per
// challenge, one thread). It is NOT a sound hash. Benchmark only.
#include "../outer_gkr_projector.cuh"

namespace gb {
using namespace stwo::cuda::rv64;
namespace tup = stwo::cuda::circuit_interaction;
constexpr int MAXI = 8, MAXV = 28;
constexpr uint32_t P31 = 2147483647u;

struct Inst {
  uint32_t comp, row_log, lane_first, lane_log;
};
struct ClassSpec {
  const char *name;
  int n;
  Inst inst[MAXI];
};
// Real D2 roster lane groups (rv64-m9-outer-gkr.md section 6): blake 16+8+2,
// triple_xor 8+4, m31_to_u32 4+1, xor12 table 16. Row logs from section 2.
inline ClassSpec class_spec(int which, uint32_t shift) {
  // which 0: D2 CPU leaf (eq,qm31,triple,m31,blake = 18,23,19,20,22; xor12 2^20)
  // which 1: 2^23 fold   (16,23,20,21,23; xor12 2^20)
  const uint32_t tri = which ? 20 : 19, m31 = which ? 21 : 20, bl = which ? 23 : 22, x12 = 20;
  ClassSpec s{which ? "fold23" : "leaf_d2", 8, {}};
  const Inst v[8] = {{4, bl - shift, 0, 4},  {4, bl - shift, 16, 3}, {4, bl - shift, 24, 1},
                     {2, tri - shift, 0, 3}, {2, tri - shift, 8, 2}, {3, m31 - shift, 0, 2},
                     {3, m31 - shift, 4, 0}, {6, x12 - shift, 0, 4}};
  for (int i = 0; i < 8; ++i) s.inst[i] = v[i];
  return s;
}
inline uint32_t inst_vars(const Inst &i) { return i.row_log + i.lane_log; }

// ---------------- deterministic synthetic trace (host == device) ----------
__host__ __device__ __forceinline__ uint32_t hash_word(uint64_t x) {
  x += 0x9E3779B97F4A7C15ull;
  x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
  x ^= x >> 31;
  const uint32_t v = uint32_t(x) & 0x7fffffffu;
  return v == P31 ? 0u : v;
}
// MAIN/FIXED column value of component comp, column col (fixed: col+64), row.
__host__ __device__ __forceinline__ uint32_t trace_value(uint32_t seed, uint32_t comp,
                                                         uint32_t col, uint32_t row) {
  return hash_word((uint64_t(seed) << 48) ^ (uint64_t(comp) << 40) ^ (uint64_t(col) << 32) ^ row);
}

// ---------------- channel stand-in ----------------
struct Chan {
  uint32_t s[8];
};
__host__ __device__ __forceinline__ uint32_t rotl(uint32_t x, int r) {
  return (x << r) | (x >> (32 - r));
}
__host__ __device__ __forceinline__ void permute(Chan &c) {
  for (int round = 0; round < 6; ++round)
    for (int i = 0; i < 8; ++i) {
      c.s[i] += c.s[(i + 1) & 7] ^ (0x9E3779B9u * (round + 1));
      c.s[(i + 3) & 7] = rotl(c.s[(i + 3) & 7] ^ c.s[i], 5 + (i & 3) * 4);
    }
}
__host__ __device__ __forceinline__ void absorb(Chan &c, const uint32_t *w, uint32_t n) {
  for (uint32_t i = 0; i < n; ++i) {
    c.s[i & 7] ^= w[i];
    if ((i & 7) == 7 || i + 1 == n) permute(c);
  }
}
__host__ __device__ __forceinline__ OM31 draw(Chan &c) {
  permute(c);
  uint32_t w[8];
  for (int i = 0; i < 8; ++i) {
    w[i] = c.s[i] & 0x7fffffffu;
    if (w[i] == P31) w[i] = 0;
  }
  c.s[0] ^= 0x5bd1e995u;
  return from_words(w);
}
__host__ __device__ __forceinline__ void absorb_om(Chan &c, OM31 a) {
  uint32_t w[8];
  for (int i = 0; i < 8; ++i) w[i] = coordinate(a, i);
  absorb(c, w, 8);
}

// ---------------- small field helpers ----------------
__host__ __device__ __forceinline__ OM31 om_inv2() { return base(1073741824u); }
__host__ __device__ __forceinline__ OM31 eq1(OM31 y, OM31 x) {
  // (1-y)(1-x) + y x
  return add(mul(sub(one(), y), sub(one(), x)), mul(y, x));
}
__host__ __device__ __forceinline__ bool same(OM31 a, OM31 b) { return is_zero(sub(a, b)); }

// ---------------- prover/verifier state ----------------
struct State {
  Chan chan;
  OM31 alpha, lambda;
  OM31 cn[MAXI], cd[MAXI];  // layer claims
  OM31 point[MAXI][MAXV];   // y of the current depth (length v_i)
  OM31 c[MAXI];             // scaled claim (pre-own) / reduced claim (own)
  OM31 P[MAXI];             // Eq prefix of own rounds
  OM31 apow[MAXI];
  OM31 r[MAXV];             // this depth's round challenges r_1..r_d
  OM31 rstar;
  OM31 yinv[MAXI][MAXV];    // GPU: 1/y_k of this depth's point (precomputed in parallel)
  uint32_t log_words, status, pad[2];
};
// Proof/transcript log layout (u32 words, appended): per depth: claims of
// joiners (16 each), per round S coefficients (32), masks (32 each active).
struct DepthDesc {
  uint32_t d, n;              // depth, instance count
  uint32_t active[MAXI];      // 0/1
  uint32_t v[MAXI];           // local variables (rounds) at this depth
};
__host__ __device__ inline void log_put(uint32_t *log, State &s, OM31 a) {
  if (log)
    for (int c = 0; c < 8; ++c) log[s.log_words + c] = coordinate(a, c);
  s.log_words += 8;
}
// Joiners (v==0) take the root as claim. Absorb claims, draw alpha, lambda.
__host__ __device__ inline void begin_depth(State &s, const DepthDesc &dd, const OM31 *root_n,
                                            const OM31 *root_d, uint32_t *log) {
  for (uint32_t i = 0; i < dd.n; ++i)
    if (dd.active[i] && dd.v[i] == 0) {
      s.cn[i] = root_n[i];
      s.cd[i] = root_d[i];
      log_put(log, s, s.cn[i]);
      log_put(log, s, s.cd[i]);
    }
  for (uint32_t i = 0; i < dd.n; ++i)
    if (dd.active[i]) {
      absorb_om(s.chan, s.cn[i]);
      absorb_om(s.chan, s.cd[i]);
    }
  s.alpha = draw(s.chan);
  s.lambda = draw(s.chan);
  OM31 ap = one();
  for (uint32_t i = 0; i < dd.n; ++i)
    if (dd.active[i]) {
      s.apow[i] = ap;
      ap = mul(ap, s.alpha);
      OM31 c = add(s.cn[i], mul(s.lambda, s.cd[i]));
      for (uint32_t k = dd.v[i]; k < dd.d; ++k) c = add(c, c);
      s.c[i] = c;
      s.P[i] = one();
    }
}
__host__ __device__ inline OM31 lagrange012(OM31 h0, OM31 h1, OM31 h2, OM31 r) {
  const OM31 r1 = sub(r, one()), r2 = sub(r, base(2));
  const OM31 l0 = mul(mul(r1, r2), om_inv2());
  const OM31 l1 = sub(zero(), mul(r, r2));
  const OM31 l2 = mul(mul(r, r1), om_inv2());
  return add(add(mul(h0, l0), mul(h1, l1)), mul(h2, l2));
}
// Round t (1-based) of depth dd.d. h0/h2 per instance = raw at0/at2 (only
// read for instances in an own round). Split per instance so the GPU round
// kernel runs instances in parallel; round_step is the sequential composition.
__host__ __device__ inline void inst_poly(const State &s, const DepthDesc &dd, uint32_t t, uint32_t i,
                                          OM31 h0, OM31 h2, const OM31 *yinv, OM31 *Sv, OM31 &h1o) {
  const uint32_t lead = dd.d - dd.v[i];
  if (t <= lead) {  // constant contribution c/2
    Sv[0] = mul(s.apow[i], mul(s.c[i], om_inv2()));
    Sv[1] = Sv[2] = Sv[3] = zero();
    return;
  }
  const uint32_t k = t - lead;
  const OM31 y = s.point[i][k - 1];
  const OM31 a0 = sub(one(), y), a1 = sub(add(y, y), one());
  const OM31 h1 = mul(sub(s.c[i], mul(a0, h0)), yinv ? yinv[k - 1] : inverse_nonzero(y));
  h1o = h1;
  const OM31 b2 = mul(add(sub(h2, add(h1, h1)), h0), om_inv2());
  const OM31 b1 = sub(sub(h1, h0), b2);
  const OM31 w = mul(s.apow[i], s.P[i]);
  Sv[0] = mul(w, mul(a0, h0));
  Sv[1] = mul(w, add(mul(a0, b1), mul(a1, h0)));
  Sv[2] = mul(w, add(mul(a0, b2), mul(a1, b1)));
  Sv[3] = mul(w, mul(a1, b2));
}
__host__ __device__ inline void inst_update(State &s, const DepthDesc &dd, uint32_t t, uint32_t i,
                                            OM31 h0, OM31 h1, OM31 h2, OM31 r) {
  const uint32_t lead = dd.d - dd.v[i];
  if (t <= lead) {
    s.c[i] = mul(s.c[i], om_inv2());
    return;
  }
  const uint32_t k = t - lead;
  s.c[i] = lagrange012(h0, h1, h2, r);
  s.P[i] = mul(s.P[i], eq1(s.point[i][k - 1], r));
}
__host__ __device__ inline OM31 absorb_round(State &s, const OM31 *S, uint32_t t, uint32_t *log) {
  for (int j = 0; j < 4; ++j) {
    absorb_om(s.chan, S[j]);
    log_put(log, s, S[j]);
  }
  const OM31 r = draw(s.chan);
  s.r[t - 1] = r;
  return r;
}
__host__ __device__ inline void round_step(State &s, const DepthDesc &dd, uint32_t t,
                                           const OM31 *h0, const OM31 *h2, uint32_t *log) {
  OM31 S[4] = {zero(), zero(), zero(), zero()}, h1[MAXI];
  for (uint32_t i = 0; i < dd.n; ++i) {
    if (!dd.active[i]) continue;
    OM31 Sv[4];
    inst_poly(s, dd, t, i, h0[i], h2[i], nullptr, Sv, h1[i]);
    for (int j = 0; j < 4; ++j) S[j] = add(S[j], Sv[j]);
  }
  const OM31 r = absorb_round(s, S, t, log);
  for (uint32_t i = 0; i < dd.n; ++i)
    if (dd.active[i]) inst_update(s, dd, t, i, h0[i], h1[i], h2[i], r);
}
// Masks: (n0,d0,n1,d1) per active instance.
__host__ __device__ inline void close_depth(State &s, const DepthDesc &dd, const OM31 (*mask)[4],
                                            uint32_t *log) {
  for (uint32_t i = 0; i < dd.n; ++i)
    if (dd.active[i])
      for (int j = 0; j < 4; ++j) {
        absorb_om(s.chan, mask[i][j]);
        log_put(log, s, mask[i][j]);
      }
  const OM31 rs = draw(s.chan);
  s.rstar = rs;
  for (uint32_t i = 0; i < dd.n; ++i) {
    if (!dd.active[i]) continue;
    s.cn[i] = fold(mask[i][0], mask[i][2], rs);
    s.cd[i] = fold(mask[i][1], mask[i][3], rs);
    const uint32_t v = dd.v[i];
    for (uint32_t k = 0; k < v; ++k) s.point[i][k] = s.r[dd.d - v + k];
    s.point[i][v] = rs;
  }
}
__host__ __device__ inline void init_state(State &s, uint32_t seed) {
  for (int i = 0; i < 8; ++i) s.chan.s[i] = 0x6a09e667u ^ (seed * (i + 1));
  permute(s.chan);
  s.log_words = 0;
  s.status = 0;
}
inline DepthDesc depth_desc(const ClassSpec &cs, uint32_t d) {
  DepthDesc dd{};
  uint32_t lmax = 0;
  for (int i = 0; i < cs.n; ++i) lmax = inst_vars(cs.inst[i]) > lmax ? inst_vars(cs.inst[i]) : lmax;
  dd.d = d;
  dd.n = cs.n;
  for (int i = 0; i < cs.n; ++i) {
    const uint32_t L = inst_vars(cs.inst[i]);
    dd.active[i] = L >= lmax - d;
    dd.v[i] = dd.active[i] ? d - (lmax - L) : 0;
  }
  return dd;
}
inline uint32_t class_layers(const ClassSpec &cs) {
  uint32_t lmax = 0;
  for (int i = 0; i < cs.n; ++i) lmax = inst_vars(cs.inst[i]) > lmax ? inst_vars(cs.inst[i]) : lmax;
  return lmax;
}

// ---------------- Eq suffix tables ----------------
// E_{k+1}[b] = eq(y[k..v-1], b), y[k] = top bit of b. Suffix length n = v-k.
// SP[n] = suffix tables of y[v-n..v-1] for n <= SPLIT (offset 2^n - 1).
// For n > SPLIT: E[b] = HP[n-SPLIT][b >> SPLIT] * SP[SPLIT][b & (2^SPLIT-1)],
// HP[m] = suffix tables of y' = y[0..v-SPLIT-1] (offset 2^m - 1).
constexpr uint32_t SPLIT = 12;
constexpr uint32_t SP_WORDS = (1u << (SPLIT + 1)) - 1;  // entries
constexpr uint32_t HP_ENTRIES = (1u << 16) - 1;         // m <= 15
struct EqTables {
  OM31 sp[SP_WORDS];
  OM31 hp[HP_ENTRIES];
};
__host__ __device__ __forceinline__ OM31 eq_at(const EqTables *t, uint32_t n, uint32_t b) {
  if (n <= SPLIT) return t->sp[(1u << n) - 1 + b];
  const uint32_t m = n - SPLIT;
  return mul(t->hp[(1u << m) - 1 + (b >> SPLIT)], t->sp[(1u << SPLIT) - 1 + (b & ((1u << SPLIT) - 1))]);
}
// Entry e of the table level n for a suffix y_suffix (pointer to its first
// coordinate, top bit). Computes the product directly (used by generators).
__host__ __device__ __forceinline__ OM31 eq_direct(const OM31 *ys, uint32_t n, uint32_t b) {
  OM31 acc = one();
  for (uint32_t j = 0; j < n; ++j) {
    const uint32_t bit = (b >> (n - 1 - j)) & 1u;
    acc = mul(acc, bit ? ys[j] : sub(one(), ys[j]));
  }
  return acc;
}
}  // namespace gb
