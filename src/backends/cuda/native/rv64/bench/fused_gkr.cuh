#pragma once
// Route B ("fused") kernels for the M9 outer-GKR benchmark. New code only;
// production files are untouched. Facts come from the ORIGINAL row-to-lookup
// tuple emitter (circuit/lookup_tuples.cuh lookup_at), with the projection
// parameters staged in shared memory instead of re-read from global memory.
#include "gkr_bench_common.h"
#include "../reduce.cuh"

namespace gb {
struct Table {  // OM31 fraction table: n plane + d plane
  StwoRv64Plane n, d;
  uint64_t cap;
};
namespace fused {
using Src = StwoCircuitOuterGkrSource;
constexpr uint32_t TPB = 128;
constexpr uint32_t KBMAX = 6;

template <unsigned Kind, unsigned Lookup>
__device__ __forceinline__ void fact_lk(const Src &s, const OM31 *prm, uint32_t row, uint32_t &n,
                                        OM31 &d) {
  if constexpr (Lookup < tup::lookup_count<Kind>()) {
    const uint32_t rows = 1u << s.row_log;
    tup::Columns cols;
    for (unsigned c = 0; c < tup::pp_width<Kind>(); ++c) cols.pp[c] = s.fixed + uint64_t(c) * rows;
    for (unsigned c = 0; c < tup::base_width<Kind>(); ++c) cols.base[c] = s.main + uint64_t(c) * rows;
    const auto lk = tup::lookup_at<Kind>(Lookup, row, cols);
    OM31 den = sub(zero(), prm[0]);
    for (unsigned c = 0; c < lk.len; ++c) den = add(den, scale(prm[c + 1], lk.tuple[c]));
    if (lk.numerator >= P31 || !canonical(den) || is_zero(den)) atomicOr(s.status, 1u);
    n = lk.numerator;
    d = den;
  } else {
    n = 0;
    d = one();
  }
}
template <unsigned Kind>
__device__ __forceinline__ void fact(const Src &s, const OM31 *prm, uint32_t idx, uint32_t &n,
                                     OM31 &d) {
  const uint32_t row = idx & ((1u << s.row_log) - 1);
  const uint32_t term = s.lane_first + (idx >> s.row_log);
#define FK(C)                            \
  case C:                                \
    fact_lk<Kind, C>(s, prm, row, n, d); \
    return
  switch (term) {
    FK(0); FK(1); FK(2); FK(3); FK(4); FK(5); FK(6); FK(7); FK(8); FK(9); FK(10); FK(11); FK(12);
    FK(13); FK(14); FK(15); FK(16); FK(17); FK(18); FK(19); FK(20); FK(21); FK(22); FK(23);
    FK(24); FK(25);
    default:
      atomicOr(s.status, 2u);
      n = 0;
      d = one();
  }
#undef FK
}
// Tuple-only view (lazy passes): poles/noncanonical inputs were already
// checked for every fact by the forward pass (tree_kernel), which always runs.
template <unsigned Kind, unsigned Lookup>
__device__ __forceinline__ tup::Lookup tuple_lk(const Src &s, uint32_t row) {
  if constexpr (Lookup < tup::lookup_count<Kind>()) {
    const uint32_t rows = 1u << s.row_log;
    tup::Columns cols;
    for (unsigned c = 0; c < tup::pp_width<Kind>(); ++c) cols.pp[c] = s.fixed + uint64_t(c) * rows;
    for (unsigned c = 0; c < tup::base_width<Kind>(); ++c) cols.base[c] = s.main + uint64_t(c) * rows;
    return tup::lookup_at<Kind>(Lookup, row, cols);
  }
  return {0u, {0u, 0u, 0u, 0u, 0u, 0u}, 0u};
}
// w * fact via the folded projection w*d = -w z + sum_k (w alpha_k) t_k
// (WA = [w z, w alpha_0..5]); numerator 1 skips its scale.
template <unsigned Kind>
__device__ __forceinline__ void wfact(const Src &s, const OM31 *WA, OM31 w, uint32_t idx, OM31 &wn, OM31 &wd) {
  const uint32_t row = idx & ((1u << s.row_log) - 1);
  const uint32_t term = s.lane_first + (idx >> s.row_log);
  tup::Lookup lk;
#define TK(C)                           \
  case C:                               \
    lk = tuple_lk<Kind, C>(s, row);     \
    break
  switch (term) {
    TK(0); TK(1); TK(2); TK(3); TK(4); TK(5); TK(6); TK(7); TK(8); TK(9); TK(10); TK(11); TK(12);
    TK(13); TK(14); TK(15); TK(16); TK(17); TK(18); TK(19); TK(20); TK(21); TK(22); TK(23);
    TK(24); TK(25);
    default: lk = {0u, {0u, 0u, 0u, 0u, 0u, 0u}, 0u};
  }
#undef TK
  wn = lk.numerator == 1u ? w : scale(w, lk.numerator);
  OM31 d = sub(zero(), WA[0]);
  for (unsigned c = 0; c < lk.len; ++c) d = add(d, scale(WA[c + 1], lk.tuple[c]));
  if (!lk.len) d = w;  // padding fraction (0, 1) weighted
  wd = d;
}
struct Acc4 {
  OM31 n0, d0, n2, d2;
};
__device__ __forceinline__ void acc_term(Acc4 &a, const Fraction &x, const Fraction &y,
                                         const Fraction &u, const Fraction &v, OM31 e) {
  const Fraction p = combine(x, y);
  const Fraction q = combine({sub(add(u.n, u.n), x.n), sub(add(u.d, u.d), x.d)},
                             {sub(add(v.n, v.n), y.n), sub(add(v.d, v.d), y.d)});
  a.n0 = add(a.n0, mul(e, p.n));
  a.d0 = add(a.d0, mul(e, p.d));
  a.n2 = add(a.n2, mul(e, q.n));
  a.d2 = add(a.d2, mul(e, q.d));
}
__device__ __forceinline__ OM31 scl(OM31 x, uint32_t n) { return n == 1u ? x : scale(x, n); }
__device__ __forceinline__ void acc_term_base(Acc4 &a, uint32_t xn, OM31 xd, uint32_t yn, OM31 yd,
                                              uint32_t un, OM31 ud, uint32_t vn, OM31 vd, OM31 e) {
  const OM31 n0 = add(scl(yd, xn), scl(xd, yn)), d0 = mul(xd, yd);
  const uint32_t xn2 = q::sub(q::add(un, un), xn), yn2 = q::sub(q::add(vn, vn), yn);
  const OM31 xd2 = sub(add(ud, ud), xd), yd2 = sub(add(vd, vd), yd);
  const OM31 n2 = add(scl(yd2, xn2), scl(xd2, yn2)), d2 = mul(xd2, yd2);
  a.n0 = add(a.n0, mul(e, n0));
  a.d0 = add(a.d0, mul(e, d0));
  a.n2 = add(a.n2, mul(e, n2));
  a.d2 = add(a.d2, mul(e, d2));
}
__device__ __forceinline__ Pair finish(const Acc4 &a, OM31 lam) {
  return {add(a.n0, mul(lam, a.d0)), add(a.n2, mul(lam, a.d2))};
}
// Entry idx of V_{L-S}: balanced combine of facts [idx*2^S, (idx+1)*2^S).
template <unsigned Kind, unsigned S>
__device__ __forceinline__ Fraction ventry(const Src &s, const OM31 *prm, uint32_t idx) {
  if constexpr (S == 0) {
    uint32_t n;
    OM31 d;
    fact<Kind>(s, prm, idx, n, d);
    return {base(n), d};
  } else if constexpr (S == 1) {
    uint32_t na, nb;
    OM31 da, db;
    fact<Kind>(s, prm, 2 * idx, na, da);
    fact<Kind>(s, prm, 2 * idx + 1, nb, db);
    return combine_base(na, da, nb, db);
  } else {
    return combine(ventry<Kind, S - 1>(s, prm, 2 * idx), ventry<Kind, S - 1>(s, prm, 2 * idx + 1));
  }
}
__device__ __forceinline__ void load_params(const Src &s, OM31 *prm) {
  if (threadIdx.x < 7) prm[threadIdx.x] = from_words(s.parameters + 8 * threadIdx.x);
}
__device__ __forceinline__ void put(StwoRv64Plane n, StwoRv64Plane d, uint64_t i, const Fraction &f) {
  store(n.words, n.stride, i, f.n);
  store(d.words, d.stride, i, f.d);
}
__device__ __forceinline__ Fraction get(const Table &t, uint64_t i) {
  return {load(t.n.words, t.n.stride, i), load(t.d.words, t.d.stride, i)};
}
__device__ __forceinline__ void write_partial(Pair acc, StwoRv64Plane part, uint32_t block) {
  const Pair sum = block_pair_sum<TPB>(acc);
  if (threadIdx.x == 0) {
    store(part.words, part.stride, 2 * block, sum.at0);
    store(part.words, part.stride, 2 * block + 1, sum.at2);
  }
}

// ---------------- forward tree: write V_{L-S} straight from MAIN ----------------
// Entry of V_{L-S} by a SEQUENTIAL exact combine of its 2^S facts. combine is
// the formal fraction sum (n1 d2 + n2 d1, d1 d2), associative and commutative
// exactly, so any order equals the balanced tree bit-for-bit. One fact call
// site per kernel keeps SASS small (the 26-way lookup switch is large).
__device__ __forceinline__ void absorb_fact(Fraction &acc, uint32_t j, uint32_t n, OM31 d) {
  if (j == 0) {
    acc = {base(n), d};
  } else {
    acc = {add(mul(acc.n, d), scl(acc.d, n)), mul(acc.d, d)};
  }
}
template <unsigned Kind, unsigned S>
__global__ void __launch_bounds__(TPB) tree_kernel(Src s, uint32_t top, StwoRv64Plane on,
                                                   StwoRv64Plane od) {
  __shared__ OM31 prm[7];
  load_params(s, prm);
  __syncthreads();
  const uint32_t count = 1u << top;
  for (uint32_t i = blockIdx.x * TPB + threadIdx.x; i < count; i += gridDim.x * TPB) {
    Fraction acc;
#pragma unroll 1
    for (uint32_t j = 0; j < (1u << S); ++j) {
      uint32_t n;
      OM31 d;
      fact<Kind>(s, prm, (i << S) + j, n, d);
      absorb_fact(acc, j, n, d);
    }
    put(on, od, i, acc);
  }
}
template <unsigned Kind>
int tree_k(cudaStream_t st, const Src &s, uint32_t S, uint32_t top, StwoRv64Plane on, StwoRv64Plane od);
template <unsigned Kind>
uint32_t lazy_k(cudaStream_t st, const struct LazyArgs &a, uint32_t s, uint32_t grid);
#ifdef GB_KIND_TU
template <unsigned Kind>
int tree_k(cudaStream_t st, const Src &s, uint32_t S, uint32_t top, StwoRv64Plane on, StwoRv64Plane od) {
  const uint32_t grid = std::min<uint32_t>(((1u << top) + TPB - 1) / TPB, 65535u);
  switch (S) {
    case 1: tree_kernel<Kind, 1><<<grid, TPB, 0, st>>>(s, top, on, od); break;
    case 2: tree_kernel<Kind, 2><<<grid, TPB, 0, st>>>(s, top, on, od); break;
    case 3: tree_kernel<Kind, 3><<<grid, TPB, 0, st>>>(s, top, on, od); break;
    default: return int(cudaErrorInvalidValue);
  }
  return int(cudaPeekAtLastError());
}
#endif
inline int tree(cudaStream_t st, const Src &s, uint32_t S, uint32_t top, StwoRv64Plane on, StwoRv64Plane od) {
  switch (s.component) {
    case 2: return tree_k<2>(st, s, S, top, on, od);
    case 3: return tree_k<3>(st, s, S, top, on, od);
    case 4: return tree_k<4>(st, s, S, top, on, od);
    case 6: return tree_k<6>(st, s, S, top, on, od);
  }
  return int(cudaErrorInvalidValue);
}

// ---------------- lazy rounds over an unstored level ----------------
// Round k = kb+1 of the sumcheck into V_{L-S} (size 2^log_m). The current
// table is T_k[e] = sum_c eq(r_1..r_kb, c) * V[c * M_k + e], evaluated in
// registers. write=1 (kb = J) also stores T_k: the fused fold+sum that
// materialises the 2^-J table.
struct LazyArgs {
  Src src;
  uint32_t log_m, kb;
  const OM31 *r;
  const EqTables *eq;
  uint32_t n_eq;
  const OM31 *lambda;
  uint32_t write;
  StwoRv64Plane on, od, part;
};
__device__ __forceinline__ void add_to(Fraction (&f)[4], uint32_t q, const Fraction &v) {
  // q is runtime; predicated adds keep f[] in registers (no local array).
#pragma unroll
  for (uint32_t k = 0; k < 4; ++k)
    if (k == q) f[k] = {add(f[k].n, v.n), add(f[k].d, v.d)};
}
__device__ __forceinline__ void set_to(Fraction (&f)[4], uint32_t q, const Fraction &v) {
#pragma unroll
  for (uint32_t k = 0; k < 4; ++k)
    if (k == q) f[k] = v;
}
template <unsigned Kind, unsigned S>
__global__ void __launch_bounds__(TPB) lazy_kernel(LazyArgs a) {
  __shared__ OM31 prm[7];
  __shared__ OM31 W[1u << KBMAX];
  __shared__ OM31 WA[S == 0 ? (1u << KBMAX) : 1][7];
  load_params(a.src, prm);
  for (uint32_t c = threadIdx.x; c < (1u << a.kb); c += TPB) W[c] = eq_direct(a.r, a.kb, c);
  __syncthreads();
  if constexpr (S == 0)
    for (uint32_t x = threadIdx.x; x < 7u * (1u << a.kb); x += TPB) WA[x / 7][x % 7] = mul(W[x / 7], prm[x % 7]);
  __syncthreads();
  const uint32_t Mk = 1u << (a.log_m - a.kb), Tk = Mk >> 2, ncs = 1u << a.kb;
  Acc4 acc{zero(), zero(), zero(), zero()};
  for (uint32_t i = blockIdx.x * TPB + threadIdx.x; i < Tk; i += gridDim.x * TPB) {
    const OM31 e = eq_at(a.eq, a.n_eq, i);
    Fraction f[4];
    for (int q = 0; q < 4; ++q) f[q] = {zero(), zero()};
    if (S == 0 && a.kb == 0) {
      uint32_t n[4];
#pragma unroll 1
      for (uint32_t q = 0; q < 4; ++q) {
        const uint32_t pos = (q >> 1) * 2 * Tk + 2 * i + (q & 1);
        uint32_t nq;
        OM31 dq;
        fact<Kind>(a.src, prm, pos, nq, dq);
        set_to(f, q, {base(nq), dq});
      }
      for (int q = 0; q < 4; ++q) n[q] = f[q].n.c0.a.a;
      acc_term_base(acc, n[0], f[0].d, n[1], f[1].d, n[2], f[2].d, n[3], f[3].d, e);
      continue;
    }
    if constexpr (S == 0) {
#pragma unroll 1
      for (uint32_t u = 0; u < 4 * ncs; ++u) {
        const uint32_t q = u & 3, c = u >> 2;
        const uint32_t pos = (q >> 1) * 2 * Tk + 2 * i + (q & 1);
        Fraction v;
        wfact<Kind>(a.src, WA[c], W[c], c * Mk + pos, v.n, v.d);
        add_to(f, q, v);
      }
    } else {
      Fraction ent;
#pragma unroll 1
      for (uint32_t u = 0; u < (4u << S) * ncs; ++u) {
        const uint32_t j = u & ((1u << S) - 1), q = (u >> S) & 3, c = u >> (S + 2);
        const uint32_t pos = (q >> 1) * 2 * Tk + 2 * i + (q & 1);
        uint32_t n;
        OM31 d;
        fact<Kind>(a.src, prm, ((c * Mk + pos) << S) + j, n, d);
        absorb_fact(ent, j, n, d);
        if (j == (1u << S) - 1) {
          if (a.kb) ent = {mul(W[c], ent.n), mul(W[c], ent.d)};
          add_to(f, q, ent);
        }
      }
    }
    if (a.write)
      for (uint32_t q = 0; q < 4; ++q) put(a.on, a.od, (q >> 1) * 2 * Tk + 2 * i + (q & 1), f[q]);
    acc_term(acc, f[0], f[1], f[2], f[3], e);
  }
  const Pair p = finish(acc, *a.lambda);
  write_partial(p, a.part, blockIdx.x);
}
#ifdef GB_KIND_TU
template <unsigned Kind>
uint32_t lazy_k(cudaStream_t st, const LazyArgs &a, uint32_t s, uint32_t grid) {
  switch (s) {
    case 0: lazy_kernel<Kind, 0><<<grid, TPB, 0, st>>>(a); break;
    case 1: lazy_kernel<Kind, 1><<<grid, TPB, 0, st>>>(a); break;
    case 2: lazy_kernel<Kind, 2><<<grid, TPB, 0, st>>>(a); break;
  }
  return grid;
}
template int tree_k<GB_KIND_TU>(cudaStream_t, const Src &, uint32_t, uint32_t, StwoRv64Plane, StwoRv64Plane);
template uint32_t lazy_k<GB_KIND_TU>(cudaStream_t, const LazyArgs &, uint32_t, uint32_t);
#endif
inline uint32_t lazy(cudaStream_t st, const LazyArgs &a, uint32_t s, uint32_t grid_cap) {
  const uint32_t terms = 1u << (a.log_m - a.kb - 2);
  const uint32_t grid = std::max<uint32_t>(1, std::min<uint32_t>((terms + TPB - 1) / TPB, grid_cap));
  if (a.kb > KBMAX || s > 2) {
    fprintf(stderr, "lazy kb/s out of range\n");
    exit(5);
  }
  switch (a.src.component) {
    case 2: return lazy_k<2>(st, a, s, grid);
    case 3: return lazy_k<3>(st, a, s, grid);
    case 4: return lazy_k<4>(st, a, s, grid);
    default: return lazy_k<6>(st, a, s, grid);
  }
}

// ---------------- batched materialised rounds (one launch / round) ----------------
struct MatJob {
  uint32_t mode;  // 0 sum, 1 fold+sum, 2 fold only
  Table in;
  uint64_t count;
  const OM31 *x;
  Table out;
  const EqTables *eq;
  uint32_t n_eq;
  const OM31 *lambda;
  StwoRv64Plane part;
  uint32_t first, blocks;
};
struct MatBatch {
  MatJob j[MAXI];
  uint32_t n, total;
};
#ifndef GB_KIND_TU
__global__ void __launch_bounds__(TPB) mat_kernel(const __grid_constant__ MatBatch b) {
  uint32_t q = 0;
  while (q + 1 < b.n && blockIdx.x >= b.j[q + 1].first) ++q;
  const MatJob &j = b.j[q];
  const uint32_t lb = blockIdx.x - j.first, stride = j.blocks * TPB;
  if (j.mode == 2) {
    const OM31 x = *j.x;
    const uint64_t half = j.count / 2;
    for (uint64_t i = lb * TPB + threadIdx.x; i < half; i += stride) {
      const Fraction a = get(j.in, i), c = get(j.in, i + half);
      put(j.out.n, j.out.d, i, {fold(a.n, c.n, x), fold(a.d, c.d, x)});
    }
    return;
  }
  Acc4 acc{zero(), zero(), zero(), zero()};
  if (j.mode == 0) {
    const uint64_t T = j.count / 4;
    for (uint64_t i = lb * TPB + threadIdx.x; i < T; i += stride) {
      acc_term(acc, get(j.in, 2 * i), get(j.in, 2 * i + 1), get(j.in, 2 * (T + i)),
               get(j.in, 2 * (T + i) + 1), eq_at(j.eq, j.n_eq, uint32_t(i)));
    }
  } else {
    const OM31 x = *j.x;
    const uint64_t half = j.count / 2, T = j.count / 8;
    for (uint64_t i = lb * TPB + threadIdx.x; i < T; i += stride) {
      const uint64_t pos[4] = {2 * i, 2 * i + 1, 2 * (T + i), 2 * (T + i) + 1};
      Fraction f[4];
      for (int k = 0; k < 4; ++k) {
        const Fraction a = get(j.in, pos[k]), c = get(j.in, pos[k] + half);
        f[k] = {fold(a.n, c.n, x), fold(a.d, c.d, x)};
        put(j.out.n, j.out.d, pos[k], f[k]);
      }
      acc_term(acc, f[0], f[1], f[2], f[3], eq_at(j.eq, j.n_eq, uint32_t(i)));
    }
  }
  write_partial(finish(acc, *j.lambda), j.part, lb);
}
inline uint32_t add_job(MatBatch &b, MatJob j, uint32_t grid_cap, int) {
  const uint64_t work = j.mode == 0 ? j.count / 4 : j.mode == 1 ? j.count / 8 : j.count / 2;
  j.blocks = uint32_t(std::max<uint64_t>(1, std::min<uint64_t>((work + TPB - 1) / TPB, grid_cap)));
  j.first = b.total;
  b.total += j.blocks;
  b.j[b.n++] = j;
  return j.blocks;
}
inline void launch(cudaStream_t st, const MatBatch &b) {
  if (!b.n) return;
  mat_kernel<<<b.total, TPB, 0, st>>>(b);
}
#endif
}  // namespace fused
}  // namespace gb
