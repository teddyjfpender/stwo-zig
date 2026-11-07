// M9 outer-GKR kernel benchmark (stream m9-gkr-bench, STWO_RV64_M9_GKR_BENCH).
// Standalone: nvcc -O3 -arch=sm_120 -std=c++17 -I src/backends/cuda/native \
//   -Xcompiler -fopenmp src/backends/cuda/native/rv64/bench/m9_gkr_bench.cu
//
// Route A ("m7"): the production kernels unchanged (gkr.cu, outer_gkr_projected.cu
//   lazy callbacks for the input layer, retained tree of every level, eq plane
//   per round), driven in the resident order by this harness.
// Route B ("fused"): new kernels in fused_gkr.cuh. Bottom S tree levels are never
//   stored; their sumchecks evaluate entries lazily from MAIN/FIXED, the first J
//   rounds fold in registers, round J+1 materialises the 2^-J-size table, the
//   rest run on one batched multi-instance launch per round. Split Eq tables.
// Both routes share the round/close/begin kernels (one thread does the
// transcript, as gkr_loop.cu) and produce bit-identical proofs; the CPU
// verifier (gkr_bench_cpu.h) checks every round and the terminal input MLE.
#include <cuda_runtime.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// ---- exec-context stubs: production custody runs unchanged ----
struct BenchCtx {
  cudaStream_t stream;
};
extern "C" int stwo_exec_context_lane_stream(void *ctx, uint32_t, void **out) {
  *out = static_cast<BenchCtx *>(ctx)->stream;
  return 0;
}
extern "C" int stwo_exec_context_validate_allocation(void *, const void *, size_t) { return 0; }

#include "../gkr.cu"
#include "../outer_gkr_projected.cu"
#include "../outer_gkr_binding.cu"
#include "gkr_bench_cpu.h"
#include "fused_gkr.cuh"

#define CK(x)                                                                              \
  do {                                                                                     \
    cudaError_t e_ = (x);                                                                  \
    if (e_ != cudaSuccess) {                                                               \
      fprintf(stderr, "CUDA %s at %s:%d: %s\n", #x, __FILE__, __LINE__, cudaGetErrorString(e_)); \
      exit(2);                                                                             \
    }                                                                                      \
  } while (0)
#define CKI(x)                                                                \
  do {                                                                        \
    int s_ = (x);                                                             \
    if (s_) {                                                                 \
      fprintf(stderr, "status %d at %s:%d (%s)\n", s_, __FILE__, __LINE__, #x); \
      exit(3);                                                                \
    }                                                                         \
  } while (0)

namespace gb {
// ------------------------------------------------------------------ memory
struct Arena {
  std::vector<void *> blocks;
  size_t bytes = 0;
  template <class T>
  T *get(size_t n) {
    void *p = nullptr;
    CK(cudaMalloc(&p, n * sizeof(T) + 256));
    blocks.push_back(p);
    bytes += n * sizeof(T);
    return static_cast<T *>(p);
  }
  void release() {
    for (auto *p : blocks) cudaFree(p);
    blocks.clear();
    bytes = 0;
  }
};
inline StwoRv64Plane plane(uint32_t *w, uint64_t stride, uint32_t coords = 8) {
  return StwoRv64Plane{w, stride, coords, 0};
}
inline Table make_table(Arena &a, uint64_t cap) {
  uint32_t *w = a.get<uint32_t>(16 * cap);
  return {plane(w, cap), plane(w + 8 * cap, cap), cap};
}

// ------------------------------------------------------------------ trace
__global__ void gen_cols(uint32_t *out, uint32_t seed, uint32_t comp, uint32_t col0,
                         uint32_t cols, uint32_t row_log) {
  const uint64_t rows = 1ull << row_log, total = rows * cols;
  for (uint64_t i = blockIdx.x * uint64_t(blockDim.x) + threadIdx.x; i < total;
       i += uint64_t(gridDim.x) * blockDim.x) {
    const uint32_t c = uint32_t(i >> row_log), r = uint32_t(i & (rows - 1));
    out[i] = trace_value(seed, comp, col0 + c, r);
  }
}
struct DevTrace {
  uint32_t *main[11]{}, *fixed[11]{}, *params = nullptr, *status = nullptr;
  uint32_t row_log[11]{};
  size_t bytes = 0;
};
inline DevTrace dev_trace(Arena &a, const ClassSpec &cs, uint32_t seed, cudaStream_t st) {
  DevTrace t;
  for (int i = 0; i < cs.n; ++i) {
    const uint32_t k = cs.inst[i].comp, rl = cs.inst[i].row_log;
    if (t.main[k]) continue;
    const uint64_t rows = 1ull << rl;
    t.row_log[k] = rl;
    t.main[k] = a.get<uint32_t>(rows * tup::kBaseWidths[k]);
    gen_cols<<<2048, 256, 0, st>>>(t.main[k], seed, k, 0, tup::kBaseWidths[k], rl);
    t.bytes += rows * tup::kBaseWidths[k] * 4;
    if (tup::kPpWidths[k]) {
      t.fixed[k] = a.get<uint32_t>(rows * tup::kPpWidths[k]);
      gen_cols<<<2048, 256, 0, st>>>(t.fixed[k], seed, k, 64, tup::kPpWidths[k], rl);
      t.bytes += rows * tup::kPpWidths[k] * 4;
    }
  }
  uint32_t hp[56];
  make_params(seed, hp);
  t.params = a.get<uint32_t>(56);
  t.status = a.get<uint32_t>(1);
  CK(cudaMemcpyAsync(t.params, hp, sizeof(hp), cudaMemcpyHostToDevice, st));
  CK(cudaMemsetAsync(t.status, 0, 4, st));
  return t;
}
inline StwoCircuitOuterGkrSource dev_source(const DevTrace &t, const Inst &in) {
  const uint64_t rows = 1ull << in.row_log;
  StwoCircuitOuterGkrSource s{};
  s.fixed = t.fixed[in.comp];
  s.main = t.main[in.comp];
  s.parameters = t.params;
  s.status = t.status;
  s.fixed_words = rows * tup::kPpWidths[in.comp];
  s.main_words = rows * tup::kBaseWidths[in.comp];
  s.component = in.comp;
  s.row_log = in.row_log;
  s.lane_first = in.lane_first;
  s.lane_log = in.lane_log;
  return s;
}

// ------------------------------------------------------------------ shared protocol kernels
struct PartRefs {
  StwoRv64Plane p[MAXI];
  uint32_t blocks[MAXI];
};
struct MaskRefs {
  StwoRv64Plane n[MAXI], d[MAXI];
};
struct RootRefs {
  StwoRv64Plane n[MAXI], d[MAXI];
};
__global__ void init_kernel(State *s, uint32_t seed) {
  if (threadIdx.x == 0) init_state(*s, seed);
}
__global__ void begin_kernel(State *s, const __grid_constant__ DepthDesc dd, const __grid_constant__ RootRefs roots, uint32_t *log) {
  if (threadIdx.x) return;
  OM31 rn[MAXI], rd[MAXI];
  for (uint32_t i = 0; i < dd.n; ++i)
    if (dd.active[i] && dd.v[i] == 0) {
      rn[i] = load(roots.n[i].words, roots.n[i].stride, 0);
      rd[i] = load(roots.d[i].words, roots.d[i].stride, 0);
    }
  begin_depth(*s, dd, rn, rd, log);
}
// Eq suffix tables of every active instance (blockIdx.y = instance).
__global__ void eq_gen_kernel(const State *s, const __grid_constant__ DepthDesc dd, EqTables *tabs) {
  const uint32_t i = blockIdx.y;
  if (!dd.active[i] || dd.v[i] == 0) return;
  const uint32_t v = dd.v[i];
  const OM31 *y = s->point[i];
  if (blockIdx.x == 0)
    for (uint32_t k = threadIdx.x; k < v; k += blockDim.x)
      const_cast<State *>(s)->yinv[i][k] = inverse_nonzero(y[k]);
  const uint32_t spn = v - 1 < SPLIT ? v - 1 : SPLIT;  // max suffix needed = v-1
  const uint32_t sp_total = (1u << (spn + 1)) - 1;
  const uint32_t hm = v - 1 > SPLIT ? v - 1 - SPLIT : 0;
  const uint32_t hp_total = hm ? (1u << (hm + 1)) - 1 : 0;
  for (uint32_t e = blockIdx.x * blockDim.x + threadIdx.x; e < sp_total + hp_total;
       e += gridDim.x * blockDim.x) {
    if (e < sp_total) {
      const uint32_t n = 31 - __clz(e + 1), b = e + 1 - (1u << n);
      tabs[i].sp[e] = eq_direct(y + (v - n), n, b);
    } else {
      const uint32_t f = e - sp_total;
      const uint32_t m = 31 - __clz(f + 1), b = f + 1 - (1u << m);
      tabs[i].hp[f] = eq_direct(y + (v - SPLIT - m), m, b);
    }
  }
}
__global__ void __launch_bounds__(256) round_kernel(State *s, const __grid_constant__ DepthDesc dd, uint32_t t,
                                                    const __grid_constant__ PartRefs parts, uint32_t *log) {
  // Warp w reduces instance w's partials; lane 0 of warp w forms its round
  // polynomial; thread 0 batches, absorbs and draws; lanes update in parallel.
  __shared__ OM31 h0[MAXI], h1[MAXI], h2[MAXI], Sv[MAXI][4], r;
  const uint32_t w = threadIdx.x >> 5, lane = threadIdx.x & 31;
  const bool own = w < dd.n && dd.active[w] && t > dd.d - dd.v[w];
  if (own) {
    Pair acc{zero(), zero()};
    for (uint32_t b = lane; b < parts.blocks[w]; b += 32) {
      acc.at0 = add(acc.at0, load(parts.p[w].words, parts.p[w].stride, 2 * b));
      acc.at2 = add(acc.at2, load(parts.p[w].words, parts.p[w].stride, 2 * b + 1));
    }
    acc.at0 = warp_sum(acc.at0);
    acc.at2 = warp_sum(acc.at2);
    if (!lane) {
      h0[w] = acc.at0;
      h2[w] = acc.at2;
    }
  }
  __syncwarp();
  if (w < dd.n && dd.active[w] && !lane) inst_poly(*s, dd, t, w, h0[w], h2[w], s->yinv[w], Sv[w], h1[w]);
  __syncthreads();
  if (threadIdx.x == 0) {
    OM31 S[4] = {zero(), zero(), zero(), zero()};
    for (uint32_t i = 0; i < dd.n; ++i)
      if (dd.active[i])
        for (int j = 0; j < 4; ++j) S[j] = add(S[j], Sv[i][j]);
    r = absorb_round(*s, S, t, log);
  }
  __syncthreads();
  if (w < dd.n && dd.active[w] && !lane) inst_update(*s, dd, t, w, h0[w], h1[w], h2[w], r);
}
__global__ void close_kernel(State *s, const __grid_constant__ DepthDesc dd, const __grid_constant__ MaskRefs m, uint32_t *log) {
  if (threadIdx.x) return;
  OM31 mask[MAXI][4];
  for (uint32_t i = 0; i < dd.n; ++i)
    if (dd.active[i]) {
      mask[i][0] = load(m.n[i].words, m.n[i].stride, 0);
      mask[i][1] = load(m.d[i].words, m.d[i].stride, 0);
      mask[i][2] = load(m.n[i].words, m.n[i].stride, 1);
      mask[i][3] = load(m.d[i].words, m.d[i].stride, 1);
    }
  close_depth(*s, dd, mask, log);
}
__global__ void eq_full_kernel(const EqTables *t, uint32_t n, StwoRv64Plane out) {
  const uint32_t count = 1u << n;
  for (uint32_t b = blockIdx.x * blockDim.x + threadIdx.x; b < count; b += gridDim.x * blockDim.x)
    store(out.words, out.stride, b, eq_at(t, n, b));
}

// ------------------------------------------------------------------ prover config
struct Config {
  int route = 1;      // 0 = A (production kernels), 1 = B (fused)
  uint32_t S = 3;     // B: unstored bottom levels (lazy)
  uint32_t J = 4;     // B: lazy rounds before materialising
  uint32_t grid_cap = 1360;
  bool graph = true;
  int reps = 5;
};
struct PhaseTimer {
  std::vector<cudaEvent_t> ev;
  std::vector<std::string> name;
  bool on = false;
  void mark(cudaStream_t st, const std::string &n) {
    if (!on) return;
    cudaEvent_t e;
    CK(cudaEventCreate(&e));
    CK(cudaEventRecord(e, st));
    ev.push_back(e);
    name.push_back(n);
  }
};

struct Prover {
  ClassSpec cs;
  Config cfg;
  BenchCtx ctx;
  cudaStream_t st;
  Arena arena;
  DevTrace tr;
  uint32_t lmax = 0, seed = 7;
  State *state = nullptr;
  uint32_t *log = nullptr;
  EqTables *eqt = nullptr;
  StwoCircuitOuterGkrSource src[MAXI];
  // tree slots: level m of instance i (count 2^m); nullptr planes when unstored
  std::vector<Table> slot[MAXI];
  Table mask[MAXI];
  // route A extras
  uint32_t *eqfull[MAXI];
  uint32_t *scratch_a[MAXI], *scratch_b[MAXI], *outw[MAXI];
  uint64_t scratch_groups[MAXI];
  // route B partial planes
  uint32_t *part[MAXI];
  size_t workspace_bytes = 0;

  uint32_t L(int i) const { return inst_vars(cs.inst[i]); }
  void setup() {
    CK(cudaStreamCreateWithFlags(&st, cudaStreamNonBlocking));
    ctx.stream = st;
    lmax = class_layers(cs);
    tr = dev_trace(arena, cs, seed, st);
    const size_t trace_bytes = arena.bytes;
    state = arena.get<State>(1);
    log = arena.get<uint32_t>(1u << 17);
    eqt = arena.get<EqTables>(MAXI);
    for (int i = 0; i < cs.n; ++i) {
      src[i] = dev_source(tr, cs.inst[i]);
      const uint32_t Li = L(i);
      slot[i].assign(Li + 1, Table{});
      const uint32_t top = cfg.route == 0 ? Li - 1 : Li - cfg.S;  // highest stored level
      for (uint32_t m = 0; m <= top; ++m) slot[i][m] = make_table(arena, 1ull << m);
      mask[i] = make_table(arena, 2);
      if (cfg.route == 0) {
        eqfull[i] = arena.get<uint32_t>(8ull << (Li - 2));
        scratch_groups[i] = ((1ull << Li) / 4 + 127) / 128;
        scratch_a[i] = arena.get<uint32_t>(16 * scratch_groups[i]);
        scratch_b[i] = arena.get<uint32_t>(16 * scratch_groups[i]);
        outw[i] = arena.get<uint32_t>(16);
      } else {
        part[i] = arena.get<uint32_t>(16ull * cfg.grid_cap);
      }
    }
    workspace_bytes = arena.bytes - trace_bytes;
    CK(cudaStreamSynchronize(st));
  }
  // ---------------- forward product tree ----------------
  void forward(PhaseTimer &pt) {
    for (int i = 0; i < cs.n; ++i) {
      const uint32_t Li = L(i);
      if (cfg.route == 0) {
        CKI(stwo_circuit_outer_gkr_layer_on(&ctx, 0, &src[i], 1u << Li, 1, slot[i][Li - 1].n,
                                            slot[i][Li - 1].d));
        for (uint32_t m = Li - 1; m >= 1; --m)
          CKI(stwo_rv64_gkr_layer_on(&ctx, 0, slot[i][m].n, slot[i][m].d, 1u << m, 1,
                                     slot[i][m - 1].n, slot[i][m - 1].d));
      } else {
        const uint32_t top = Li - cfg.S;
        CKI(fused::tree(st, src[i], cfg.S, top, slot[i][top].n, slot[i][top].d));
        for (uint32_t m = top; m >= 1; --m)
          CKI(stwo_rv64_gkr_layer_on(&ctx, 0, slot[i][m].n, slot[i][m].d, 1u << m, 1,
                                     slot[i][m - 1].n, slot[i][m - 1].d));
      }
    }
    pt.mark(st, "forward");
  }
  const OM31 *rptr(uint32_t t) const { return &state->r[t - 1]; }  // global round t
  const uint32_t *rwords(uint32_t t) const { return reinterpret_cast<const uint32_t *>(&state->r[t - 1]); }
  const uint32_t *lamw() const { return reinterpret_cast<const uint32_t *>(&state->lambda); }
  // ---------------- route A: one own round of instance i ----------------
  // cur: table holding the current round input (after the previous fold).
  struct Cursor {
    Table cur;
    uint64_t count;
    int bank;  // which bank next fold writes
  };
  Cursor cursorA[MAXI], cursorB[MAXI];
  void routeA_round(int i, const DepthDesc &dd, uint32_t t, PartRefs &pr) {
    const uint32_t v = dd.v[i], lead = dd.d - v, k = t - lead, m = v + 1;
    const bool input = m == L(i);
    const uint32_t n_eq = v - k;
    StwoRv64Plane eqp = plane(eqfull[i], 1ull << n_eq);
    eq_full_kernel<<<std::min<uint32_t>(1024, ((1u << n_eq) + 255) / 256), 256, 0, st>>>(&eqt[i], n_eq, eqp);
    const StwoRv64Plane a = plane(scratch_a[i], 2 * scratch_groups[i]);
    const StwoRv64Plane b = plane(scratch_b[i], 2 * scratch_groups[i]);
    const StwoRv64Plane out = plane(outw[i], 2);
    Cursor &c = cursorA[i];
    const Table bank0 = slot[i][m - 1], bank1 = m >= 2 ? slot[i][m - 2] : Table{};
    if (k == 1) {
      c.count = 1ull << m;
      c.bank = 0;
      if (input) {
        CKI(stwo_circuit_outer_gkr_sum_on(&ctx, 0, &src[i], uint32_t(c.count), eqp, lamw(), a, b, out));
      } else {
        c.cur = slot[i][m];
        CKI(stwo_rv64_gkr_sum_on(&ctx, 0, c.cur.n, c.cur.d, uint32_t(c.count), eqp, lamw(), a, b, out));
      }
    } else if (k == 2 && input) {
      CKI(stwo_circuit_outer_gkr_fold_on(&ctx, 0, &src[i], uint32_t(c.count), rwords(t - 1), bank0.n, bank0.d));
      c.cur = bank0;
      c.count /= 2;
      c.bank = 1;
      CKI(stwo_rv64_gkr_sum_on(&ctx, 0, c.cur.n, c.cur.d, uint32_t(c.count), eqp, lamw(), a, b, out));
    } else {
      const Table nx = c.bank == 0 ? bank0 : bank1;
      CKI(stwo_rv64_gkr_fold_sum_on(&ctx, 0, c.cur.n, c.cur.d, uint32_t(c.count), rwords(t - 1), nx.n, nx.d,
                                    eqp, lamw(), a, b, out));
      c.cur = nx;
      c.count /= 2;
      c.bank ^= 1;
    }
    pr.p[i] = out;
    pr.blocks[i] = 1;
  }
  void routeA_final(int i, const DepthDesc &dd) {
    const uint32_t v = dd.v[i];
    if (v == 0) return;
    Cursor &c = cursorA[i];
    if (v == 1) c.cur = slot[i][2], c.count = 4;
    CKI(stwo_rv64_gkr_fold_on(&ctx, 0, c.cur.n, c.cur.d, uint32_t(c.count), rwords(dd.d), mask[i].n, mask[i].d));
  }
  // ---------------- route B ----------------
  void routeB_round(const DepthDesc &dd, uint32_t t, PartRefs &pr, fused::MatBatch &mb) {
    for (int i = 0; i < cs.n; ++i) {
      if (!dd.active[i] || t <= dd.d - dd.v[i]) continue;
      const uint32_t v = dd.v[i], lead = dd.d - v, k = t - lead, m = v + 1, s = L(i) - m;
      const uint32_t n_eq = v - k;
      Cursor &c = cursorB[i];
      const bool lazy = s < cfg.S;
      const Table bank0 = lazy ? slot[i][L(i) - cfg.S] : slot[i][m - 1];
      const Table bank1 = lazy ? slot[i][L(i) - cfg.S - 1] : (m >= 2 ? slot[i][m - 2] : Table{});
      pr.p[i] = plane(part[i], 2ull * cfg.grid_cap);
      if (lazy && k <= cfg.J + 1) {
        fused::LazyArgs a{};
        a.src = src[i];
        a.log_m = m;
        a.kb = k - 1;
        a.r = rptr(lead + 1);
        a.eq = &eqt[i];
        a.n_eq = n_eq;
        a.lambda = &state->lambda;
        a.write = k == cfg.J + 1;
        a.on = bank0.n;
        a.od = bank0.d;
        a.part = pr.p[i];
        pr.blocks[i] = fused::lazy(st, a, s, cfg.grid_cap);
        if (a.write) {
          c.cur = bank0;
          c.count = 1ull << (m - cfg.J);
          c.bank = 1;
        }
        continue;
      }
      fused::MatJob j{};
      j.eq = &eqt[i];
      j.n_eq = n_eq;
      j.lambda = &state->lambda;
      j.part = pr.p[i];
      if (k == 1) {
        c.cur = slot[i][m];
        c.count = 1ull << m;
        c.bank = 0;
        j.mode = 0;
        j.in = c.cur;
        j.count = c.count;
      } else {
        const Table nx = c.bank == 0 ? bank0 : bank1;
        j.mode = 1;
        j.in = c.cur;
        j.count = c.count;
        j.x = rptr(t - 1);
        j.out = nx;
        c.cur = nx;
        c.count /= 2;
        c.bank ^= 1;
      }
      pr.blocks[i] = fused::add_job(mb, j, cfg.grid_cap, i);
    }
    fused::launch(st, mb);
  }
  void routeB_final(const DepthDesc &dd) {
    fused::MatBatch mb{};
    for (int i = 0; i < cs.n; ++i) {
      if (!dd.active[i] || dd.v[i] == 0) continue;
      Cursor &c = cursorB[i];
      if (dd.v[i] == 1) c.cur = slot[i][2], c.count = 4;
      fused::MatJob j{};
      j.mode = 2;
      j.in = c.cur;
      j.count = c.count;
      j.x = rptr(dd.d);
      j.out = mask[i];
      fused::add_job(mb, j, cfg.grid_cap, i);
    }
    fused::launch(st, mb);
  }
  // ---------------- whole proof ----------------
  void prove(PhaseTimer &pt) {
    pt.mark(st, "start");
    CK(cudaMemsetAsync(tr.status, 0, 4, st));
    init_kernel<<<1, 32, 0, st>>>(state, seed);
    forward(pt);
    for (uint32_t d = 0; d < lmax; ++d) {
      const DepthDesc dd = depth_desc(cs, d);
      RootRefs roots{};
      MaskRefs masks{};
      for (int i = 0; i < cs.n; ++i) {
        roots.n[i] = slot[i][0].n;
        roots.d[i] = slot[i][0].d;
        const bool v0 = dd.active[i] && dd.v[i] == 0;
        masks.n[i] = v0 ? slot[i][1].n : mask[i].n;
        masks.d[i] = v0 ? slot[i][1].d : mask[i].d;
      }
      begin_kernel<<<1, 32, 0, st>>>(state, dd, roots, log);
      if (d) eq_gen_kernel<<<dim3(64, cs.n), 128, 0, st>>>(state, dd, eqt);
      for (uint32_t t = 1; t <= d; ++t) {
        PartRefs pr{};
        if (cfg.route == 0) {
          for (int i = 0; i < cs.n; ++i)
            if (dd.active[i] && t > dd.d - dd.v[i]) routeA_round(i, dd, t, pr);
        } else {
          fused::MatBatch mb{};
          routeB_round(dd, t, pr, mb);
        }
        round_kernel<<<1, 256, 0, st>>>(state, dd, t, pr, log);
      }
      if (cfg.route == 0) {
        for (int i = 0; i < cs.n; ++i)
          if (dd.active[i]) routeA_final(i, dd);
      } else {
        routeB_final(dd);
      }
      close_kernel<<<1, 32, 0, st>>>(state, dd, masks, log);
      char nm[32];
      snprintf(nm, sizeof nm, "depth%u", d);
      pt.mark(st, nm);
    }
    CK(cudaPeekAtLastError());
  }
};
}  // namespace gb

// ------------------------------------------------------------------ main
int main(int argc, char **argv) {
  using namespace gb;
  int which = 0;
  uint32_t shift = 0;
  Config cfg;
  bool cpu_ref = false, verify = true, phases = false, terminal = true, binding = false;
  for (int a = 1; a < argc; ++a) {
    std::string s = argv[a];
    auto val = [&](const char *k) { return s.rfind(k, 0) == 0 ? s.substr(strlen(k)) : std::string(); };
    if (s == "--fold") which = 1;
    else if (s == "--leaf") which = 0;
    else if (s == "--route=A") cfg.route = 0;
    else if (s == "--route=B") cfg.route = 1;
    else if (s == "--cpu-ref") cpu_ref = true;
    else if (s == "--no-verify") verify = false;
    else if (s == "--no-terminal") terminal = false;
    else if (s == "--no-graph") cfg.graph = false;
    else if (s == "--phases") phases = true;
    else if (s == "--binding") binding = true;
    else if (!val("--shift=").empty()) shift = atoi(val("--shift=").c_str());
    else if (!val("--S=").empty()) cfg.S = atoi(val("--S=").c_str());
    else if (!val("--J=").empty()) cfg.J = atoi(val("--J=").c_str());
    else if (!val("--reps=").empty()) cfg.reps = atoi(val("--reps=").c_str());
    else if (!val("--grid=").empty()) cfg.grid_cap = atoi(val("--grid=").c_str());
    else {
      fprintf(stderr, "unknown arg %s\n", s.c_str());
      return 1;
    }
  }
  if (cfg.route == 1 && cfg.J < cfg.S) {
    fprintf(stderr, "route B needs J >= S (fold banks reuse the consumed V_{L-S} slot)\n");
    return 1;
  }
  Prover p;
  p.cs = class_spec(which, shift);
  p.cfg = cfg;
  uint64_t facts = 0;
  for (int i = 0; i < p.cs.n; ++i) facts += 1ull << inst_vars(p.cs.inst[i]);
  p.setup();
  // one untimed proof for the log (and parity)
  PhaseTimer none;
  p.prove(none);
  CK(cudaStreamSynchronize(p.st));
  uint32_t words = 0, status = 0;
  {
    State hs;
    CK(cudaMemcpy(&hs, p.state, sizeof(State), cudaMemcpyDeviceToHost));
    words = hs.log_words;
    CK(cudaMemcpy(&status, p.tr.status, 4, cudaMemcpyDeviceToHost));
  }
  std::vector<uint32_t> glog(words);
  CK(cudaMemcpy(glog.data(), p.log, 4ull * words, cudaMemcpyDeviceToHost));
  uint64_t digest = 1469598103934665603ull;
  for (auto w : glog) digest = (digest ^ w) * 1099511628211ull;
  // timed proofs
  std::vector<double> ms;
  cudaGraphExec_t exec = nullptr;
  if (cfg.graph) {
    cudaGraph_t g;
    CK(cudaStreamBeginCapture(p.st, cudaStreamCaptureModeThreadLocal));
    p.prove(none);
    CK(cudaStreamEndCapture(p.st, &g));
    CK(cudaGraphInstantiate(&exec, g, 0));
    CK(cudaGraphDestroy(g));
    CK(cudaGraphLaunch(exec, p.st));  // warm
    CK(cudaStreamSynchronize(p.st));
  }
  cudaEvent_t e0, e1;
  CK(cudaEventCreate(&e0));
  CK(cudaEventCreate(&e1));
  for (int r = 0; r < cfg.reps; ++r) {
    CK(cudaEventRecord(e0, p.st));
    if (exec) CK(cudaGraphLaunch(exec, p.st));
    else p.prove(none);
    CK(cudaEventRecord(e1, p.st));
    CK(cudaEventSynchronize(e1));
    float t;
    CK(cudaEventElapsedTime(&t, e0, e1));
    ms.push_back(t);
  }
  // re-check the log after timed runs is unchanged
  std::vector<uint32_t> glog2(words);
  CK(cudaMemcpy(glog2.data(), p.log, 4ull * words, cudaMemcpyDeviceToHost));
  const bool stable = glog2 == glog;
  std::vector<double> sorted = ms;
  std::sort(sorted.begin(), sorted.end());
  const double med = sorted[sorted.size() / 2], best = sorted[0];
  // phase breakdown (direct launches)
  std::string phase_json;
  if (phases) {
    PhaseTimer pt;
    pt.on = true;
    p.prove(pt);
    CK(cudaStreamSynchronize(p.st));
    phase_json = ",\"phases_ms\":{";
    for (size_t k = 1; k < pt.ev.size(); ++k) {
      float t;
      CK(cudaEventElapsedTime(&t, pt.ev[k - 1], pt.ev[k]));
      phase_json += (k > 1 ? "," : "") + std::string("\"") + pt.name[k] + "\":" + std::to_string(t);
    }
    phase_json += "}";
  }
  // v2 late binding pass (production outer_gkr_binding.cu, one launch per
  // instance): timing only, synthetic canonical metadata/Eq (not parity-checked).
  double bind_ms = -1;
  if (binding) {
    std::vector<uint32_t *> eqw(p.cs.n), prw(p.cs.n);
    uint32_t *meta = p.arena.get<uint32_t>(28 * 8);
    std::vector<uint32_t> hm(28 * 8);
    for (int k = 0; k < 28 * 8; ++k) hm[k] = hash_word(0x77000000ull + k);
    CK(cudaMemcpy(meta, hm.data(), hm.size() * 4, cudaMemcpyHostToDevice));
    std::vector<StwoCircuitOuterBinding> jobs(p.cs.n);
    for (int i = 0; i < p.cs.n; ++i) {
      const uint64_t rows = 1ull << p.cs.inst[i].row_log;
      eqw[i] = p.arena.get<uint32_t>(8 * rows);
      prw[i] = p.arena.get<uint32_t>(8 * rows);
      gen_cols<<<2048, 256, 0, p.st>>>(eqw[i], 99, 1, 0, 8, p.cs.inst[i].row_log);
      jobs[i].source = p.src[i];
      jobs[i].metadata = meta;
      jobs[i].eq = plane(eqw[i], rows);
      jobs[i].prefix = plane(prw[i], rows);
    }
    CK(cudaStreamSynchronize(p.st));
    std::vector<double> bms;
    for (int r = 0; r < 4; ++r) {
      CK(cudaEventRecord(e0, p.st));
      for (int i = 0; i < p.cs.n; ++i) CKI(stwo_circuit_outer_gkr_binding_on(&p.ctx, 0, &jobs[i]));
      CK(cudaEventRecord(e1, p.st));
      CK(cudaEventSynchronize(e1));
      float t;
      CK(cudaEventElapsedTime(&t, e0, e1));
      bms.push_back(t);
    }
    std::sort(bms.begin(), bms.end());
    bind_ms = bms[bms.size() / 2];
    CK(cudaMemsetAsync(p.tr.status, 0, 4, p.st));
  }
  // parity / verification
  std::string cpu_json = ",\"cpu_ref\":null";
  HostTrace h;
  bool vok = true;
  const char *vwhy = "skipped";
  double vsec = 0;
  if (cpu_ref || verify) host_trace(h, p.cs, p.seed);
  if (cpu_ref) {
    auto clog = cpu_prove(h, p.cs, p.seed);
    const bool eq = clog == glog;
    cpu_json = std::string(",\"cpu_ref\":{\"words\":") + std::to_string(clog.size()) +
               ",\"bit_identical\":" + (eq ? "true" : "false") + "}";
  }
  if (verify) {
    auto r = cpu_verify(h, p.cs, p.seed, glog.data(), words, terminal);
    vok = r.ok;
    vwhy = r.why;
    vsec = r.terminal_seconds;
  }
  cudaDeviceProp prop;
  CK(cudaGetDeviceProperties(&prop, 0));
  printf("{\"class\":\"%s\",\"shift\":%u,\"route\":\"%s\",\"S\":%u,\"J\":%u,\"graph\":%s,"
         "\"facts\":%llu,\"layers\":%u,\"device\":\"%s\",\"reps_ms\":[",
         p.cs.name, shift, cfg.route ? "B" : "A", cfg.S, cfg.J, cfg.graph ? "true" : "false",
         (unsigned long long)facts, p.lmax, prop.name);
  for (size_t k = 0; k < ms.size(); ++k) printf("%s%.3f", k ? "," : "", ms[k]);
  printf("],\"median_ms\":%.3f,\"best_ms\":%.3f,\"ns_per_fact_median\":%.4f,\"ns_per_fact_best\":%.4f,"
         "\"workspace_bytes\":%zu,\"workspace_B_per_fact\":%.2f,\"trace_bytes\":%zu,"
         "\"log_words\":%u,\"log_fnv64\":\"%016llx\",\"log_stable_across_reps\":%s,\"source_status\":%u,"
         "\"binding_ms\":%.3f,\"verify\":{\"ok\":%s,\"why\":\"%s\",\"terminal\":%s,\"terminal_s\":%.2f}%s%s}\n",
         med, best, med * 1e6 / facts, best * 1e6 / facts, p.workspace_bytes,
         double(p.workspace_bytes) / facts, p.tr.bytes, words, (unsigned long long)digest,
         stable ? "true" : "false", status, bind_ms, vok ? "true" : "false", vwhy, terminal ? "true" : "false",
         vsec, cpu_json.c_str(), phase_json.c_str());
  p.arena.release();
  return vok && stable && status == 0 ? 0 : 4;
}
