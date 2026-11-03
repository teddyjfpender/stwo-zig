// Primitive throughputs of FlashProve's blocks/ CPU reference code (commit 9e2bdd8f), measured by
// including its headers. Every kernel below calls the repo's own functions (operator* on F/E,
// Encoder::encode, leaf(), vertex(), Tree, SumcheckCpu). Two loops (fold_round, halve) are private
// members of EngineCpu, so they are copied verbatim from blocks/engine/engine_cpu.h (marked).
//   prim_bench [threads]   threads=1: single core. threads>1: the same single-thread kernel run
//   independently in T threads at once (aggregate = T * per-thread work / wall). The repo's
//   EngineCpu itself is sequential; the multi-thread figures are an embarrassingly parallel upper
//   bound of this harness, not something their engine does.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "code/code.h"
#include "engine/sumcheck_cpu.h"
#include "field/field.h"
#include "hash/hash.h"
#include "toy/product.h"  // toy_summand(), toy_claim(): the sumcheck the toy run uses
#include "tree/opening.h"
#include "tree/tree.h"

using namespace blk;
using clk = std::chrono::steady_clock;

static volatile u64 g_sink = 0;
static unsigned g_threads = 1;
static FILE *g_json = nullptr;
static bool g_first_json = true;

static u64 rng_state = 0x9E3779B97F4A7C15ull;
static u64 rnd() {  // splitmix64
  u64 z = (rng_state += 0x9E3779B97F4A7C15ull);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
static F rF() { return F{rnd() % P}; }
static E rE() { return E{{rF(), rF(), rF()}}; }

// Runs body(tid) on g_threads threads at once (each thread owns its data, made by setup(tid)
// before the timer). Returns median wall seconds over reps (after 1 warm-up).
static double timeit(const std::function<void(unsigned)> &body, int reps = 7) {
  std::vector<double> ts;
  for (int r = -1; r < reps; r++) {
    std::atomic<unsigned> ready{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> th;
    for (unsigned t = 0; t < g_threads; t++)
      th.emplace_back([&, t] {
        ready++;
        while (!go.load()) {}
        body(t);
      });
    while (ready.load() < g_threads) {}
    const auto t0 = clk::now();
    go = true;
    for (auto &x : th) x.join();
    const double s = std::chrono::duration<double>(clk::now() - t0).count();
    if (r >= 0) ts.push_back(s);
  }
  std::sort(ts.begin(), ts.end());
  return ts[ts.size() / 2];
}

static void report(const char *name, const std::string &params, double per_thread_items, const char *unit, double secs, const char *extra = "") {
  const double agg = per_thread_items * g_threads / secs;
  std::printf("%-34s %-44s threads=%2u  %12.4g %s/s  (median %.4g s; %.3f ns/item/thread) %s\n", name, params.c_str(), g_threads, agg, unit, secs,
              secs * 1e9 / per_thread_items, extra);
  std::fflush(stdout);
  if (g_json) {
    std::fprintf(g_json, "%s  {\"bench\":\"%s\",\"params\":\"%s\",\"threads\":%u,\"value\":%.6g,\"unit\":\"%s/s\",\"median_s\":%.6g,\"ns_per_item_per_thread\":%.6g}",
                 g_first_json ? "" : ",\n", name, params.c_str(), g_threads, agg, unit, secs, secs * 1e9 / per_thread_items);
    g_first_json = false;
  }
}

// ---------------- (a)-(c) field arithmetic ----------------
// Throughput: N = 4096 independent products per pass (L1-resident), repeated R times.
// Latency: one dependent chain.
static void bench_field() {
  const size_t N = 4096;
  const int R = 2000;
  std::vector<std::vector<F>> xa(g_threads), ya(g_threads), za(g_threads);
  std::vector<std::vector<E>> Xa(g_threads), Ya(g_threads), Za(g_threads);
  for (unsigned t = 0; t < g_threads; t++) {
    xa[t].resize(N), ya[t].resize(N), za[t].resize(N), Xa[t].resize(N), Ya[t].resize(N), Za[t].resize(N);
    for (size_t i = 0; i < N; i++) xa[t][i] = rF(), ya[t][i] = rF(), Xa[t][i] = rE(), Ya[t][i] = rE();
  }
  double s;
  // F * F, array form z[i] = x[i] * y[i]; x is fed back so the compiler cannot hoist.
  s = timeit([&](unsigned t) {
    F *x = xa[t].data(), *y = ya[t].data(), *z = za[t].data();
    for (int r = 0; r < R; r++) {
      for (size_t i = 0; i < N; i++) z[i] = x[i] * y[i];
      std::swap(x, z);
    }
    g_sink += x[7].v;
  });
  report("F mul (z=x*y, arrays)", "N=4096 L1-resident", (double)N * R, "mul", s);
  // F multiply-add: 4 independent register accumulators acc_j += x*y (throughput-bound shape)
  s = timeit([&](unsigned t) {
    const F *x = xa[t].data(), *y = ya[t].data();
    F q0{0}, q1{0}, q2{0}, q3{0};
    for (int r = 0; r < R; r++)
#pragma clang loop vectorize(disable)
      for (size_t i = 0; i < N; i += 4) {
        q0 += x[i] * y[i]; q1 += x[i + 1] * y[i + 1]; q2 += x[i + 2] * y[i + 2]; q3 += x[i + 3] * y[i + 3];
      }
    g_sink += q0.v ^ q1.v ^ q2.v ^ q3.v;
  });
  report("F mul-add (4 reg acc += x*y)", "N=4096 L1-resident", (double)N * R, "muladd", s);
  // F mul latency chain
  s = timeit([&](unsigned t) {
    F a = xa[t][0], b = ya[t][1];
    for (long i = 0; i < (long)N * R; i++) a = a * b;
    g_sink += a.v;
  });
  report("F mul latency chain (a=a*b)", "dependent", (double)N * R, "mul", s);
  // F add
  s = timeit([&](unsigned t) {
    F *x = xa[t].data(), *y = ya[t].data(), *z = za[t].data();
    for (int r = 0; r < R; r++) {
      for (size_t i = 0; i < N; i++) z[i] = x[i] + y[i];
      std::swap(x, z);
    }
    g_sink += x[3].v;
  });
  report("F add (z=x+y, arrays)", "N=4096 L1-resident", (double)N * R, "add", s);
  const int RE = 500;
  // E * E
  s = timeit([&](unsigned t) {
    E *x = Xa[t].data(), *y = Ya[t].data(), *z = Za[t].data();
    for (int r = 0; r < RE; r++) {
      for (size_t i = 0; i < N; i++) z[i] = x[i] * y[i];
      std::swap(x, z);
    }
    g_sink += x[5].c[1].v;
  });
  report("E mul (z=x*y, arrays)", "N=4096 E=F[X]/(X^3-2)", (double)N * RE, "mul", s);
  // E multiply-add: 4 independent register accumulators
  s = timeit([&](unsigned t) {
    const E *x = Xa[t].data(), *y = Ya[t].data();
    E q0 = E::zero(), q1 = q0, q2 = q0, q3 = q0;
    for (int r = 0; r < RE; r++)
#pragma clang loop vectorize(disable)
      for (size_t i = 0; i < N; i += 4) {
        q0 += x[i] * y[i]; q1 += x[i + 1] * y[i + 1]; q2 += x[i + 2] * y[i + 2]; q3 += x[i + 3] * y[i + 3];
      }
    g_sink += q0.c[0].v ^ q1.c[1].v ^ q2.c[2].v ^ q3.c[0].v;
  });
  report("E mul-add (4 reg acc += x*y)", "N=4096", (double)N * RE, "muladd", s);
  // E mul latency
  s = timeit([&](unsigned t) {
    E a = Xa[t][0];
    const E b = Ya[t][1];
    for (long i = 0; i < (long)N * RE; i++) a = a * b;
    g_sink += a.c[2].v;
  });
  report("E mul latency chain", "dependent", (double)N * RE, "mul", s);
  // E * F
  s = timeit([&](unsigned t) {
    E *x = Xa[t].data(), *z = Za[t].data();
    const F *y = ya[t].data();
    for (int r = 0; r < RE; r++) {
      for (size_t i = 0; i < N; i++) z[i] = x[i] * y[i];
      std::swap(x, z);
    }
    g_sink += x[9].c[0].v;
  });
  report("ExF mul (z=X*f, arrays)", "N=4096", (double)N * RE, "mul", s);
  // E += E * F: 4 independent register accumulators
  s = timeit([&](unsigned t) {
    const E *x = Xa[t].data();
    const F *y = ya[t].data();
    E q0 = E::zero(), q1 = q0, q2 = q0, q3 = q0;
    for (int r = 0; r < RE; r++)
#pragma clang loop vectorize(disable)
      for (size_t i = 0; i < N; i += 4) {
        q0 += x[i] * y[i]; q1 += x[i + 1] * y[i + 1]; q2 += x[i + 2] * y[i + 2]; q3 += x[i + 3] * y[i + 3];
      }
    g_sink += q0.c[0].v ^ q1.c[1].v ^ q2.c[2].v ^ q3.c[0].v;
  });
  report("ExF mul-add (4 reg acc += X*f)", "N=4096", (double)N * RE, "muladd", s);
}

// ---------------- (d) BLAKE2b: leaves, vertices, Merkle tree ----------------
static Digest nonzero_digest(u32 seed) {
  Digest d;
  for (int i = 0; i < 8; i++) d.w[i] = 0x01010101u * (seed + i + 1);
  return d;
}
static void bench_hash() {
  OracleTreeShape base;
  base.log_n = 20, base.log_n_zk = 20;
  base.run = nonzero_digest(1), base.parameters = nonzero_digest(2);
  base.salt_bytes = SALT_FLOOR_BYTES;  // 40, the default (Setting::salt_bytes)
  // Leaf hashing at several column widths (symbols of F per leaf).
  for (size_t width : {3, 12, 96, 2048}) {
    OracleTreeShape s = base;
    s.main_symbols = {width}, s.mask_symbols = {0};
    const LeafHash lh(s);
    const size_t leaves = width >= 2048 ? 2048 : (size_t(1) << 16) / std::max<size_t>(1, width / 4);
    std::vector<std::vector<F>> col(g_threads, std::vector<F>(width * 64));
    std::vector<u8> salt(64 * 40, 7);
    for (auto &c : col)
      for (F &f : c) f = rF();
    const double s_ = timeit([&](unsigned t) {
      u64 h = 0;
      for (size_t x = 0; x < leaves; x++) h ^= lh(x, col[t].data() + (x & 63) * width, width, salt.data() + (x & 63) * 40).w[0];
      g_sink += h;
    }, 5);
    const double bytes_hashed = (double)leaf_bytes(width, 40);  // label + symbols + padding + salt
    const double payload = 8.0 * width;
    char extra[160];
    std::snprintf(extra, sizeof extra, "[%.1f MB/s of column payload; %.1f MB/s of all hashed bytes; %.0f compressions/leaf]",
                  payload * leaves * g_threads / s_ / 1e6, bytes_hashed * leaves * g_threads / s_ / 1e6, (double)mode_calls(8 * width + 40));
    report("BLAKE2b leaf()", "width=" + std::to_string(width) + " F symbols, salt 40 B", (double)leaves, "leaf", s_, extra);
  }
  // Vertex hashing (one compression per vertex).
  {
    const Tag tag = TreeShape::plain(20, nonzero_digest(3)).vertex_tag();
    const size_t n = size_t(1) << 18;
    const double s_ = timeit([&](unsigned) {
      Digest a = nonzero_digest(4), b = nonzero_digest(5);
      for (size_t i = 0; i < n; i++) {
        Digest c = vertex(tag, a, b);
        a = b, b = c;
      }
      g_sink += b.w[0];
    }, 5);
    report("BLAKE2b vertex() (1 compression)", "dependent chain", (double)n, "vertex", s_, "[128-byte block each]");
  }
  // Merkle tree build: 2^20 leaves, the OracleTree leaf format (column + 40-byte salt), then Tree.
  for (size_t width : {3, 96}) {
    if (g_threads > 1 && width > 3) continue;  // ~0.8 GB per thread: skipped on a shared host
    const unsigned logn = 20;
    const size_t n = size_t(1) << logn;
    OracleTreeShape s = base;
    s.log_n = logn, s.log_n_zk = logn;
    s.main_symbols = {width}, s.mask_symbols = {0};
    std::vector<std::vector<F>> cols(g_threads);
    for (auto &c : cols) {
      c.resize(n * width);
      for (F &f : c) f = rF();
    }
    std::vector<u8> salts(n * 40, 0x5a);
    std::vector<double> leaf_s(g_threads), vert_s(g_threads);
    const double s_ = timeit([&](unsigned t) {
      const auto t0 = clk::now();
      const LeafHash lh(s);
      std::vector<Digest> leaves(n);
      for (size_t x = 0; x < n; x++) leaves[x] = lh(x, cols[t].data() + x * width, width, salts.data() + x * 40);
      const auto t1 = clk::now();
      Tree tree(s.tree(), std::move(leaves));
      const auto t2 = clk::now();
      leaf_s[t] = std::chrono::duration<double>(t1 - t0).count();
      vert_s[t] = std::chrono::duration<double>(t2 - t1).count();
      g_sink += tree.root().w[0];
    }, 5);
    char extra[200];
    std::snprintf(extra, sizeof extra, "[last rep thread0: leaves %.3f s + inner vertices %.3f s; %.1f MB of column data]", leaf_s[0], vert_s[0],
                  8.0 * width * n / 1e6);
    report("Merkle tree build 2^20 leaves", "width=" + std::to_string(width) + " F + 40 B salt", (double)n, "leaf", s_, extra);
  }
}

// ---------------- (e) Reed-Solomon encoding ----------------
static void bench_rs() {
  struct Case {
    unsigned log_ell, extra;
    size_t r;
  };
  std::vector<Case> cases;
  for (unsigned le : {16u, 18u, 20u, 22u}) {
    cases.push_back({le, 1, 0});    // rate 1/2, no tail
    cases.push_back({le, 1, 218});  // rate ~1/2 with the full-size config's tail r=218 ("code long": log_n=23 ell=2^22 r=218)
    cases.push_back({le, 3, 86});   // rate ~1/8 with r=86, the toy runs' first stage
  }
  for (const Case &c : cases) {
    if (g_threads > 1 && c.log_ell > 20) continue;  // memory on a shared host
    const Code code{c.log_ell + c.extra, size_t(1) << c.log_ell, c.r};
    const Encoder enc(code);
    const size_t n = code.n();
    std::vector<std::vector<F>> msg(g_threads), tail(g_threads), word(g_threads);
    for (unsigned t = 0; t < g_threads; t++) {
      msg[t].resize(code.ell), tail[t].resize(code.r + 1), word[t].resize(n);
      for (F &f : msg[t]) f = rF();
      for (F &f : tail[t]) f = rF();
    }
    const int reps = c.log_ell >= 22 ? 5 : 7;
    const double s_ = timeit([&](unsigned t) {
      enc.encode(msg[t].data(), tail[t].data(), word[t].data());
      g_sink += word[t][n / 3].v;
    }, reps);
    char extra[200];
    std::snprintf(extra, sizeof extra, "[%.4g codeword symbols/s; log_dim=%u, NTT layers=%u; rate %.4f]", (double)n * g_threads / s_, code.log_dim(), code.log_dim(), code.rate());
    report("RS encode over F (Encoder::encode)",
           "ell=2^" + std::to_string(c.log_ell) + " n=2^" + std::to_string(code.log_n) + " r=" + std::to_string(c.r), (double)code.ell, "msg-elt", s_, extra);
  }
  // One E-row case (encoded coordinate-wise in EngineCpu; Encoder<E> here for reference).
  if (g_threads == 1) {
    const Code code{21, size_t(1) << 18, 86};
    const Encoder enc(code);
    std::vector<E> msg(code.ell), tail(code.r), word(code.n());
    for (E &e : msg) e = rE();
    for (E &e : tail) e = rE();
    const double s_ = timeit([&](unsigned) {
      enc.encode(msg.data(), tail.data(), word.data());
      g_sink += word[123].c[1].v;
    }, 5);
    report("RS encode over E (Encoder<E>)", "ell=2^18 n=2^21 r=86", (double)code.ell, "msg-elt(E)", s_);
  }
}

// ---------------- (f) fold / sumcheck kernels ----------------
// VERBATIM COPY of EngineCpu::fold_round's loop (blocks/engine/engine_cpu.h, lines ~298-310).
static void fold_round_copy(const std::vector<E> &c, const std::vector<E> &m, size_t rows, size_t ell, E q[3]) {
  q[0] = q[1] = q[2] = E::zero();
  for (size_t b = 0; b < rows; b += 2)
    for (size_t i = 0; i < ell; i++) {
      const E c0 = c[b * ell + i], dc = c[(b + 1) * ell + i] - c0;
      const E m0 = m[b * ell + i], dm = m[(b + 1) * ell + i] - m0;
      q[0] += c0 * m0;
      q[1] += c0 * dm + dc * m0;
      q[2] += dc * dm;
    }
}
// VERBATIM COPY of EngineCpu::halve (blocks/engine/engine_cpu.h): the fold_bind kernel.
static void halve_copy(std::vector<E> &t, size_t rows, size_t len, const E &g) {
  for (size_t b = 0; b < rows / 2; b++)
    for (size_t i = 0; i < len; i++) {
      const E lo = t[2 * b * len + i], hi = t[(2 * b + 1) * len + i];
      t[b * len + i] = lo + g * (hi - lo);
    }
  t.resize(rows / 2 * len);
}

static void bench_fold() {
  // A group of 2^k rows of ell entries; one fold round + one bind on the full table.
  for (unsigned logtotal : {18u, 20u, 22u}) {
    if (g_threads > 1 && logtotal > 20) continue;
    const size_t rows = 4, ell = (size_t(1) << logtotal) / rows;  // toy: k=2 (4 rows); full config groups have k=7
    std::vector<std::vector<E>> cs(g_threads), ms(g_threads);
    for (unsigned t = 0; t < g_threads; t++) {
      cs[t].resize(rows * ell), ms[t].resize(rows * ell);
      for (E &e : cs[t]) e = rE();
      for (E &e : ms[t]) e = rE();
    }
    double s_ = timeit([&](unsigned t) {
      E q[3];
      fold_round_copy(cs[t], ms[t], rows, ell, q);
      g_sink += q[0].c[0].v ^ q[2].c[1].v;
    }, 7);
    report("fold_round (EngineCpu, copied)", "2^" + std::to_string(logtotal) + " E entries in m and c", (double)(rows * ell), "elt", s_,
           "[per entry of the current table; 4 ExE mul]");
    const E g = rE();
    s_ = timeit([&](unsigned t) {
      std::vector<E> m = ms[t];  // copy outside? no: halve shrinks; copy cost is included and reported
      halve_copy(m, rows, ell, g);
      g_sink += m[5].c[0].v;
    }, 7);
    // separate the copy cost
    const double s_copy = timeit([&](unsigned t) {
      std::vector<E> m = ms[t];
      g_sink += m[5].c[0].v;
    }, 7);
    char extra[160];
    std::snprintf(extra, sizeof extra, "[incl. a vector copy of %.3g s; net halve %.3g s => %.3f ns/entry]", s_copy, s_ - s_copy, (s_ - s_copy) * 1e9 / (rows * ell));
    report("fold_bind/halve (copied)", "2^" + std::to_string(logtotal) + " E entries, one table", (double)(rows * ell), "elt", s_, extra);
  }
  // SumcheckCpu (blocks/engine/sumcheck_cpu.h), the toy run's summand: eq(zeta,.) * (a*b - c), 3 maps over E.
  if (g_threads == 1)
    for (unsigned k : {14u, 16u, 18u}) {
      std::vector<E> zeta(k);
      for (E &z : zeta) z = rE();
      const Summand<E> summand = toy_summand();
      SumClaim<E> claim = toy_claim(zeta);
      std::vector<std::vector<E>> maps(3, std::vector<E>(size_t(1) << k));
      for (auto &m : maps)
        for (E &e : m) e = rE();
      std::vector<double> round_s, bind_s;
      for (int rep = 0; rep < 5; rep++) {
        SumcheckCpu<E> sc(summand, claim.vars, maps);
        auto t0 = clk::now();
        std::vector<E> p = sc.round();
        auto t1 = clk::now();
        sc.bind(rE());
        auto t2 = clk::now();
        g_sink += p[0].c[0].v;
        round_s.push_back(std::chrono::duration<double>(t1 - t0).count());
        bind_s.push_back(std::chrono::duration<double>(t2 - t1).count());
      }
      std::sort(round_s.begin(), round_s.end());
      std::sort(bind_s.begin(), bind_s.end());
      char extra[200];
      std::snprintf(extra, sizeof extra, "[first round over 2^%u points x 3 maps; O(k 2^k) eq-weight recompute in round()]", k);
      report("SumcheckCpu::round() (toy summand)", "k=" + std::to_string(k), (double)(size_t(1) << k), "point", round_s[2], extra);
      report("SumcheckCpu::bind() (3 maps)", "k=" + std::to_string(k), (double)(size_t(1) << k) * 3, "elt", bind_s[2]);
    }
}

int main(int argc, char **argv) {
  g_threads = argc > 1 ? (unsigned)std::atoi(argv[1]) : 1;
  const std::string which = argc > 2 ? argv[2] : "all";
  const char *json_path = argc > 3 ? argv[3] : nullptr;
  if (json_path) g_json = std::fopen(json_path, "w");
  if (g_json) std::fprintf(g_json, "[\n");
  std::printf("FlashProve blocks/ primitive bench, threads=%u\n", g_threads);
  if (which == "all" || which == "field") bench_field();
  if (which == "all" || which == "hash") bench_hash();
  if (which == "all" || which == "rs") bench_rs();
  if (which == "all" || which == "fold") bench_fold();
  if (g_json) std::fprintf(g_json, "\n]\n"), std::fclose(g_json);
  std::printf("sink %llu\n", (unsigned long long)g_sink);
}
