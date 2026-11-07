// M8 T3 kernel parity + CUDA-event microbenchmark for the DEEP/OODS kernels.
// Self-contained: links deep.cu and samples.cu directly and stubs the two
// execution-context hooks RangeCustody needs. Every case runs the legacy
// kernels (STWO_RV64_M8_{DEEP,SAMPLE}_LEGACY=1) and the M8 kernels on the
// same device inputs and requires bit-identical outputs, valid words and
// status words. Timing: CUDA events around the exported entry point.
//   nvcc -O3 -std=c++17 -gencode arch=compute_120,code=sm_120 \
//     -I src/backends/cuda/native tests/cuda/rv64/deep_t3_parity_bench.cu \
//     src/backends/cuda/native/rv64/deep.cu src/backends/cuda/native/rv64/samples.cu
//   ./a.out [parity|bench] [reps]
#include "rv64/deep.h"
#include "rv64/om31.cuh"
#include "rv64/samples.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
using namespace stwo::cuda::rv64;
static cudaStream_t g_stream;
extern "C" int stwo_exec_context_lane_stream(void *, uint32_t, void **out) {
  *out = g_stream;
  return 0;
}
extern "C" int stwo_exec_context_validate_allocation(void *, const void *,
                                                     size_t) {
  return 0;
}
#define CK(x)                                                                  \
  do {                                                                         \
    const int s_ = int(x);                                                     \
    if (s_) {                                                                  \
      std::fprintf(stderr, "%s:%d %s -> %d (%s)\n", __FILE__, __LINE__, #x,   \
                   s_, cudaGetErrorString(cudaError_t(s_)));                   \
      std::exit(2);                                                            \
    }                                                                          \
  } while (0)
static std::mt19937_64 rng(0x7e3d00d5ull);
static uint32_t rnd() { return uint32_t(rng() % q::kPrime); }
static OM31 rnd_om31() {
  return {{{rnd(), rnd()}, {rnd(), rnd()}}, {{rnd(), rnd()}, {rnd(), rnd()}}};
}
static void put(std::vector<uint32_t> &v, size_t at, OM31 x) {
  for (uint32_t k = 0; k < 8; ++k) v[at + k] = coordinate(x, k);
}
static void circle_point(std::vector<uint32_t> &v, size_t at) {
  for (;;) {
    const OM31 t = rnd_om31(), t2 = mul(t, t), den = add(one(), t2);
    if (is_zero(den)) continue;
    const OM31 r = inverse_nonzero(den);
    const OM31 x = mul(sub(one(), t2), r), y = mul(add(t, t), r);
    if (!(y.c1.a.a | y.c1.a.b | y.c1.b.a | y.c1.b.b)) continue;
    put(v, at, x);
    put(v, at + 8, y);
    return;
  }
}
struct Dev {
  std::vector<void *> all;
  ~Dev() {
    for (auto p : all) cudaFree(p);
  }
  uint32_t *up(const std::vector<uint32_t> &h, size_t extra = 0) {
    uint32_t *p = nullptr;
    CK(cudaMalloc(&p, (h.size() + extra) * 4 + 4));
    all.push_back(p);
    if (!h.empty()) CK(cudaMemcpy(p, h.data(), h.size() * 4, cudaMemcpyHostToDevice));
    if (extra) CK(cudaMemset(p + h.size(), 0, extra * 4));
    return p;
  }
  uint32_t *zeros(size_t words) { return up({}, words); }
};
static std::vector<uint32_t> down(const uint32_t *p, size_t words) {
  std::vector<uint32_t> h(words);
  CK(cudaMemcpy(h.data(), p, words * 4, cudaMemcpyDeviceToHost));
  return h;
}
static void set_legacy(bool legacy) {
  setenv("STWO_RV64_M8_DEEP_LEGACY", legacy ? "1" : "0", 1);
  setenv("STWO_RV64_M8_SAMPLE_LEGACY", legacy ? "1" : "0", 1);
}
struct Timing {
  std::vector<float> ms;
  void print(const char *what, const char *arm) const {
    auto s = ms;
    std::sort(s.begin(), s.end());
    std::printf("BENCH kernel=%s arm=%s reps=%zu median_ms=%.4f min_ms=%.4f "
                "max_ms=%.4f\n",
                what, arm, s.size(), s[s.size() / 2], s.front(), s.back());
  }
};
template <class F> static Timing time_it(F f, int reps) {
  cudaEvent_t a, b;
  CK(cudaEventCreate(&a));
  CK(cudaEventCreate(&b));
  f(); // warm-up (also builds the occupancy cache)
  CK(cudaStreamSynchronize(g_stream));
  Timing t;
  for (int i = 0; i < reps; ++i) {
    CK(cudaEventRecord(a, g_stream));
    f();
    CK(cudaEventRecord(b, g_stream));
    CK(cudaEventSynchronize(b));
    float ms = 0;
    CK(cudaEventElapsedTime(&ms, a, b));
    t.ms.push_back(ms);
  }
  cudaEventDestroy(a);
  cudaEventDestroy(b);
  return t;
}
static int failures = 0;
static void expect_same(const char *what, const std::vector<uint32_t> &a,
                        const std::vector<uint32_t> &b) {
  if (a == b) return;
  size_t i = 0;
  while (i < a.size() && a[i] == b[i]) ++i;
  std::printf("MISMATCH %s at word %zu: legacy=%u new=%u\n", what, i,
              i < a.size() ? a[i] : 0, i < b.size() ? b[i] : 0);
  ++failures;
}
// ------------------------------- deep_combine -------------------------------
struct CombineCase {
  uint32_t output_log = 14, groups = 68, shared = 20, max_eval_log = 14;
  uint32_t fault = 0;
  bool all_shared = false; // every group uses point 0: a single class
};
static void combine_case(const CombineCase &cc, bool bench, int reps) {
  const uint32_t gc = cc.groups, n = 1u << cc.output_log;
  // Group heights: the "shared" groups (the OODS point at every height) use
  // point 0; the rest have distinct points. Classes are interleaved so class
  // members are non-adjacent in group order.
  std::vector<uint32_t> group_words(gc * 8), points(gc * 16), linear(gc * 16);
  uint64_t eval_words = 0;
  std::vector<uint32_t> base(16);
  circle_point(base, 0);
  uint64_t coeff_words = 0;
  const uint32_t span = cc.max_eval_log > 3 ? std::min(cc.max_eval_log - 2, 12u) : 1u;
  for (uint32_t g = 0; g < gc; ++g) {
    uint32_t log = cc.max_eval_log - g % span;
    if (g >= 4 && log + 2 > cc.max_eval_log && log > 4) log -= 2; // few full-height groups
    log = std::max(log, 2u);
    const bool is_shared =
        cc.all_shared || (g % 3 == 0 && g / 3 < cc.shared);
    if (is_shared)
      std::copy(base.begin(), base.end(), points.begin() + g * 16);
    else
      circle_point(points, g * 16);
    put(linear, g * 16, rnd_om31());
    put(linear, g * 16 + 8, rnd_om31());
    group_words[g * 8 + 0] = 0;
    group_words[g * 8 + 1] = 1;
    group_words[g * 8 + 2] = log - 1;
    group_words[g * 8 + 3] = log;
    group_words[g * 8 + 4] = uint32_t(coeff_words);
    group_words[g * 8 + 5] = uint32_t(coeff_words >> 32);
    coeff_words += uint64_t(8) << (log - 1);
    group_words[g * 8 + 6] = uint32_t(eval_words);
    group_words[g * 8 + 7] = uint32_t(eval_words >> 32);
    eval_words += uint64_t(8) << log;
  }
  std::vector<uint32_t> evaluations(eval_words), domain(uint64_t(n) * 2);
  for (auto &w : evaluations) w = rnd();
  const auto generator = q::kCircleGenerator;
  for (uint32_t i = 0; i < n; ++i) {
    const auto pt = q::point_pow(generator, 1u + uint32_t(rng() % 0x7ffffffeu));
    domain[2 * i] = pt.x;
    domain[2 * i + 1] = pt.y;
  }
  uint32_t status0 = 0;
  switch (cc.fault) {
  case 1: domain[2 * 7] = q::kPrime; break;          // non-canonical domain x
  case 2: domain[2 * 9 + 1] = q::add(domain[2 * 9 + 1], 1); break; // off circle
  case 3: linear[5 * 16 + 3] = q::kPrime; break;     // non-canonical a
  case 4: linear[6 * 16 + 8 + 2] = q::kPrime + 3; break; // non-canonical b
  case 5: evaluations[100] = q::kPrime; break;       // non-canonical value
  case 6: status0 = 16; break;                       // poisoned before combine
  case 7: points[3 * 16] = q::kPrime; break;         // point non-canonical
  case 8: points[4 * 16 + 1] = q::add(points[4 * 16 + 1], 1); break; // off circle
  default: break;
  }
  std::vector<uint32_t> outs[2], stats[2];
  Timing timings[2];
  for (int arm = 0; arm < 2; ++arm) {
    Dev d;
    StwoRv64DeepCombine j{};
    j.groups = reinterpret_cast<const StwoRv64DeepGroup *>(d.up(group_words));
    j.points = d.up(points);
    j.linear = d.up(linear);
    j.evaluations = d.up(evaluations);
    j.domain_xy = d.up(domain);
    j.valid = d.up({1u, 0u});
    j.output = {d.zeros(uint64_t(n) * 8), n, 8, 0};
    j.status = d.up({status0});
    j.evaluation_words = eval_words;
    j.group_count = gc;
    j.output_log = cc.output_log;
    set_legacy(arm == 0);
    auto run = [&] {
      CK(cudaMemcpyAsync(j.status, &status0, 4, cudaMemcpyHostToDevice, g_stream));
      CK(stwo_rv64_deep_combine_on(nullptr, 1, &j));
    };
    if (bench) {
      timings[arm] = time_it(run, reps);
    } else {
      run();
    }
    CK(cudaStreamSynchronize(g_stream));
    outs[arm] = down(j.output.words, uint64_t(n) * 8);
    stats[arm] = down(j.status, 1);
    stats[arm].push_back(down(j.valid, 2)[1]);
  }
  char name[96];
  std::snprintf(name, sizeof name,
                "deep_combine[log=%u,g=%u,shared=%u,fault=%u%s]", cc.output_log,
                gc, cc.shared, cc.fault, cc.all_shared ? ",one-class" : "");
  expect_same(name, outs[0], outs[1]);
  expect_same(name, stats[0], stats[1]);
  std::printf("CASE %s status=%u valid1=%u\n", name, stats[1][0], stats[1][1]);
  if (bench) {
    timings[0].print(name, "legacy");
    timings[1].print(name, "m8");
  }
}
// ------------------------------- deep_prepare -------------------------------
static void prepare_case(uint32_t fault, uint32_t gc, uint32_t terms_per_group,
                         bool bench, int reps) {
  const uint32_t tc = gc * terms_per_group, sc = tc;
  std::vector<uint32_t> group_words(gc * 8), points(gc * 16), values(tc * 8),
      sources(sc * 4), terms(tc * 4), alpha(8);
  uint64_t coeff_words = 0, tree_words = 0, eval_offset = 0;
  std::vector<uint32_t> logs(gc);
  for (uint32_t g = 0; g < gc; ++g) logs[g] = 4 + g % 9;
  for (uint32_t g = 0; g < gc; ++g) {
    circle_point(points, g * 16);
    const uint32_t begin = g * terms_per_group, end = begin + terms_per_group;
    group_words[g * 8 + 0] = begin;
    group_words[g * 8 + 1] = end;
    group_words[g * 8 + 2] = logs[g];
    group_words[g * 8 + 3] = logs[g] + 1;
    group_words[g * 8 + 4] = uint32_t(coeff_words);
    group_words[g * 8 + 5] = uint32_t(coeff_words >> 32);
    coeff_words += uint64_t(8) << logs[g];
    group_words[g * 8 + 6] = uint32_t(eval_offset);
    group_words[g * 8 + 7] = uint32_t(eval_offset >> 32);
    eval_offset += uint64_t(8) << (logs[g] + 1);
    for (uint32_t t = begin; t < end; ++t) {
      sources[t * 4 + 0] = uint32_t(tree_words);
      sources[t * 4 + 1] = 0;
      sources[t * 4 + 2] = 0;
      sources[t * 4 + 3] = logs[g];
      tree_words += 1u << logs[g];
      terms[t * 4 + 0] = t;
      terms[t * 4 + 1] = g;
      terms[t * 4 + 2] = uint32_t(rng() % tc);
      terms[t * 4 + 3] = 0;
      put(values, t * 8, rnd_om31());
    }
  }
  put(alpha, 0, rnd_om31());
  std::vector<uint32_t> tree(tree_words);
  for (auto &w : tree) w = rnd();
  uint32_t status0 = 0;
  const uint32_t tpg = terms_per_group;
  switch (fault) {
  case 1: status0 = 32; break;
  case 2: group_words[2 * 8 + 4] += 8; break;                 // layout
  case 3: alpha[1] = q::kPrime; break;
  case 4: group_words[3 * 8 + 0] += 1; break;                 // header begin
  case 5: points[5 * 16 + 2] = q::kPrime; break;              // point canonical
  case 6: points[5 * 16 + 9] = q::add(points[5 * 16 + 9], 1); break; // circle
  case 7: // term-check at t=5, value at t=3 of group 2: value (2) wins
    terms[(2 * tpg + 5) * 4 + 3] = 1;
    values[(2 * tpg + 3) * 8 + 4] = q::kPrime;
    break;
  case 8: // term-check at t=3, value at t=5 of group 2: term (1) wins
    terms[(2 * tpg + 3) * 4 + 1] = 0;
    values[(2 * tpg + 5) * 8 + 4] = q::kPrime;
    break;
  case 9: // value failure in group 1, header failure in group 3 -> 2
    values[(1 * tpg + 7) * 8] = q::kPrime;
    group_words[3 * 8 + 1] = group_words[3 * 8 + 0];
    break;
  case 10: // trailing terms: final previous != term_count -> 1
    group_words[(gc - 1) * 8 + 1] -= 1;
    break;
  case 11: // source out of range on the last term of the last group
    sources[(tc - 1) * 4 + 0] = uint32_t(tree_words);
    break;
  case 12: // same term carries both failures: term check (1) is first
    terms[(4 * tpg + 9) * 4 + 2] = tc;
    values[(4 * tpg + 9) * 8] = q::kPrime;
    break;
  case 13: // many value failures across threads of one group -> earliest only
    for (uint32_t t = 2 * tpg + 1; t < 3 * tpg; t += 37) values[t * 8 + 1] = q::kPrime;
    terms[(2 * tpg + tpg - 1) * 4 + 3] = 9;
    break;
  default: break;
  }
  std::vector<uint32_t> outs[2];
  Timing timings[2];
  for (int arm = 0; arm < 2; ++arm) {
    Dev d;
    StwoRv64DeepPrepare j{};
    j.trees[0] = d.up(tree);
    j.tree_words[0] = tree_words;
    j.sources = reinterpret_cast<const StwoRv64DeepSource *>(d.up(sources));
    j.terms = reinterpret_cast<const StwoRv64DeepTerm *>(d.up(terms));
    j.groups = reinterpret_cast<const StwoRv64DeepGroup *>(d.up(group_words));
    j.points = d.up(points);
    j.values = d.up(values);
    j.alpha = d.up(alpha);
    j.weights = d.zeros(uint64_t(tc) * 8);
    j.linear = d.zeros(uint64_t(gc) * 16);
    j.coefficients = d.zeros(coeff_words);
    j.valid = d.up({7u, 7u});
    j.status = d.up({status0});
    j.coefficient_words = coeff_words;
    j.source_count = sc;
    j.term_count = tc;
    j.group_count = gc;
    set_legacy(arm == 0);
    auto run = [&] {
      CK(cudaMemcpyAsync(j.status, &status0, 4, cudaMemcpyHostToDevice, g_stream));
      CK(stwo_rv64_deep_prepare_on(nullptr, 1, &j));
    };
    if (bench) {
      // Time only the validation step by running the whole prepare with
      // STWO_RV64_DEEP_TIMING=1 would sync; event-time the full entry instead
      // and report the validate share separately below.
      timings[arm] = time_it(run, reps);
    } else {
      run();
    }
    CK(cudaStreamSynchronize(g_stream));
    auto &o = outs[arm];
    for (auto part : {down(j.status, 1), down(j.valid, 2),
                      down(j.weights, uint64_t(tc) * 8),
                      down(j.linear, uint64_t(gc) * 16),
                      down(j.coefficients, coeff_words)})
      o.insert(o.end(), part.begin(), part.end());
  }
  char name[96];
  std::snprintf(name, sizeof name, "deep_prepare[g=%u,terms=%u,fault=%u]", gc, tc,
                fault);
  expect_same(name, outs[0], outs[1]);
  std::printf("CASE %s status=%u valid0=%u\n", name, outs[1][0], outs[1][1]);
  if (bench) {
    timings[0].print(name, "legacy");
    timings[1].print(name, "m8");
  }
}
// ------------------------------ sample_evaluate -----------------------------
static void sample_case(uint32_t coefficient_log, uint32_t count,
                        uint32_t columns, uint32_t fault, bool bench, int reps) {
  const uint32_t gc = 4, group = 2, n = 1u << coefficient_log;
  const uint32_t first = 3, capacity = first + count + 2;
  std::vector<uint32_t> tree(uint64_t(columns) * n), sources(columns * 4),
      terms(capacity * 4), recipes(gc * 4), factors(gc * 28 * 8),
      ready(gc + 1, 1u);
  for (auto &w : tree) w = rnd();
  for (uint32_t c = 0; c < columns; ++c) {
    sources[c * 4] = uint32_t(uint64_t(c) * n);
    sources[c * 4 + 1] = uint32_t((uint64_t(c) * n) >> 32);
    sources[c * 4 + 3] = coefficient_log;
  }
  for (uint32_t g = 0; g < gc; ++g) {
    recipes[g * 4 + 3] = g == 3 ? coefficient_log + 1 : coefficient_log;
    for (uint32_t k = 0; k < coefficient_log; ++k)
      put(factors, (g * 28 + k) * 8, rnd_om31());
  }
  for (uint32_t t = 0; t < capacity; ++t) {
    terms[t * 4] = uint32_t(rng() % columns);
    terms[t * 4 + 1] = group;
  }
  switch (fault) {
  case 1: terms[(first + 5) * 4 + 1] = 1; break;         // mixed group
  case 2: ready[1 + 1] = 0; terms[(first + 2) * 4 + 1] = 1; break; // invalid
  case 3: tree[uint64_t(terms[(first + 4) * 4]) * n + n / 2 + 3] = q::kPrime; break;
  case 4: terms[(first + 1) * 4 + 1] = 3; break;         // height mismatch
  case 5: ready[group + 1] = 0; break;                   // every sample invalid
  case 6: // first sample invalid: the basis takes the next valid group
    ready[1 + 1] = 0;
    terms[first * 4 + 1] = 1;
    break;
  default: break;
  }
  const uint32_t blocks = (n + 1023) / 1024;
  const uint64_t scratch_words = uint64_t(blocks) * count * 8;
  std::vector<uint32_t> outs[2];
  Timing timings[2];
  for (int arm = 0; arm < 2; ++arm) {
    Dev d;
    StwoRv64SampleEvaluation j{};
    j.trees[0] = d.up(tree);
    j.tree_words[0] = tree.size();
    j.sources = reinterpret_cast<const StwoRv64DeepSource *>(d.up(sources));
    j.terms = reinterpret_cast<const StwoRv64DeepTerm *>(d.up(terms));
    j.recipes = reinterpret_cast<const StwoRv64PointRecipe *>(d.up(recipes));
    j.factors = d.up(factors);
    j.point_ready = d.up(ready);
    j.scratch_a = d.zeros(scratch_words);
    j.scratch_b = d.zeros(scratch_words);
    j.values = d.zeros(uint64_t(capacity) * 8);
    j.valid = d.zeros(count);
    j.status = d.zeros(1);
    j.scratch_words = scratch_words;
    j.value_words = uint64_t(capacity) * 8;
    j.source_count = columns;
    j.term_capacity = capacity;
    j.group_count = gc;
    j.first = first;
    j.count = count;
    j.coefficient_log = coefficient_log;
    set_legacy(arm == 0);
    auto run = [&] { CK(stwo_rv64_sample_evaluate_on(nullptr, 1, &j)); };
    if (bench)
      timings[arm] = time_it(run, reps);
    else
      run();
    CK(cudaStreamSynchronize(g_stream));
    auto &o = outs[arm];
    for (auto part : {down(j.status, 1), down(j.valid, count),
                      down(j.values, uint64_t(capacity) * 8)})
      o.insert(o.end(), part.begin(), part.end());
  }
  char name[112];
  std::snprintf(name, sizeof name, "sample_evaluate[log=%u,count=%u,cols=%u,fault=%u]",
                coefficient_log, count, columns, fault);
  expect_same(name, outs[0], outs[1]);
  std::printf("CASE %s status=%u\n", name, outs[1][0]);
  if (bench) {
    timings[0].print(name, "legacy");
    timings[1].print(name, "m8");
  }
}
int main(int argc, char **argv) {
  const std::string mode = argc > 1 ? argv[1] : "parity";
  const int reps = argc > 2 ? std::atoi(argv[2]) : 7;
  CK(cudaStreamCreateWithFlags(&g_stream, cudaStreamNonBlocking));
  if (mode == "parity") {
    for (uint32_t fault = 0; fault <= 8; ++fault)
      combine_case({14, 68, 20, 14, fault}, false, 0);
    combine_case({13, 5, 0, 13, 0}, false, 0);    // < 8 groups, all distinct
    combine_case({13, 17, 17, 12, 0}, false, 0);  // heavy sharing
    combine_case({12, 128, 40, 12, 0}, false, 0); // fast-path cap
    combine_case({12, 129, 40, 12, 0}, false, 0); // legacy above the cap
    combine_case({2, 3, 1, 2, 0}, false, 0);      // four rows
    combine_case({2, 1, 0, 2, 0}, false, 0);      // one group, four rows
    combine_case({12, 40, 0, 12, 0, true}, false, 0); // one class, 40 members
    combine_case({12, 128, 0, 12, 0, true}, false, 0); // one class at the cap
    // 2^18 rows = 1024 CTAs of 256: more than resident, so the persistent
    // grid-stride loop runs several rows per thread in parity mode too.
    combine_case({18, 68, 20, 18, 0}, false, 0);
    combine_case({18, 68, 20, 18, 5}, false, 0);  // + non-canonical value
    for (uint32_t fault = 0; fault <= 13; ++fault)
      prepare_case(fault, 68, 60, false, 0);
    prepare_case(0, 1, 1, false, 0);
    prepare_case(0, 3, 700, false, 0);
    for (uint32_t fault = 0; fault <= 6; ++fault)
      sample_case(14, 80, 9, fault, false, 0);
    sample_case(10, 1100, 5, 0, false, 0);  // one tile, basis path
    sample_case(3, 1500, 5, 0, false, 0);   // n < 1024 basis path
    sample_case(1, 1200, 3, 1, false, 0);   // n = 2, mixed groups
    sample_case(2, 1100, 3, 6, false, 0);   // n = 4, basis from 2nd sample
    sample_case(11, 1030, 4, 3, false, 0);  // two tiles + reduce, bad coeff
    sample_case(12, 3, 2, 0, false, 0);     // small scratch -> legacy kernel
    sample_case(17, 70, 20, 3, false, 0);
    sample_case(20, 70, 6, 1, false, 0);    // chunk-32 kernel, mixed groups
    sample_case(20, 45, 6, 2, false, 0);    // chunk-32 kernel, invalid samples
  } else {
    // Shapes from the M7-P1 24628607 warm census: deep_combine output 2^24,
    // 68 groups; sample_first up to 4096 tiles x 72 samples. Device memory
    // on the shared pod is tight, so combine uses 2^22 rows (time is linear
    // in rows: grid-stride, no cross-row state).
    combine_case({22, 68, 20, 22, 0}, true, reps);
    combine_case({22, 68, 0, 22, 0}, true, reps);
    prepare_case(0, 68, 60, true, reps);
    sample_case(22, 72, 24, 0, true, reps);
    sample_case(18, 72, 24, 0, true, reps);
    sample_case(14, 200, 24, 0, true, reps);
  }
  std::printf("%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
  return failures ? 1 : 0;
}
