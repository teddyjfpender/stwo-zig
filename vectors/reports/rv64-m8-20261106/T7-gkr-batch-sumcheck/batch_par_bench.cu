// T7 parity + microbenchmark: serial batch_round/batch_tail<false> vs the
// STWO_RV64_M8_GKR_BATCH_PAR block transition (batch_round_par, batch_tail<true>).
// Includes the product TU so the exact shipped kernels are exercised.
// Build (pod): nvcc -O3 -std=c++17 -gencode arch=compute_120,code=sm_120 \
//   -I<src>/src/backends/cuda/native batch_par_bench.cu -o batch_par_bench
// Usage: batch_par_bench selftest | bench [reps]
#include "rv64/batch.cu"
#include <cstdio>
#include <random>
#include <vector>
#include <algorithm>

extern "C" int stwo_exec_context_lane_stream(void *, uint32_t, void **out) {
  static cudaStream_t s = [] { cudaStream_t x; cudaStreamCreate(&x); return x; }();
  *out = s;
  return 0;
}
extern "C" int stwo_exec_context_validate_allocation(void *, const void *, size_t) { return 0; }

#define CK(x) do { cudaError_t e_ = (x); if (e_) { std::printf("CUDA %s at %d: %s\n", #x, __LINE__, cudaGetErrorString(e_)); std::exit(2); } } while (0)

static std::mt19937_64 rng(0x7e57);
static uint32_t rm31() { return uint32_t(rng() % 2147483647ull); }
static void rom(uint32_t *w) { for (int i = 0; i < 8; ++i) w[i] = rm31(); }

template <class T> struct Dev {
  T *p = nullptr; size_t n = 0;
  explicit Dev(size_t n_) : n(n_) { CK(cudaMalloc(&p, n * sizeof(T))); CK(cudaMemset(p, 0, n * sizeof(T))); }
  ~Dev() { cudaFree(p); }
  void put(const std::vector<T> &h) { CK(cudaMemcpy(p, h.data(), h.size() * sizeof(T), cudaMemcpyHostToDevice)); }
  std::vector<T> get() const { std::vector<T> h(n); CK(cudaMemcpy(h.data(), p, n * sizeof(T), cudaMemcpyDeviceToHost)); return h; }
};

struct Case {
  uint32_t count, variables, stride;
  std::vector<uint32_t> heights;
};
static Case make_case(uint32_t count, uint32_t variables, bool mixed) {
  Case c{count, variables, uint32_t(2 + rng() % 3), {}};
  for (uint32_t i = 0; i < count; ++i)
    c.heights.push_back(mixed ? uint32_t(rng() % (variables + 1)) : variables);
  c.heights[rng() % count] = variables;
  return c;
}

static int status_seen[4] = {0, 0, 0, 0}; // final RoundState.status over round cases
// One sumcheck: both arms are initialised identically, each round gets identical
// random raw sums (optionally poisoned), and state + record are compared bitwise.
static int run_round_case(const Case &cs, int poison) {
  const uint32_t n = cs.count, V = cs.variables;
  Dev<uint32_t> seed(9), claims(8 * n), alpha(8), point(8 * V), raw(8 * cs.stride * n);
  Dev<uint32_t> sa(STWO_RV64_BATCH_STATE_WORDS), sb(STWO_RV64_BATCH_STATE_WORDS), ra(round_record_words), rb(round_record_words);
  std::vector<uint32_t> h(9); rom(h.data()); h[8] = uint32_t(rng() % (1u << 20)); seed.put(h);
  h.assign(8 * n, 0); for (auto &x : h) x = rm31(); claims.put(h);
  h.assign(8, 0); rom(h.data()); alpha.put(h);
  h.assign(8 * V, 0); for (auto &x : h) x = rm31(); point.put(h);
  BatchJobs jobs{};
  for (uint32_t i = 0; i < n; ++i)
    jobs.oracles[i] = {cs.heights[i] ? raw.p + 8 * cs.stride * i : nullptr, cs.heights[i] ? uint64_t(cs.stride) : 0ull, cs.heights[i], 0};
  jobs.count = n; jobs.variables = V;
  batch_init<<<1, 1>>>(sa.p, seed.p, claims.p, alpha.p, jobs);
  CK(cudaDeviceSynchronize());
  CK(cudaMemcpy(sb.p, sa.p, sa.n * 4, cudaMemcpyDeviceToDevice));
  const uint32_t poison_round = V ? uint32_t(rng() % V) : 0;
  for (uint32_t r = 0; r < V; ++r) {
    h.assign(raw.n, 0); for (auto &x : h) x = rm31();
    BatchJobs j = jobs; uint32_t expected = r;
    if (r == poison_round) switch (poison) {
      case 1: { // non-canonical raw coordinate in a random active oracle
        std::vector<uint32_t> act; for (uint32_t i = 0; i < n; ++i) if (cs.heights[i] >= V - r) act.push_back(i);
        const uint32_t i = act[rng() % act.size()];
        h[8 * cs.stride * i + (rng() % 8) * cs.stride + (rng() % 2)] = 2147483647u + uint32_t(rng() % 2);
        break; }
      case 2: expected = r + 1; break; // out-of-order round (== V at the last round: out of range)
      case 3: { const uint32_t i = uint32_t(rng() % n); j.oracles[i].variables ^= 1; break; } // height mismatch
      case 4: j.count = n > 1 ? n - 1 : n; break; // count mismatch
      case 5: j.variables = V + 1; break; // variables mismatch
      case 6: h[8 * cs.stride * 0] = 2147483647u; // sleeping or active oracle 0 (only checked if active)
              break;
      case 7: case 8: case 9: { // pole: y = 1 (prefix 0), y = 1/2 (1-2y = 0), y = 1/3 (3y-1 = 0)
        const uint32_t ys[3] = {1u, 1073741824u, 1431655765u};
        std::vector<uint32_t> y(8, 0); y[0] = ys[poison - 7];
        CK(cudaMemcpy(point.p + 8 * r, y.data(), 32, cudaMemcpyHostToDevice));
        break; }
      case 10: { std::vector<uint32_t> y(8, 0); y[3] = 2147483647u; // non-canonical y
        CK(cudaMemcpy(point.p + 8 * r, y.data(), 32, cudaMemcpyHostToDevice)); break; }
    }
    raw.put(h);
    CK(cudaMemset(ra.p, 0xab, ra.n * 4)); CK(cudaMemset(rb.p, 0xcd, rb.n * 4));
    batch_round<<<1, 1>>>(sa.p, j, expected, point.p, ra.p);
    batch_round_par<<<1, batch_par_threads>>>(sb.p, j, expected, point.p, rb.p);
    CK(cudaDeviceSynchronize());
    if (sa.get() != sb.get() || ra.get() != rb.get()) {
      std::printf("MISMATCH count=%u V=%u round=%u poison=%d\n", n, V, r, poison);
      return 1;
    }
  }
  const uint32_t status = sa.get()[10]; // RoundState: digest[8], draws, next_round, status
  if (status < 4) ++status_seen[status];
  return 0;
}

// Tail: random fractions, the last R rounds of a V-variable batch fused in one CTA.
// poison: 0 clean; 1 pole (y = 1/2) or 2 non-canonical y at a random tail round
// (later rounds must take the block-uniform early exit in every round, no
// barrier divergence); 3 the state enters the tail already failed (round_field).
static int tail_status_seen[4] = {0, 0, 0, 0};
static int run_tail_case(const Case &cs, uint32_t R, int poison) {
  const uint32_t n = cs.count, V = cs.variables, first = V - R;
  Dev<uint32_t> seed(9), claims(8 * n), alpha(8), point(8 * V), raw(16 * n), lambda(8);
  Dev<uint32_t> state0(STWO_RV64_BATCH_STATE_WORDS), rec(round_record_words);
  std::vector<uint32_t> h(9); rom(h.data()); h[8] = uint32_t(rng() % (1u << 20)); seed.put(h);
  h.assign(8 * n, 0); for (auto &x : h) x = rm31(); claims.put(h);
  h.assign(8, 0); rom(h.data()); alpha.put(h); lambda.put(std::vector<uint32_t>(h.rbegin(), h.rend()));
  h.assign(8 * V, 0); for (auto &x : h) x = rm31(); point.put(h);
  BatchJobs jobs{};
  for (uint32_t i = 0; i < n; ++i)
    jobs.oracles[i] = {cs.heights[i] ? raw.p + 16 * i : nullptr, cs.heights[i] ? 2ull : 0ull, cs.heights[i], 0};
  jobs.count = n; jobs.variables = V;
  batch_init<<<1, 1>>>(state0.p, seed.p, claims.p, alpha.p, jobs);
  for (uint32_t r = 0; r < first; ++r) { // reach the tail through the serial path
    h.assign(raw.n, 0); for (auto &x : h) x = rm31(); raw.put(h);
    batch_round<<<1, 1>>>(state0.p, jobs, r, point.p, rec.p);
  }
  CK(cudaDeviceSynchronize());
  if (poison == 1 || poison == 2) {
    std::vector<uint32_t> y(8, 0);
    if (poison == 1) y[0] = 1073741824u; else y[5] = 2147483647u;
    CK(cudaMemcpy(point.p + 8 * (first + uint32_t(rng() % R)), y.data(), 32, cudaMemcpyHostToDevice));
  } else if (poison == 3) {
    const uint32_t field = round_field; // RoundState: digest[8], draws, next_round, status
    CK(cudaMemcpy(state0.p + 10, &field, 4, cudaMemcpyHostToDevice));
  }
  const uint32_t eq_rows = 1u << (R - 1);
  Dev<uint32_t> eq(8 * eq_rows); h.assign(eq.n, 0); for (auto &x : h) x = rm31(); eq.put(h);
  std::vector<std::vector<uint32_t>> outs[2];
  for (int arm = 0; arm < 2; ++arm) {
    std::mt19937_64 data_rng(0x5eed + n * 131 + V); // identical inputs per arm
    Dev<uint32_t> state(STWO_RV64_BATCH_STATE_WORDS), records(R * round_record_words);
    CK(cudaMemcpy(state.p, state0.p, state.n * 4, cudaMemcpyDeviceToDevice));
    std::vector<Dev<uint32_t> *> bufs;
    BatchTailPacket packet{};
    packet.count = n; packet.variables = V; packet.first = first; packet.state = state.p; packet.point = point.p;
    packet.eq = {eq.p, eq_rows, 8, 0}; packet.lambda = lambda.p; packet.records = records.p;
    for (uint32_t j = 0; j < n; ++j) {
      const uint32_t v = cs.heights[j], rows = 2u << std::min(v, R), coords = (j % 3 == 0) ? 1 : 8;
      auto *bn = new Dev<uint32_t>(size_t(coords) * rows), *bd = new Dev<uint32_t>(size_t(8) * rows), *bm = new Dev<uint32_t>(32);
      std::vector<uint32_t> x(bn->n); for (auto &w : x) w = uint32_t(data_rng() % 2147483647ull); bn->put(x);
      x.assign(bd->n, 0); for (auto &w : x) w = uint32_t(data_rng() % 2147483647ull); bd->put(x);
      bufs.push_back(bn); bufs.push_back(bd); bufs.push_back(bm);
      StwoRv64BatchTailOracle o{bn->p, bd->p, nullptr, nullptr, bm->p, rows, 0, v, coords};
      if (v) {
        auto *on = new Dev<uint32_t>(size_t(8) * rows / 2), *od = new Dev<uint32_t>(size_t(8) * rows / 2);
        bufs.push_back(on); bufs.push_back(od);
        o.out_n = on->p; o.out_d = od->p; o.output_stride = rows / 2;
      }
      packet.oracles[j] = o;
    }
    if (arm) batch_tail<true><<<1, batch_tail_threads>>>(packet); else batch_tail<false><<<1, batch_tail_threads>>>(packet);
    CK(cudaDeviceSynchronize());
    outs[arm].push_back(state.get()); outs[arm].push_back(records.get());
    for (auto *b : bufs) { outs[arm].push_back(b->get()); delete b; }
  }
  if (outs[0] != outs[1]) { std::printf("TAIL MISMATCH count=%u V=%u R=%u poison=%d\n", n, V, R, poison); return 1; }
  if (outs[0][0][10] < 4) ++tail_status_seen[outs[0][0][10]];
  return 0;
}

static int selftest() {
  int bad = 0, cases = 0;
  const uint32_t counts[] = {1, 2, 5, 31, 32, 33, 63, 64, 65, 100, 127, 128};
  for (uint32_t c : counts)
    for (int mixed = 0; mixed < 2; ++mixed)
      for (int poison = 0; poison <= 10; ++poison) {
        const uint32_t V = 1 + uint32_t(rng() % 22);
        bad += run_round_case(make_case(c, V, mixed), poison); ++cases;
      }
  int tails = 0;
  for (uint32_t c : counts)
    for (uint32_t R = 1; R <= 4; ++R)
      for (int poison = 0; poison <= 3; ++poison) {
        const uint32_t V = R + uint32_t(rng() % 6);
        bad += run_tail_case(make_case(c, V, true), R, poison); ++tails;
      }
  for (int k = 0; k < 40; ++k) { // long clean sumchecks at random shapes
    const uint32_t c = 1 + uint32_t(rng() % 128), V = 1 + uint32_t(rng() % 26);
    bad += run_round_case(make_case(c, V, k & 1), 0); ++cases;
  }
  std::printf("selftest round_cases=%d (final status ok/order/field/pole = %d/%d/%d/%d) tail_cases=%d (ok/order/field/pole = %d/%d/%d/%d) mismatches=%d %s\n",
              cases, status_seen[0], status_seen[1], status_seen[2], status_seen[3], tails, tail_status_seen[0],
              tail_status_seen[1], tail_status_seen[2], tail_status_seen[3], bad, bad ? "FAIL" : "PASS");
  return bad ? 1 : 0;
}

__global__ void spin(long long cycles) {
  const long long t0 = clock64();
  while (clock64() - t0 < cycles) {}
}
static long long clock_spin_cycles = 200000000ll; // ~70-100 ms at boost clocks
// CUDA-event timing of one launch of each transition, same state/inputs per rep.
static void bench(int reps) {
  struct Shape { uint32_t count, variables; bool mixed; const char *name; } shapes[] = {
    {128, 20, false, "128 active"}, {128, 20, true, "128 mixed"}, {68, 20, true, "68 mixed"},
    {32, 18, true, "32 mixed"}, {8, 16, true, "8 mixed"}, {1, 16, false, "1 active"}};
  cudaEvent_t e0, e1; CK(cudaEventCreate(&e0)); CK(cudaEventCreate(&e1));
  std::printf("{\"schema\":\"rv64-m8-T7-batch-round-bench/v1\",\"label\":\"M\",\"reps\":%d,\"shapes\":[\n", reps);
  for (size_t si = 0; si < sizeof shapes / sizeof *shapes; ++si) {
    const auto &sh = shapes[si];
    Case cs = make_case(sh.count, sh.variables, sh.mixed);
    const uint32_t n = cs.count, V = cs.variables;
    Dev<uint32_t> seed(9), claims(8 * n), alpha(8), point(8 * V), raw(8 * cs.stride * n), st(STWO_RV64_BATCH_STATE_WORDS), base(STWO_RV64_BATCH_STATE_WORDS), rec(round_record_words);
    std::vector<uint32_t> h(9); rom(h.data()); h[8] = 7; seed.put(h);
    h.assign(8 * n, 0); for (auto &x : h) x = rm31(); claims.put(h);
    h.assign(8, 0); rom(h.data()); alpha.put(h);
    h.assign(8 * V, 0); for (auto &x : h) x = rm31(); point.put(h);
    h.assign(raw.n, 0); for (auto &x : h) x = rm31(); raw.put(h);
    BatchJobs jobs{};
    for (uint32_t i = 0; i < n; ++i)
      jobs.oracles[i] = {cs.heights[i] ? raw.p + 8 * cs.stride * i : nullptr, cs.heights[i] ? uint64_t(cs.stride) : 0ull, cs.heights[i], 0};
    jobs.count = n; jobs.variables = V;
    batch_init<<<1, 1>>>(base.p, seed.p, claims.p, alpha.p, jobs);
    CK(cudaDeviceSynchronize());
    std::printf("  {\"shape\":\"%s\",\"count\":%u,\"variables\":%u,\"active_round0\":%u", sh.name, n, V,
                uint32_t(std::count(cs.heights.begin(), cs.heights.end(), V)));
    for (int arm = 0; arm < 2; ++arm) {
      std::vector<float> per; // per-launch us, over all rounds of all reps
      std::vector<float> rep_mean;
      std::vector<cudaEvent_t> ev(V + 1);
      for (auto &e : ev) CK(cudaEventCreate(&e));
      for (int rep = 0; rep < reps + 1; ++rep) {
        // Rounds are enqueued back to back (no host sync between launches) after
        // a clock warm-up, as in the production stream; a host sync between
        // tiny launches lets the SM clock fall (24 MHz idle observed) and
        // inflates every single-CTA timing.
        spin<<<170, 256>>>(clock_spin_cycles);
        CK(cudaMemcpyAsync(st.p, base.p, st.n * 4, cudaMemcpyDeviceToDevice));
        for (uint32_t r = 0; r < V; ++r) {
          CK(cudaEventRecord(ev[r]));
          if (arm) batch_round_par<<<1, batch_par_threads>>>(st.p, jobs, r, point.p, rec.p);
          else batch_round<<<1, 1>>>(st.p, jobs, r, point.p, rec.p);
        }
        CK(cudaEventRecord(ev[V])); CK(cudaEventSynchronize(ev[V]));
        float sum = 0;
        for (uint32_t r = 0; r < V; ++r) {
          float ms; CK(cudaEventElapsedTime(&ms, ev[r], ev[r + 1]));
          if (rep) { per.push_back(ms * 1000); sum += ms * 1000; } // rep 0 = warm-up
        }
        if (rep) rep_mean.push_back(sum / V);
        // Every timed launch must be a full transition, not an early exit.
        const auto final_state = st.get();
        if (final_state[9] != V || final_state[10] != round_ok) {
          std::printf("BENCH INVALID shape=%s arm=%d next_round=%u status=%u\n", sh.name, arm, final_state[9], final_state[10]);
          std::exit(3);
        }
      }
      for (auto &e : ev) cudaEventDestroy(e);
      std::sort(per.begin(), per.end()); std::sort(rep_mean.begin(), rep_mean.end());
      std::printf(",\"%s\":{\"median_us\":%.2f,\"p10_us\":%.2f,\"p90_us\":%.2f,\"rep_mean_median_us\":%.2f,\"rep_mean_min_us\":%.2f,\"rep_mean_max_us\":%.2f}",
                  arm ? "par" : "serial", per[per.size() / 2], per[per.size() / 10], per[per.size() * 9 / 10],
                  rep_mean[rep_mean.size() / 2], rep_mean.front(), rep_mean.back());
    }
    std::printf("}%s\n", si + 1 < sizeof shapes / sizeof *shapes ? "," : "");
  }
  std::printf("]}\n");
}

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "selftest";
  if (!std::strcmp(mode, "selftest")) return selftest();
  if (!std::strcmp(mode, "bench")) { bench(argc > 2 ? std::atoi(argv[2]) : 7); return 0; }
  std::printf("usage: %s selftest|bench [reps]\n", argv[0]);
  return 2;
}
