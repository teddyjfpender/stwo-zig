// Kernels stream (M4): N2B / LDE schedule A/B microbenchmark and equivalence
// check. Runs the M3 schedule and a candidate schedule on identical random
// columns and twiddles, byte-compares the outputs, and times every interval
// with events so per-pass bandwidth can be compared with the 1.79 TB/s peak.
//   nvcc -O3 -std=c++17 -arch=sm_120 -I src/backends/cuda/native \
//        tests/cuda/rv64/native/transform/bench/n2b_schedule_bench.cu -o n2b_bench
//   ./n2b_bench LOG_N COLUMNS OLD NEW   (schedules like 6,6,6,6 and 8,8,8)
#include "transform/n2b_fused.cuh"
#include "transform/n2b_smem.cuh"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace stwo::cuda;
using namespace stwo::cuda::transform;

#define CK(x)                                                              \
  do {                                                                     \
    cudaError_t e_ = (x);                                                  \
    if (e_ != cudaSuccess) {                                               \
      std::fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__,               \
                   cudaGetErrorString(e_));                                \
      std::exit(2);                                                        \
    }                                                                      \
  } while (0)

static std::vector<uint32_t> parse(const char *s) {
  std::vector<uint32_t> v;
  for (const char *p = s; *p;) {
    v.push_back(uint32_t(std::strtoul(p, const_cast<char **>(&p), 10)));
    if (*p == ',') ++p;
  }
  return v;
}

__global__ void fill(uint32_t *x, size_t n, uint32_t seed) {
  for (size_t i = blockIdx.x * size_t(blockDim.x) + threadIdx.x; i < n;
       i += size_t(gridDim.x) * blockDim.x) {
    uint64_t z = (i + 1) * 0x9E3779B97F4A7C15ull ^ seed;
    z ^= z >> 31;
    z *= 0xBF58476D1CE4E5B9ull;
    z ^= z >> 29;
    x[i] = uint32_t(z % 2147483647ull);
  }
}

// Mirrors lde_columns_on (LDE=1) / n2b_fused_columns_from_interval_on.
static void run(const std::vector<uint32_t> &sch, bool lde, uint32_t log_n,
                uint32_t cols, const M31 *coeffs, const uint32_t *log_sizes,
                M31 *evals, const M31 *tw, cudaStream_t s,
                std::vector<float> *ms) {
  const size_t n = size_t(1) << log_n;
  ColumnSlab<M31> slab{evals, n};
  std::vector<cudaEvent_t> ev(sch.size() + 1);
  for (auto &e : ev) CK(cudaEventCreate(&e));
  CK(cudaEventRecord(ev[0], s));
  uint32_t start = 1;
  for (size_t i = 0; i < sch.size(); ++i) {
    const uint32_t st = sch[i];
    cudaError_t status;
    if (i == 0 && lde) {
      status = launch_n2b_first_from_coefficients(
          {coeffs, n / 2}, log_sizes, slab, log_n, cols, st, tw, s);
    } else if (i + 1 == sch.size()) {
      status = launch_n2b_final<true>(slab, log_n, cols, start, st, tw, s);
    } else {
      status = launch_n2b_continue(slab, log_n, cols, start, st, tw, s);
    }
    CK(status);
    start += st;
    CK(cudaEventRecord(ev[i + 1], s));
  }
  CK(cudaEventSynchronize(ev.back()));
  ms->assign(sch.size(), 0.f);
  for (size_t i = 0; i < sch.size(); ++i)
    CK(cudaEventElapsedTime(&(*ms)[i], ev[i], ev[i + 1]));
  for (auto &e : ev) CK(cudaEventDestroy(e));
}

// Two-pass candidates: strided pass A (stages 1..sa) + contiguous pass B.
template <uint32_t ATile, uint32_t ALane, uint32_t AThreads, uint32_t BTile,
          uint32_t BThreads>
static float run_two_pass(bool lde, uint32_t log_n, uint32_t cols,
                          const M31 *coeffs, const uint32_t *log_sizes,
                          M31 *evals, const M31 *tw, cudaStream_t s) {
  const size_t n = size_t(1) << log_n;
  const uint32_t sa = ATile - ALane;
  ColumnSlab<M31> slab{evals, n};
  cudaEvent_t a, b;
  CK(cudaEventCreate(&a));
  CK(cudaEventCreate(&b));
  CK(cudaEventRecord(a, s));
  if (lde)
    CK((launch_n2b_smem_pass<ATile, ALane, true, true, AThreads>(
        {coeffs, n / 2}, log_sizes, slab, log_n, cols, 1, sa, tw, s)));
  else
    CK((launch_n2b_smem_pass<ATile, ALane, true, false, AThreads>(
        {evals, n}, nullptr, slab, log_n, cols, 1, sa, tw, s)));
  CK((launch_n2b_smem_pass<BTile, 0, false, false, BThreads>(
      {evals, n}, nullptr, slab, log_n, cols, sa + 1, log_n, tw, s)));
  CK(cudaEventRecord(b, s));
  CK(cudaEventSynchronize(b));
  float ms = 0;
  CK(cudaEventElapsedTime(&ms, a, b));
  CK(cudaEventDestroy(a));
  CK(cudaEventDestroy(b));
  return ms;
}

template <uint32_t ATile, uint32_t ALane, uint32_t AThreads, uint32_t BTile,
          uint32_t BThreads>
static void compare_two_pass(const char *name, uint32_t log_n, uint32_t cols,
                             const std::vector<uint32_t> &reference,
                             const M31 *coeffs, const uint32_t *log_sizes,
                             M31 *ea, M31 *eb, const M31 *tw, cudaStream_t s,
                             int reps) {
  if (ATile - ALane + BTile != log_n) return;
  const size_t n = size_t(1) << log_n;
  for (int lde = 0; lde < 2; ++lde) {
    double best_ref = 1e30, best = 1e30;
    for (int r = 0; r < reps; ++r) {
      if (!lde) {
        fill<<<1024, 256, 0, s>>>(ea, cols * n, 3);
        fill<<<1024, 256, 0, s>>>(eb, cols * n, 3);
      }
      std::vector<float> ms;
      run(reference, lde, log_n, cols, coeffs, log_sizes, ea, tw, s, &ms);
      double t = 0;
      for (float m : ms) t += m;
      best_ref = t < best_ref ? t : best_ref;
      const float t2 = run_two_pass<ATile, ALane, AThreads, BTile, BThreads>(
          lde, log_n, cols, coeffs, log_sizes, eb, tw, s);
      best = t2 < best ? t2 : best;
    }
    std::vector<uint32_t> ha(cols * n), hb(cols * n);
    CK(cudaMemcpy(ha.data(), ea, cols * n * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(hb.data(), eb, cols * n * 4, cudaMemcpyDeviceToHost));
    const bool same = std::memcmp(ha.data(), hb.data(), cols * n * 4) == 0;
    std::printf("{\"two_pass\":\"%s\",\"log_n\":%u,\"columns\":%u,\"mode\":\"%s\",\"identical\":%s,\"reference_ms\":%.4f,\"two_pass_ms\":%.4f,\"speedup\":%.3f}\n",
                name, log_n, cols, lde ? "lde" : "n2b", same ? "true" : "false",
                best_ref, best, best_ref / best);
    if (!same) std::exit(3);
  }
}

static void compare_wide(uint32_t log_n, uint32_t cols,
                         const std::vector<uint32_t> &reference,
                         const M31 *coeffs, const uint32_t *log_sizes, M31 *ea,
                         M31 *eb, const M31 *tw, cudaStream_t s, int reps) {
  if (!n2b_wide_supported(log_n)) return;
  const size_t n = size_t(1) << log_n;
  for (int lde = 0; lde < 2; ++lde) {
    double best_ref = 1e30, best = 1e30;
    for (int r = 0; r < reps; ++r) {
      if (!lde) {
        fill<<<1024, 256, 0, s>>>(ea, cols * n, 3);
        fill<<<1024, 256, 0, s>>>(eb, cols * n, 3);
      }
      std::vector<float> ms;
      run(reference, lde, log_n, cols, coeffs, log_sizes, ea, tw, s, &ms);
      double t = 0;
      for (float m : ms) t += m;
      best_ref = t < best_ref ? t : best_ref;
      cudaEvent_t a, b;
      CK(cudaEventCreate(&a));
      CK(cudaEventCreate(&b));
      CK(cudaEventRecord(a, s));
      ColumnSlab<M31> slab{eb, n};
      if (lde)
        CK(launch_n2b_wide<true>({coeffs, n / 2}, log_sizes, slab, log_n, cols, true, tw, s));
      else
        CK(launch_n2b_wide<false>({eb, n}, nullptr, slab, log_n, cols, true, tw, s));
      CK(cudaEventRecord(b, s));
      CK(cudaEventSynchronize(b));
      float m2 = 0;
      CK(cudaEventElapsedTime(&m2, a, b));
      best = m2 < best ? m2 : best;
      CK(cudaEventDestroy(a));
      CK(cudaEventDestroy(b));
    }
    std::vector<uint32_t> ha(cols * n), hb(cols * n);
    CK(cudaMemcpy(ha.data(), ea, cols * n * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(hb.data(), eb, cols * n * 4, cudaMemcpyDeviceToHost));
    const bool same = std::memcmp(ha.data(), hb.data(), cols * n * 4) == 0;
    const double bytes = double(cols) * n * 4 * (lde ? 3.5 : 4.0);
    std::printf("{\"wide\":\"W1(11 strided)+W2(13 contiguous)\",\"log_n\":%u,\"columns\":%u,\"mode\":\"%s\",\"identical\":%s,\"reference_ms\":%.4f,\"wide_ms\":%.4f,\"speedup\":%.3f,\"wide_tbps\":%.3f}\n",
                log_n, cols, lde ? "lde" : "n2b", same ? "true" : "false",
                best_ref, best, best_ref / best, bytes / (best * 1e-3) / 1e12);
    if (!same) std::exit(3);
  }
}

int main(int argc, char **argv) {
  if (argc < 5) {
    std::fprintf(stderr, "usage: LOG_N COLUMNS OLD NEW [REPS]\n");
    return 1;
  }
  const uint32_t log_n = std::atoi(argv[1]), cols = std::atoi(argv[2]);
  const auto a = parse(argv[3]), b = parse(argv[4]);
  const int reps = argc > 5 ? std::atoi(argv[5]) : 5;
  const size_t n = size_t(1) << log_n;
  M31 *coeffs, *ea, *eb, *tw;
  uint32_t *log_sizes;
  CK(cudaMalloc(&coeffs, cols * n / 2 * 4));
  CK(cudaMalloc(&ea, cols * n * 4));
  CK(cudaMalloc(&eb, cols * n * 4));
  CK(cudaMalloc(&tw, n * 4));
  CK(cudaMalloc(&log_sizes, cols * 4));
  std::vector<uint32_t> ls(cols, log_n - 1);
  CK(cudaMemcpy(log_sizes, ls.data(), cols * 4, cudaMemcpyHostToDevice));
  fill<<<1024, 256>>>(coeffs, cols * n / 2, 1);
  fill<<<1024, 256>>>(tw, n, 2);
  cudaStream_t s;
  CK(cudaStreamCreate(&s));
  for (int lde = 0; lde < 2; ++lde) {
    double best[2] = {1e30, 1e30};
    std::vector<float> per[2];
    for (int r = 0; r < reps; ++r) {
      for (int k = 0; k < 2; ++k) {
        M31 *e = k ? eb : ea;
        if (!lde) fill<<<1024, 256, 0, s>>>(e, cols * n, 3);
        std::vector<float> ms;
        run(k ? b : a, lde, log_n, cols, coeffs, log_sizes, e, tw, s, &ms);
        double t = 0;
        for (float m : ms) t += m;
        if (t < best[k]) {
          best[k] = t;
          per[k] = ms;
        }
      }
    }
    std::vector<uint32_t> ha(cols * n), hb(cols * n);
    CK(cudaMemcpy(ha.data(), ea, cols * n * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(hb.data(), eb, cols * n * 4, cudaMemcpyDeviceToHost));
    const bool same = std::memcmp(ha.data(), hb.data(), cols * n * 4) == 0;
    const double bytes_pass = double(cols) * n * 8;  // read + write
    std::printf("{\"log_n\":%u,\"columns\":%u,\"mode\":\"%s\",\"identical\":%s,",
                log_n, cols, lde ? "lde" : "n2b", same ? "true" : "false");
    for (int k = 0; k < 2; ++k) {
      std::printf("\"%s\":{\"schedule\":\"%s\",\"ms\":%.4f,\"ns_per_cell\":%.5f,\"passes\":[",
                  k ? "new" : "old", argv[3 + k], best[k],
                  best[k] * 1e6 / (double(cols) * n));
      for (size_t i = 0; i < per[k].size(); ++i) {
        const double by = (i == 0 && lde) ? bytes_pass * 0.75 : bytes_pass;
        std::printf("%s{\"ms\":%.4f,\"tbps\":%.3f}", i ? "," : "", per[k][i],
                    by / (per[k][i] * 1e-3) / 1e12);
      }
      std::printf("]}%s", k ? "" : ",");
    }
    std::printf(",\"speedup\":%.3f}\n", best[0] / best[1]);
    if (!same) return 3;
  }
  if (std::getenv("WIDE")) compare_wide(log_n, cols, b, coeffs, log_sizes, ea, eb, tw, s, reps);
  if (std::getenv("TWO_PASS")) {
    compare_two_pass<13, 2, 512, 13, 512>("A13l2t512+B13t512", log_n, cols, b, coeffs, log_sizes, ea, eb, tw, s, reps);
    compare_two_pass<13, 2, 1024, 13, 1024>("A13l2t1024+B13t1024", log_n, cols, b, coeffs, log_sizes, ea, eb, tw, s, reps);
    compare_two_pass<14, 3, 1024, 13, 512>("A14l3t1024+B13t512", log_n, cols, b, coeffs, log_sizes, ea, eb, tw, s, reps);
    compare_two_pass<13, 3, 512, 14, 1024>("A13l3t512+B14t1024", log_n, cols, b, coeffs, log_sizes, ea, eb, tw, s, reps);
    compare_two_pass<12, 2, 512, 12, 512>("A12l2t512+B12t512", log_n, cols, b, coeffs, log_sizes, ea, eb, tw, s, reps);
    compare_two_pass<12, 3, 512, 13, 512>("A12l3t512+B13t512", log_n, cols, b, coeffs, log_sizes, ea, eb, tw, s, reps);
  }
  return 0;
}
