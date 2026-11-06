// T4 FFT passes (M8 optimisation round 1): bit-exact parity and CUDA-event
// A/B for the production transform entry points, old schedule vs new.
//   OLD: b2n three-interval schedules (STWO_RV64_M8_B2N_WIDE=0), n2b wide
//        from log 21 with the 8-word strided kernels only, stagewise
//        kernels for log_n <= 12 (STWO_RV64_M8_FFT_SMALL=0).
//   NEW: the compiled defaults of this tree.
// Both arms run the real extern "C" entry points (linked from the production
// translation units with -rdc, like the image), on identical random columns
// and twiddles, and every output word is compared. Timing: CUDA events around one entry-point call,
// reps interleaved old/new, median and [min, max] reported.
//   T=src/backends/cuda/native/transform
//   nvcc -O3 -std=c++17 -rdc=true -arch=sm_120 -I src/backends/cuda/native \
//     $T/bench/fft_passes_bench.cu $T/b2n_retained.cu $T/n2b.cu $T/lde.cu \
//     -o fft_bench
//   ./fft_bench parity            # log_n 4..24, every op, small shapes
//   ./fft_bench bench MIB REPS LOG...   # MIB of input per call (default 256)
#include "transform/b2n_fused.cuh"
#include "transform/fft_small.cuh"
#include "transform/n2b_smem.cuh"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace stwo::cuda;
using namespace stwo::cuda::transform;

extern "C" {
int stwo_ntt_b2n_columns_compact_on(const uint32_t *, size_t, uint32_t *,
                                    size_t, uint32_t, uint32_t,
                                    const uint32_t *, uint32_t, uint32_t,
                                    void *, uint32_t *);
int stwo_ntt_b2n_columns_to_retained_on(const uint32_t *, size_t, uint32_t *,
                                        size_t, uint32_t, uint32_t,
                                        const uint32_t *, uint32_t, uint32_t,
                                        void *, uint32_t *);
int stwo_ntt_n2b_columns_on(uint32_t *, size_t, uint32_t, uint32_t,
                            const uint32_t *, uint32_t, uint32_t, void *,
                            uint32_t *);
int stwo_lde_n2b_columns_on(const uint32_t *, size_t, const uint32_t *,
                            uint32_t *, size_t, uint32_t, uint32_t,
                            const uint32_t *, uint32_t, uint32_t, void *,
                            uint32_t *);
int stwo_lde_n2b_columns_before_circle_on(const uint32_t *, size_t,
                                          const uint32_t *, uint32_t *, size_t,
                                          uint32_t, uint32_t, const uint32_t *,
                                          uint32_t, uint32_t, void *,
                                          uint32_t *);
}

#define CK(x)                                                              \
  do {                                                                     \
    cudaError_t e_ = (x);                                                  \
    if (e_ != cudaSuccess) {                                               \
      std::fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__,               \
                   cudaGetErrorString(e_));                                \
      std::exit(2);                                                        \
    }                                                                      \
  } while (0)
#define CKI(x) CK(static_cast<cudaError_t>(x))

__global__ void fill(uint32_t *x, size_t n, uint32_t seed) {
  for (size_t i = blockIdx.x * size_t(blockDim.x) + threadIdx.x; i < n;
       i += size_t(gridDim.x) * blockDim.x) {
    uint64_t z = (i + 1) * 0x9E3779B97F4A7C15ull ^ (uint64_t(seed) << 32);
    z ^= z >> 31;
    z *= 0xBF58476D1CE4E5B9ull;
    z ^= z >> 29;
    x[i] = uint32_t(z % 2147483647ull);
  }
}

static void set_arm(bool fresh) {
  g_b2n_wide_override = fresh ? -1 : 0;
  g_fft_small_override = fresh ? -1 : 0;
  g_n2b_wide_min_log_override = fresh ? -1 : 21;
  g_n2b_wide_rows_highs_override = fresh ? -1 : 0;
  g_n2b_wide_override = -1;
}

enum Op { kB2nCompact, kB2nAlias, kB2nRetained, kN2b, kLde, kLdeBeforeCircle };
static const char *op_name(Op op) {
  switch (op) {
    case kB2nCompact: return "b2n_compact";
    case kB2nAlias: return "b2n_compact_alias";
    case kB2nRetained: return "b2n_to_retained";
    case kN2b: return "n2b";
    case kLde: return "lde_n2b";
    default: return "lde_n2b_before_circle";
  }
}

struct Buffers {
  uint32_t *source = nullptr;   // cols * n
  uint32_t *output = nullptr;   // cols * 2n (retained room)
  uint32_t *twiddles = nullptr; // n words
  uint32_t *log_sizes = nullptr;
  size_t cap = 0;
};

// Runs one op once; returns ms of the entry-point call (CUDA events).
static float run_op(Op op, uint32_t log_n, uint32_t cols, Buffers &b,
                    cudaStream_t s, uint32_t *launches) {
  const size_t n = size_t(1) << log_n;
  const uint32_t domain = uint32_t(n / 2);
  const uint32_t tw_words = uint32_t(n);
  // Prepare inputs (not timed).
  switch (op) {
    case kB2nAlias:
    case kN2b:
      CK(cudaMemcpyAsync(b.output, b.source, cols * n * 4,
                         cudaMemcpyDeviceToDevice, s));
      break;
    default:
      CK(cudaMemsetAsync(b.output, 0xff, cols * n * 4 *
                         (op == kB2nRetained ? 2 : 1), s));
      break;
  }
  cudaEvent_t a, e;
  CK(cudaEventCreate(&a));
  CK(cudaEventCreate(&e));
  CK(cudaEventRecord(a, s));
  switch (op) {
    case kB2nCompact:
      CKI(stwo_ntt_b2n_columns_compact_on(b.source, n, b.output, n, log_n, cols,
                                          b.twiddles, tw_words, domain, s,
                                          launches));
      break;
    case kB2nAlias:
      CKI(stwo_ntt_b2n_columns_compact_on(b.output, n, b.output, n, log_n, cols,
                                          b.twiddles, tw_words, domain, s,
                                          launches));
      break;
    case kB2nRetained:
      CKI(stwo_ntt_b2n_columns_to_retained_on(b.source, n, b.output, 2 * n,
                                              log_n, cols, b.twiddles,
                                              tw_words, domain, s, launches));
      break;
    case kN2b:
      CKI(stwo_ntt_n2b_columns_on(b.output, n, log_n, cols, b.twiddles,
                                  tw_words, domain, s, launches));
      break;
    case kLde:
      CKI(stwo_lde_n2b_columns_on(b.source, n / 2, b.log_sizes, b.output, n,
                                  log_n, cols, b.twiddles, tw_words, domain, s,
                                  launches));
      break;
    case kLdeBeforeCircle:
      CKI(stwo_lde_n2b_columns_before_circle_on(
          b.source, n / 2, b.log_sizes, b.output, n, log_n, cols, b.twiddles,
          tw_words, domain, s, launches));
      break;
  }
  CK(cudaEventRecord(e, s));
  CK(cudaEventSynchronize(e));
  float ms = 0;
  CK(cudaEventElapsedTime(&ms, a, e));
  CK(cudaEventDestroy(a));
  CK(cudaEventDestroy(e));
  return ms;
}

static void prepare(Buffers &b, uint32_t log_n, uint32_t cols, uint32_t seed,
                    cudaStream_t s) {
  const size_t n = size_t(1) << log_n;
  const size_t need = cols * n;
  if (need > b.cap) {
    if (b.source) {
      CK(cudaFree(b.source));
      CK(cudaFree(b.output));
      CK(cudaFree(b.twiddles));
      CK(cudaFree(b.log_sizes));
    }
    CK(cudaMalloc(&b.source, need * 4));
    CK(cudaMalloc(&b.output, need * 8));
    CK(cudaMalloc(&b.twiddles, (size_t(1) << 25) * 4));
    CK(cudaMalloc(&b.log_sizes, 65536 * 4));
    b.cap = need;
  }
  fill<<<1024, 256, 0, s>>>(b.source, need, seed);
  fill<<<1024, 256, 0, s>>>(b.twiddles, n, seed + 1);
  // LDE coefficient sizes: mostly log_n - 1, some smaller (zero extension),
  // one oversized (clamped to the domain).
  std::vector<uint32_t> logs(cols);
  for (uint32_t c = 0; c < cols; ++c) {
    const uint32_t k = (c * 7u + seed) % 5u;
    logs[c] = k == 0 && log_n > 4 ? log_n - 3 : (k == 1 ? log_n : log_n - 1);
  }
  CK(cudaMemcpyAsync(b.log_sizes, logs.data(), cols * 4,
                     cudaMemcpyHostToDevice, s));
  CK(cudaStreamSynchronize(s));
}

static std::vector<uint32_t> download(const Buffers &b, size_t words) {
  std::vector<uint32_t> h(words);
  CK(cudaMemcpy(h.data(), b.output, words * 4, cudaMemcpyDeviceToHost));
  return h;
}

static int parity(cudaStream_t s) {
  Buffers b;
  int failures = 0;
  const Op ops[] = {kB2nCompact, kB2nAlias, kB2nRetained,
                    kN2b,        kLde,      kLdeBeforeCircle};
  for (uint32_t log_n = 4; log_n <= 24; ++log_n) {
    // Odd column counts exercise partial small-size CTAs; > 1 column
    // exercises the column-fastest grids.
    const uint32_t col_options[] = {
        1u, std::max<uint32_t>(3u, std::min<uint32_t>(
                (uint32_t(1) << 22 >> log_n) + 3u, 4099u))};
    for (uint32_t cols : col_options) {
      for (Op op : ops) {
        const size_t n = size_t(1) << log_n;
        const size_t words = cols * n * (op == kB2nRetained ? 2 : 1);
        prepare(b, log_n, cols, log_n * 131u + cols, s);
        uint32_t lo = 0, ln = 0;
        set_arm(false);
        run_op(op, log_n, cols, b, s, &lo);
        const auto ref = download(b, words);
        set_arm(true);
        run_op(op, log_n, cols, b, s, &ln);
        const auto got = download(b, words);
        set_arm(false);
        const bool same =
            std::memcmp(ref.data(), got.data(), words * 4) == 0;
        size_t first = 0;
        if (!same)
          while (first < words && ref[first] == got[first]) ++first;
        std::printf(
            "{\"parity\":\"%s\",\"log_n\":%u,\"columns\":%u,\"identical\":%s,"
            "\"launches_old\":%u,\"launches_new\":%u%s}\n",
            op_name(op), log_n, cols, same ? "true" : "false", lo, ln,
            same ? "" : (",\"first_diff\":" + std::to_string(first)).c_str());
        if (!same) ++failures;
      }
    }
  }
  std::printf("{\"parity_failures\":%d}\n", failures);
  return failures == 0 ? 0 : 3;
}

static int bench(cudaStream_t s, size_t mib, int reps,
                 const std::vector<uint32_t> &logs) {
  Buffers b;
  const Op ops[] = {kB2nCompact, kB2nRetained, kN2b, kLde};
  for (uint32_t log_n : logs) {
    const size_t n = size_t(1) << log_n;
    const uint32_t cols = uint32_t(std::max<size_t>(1, (mib << 18) >> log_n));
    prepare(b, log_n, cols, 7u, s);
    for (Op op : ops) {
      std::vector<float> to, tn;
      uint32_t lo = 0, ln = 0;
      for (int warm = 0; warm < 2; ++warm) {
        set_arm(false);
        run_op(op, log_n, cols, b, s, &lo);
        set_arm(true);
        run_op(op, log_n, cols, b, s, &ln);
      }
      for (int r = 0; r < reps; ++r) {
        set_arm(false);
        to.push_back(run_op(op, log_n, cols, b, s, &lo));
        set_arm(true);
        tn.push_back(run_op(op, log_n, cols, b, s, &ln));
      }
      set_arm(false);
      std::sort(to.begin(), to.end());
      std::sort(tn.begin(), tn.end());
      const double mo = to[to.size() / 2], mn = tn[tn.size() / 2];
      // HBM bytes moved by one ideal pass (read + write of the input image;
      // retained writes 2N, LDE reads N/2 coefficients).
      const double in_bytes = double(cols) * n * 4;
      std::printf(
          "{\"bench\":\"%s\",\"log_n\":%u,\"columns\":%u,\"reps\":%d,"
          "\"launches_old\":%u,\"launches_new\":%u,"
          "\"old_ms_median\":%.4f,\"old_ms_min\":%.4f,\"old_ms_max\":%.4f,"
          "\"new_ms_median\":%.4f,\"new_ms_min\":%.4f,\"new_ms_max\":%.4f,"
          "\"speedup\":%.3f,\"new_input_tbps\":%.3f}\n",
          op_name(op), log_n, cols, reps, lo, ln, mo, to.front(), to.back(), mn,
          tn.front(), tn.back(), mo / mn, in_bytes / (mn * 1e-3) / 1e12);
      std::fflush(stdout);
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  cudaStream_t s;
  CK(cudaStreamCreateWithFlags(&s, cudaStreamNonBlocking));
  const std::string mode = argc > 1 ? argv[1] : "parity";
  if (mode == "parity") return parity(s);
  const size_t mib = argc > 2 ? std::strtoul(argv[2], nullptr, 10) : 256;
  const int reps = argc > 3 ? std::atoi(argv[3]) : 7;
  std::vector<uint32_t> logs;
  for (int i = 4; i < argc; ++i) logs.push_back(std::atoi(argv[i]));
  if (logs.empty())
    for (uint32_t l = 10; l <= 24; ++l) logs.push_back(l);
  return bench(s, mib, reps, logs);
}
