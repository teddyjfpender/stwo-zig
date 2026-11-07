// T8 (STWO_RV64_M8_LOGUP_BLOCK_INVERSE) kernel parity + CUDA-event bench.
// Mode 0 (original kernels) vs mode 1 (T8) through the mode-explicit
// launchers behind stwo_rv64_global_pairs_on / stwo_rv64_prefix_scan_on.
// Parity compares EVERY word of every buffer each launcher may write (pair
// planes incl. stride padding, the row-sum plane, scan scratch, claim, status)
// on deterministic random inputs with injected non-canonical words and zero
// denominators. Build (pod):
//   nvcc -O3 -std=c++17 -arch=sm_120 -I src/backends/cuda/native \
//     tests/cuda/rv64/t8_logup_parity_bench.cu \
//     src/backends/cuda/native/rv64/global.cu src/backends/cuda/native/rv64/binding.cu
// Usage: t8 parity | t8 bench <reps> [rows_log pairs]... | t8 scanbench <reps> [rows_log]...
// Output: one JSON object per line.
#include "rv64/logup_t8.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <cuda_runtime.h>

static cudaStream_t g_stream;
extern "C" int stwo_exec_context_lane_stream(void *, uint32_t, void **out) {
  *out = g_stream;
  return 0;
}
extern "C" int stwo_exec_context_validate_allocation(void *, const void *, size_t) { return 0; }

#define CK(x)                                                                    \
  do {                                                                           \
    const cudaError_t e_ = (x);                                                  \
    if (e_ != cudaSuccess) {                                                     \
      std::fprintf(stderr, "%s:%d %s -> %s\n", __FILE__, __LINE__, #x,          \
                   cudaGetErrorString(e_));                                      \
      std::exit(2);                                                              \
    }                                                                            \
  } while (0)

constexpr uint32_t P = 2147483647u;
__host__ __device__ inline uint64_t mix(uint64_t x) {
  x += 0x9e3779b97f4a7c15ull;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
  return x ^ (x >> 31);
}
// Words of buffer `which` (0 = output/denominators, 1 = contributions/
// numerators). Pair planes hold canonical values except: one row in `bad`
// gets a non-canonical word (p .. p+15), one row in `zero` gets an all-zero
// denominator. Everything else (padding, sum plane) is garbage < 2^32.
__global__ void fill_pairs(uint32_t *buf, uint32_t which, uint64_t stride,
                           uint32_t pairs, uint32_t planes, uint32_t row_log,
                           uint64_t seed, uint32_t bad, uint32_t zero) {
  const uint64_t total = uint64_t(planes) * 8 * stride;
  for (uint64_t i = blockIdx.x * uint64_t(blockDim.x) + threadIdx.x; i < total;
       i += uint64_t(gridDim.x) * blockDim.x) {
    const uint64_t plane = i / stride, row = i % stride, pair = plane / 8;
    const uint64_t h = mix(seed ^ (uint64_t(which) << 62) ^ i);
    uint32_t v = uint32_t(h);
    if (pair < pairs && row < (1ull << row_log)) {
      v = uint32_t(h % P);
      const uint64_t r = mix(seed ^ 0x51ull ^ (pair << 32) ^ row);
      if (bad && r % bad == 0 && (h >> 40) % 8 == 0)
        v = P + uint32_t((h >> 33) & 15u);
      if (which == 0 && zero && (r >> 20) % zero == 0)
        v = 0;
    }
    buf[i] = v;
  }
}
__global__ void fill_scan(uint32_t *buf, uint64_t words, uint64_t stride, uint32_t rows,
                          uint64_t seed, uint32_t bad) {
  for (uint64_t i = blockIdx.x * uint64_t(blockDim.x) + threadIdx.x; i < words;
       i += uint64_t(gridDim.x) * blockDim.x) {
    const uint64_t h = mix(seed ^ i);
    uint32_t v = uint32_t(h % P);
    if (i % stride >= rows)
      v = uint32_t(h);
    else if (bad && (h >> 34) % bad == 0)
      v = P + uint32_t((h >> 50) & 3u);
    buf[i] = v;
  }
}
__global__ void count_diff(const uint32_t *a, const uint32_t *b, uint64_t n,
                           unsigned long long *out) {
  unsigned long long local = 0;
  for (uint64_t i = blockIdx.x * uint64_t(blockDim.x) + threadIdx.x; i < n;
       i += uint64_t(gridDim.x) * blockDim.x)
    local += a[i] != b[i];
  if (local)
    atomicAdd(out, local);
}
static unsigned long long *g_diff;
static uint64_t diff(const uint32_t *a, const uint32_t *b, uint64_t n) {
  CK(cudaMemsetAsync(g_diff, 0, 8, g_stream));
  count_diff<<<1024, 256, 0, g_stream>>>(a, b, n, g_diff);
  unsigned long long h = 0;
  CK(cudaMemcpyAsync(&h, g_diff, 8, cudaMemcpyDeviceToHost, g_stream));
  CK(cudaStreamSynchronize(g_stream));
  return h;
}
static uint64_t scan_words(uint32_t rows) {
  uint64_t w = 0;
  for (uint32_t n = rows; n > 1;) {
    n = (n + 127) / 128;
    w += uint64_t(n) * 8;
  }
  return w;
}

struct PairsArm {
  uint32_t *out = nullptr, *con = nullptr, *scratch = nullptr, *claim = nullptr,
           *status = nullptr;
  uint64_t out_words = 0, con_words = 0, scan = 0;
  void alloc(uint32_t row_log, uint32_t pairs, uint64_t stride) {
    out_words = uint64_t(pairs + 1) * 8 * stride;
    con_words = uint64_t(pairs) * 8 * stride;
    scan = scan_words(1u << row_log);
    CK(cudaMalloc(&out, out_words * 4));
    CK(cudaMalloc(&con, con_words * 4));
    CK(cudaMalloc(&scratch, scan * 4));
    CK(cudaMalloc(&claim, 32));
    CK(cudaMalloc(&status, 4));
  }
  void release() {
    cudaFree(out); cudaFree(con); cudaFree(scratch); cudaFree(claim); cudaFree(status);
  }
  void fill(uint32_t row_log, uint32_t pairs, uint64_t stride, uint64_t seed,
            uint32_t bad, uint32_t zero) {
    fill_pairs<<<2048, 256, 0, g_stream>>>(out, 0, stride, pairs, pairs + 1, row_log, seed, bad, zero);
    fill_pairs<<<2048, 256, 0, g_stream>>>(con, 1, stride, pairs, pairs, row_log, seed, bad, zero);
    CK(cudaGetLastError());
    CK(cudaMemsetAsync(scratch, 0xA5, scan * 4, g_stream));
    CK(cudaMemsetAsync(claim, 0x5A, 32, g_stream));
    CK(cudaMemsetAsync(status, 0, 4, g_stream));
  }
  StwoRv64GlobalPairs job(uint32_t row_log, uint32_t pairs, uint64_t stride) const {
    StwoRv64GlobalPairs j{};
    j.output = out; j.contributions = con; j.scan_scratch = scratch; j.claim = claim;
    j.status = status; j.stride = stride; j.scan_words = scan; j.row_log = row_log;
    j.pairs = pairs;
    return j;
  }
};

static int g_failures = 0;
static void parity_pairs(uint32_t row_log, uint32_t pairs, uint32_t pad, uint32_t bad,
                         uint32_t zero, uint64_t seed) {
  const uint64_t stride = (1ull << row_log) + pad;
  PairsArm a, b;
  a.alloc(row_log, pairs, stride);
  b.alloc(row_log, pairs, stride);
  a.fill(row_log, pairs, stride, seed, bad, zero);
  b.fill(row_log, pairs, stride, seed, bad, zero);
  const auto ja = a.job(row_log, pairs, stride), jb = b.job(row_log, pairs, stride);
  const int ra = stwo::cuda::rv64::t8::global_pairs(nullptr, 0, &ja, 0);
  const int rb = stwo::cuda::rv64::t8::global_pairs(nullptr, 0, &jb, 1);
  CK(cudaStreamSynchronize(g_stream));
  CK(cudaGetLastError());
  uint32_t sa = 0, sb = 0;
  CK(cudaMemcpy(&sa, a.status, 4, cudaMemcpyDeviceToHost));
  CK(cudaMemcpy(&sb, b.status, 4, cudaMemcpyDeviceToHost));
  const uint64_t d_out = diff(a.out, b.out, a.out_words), d_con = diff(a.con, b.con, a.con_words),
                 d_scr = diff(a.scratch, b.scratch, a.scan), d_claim = diff(a.claim, b.claim, 8);
  const bool ok = !ra && !rb && sa == sb && !d_out && !d_con && !d_scr && !d_claim;
  g_failures += !ok;
  std::printf("{\"kind\":\"parity_pairs\",\"row_log\":%u,\"pairs\":%u,\"pad\":%u,\"bad\":%u,"
              "\"zero\":%u,\"rc\":[%d,%d],\"status\":[%u,%u],\"diff_output\":%llu,"
              "\"diff_contributions\":%llu,\"diff_scratch\":%llu,\"diff_claim\":%llu,"
              "\"bit_identical\":%s}\n",
              row_log, pairs, pad, bad, zero, ra, rb, sa, sb, (unsigned long long)d_out,
              (unsigned long long)d_con, (unsigned long long)d_scr,
              (unsigned long long)d_claim, ok ? "true" : "false");
  std::fflush(stdout);
  a.release();
  b.release();
}

struct ScanArm {
  uint32_t *data = nullptr, *scratch = nullptr, *claim = nullptr, *status = nullptr;
  uint64_t words = 0, scan = 0;
  void alloc(uint32_t row_log, uint64_t stride) {
    words = 8 * stride;
    scan = scan_words(1u << row_log);
    CK(cudaMalloc(&data, words * 4));
    CK(cudaMalloc(&scratch, scan * 4));
    CK(cudaMalloc(&claim, 32));
    CK(cudaMalloc(&status, 4));
  }
  void release() { cudaFree(data); cudaFree(scratch); cudaFree(claim); cudaFree(status); }
  void fill(uint32_t row_log, uint64_t stride, uint64_t seed, uint32_t bad) {
    fill_scan<<<2048, 256, 0, g_stream>>>(data, words, stride, 1u << row_log, seed, bad);
    CK(cudaGetLastError());
    CK(cudaMemsetAsync(scratch, 0xA5, scan * 4, g_stream));
    CK(cudaMemsetAsync(claim, 0x5A, 32, g_stream));
    CK(cudaMemsetAsync(status, 0, 4, g_stream));
  }
  StwoRv64PrefixScan job(uint32_t row_log, uint64_t stride, uint32_t center) const {
    StwoRv64PrefixScan j{};
    j.data = {data, stride, 8, 0};
    j.scratch = scratch; j.scratch_words = scan; j.claim = claim; j.status = status;
    j.row_log = row_log; j.center = center;
    return j;
  }
};
static void parity_scan(uint32_t row_log, uint32_t pad, uint32_t center, uint32_t bad,
                        uint64_t seed) {
  const uint64_t stride = (1ull << row_log) + pad;
  ScanArm a, b;
  a.alloc(row_log, stride);
  b.alloc(row_log, stride);
  a.fill(row_log, stride, seed, bad);
  b.fill(row_log, stride, seed, bad);
  const auto ja = a.job(row_log, stride, center), jb = b.job(row_log, stride, center);
  const int ra = stwo::cuda::rv64::t8::prefix_scan(nullptr, 0, &ja, 0);
  const int rb = stwo::cuda::rv64::t8::prefix_scan(nullptr, 0, &jb, 1);
  CK(cudaStreamSynchronize(g_stream));
  CK(cudaGetLastError());
  uint32_t sa = 0, sb = 0;
  CK(cudaMemcpy(&sa, a.status, 4, cudaMemcpyDeviceToHost));
  CK(cudaMemcpy(&sb, b.status, 4, cudaMemcpyDeviceToHost));
  const uint64_t d_data = diff(a.data, b.data, a.words), d_scr = diff(a.scratch, b.scratch, a.scan),
                 d_claim = diff(a.claim, b.claim, 8);
  const bool ok = !ra && !rb && sa == sb && !d_data && !d_scr && !d_claim;
  g_failures += !ok;
  std::printf("{\"kind\":\"parity_scan\",\"row_log\":%u,\"pad\":%u,\"center\":%u,\"bad\":%u,"
              "\"rc\":[%d,%d],\"status\":[%u,%u],\"diff_data\":%llu,\"diff_scratch\":%llu,"
              "\"diff_claim\":%llu,\"bit_identical\":%s}\n",
              row_log, pad, center, bad, ra, rb, sa, sb, (unsigned long long)d_data,
              (unsigned long long)d_scr, (unsigned long long)d_claim, ok ? "true" : "false");
  std::fflush(stdout);
  a.release();
  b.release();
}

static void summary(std::vector<float> v, float &med, float &lo, float &hi) {
  std::sort(v.begin(), v.end());
  med = v[v.size() / 2];
  lo = v.front();
  hi = v.back();
}
// Interleaved reps: (refill untimed, mode 0 timed), (refill, mode 1 timed).
static void bench_pairs(uint32_t row_log, uint32_t pairs, int reps) {
  const uint64_t stride = 1ull << row_log;
  PairsArm a;
  a.alloc(row_log, pairs, stride);
  cudaEvent_t e0, e1;
  CK(cudaEventCreate(&e0));
  CK(cudaEventCreate(&e1));
  std::vector<float> t[2];
  for (int r = 0; r < reps + 1; ++r)
    for (int mode = 0; mode < 2; ++mode) {
      a.fill(row_log, pairs, stride, 7 + r, 0, 0);
      const auto j = a.job(row_log, pairs, stride);
      CK(cudaEventRecord(e0, g_stream));
      const int rc = stwo::cuda::rv64::t8::global_pairs(nullptr, 0, &j, mode);
      CK(cudaEventRecord(e1, g_stream));
      CK(cudaEventSynchronize(e1));
      if (rc) std::exit(3);
      float ms = 0;
      CK(cudaEventElapsedTime(&ms, e0, e1));
      if (r) t[mode].push_back(ms); // rep 0 = warm-up
    }
  float m0, l0, h0, m1, l1, h1;
  summary(t[0], m0, l0, h0);
  summary(t[1], m1, l1, h1);
  std::printf("{\"kind\":\"bench_pairs\",\"row_log\":%u,\"pairs\":%u,\"reps\":%d,"
              "\"old_ms\":{\"median\":%.4f,\"min\":%.4f,\"max\":%.4f},"
              "\"new_ms\":{\"median\":%.4f,\"min\":%.4f,\"max\":%.4f},\"speedup\":%.3f}\n",
              row_log, pairs, reps, m0, l0, h0, m1, l1, h1, m0 / m1);
  std::fflush(stdout);
  cudaEventDestroy(e0);
  cudaEventDestroy(e1);
  a.release();
}
static void bench_scan(uint32_t row_log, int reps) {
  const uint64_t stride = 1ull << row_log;
  ScanArm a;
  a.alloc(row_log, stride);
  cudaEvent_t e0, e1;
  CK(cudaEventCreate(&e0));
  CK(cudaEventCreate(&e1));
  std::vector<float> t[2];
  for (int r = 0; r < reps + 1; ++r)
    for (int mode = 0; mode < 2; ++mode) {
      a.fill(row_log, stride, 11 + r, 0);
      const auto j = a.job(row_log, stride, 1);
      CK(cudaEventRecord(e0, g_stream));
      const int rc = stwo::cuda::rv64::t8::prefix_scan(nullptr, 0, &j, mode);
      CK(cudaEventRecord(e1, g_stream));
      CK(cudaEventSynchronize(e1));
      if (rc) std::exit(3);
      float ms = 0;
      CK(cudaEventElapsedTime(&ms, e0, e1));
      if (r) t[mode].push_back(ms);
    }
  float m0, l0, h0, m1, l1, h1;
  summary(t[0], m0, l0, h0);
  summary(t[1], m1, l1, h1);
  std::printf("{\"kind\":\"bench_scan\",\"row_log\":%u,\"reps\":%d,"
              "\"old_ms\":{\"median\":%.4f,\"min\":%.4f,\"max\":%.4f},"
              "\"new_ms\":{\"median\":%.4f,\"min\":%.4f,\"max\":%.4f},\"speedup\":%.3f}\n",
              row_log, reps, m0, l0, h0, m1, l1, h1, m0 / m1);
  std::fflush(stdout);
  cudaEventDestroy(e0);
  cudaEventDestroy(e1);
  a.release();
}

int main(int argc, char **argv) {
  CK(cudaStreamCreateWithFlags(&g_stream, cudaStreamNonBlocking));
  CK(cudaMalloc(&g_diff, 8));
  const std::string cmd = argc > 1 ? argv[1] : "parity";
  if (cmd == "fillcheck") {
    PairsArm a;
    a.alloc(10, 1, 1024);
    a.fill(10, 1, 1024, 200, 101, 211);
    std::vector<uint32_t> h(a.out_words), g(a.con_words);
    CK(cudaMemcpy(h.data(), a.out, h.size() * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(g.data(), a.con, g.size() * 4, cudaMemcpyDeviceToHost));
    size_t bo = 0, bc = 0, z = 0;
    for (size_t i = 0; i < 8 * 1024; ++i) { bo += h[i] >= P; bc += g[i] >= P; z += !h[i]; }
    std::printf("bad_out=%zu bad_con=%zu zero_words=%zu\n", bo, bc, z);
    return 0;
  }
  if (cmd == "parity") {
    const uint32_t max_log = argc > 2 ? uint32_t(std::atoi(argv[2])) : 20;
    uint64_t seed = 1;
    // Pairs: every row_log 4..max_log; pair counts across the 2-D/fused
    // split, the 13-pair circuit maximum and the large native groups.
    for (uint32_t log = 4; log <= max_log; ++log)
      for (uint32_t pairs : {1u, 2u, 3u, 13u})
        for (uint32_t pad : {0u, 7u})
          parity_pairs(log, pairs, pad, log < 8 ? 3 : 101, log < 8 ? 5 : 211, seed++);
    for (uint32_t log : {10u, 14u, 16u})
      for (uint32_t pairs : {50u, 143u})
        parity_pairs(log, pairs, 3, 97, 89, seed++);
    parity_pairs(12, 640, 0, 0, 0, seed++);
    parity_pairs(16, 5, 0, 0, 0, seed++); // clean input: status 0 both
    // Scan: every row_log 4..max_log+2 (tiled from 12), both centring modes.
    for (uint32_t log = 4; log <= max_log + 2; ++log)
      for (uint32_t center : {0u, 1u})
        for (uint32_t pad : {0u, 5u})
          parity_scan(log, pad, center, (log & 1) ? 0 : 4099, seed++);
    std::printf("{\"kind\":\"parity_summary\",\"failures\":%d}\n", g_failures);
    return g_failures ? 1 : 0;
  }
  const int reps = argc > 2 ? std::atoi(argv[2]) : 7;
  if (cmd == "bench") {
    for (int i = 3; i + 1 < argc; i += 2)
      bench_pairs(uint32_t(std::atoi(argv[i])), uint32_t(std::atoi(argv[i + 1])), reps);
    return 0;
  }
  if (cmd == "scanbench") {
    for (int i = 3; i < argc; ++i)
      bench_scan(uint32_t(std::atoi(argv[i])), reps);
    return 0;
  }
  std::fprintf(stderr, "usage: %s parity [max_log] | bench reps [log pairs]... | scanbench reps [log]...\n", argv[0]);
  return 2;
}
