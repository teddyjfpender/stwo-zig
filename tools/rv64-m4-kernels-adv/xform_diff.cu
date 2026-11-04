// Adversarial differential test (kernels-stream review): drives the PRODUCTION
// extern "C" transform entries of one tree on deterministic inputs and prints a
// digest per case. Build once against the M3 tree and once against the branch;
// the outputs must match line for line. Inputs never depend on the tree.
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
extern "C" int stwo_ntt_n2b_columns_on(uint32_t *, size_t, uint32_t, uint32_t, const uint32_t *, uint32_t, uint32_t, void *, uint32_t *);
extern "C" int stwo_lde_n2b_columns_on(const uint32_t *, size_t, const uint32_t *, uint32_t *, size_t, uint32_t, uint32_t, const uint32_t *, uint32_t, uint32_t, void *, uint32_t *);
extern "C" int stwo_lde_n2b_columns_before_circle_on(const uint32_t *, size_t, const uint32_t *, uint32_t *, size_t, uint32_t, uint32_t, const uint32_t *, uint32_t, uint32_t, void *, uint32_t *);
extern "C" int stwo_ntt_b2n_columns_compact_on(const uint32_t *, size_t, uint32_t *, size_t, uint32_t, uint32_t, const uint32_t *, uint32_t, uint32_t, void *, uint32_t *);
extern "C" int stwo_ntt_b2n_columns_to_retained_on(const uint32_t *, size_t, uint32_t *, size_t, uint32_t, uint32_t, const uint32_t *, uint32_t, uint32_t, void *, uint32_t *);
#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { std::printf("CUDAERR %s:%d %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); std::exit(2);} } while (0)
__global__ void fill(uint32_t *x, size_t n, uint64_t seed) {
  for (size_t i = blockIdx.x * size_t(blockDim.x) + threadIdx.x; i < n; i += size_t(gridDim.x) * blockDim.x) {
    uint64_t z = (i + 1) * 0x9E3779B97F4A7C15ull ^ (seed * 0xD1B54A32D192ED03ull);
    z ^= z >> 31; z *= 0xBF58476D1CE4E5B9ull; z ^= z >> 29;
    x[i] = uint32_t(z % 2147483647ull);
  }
}
static uint64_t digest(const uint32_t *d, size_t words) {
  std::vector<uint32_t> h(words);
  CK(cudaMemcpy(h.data(), d, words * 4, cudaMemcpyDeviceToHost));
  uint64_t x = 1469598103934665603ull;
  for (uint32_t w : h) { x ^= w; x *= 1099511628211ull; }
  return x;
}
static uint64_t digest_cols(const uint32_t *d, size_t stride, uint32_t cols, size_t len) {
  uint64_t x = 0;
  for (uint32_t c = 0; c < cols; ++c) x = x * 31 + digest(d + c * stride, len);
  return x;
}
int main() {
  const uint32_t LOGMAX = getenv("LOGMAX") ? atoi(getenv("LOGMAX")) : 99, LOGMIN = getenv("LOGMIN") ? atoi(getenv("LOGMIN")) : 0, COLMAX = getenv("COLMAX") ? atoi(getenv("COLMAX")) : 99;
  cudaStream_t s; CK(cudaStreamCreate(&s));
  const size_t max_words = size_t(1) << 29;  // 2 GiB scratch each
  uint32_t *a, *b, *tw, *logs; CK(cudaMalloc(&a, max_words * 4)); CK(cudaMalloc(&b, max_words * 4));
  CK(cudaMalloc(&tw, (size_t(1) << 26) * 4)); CK(cudaMalloc(&logs, 4096));
  uint32_t launches = 0; int failures = 0;
  auto rc = [&](const char *what, int r) { if (r) { std::printf("%s rc=%d\n", what, r); ++failures; } };
  // ---- N2B in place --------------------------------------------------------
  for (uint32_t log_n : {18u, 20u, 21u, 22u, 23u, 24u, 25u, 26u}) {
    if (log_n > LOGMAX || log_n < LOGMIN) continue;
    const size_t n = size_t(1) << log_n;
    for (uint32_t cols : {1u, 3u, 9u}) { if (cols > COLMAX) continue;
      for (size_t pad : {size_t(0), size_t(256)}) {
        const size_t stride = n + pad;
        if (stride * cols > max_words) continue;
        fill<<<1024, 256, 0, s>>>(tw, n, 7 + log_n);
        fill<<<1024, 256, 0, s>>>(a, stride * cols, 11 * log_n + cols + pad);
        rc("n2b", stwo_ntt_n2b_columns_on(a, stride, log_n, cols, tw, uint32_t(n), uint32_t(n / 2), s, &launches));
        CK(cudaStreamSynchronize(s));
        std::printf("n2b log=%u cols=%u pad=%zu %016llx\n", log_n, cols, pad, (unsigned long long)digest_cols(a, stride, cols, n));
      }
    }
  }
  // ---- LDE (with / before circle), mixed coefficient sizes -----------------
  for (uint32_t log_n : {19u, 20u, 21u, 22u, 23u, 24u, 25u}) {
    if (log_n > LOGMAX || log_n < LOGMIN) continue;
    const size_t n = size_t(1) << log_n;
    for (uint32_t cols : {1u, 5u}) { if (cols > COLMAX) continue;
      for (int circle = 0; circle < 2; ++circle) {
        std::vector<uint32_t> ls(cols);
        const uint32_t pattern[] = {log_n - 1, log_n - 2, log_n - 4, 3, log_n + 2};
        for (uint32_t c = 0; c < cols; ++c) ls[c] = pattern[(c + circle) % 5];
        CK(cudaMemcpy(logs, ls.data(), cols * 4, cudaMemcpyHostToDevice));
        const size_t cstride = n / 2 + 64, estride = n + 128;
        if (cstride * cols > max_words || estride * cols > max_words) continue;
        fill<<<1024, 256, 0, s>>>(tw, n, 5 + log_n);
        fill<<<1024, 256, 0, s>>>(a, cstride * cols, 3 * log_n + cols);
        CK(cudaMemsetAsync(b, 0xA5, estride * cols * 4, s));
        rc("lde", (circle ? stwo_lde_n2b_columns_on : stwo_lde_n2b_columns_before_circle_on)(
            a, cstride, logs, b, estride, log_n, cols, tw, uint32_t(n), uint32_t(n / 2), s, &launches));
        CK(cudaStreamSynchronize(s));
        std::printf("lde log=%u cols=%u circle=%d %016llx\n", log_n, cols, circle, (unsigned long long)digest_cols(b, estride, cols, n));
      }
    }
  }
  // ---- B2N compact (separate + exact alias) and to_retained ----------------
  for (uint32_t log_n : {20u, 22u, 23u, 24u, 25u, 26u}) {
    if (log_n > LOGMAX || log_n < LOGMIN) continue;
    const size_t n = size_t(1) << log_n;
    for (uint32_t cols : {1u, 3u}) { if (cols > COLMAX) continue;
      if (2 * n * cols > max_words) continue;
      fill<<<1024, 256, 0, s>>>(tw, n, 9 + log_n);
      fill<<<1024, 256, 0, s>>>(a, n * cols, 13 * log_n + cols);
      rc("b2n", stwo_ntt_b2n_columns_compact_on(a, n, b, n, log_n, cols, tw, uint32_t(n), uint32_t(n / 2), s, &launches));
      CK(cudaStreamSynchronize(s));
      std::printf("b2n log=%u cols=%u %016llx\n", log_n, cols, (unsigned long long)digest_cols(b, n, cols, n));
      rc("b2n-alias", stwo_ntt_b2n_columns_compact_on(a, n, a, n, log_n, cols, tw, uint32_t(n), uint32_t(n / 2), s, &launches));
      CK(cudaStreamSynchronize(s));
      std::printf("b2n-alias log=%u cols=%u %016llx\n", log_n, cols, (unsigned long long)digest_cols(a, n, cols, n));
      fill<<<1024, 256, 0, s>>>(a, n * cols, 17 * log_n + cols);
      rc("b2n-ret", stwo_ntt_b2n_columns_to_retained_on(a, n, b, 2 * n, log_n, cols, tw, uint32_t(n), uint32_t(n / 2), s, &launches));
      CK(cudaStreamSynchronize(s));
      std::printf("b2n-ret log=%u cols=%u %016llx\n", log_n, cols, (unsigned long long)digest_cols(b, 2 * n, cols, 2 * n));
    }
  }
  std::printf("DONE failures=%d\n", failures);
  return failures ? 1 : 0;
}
