// census1 microbench: circle FFT entry throughput by log_n (CUDA events). Not product code.
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cuda_runtime.h>
extern "C" int stwo_ntt_n2b_columns_on(uint32_t*, size_t, uint32_t, uint32_t, const uint32_t*, uint32_t, uint32_t, void*, uint32_t*);
extern "C" int stwo_ntt_b2n_columns_compact_on(const uint32_t*, size_t, uint32_t*, size_t, uint32_t, uint32_t, const uint32_t*, uint32_t, uint32_t, void*, uint32_t*);
int main() {
  const size_t total = size_t(1) << 26;  // words per buffer (256 MB)
  uint32_t *a, *b, *tw; cudaMalloc(&a, total * 4); cudaMalloc(&b, total * 4); cudaMalloc(&tw, (size_t(1) << 23) * 4);
  cudaMemset(a, 3, total * 4); cudaMemset(tw, 5, (size_t(1) << 23) * 4);
  cudaStream_t st; cudaStreamCreate(&st); cudaEvent_t e0, e1; cudaEventCreate(&e0); cudaEventCreate(&e1);
  for (uint32_t log_n = 12; log_n <= 24; ++log_n) {
    const uint32_t n = 1u << log_n, cols = uint32_t(total >> log_n);
    for (int dir = 0; dir < 2; ++dir) {
      uint32_t launches = 0; int rc;
      auto run = [&]() {
        return dir == 0 ? stwo_ntt_n2b_columns_on(a, n, log_n, cols, tw, 1u << 23, n / 2, st, &launches)
                        : stwo_ntt_b2n_columns_compact_on(a, n, b, n, log_n, cols, tw, 1u << 23, n / 2, st, &launches);
      };
      rc = run(); cudaStreamSynchronize(st);
      if (rc) { printf("log_n=%u dir=%s rc=%d\n", log_n, dir ? "b2n" : "n2b", rc); continue; }
      const int reps = 5; cudaEventRecord(e0, st);
      for (int i = 0; i < reps; ++i) run();
      cudaEventRecord(e1, st); cudaEventSynchronize(e1);
      float ms; cudaEventElapsedTime(&ms, e0, e1); ms /= reps;
      printf("%s log_n=%u cols=%u launches=%u ms=%.3f one_pass_equiv_GBps=%.0f\n", dir ? "b2n" : "n2b", log_n, cols, launches, ms, 2.0 * total * 4 / ms / 1e6);
    }
  }
  return 0;
}
