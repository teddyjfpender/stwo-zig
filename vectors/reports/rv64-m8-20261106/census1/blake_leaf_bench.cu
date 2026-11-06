// census1 microbench: stwo_blake2s_mixed_leaf_on throughput (CUDA events). Not product code.
#include <cstdio>
#include <cstdint>
#include <cuda_runtime.h>
#include "mixed_layout.h"
namespace stwo::cuda::blake2s { struct Hash; }
extern "C" int stwo_blake2s_mixed_leaf_on(uint32_t size, uint32_t count, const stwo::cuda::blake2s::MixedSegment *segments, stwo::cuda::blake2s::Hash *result, void *stream);
int main(int argc, char** argv) {
  uint32_t log_rows = argc > 1 ? atoi(argv[1]) : 22, cols = argc > 2 ? atoi(argv[2]) : 32;
  uint32_t rows = 1u << log_rows;
  uint32_t *data; void *out;
  cudaMalloc(&data, size_t(rows) * cols * 4); cudaMalloc(&out, size_t(rows) * 32);
  cudaMemset(data, 1, size_t(rows) * cols * 4);
  stwo::cuda::blake2s::MixedSegment s{data, rows, size_t(rows) * cols, rows, 0};
  cudaEvent_t a, b; cudaEventCreate(&a); cudaEventCreate(&b); cudaStream_t st; cudaStreamCreate(&st);
  int rc = stwo_blake2s_mixed_leaf_on(rows, 1, &s, (stwo::cuda::blake2s::Hash*)out, st);
  cudaDeviceSynchronize();
  if (rc) { printf("rc=%d %s\n", rc, cudaGetErrorString(cudaGetLastError())); return 1; }
  const int reps = 10;
  cudaEventRecord(a, st);
  for (int i = 0; i < reps; ++i) stwo_blake2s_mixed_leaf_on(rows, 1, &s, (stwo::cuda::blake2s::Hash*)out, st);
  cudaEventRecord(b, st); cudaEventSynchronize(b);
  float ms; cudaEventElapsedTime(&ms, a, b); ms /= reps;
  double bytes = double(rows) * cols * 4, comps = double(rows) * ((cols + 15) / 16);
  printf("log_rows=%u cols=%u ms=%.3f input_GBps=%.1f Gcompress_per_s=%.2f\n", log_rows, cols, ms, bytes / ms / 1e6, comps / ms / 1e6);
  return 0;
}
