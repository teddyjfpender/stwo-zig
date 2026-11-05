// Self-test for the counter shim: static cudart, known call counts.
#include <cstdio>
#include <cstdlib>
#include <cuda_runtime.h>
__global__ void k(int *p) { p[threadIdx.x] += 1; }
int main() {
  int *d; cudaMalloc(&d, 1024);
  int *pageable = (int *)malloc(1024); int *pinned; cudaMallocHost(&pinned, 1024);
  cudaStream_t s; cudaStreamCreate(&s);
  for (int i = 0; i < 3; i++) cudaMemcpyAsync(d, pageable, 1024, cudaMemcpyHostToDevice, s);
  for (int i = 0; i < 2; i++) cudaMemcpyAsync(d, pinned, 1024, cudaMemcpyHostToDevice, s);
  for (int i = 0; i < 5; i++) k<<<1, 32, 0, s>>>(d);
  for (int i = 0; i < 4; i++) cudaStreamSynchronize(s);
  cudaMemPool_t pool; cudaDeviceGetDefaultMemPool(&pool, 0);
  void *q; cudaMallocFromPoolAsync(&q, 4096, pool, s); cudaFreeAsync(q, s); cudaStreamSynchronize(s);
  printf("selftest done err=%d\n", (int)cudaGetLastError());
  return 0;
}
