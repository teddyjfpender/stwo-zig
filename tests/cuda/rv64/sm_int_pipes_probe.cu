// Integer pipe throughput probe for sm_120 (RTX 5090): which SASS classes
// share an issue port. Each kernel runs 8 independent dependency chains per
// thread, so throughput (not latency) bounds it. CUDA-event timed.
// Operands come from an opaque kernel argument so ptxas cannot
// strength-reduce multiplies into shifts.
#include <cuda_runtime.h>
#include <cstdio>
#include <cstdint>
#define CU(x) do{auto e=(x);if(e!=cudaSuccess){std::printf("FAIL %s\n",cudaGetErrorString(e));return 1;}}while(0)
constexpr int ITER = 4096, CH = 8;
template <int MODE>
__global__ void probe(uint32_t* out, uint32_t k) {
  uint32_t v[CH];
#pragma unroll
  for (int c = 0; c < CH; ++c) v[c] = threadIdx.x * 7 + c;
#pragma unroll 4
  for (int i = 0; i < ITER; ++i) {
#pragma unroll
    for (int c = 0; c < CH; ++c) {
      uint32_t x = v[c];
      if (MODE == 0) { asm volatile("lop3.b32 %0, %0, %1, %2, 0x96;" : "+r"(x) : "r"(k), "r"(v[(c+1)%CH])); }       // ALU logic
      if (MODE == 1) { asm volatile("add.u32 %0, %0, %1;" : "+r"(x) : "r"(k)); }                                    // integer add
      if (MODE == 2) { asm volatile("mad.lo.u32 %0, %0, %1, %2;" : "+r"(x) : "r"(k), "r"(c)); }                      // IMAD
      if (MODE == 3) { asm volatile("shf.l.wrap.b32 %0, %0, %0, %1;" : "+r"(x) : "r"(k)); }                          // funnel shift
      if (MODE == 4) { asm volatile("mul.hi.u32 %0, %0, %1;" : "+r"(x) : "r"(k)); }                                  // IMAD.HI
      if (MODE == 5) { asm volatile("{.reg .u64 t; mul.wide.u32 t, %0, %1; cvt.u32.u64 %0, t;}" : "+r"(x) : "r"(k)); } // IMAD.WIDE
      if (MODE == 6) { asm volatile("lop3.b32 %0, %0, %1, %2, 0x96;" : "+r"(x) : "r"(k), "r"(c));                      // 1 ALU + 1 IMAD
                       asm volatile("mad.lo.u32 %0, %0, %1, %2;" : "+r"(x) : "r"(k), "r"(c)); }
      if (MODE == 7) { asm volatile("add.u32 %0, %0, %1;" : "+r"(x) : "r"(v[(c+3)%CH])); }                           // IADD3 (reg+reg)
      if (MODE == 8) { uint64_t w = (uint64_t(x) << 32) | v[(c+1)%CH];
                       asm volatile("add.u64 %0, %0, %1;" : "+l"(w) : "l"(uint64_t(k))); x = uint32_t(w) ^ uint32_t(w >> 32); } // IADD.64 (+lop)
      if (MODE == 9) { asm volatile("{.reg .u64 t; mul.wide.u32 t, %0, %1; xor.b64 t, t, %2; cvt.u32.u64 %0, t;}" : "+r"(x) : "r"(k), "l"(uint64_t(c))); } // wide used
      if (MODE == 10) { uint32_t y; asm volatile("shr.u32 %0, %1, 31;" : "=r"(y) : "r"(x)); asm volatile("add.u32 %0, %0, %1;" : "+r"(x) : "r"(y)); } // shr+add (LEA.HI?)
      if (MODE == 11) { asm volatile("{.reg .pred q; setp.lt.u32 q, %0, %1; selp.u32 %0, %0, %2, q;}" : "+r"(x) : "r"(k), "r"(v[(c+1)%CH])); } // ISETP+SEL
      v[c] = x;
    }
  }
  uint32_t r = 0;
#pragma unroll
  for (int c = 0; c < CH; ++c) r ^= v[c];
  out[blockIdx.x * blockDim.x + threadIdx.x] = r;
}
template <int MODE> int run(const char* name, uint32_t* out, int ops_per_step) {
  cudaEvent_t a, b; cudaEventCreate(&a); cudaEventCreate(&b);
  const int blocks = 170 * 12, threads = 128;
  probe<MODE><<<blocks, threads>>>(out, 0x9e3779b9u); CU(cudaDeviceSynchronize());
  cudaEventRecord(a); probe<MODE><<<blocks, threads>>>(out, 0x9e3779b9u); cudaEventRecord(b); CU(cudaEventSynchronize(b));
  float ms; cudaEventElapsedTime(&ms, a, b);
  const double thread_ops = double(blocks) * threads * ITER * CH * ops_per_step;
  std::printf("PIPE %-10s %.3f ms  %.2f T thread-inst/s\n", name, ms, thread_ops / ms / 1e9);
  return 0;
}
int main() {
  uint32_t* out; CU(cudaMalloc(&out, 170 * 12 * 128 * 4));
  int clk; cudaDeviceGetAttribute(&clk, cudaDevAttrClockRate, 0);
  std::printf("SM clock %d kHz\n", clk);
  run<0>("lop3", out, 1); run<1>("iadd", out, 1); run<2>("imad", out, 1); run<3>("shf", out, 1);
  run<7>("iadd3", out, 1); run<8>("iadd64+x", out, 2); run<9>("wide+x", out, 2); run<10>("shr+add", out, 2); run<11>("isetp+sel", out, 2);
  run<4>("imad.hi", out, 1); run<5>("imad.wide", out, 1); run<6>("lop3+imad", out, 2);
  return 0;
}
