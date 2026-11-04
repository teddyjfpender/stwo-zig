// Minimal stand-in for the CUDA runtime header: just enough declarations for
// a clang -x cuda syntax check of tc_host.cu on a machine without the toolkit.
#pragma once
#include <stddef.h>
#include <stdint.h>
#define __host__ __attribute__((host))
#define __device__ __attribute__((device))
#define __global__ __attribute__((global))
#define __shared__ __attribute__((shared))
#define __constant__ __attribute__((constant))
#define __forceinline__ __inline__ __attribute__((always_inline))
#include <__clang_cuda_builtin_vars.h>
struct dim3 { unsigned x, y, z; __host__ __device__ dim3(unsigned a = 1, unsigned b = 1, unsigned c = 1) : x(a), y(b), z(c) {} };
typedef struct CUstream_st *cudaStream_t;
typedef struct CUmemPoolHandle_st *cudaMemPool_t;
typedef int cudaError_t;
enum { cudaSuccess = 0 };
enum cudaMemcpyKind { cudaMemcpyHostToDevice = 1, cudaMemcpyDeviceToHost = 2 };
enum { cudaStreamNonBlocking = 1, cudaHostAllocMapped = 2, cudaMemAttachGlobal = 1, cudaMemAttachHost = 2 };
enum cudaMemPoolAttr { cudaMemPoolAttrReleaseThreshold = 4 };
struct cudaDeviceProp { char name[256]; size_t totalGlobalMem; int major, minor; };
extern "C" {
cudaError_t cudaMallocAsync(void **, size_t, cudaStream_t);
cudaError_t cudaFreeAsync(void *, cudaStream_t);
cudaError_t cudaMalloc(void **, size_t);
cudaError_t cudaFree(void *);
cudaError_t cudaMallocManaged(void **, size_t, unsigned);
cudaError_t cudaMemset(void *, int, size_t);
cudaError_t cudaMemcpyAsync(void *, const void *, size_t, cudaMemcpyKind, cudaStream_t);
cudaError_t cudaStreamSynchronize(cudaStream_t);
cudaError_t cudaStreamAttachMemAsync(cudaStream_t, void *, size_t, unsigned);
cudaError_t cudaStreamCreateWithFlags(cudaStream_t *, unsigned);
cudaError_t cudaStreamDestroy(cudaStream_t);
cudaError_t cudaSetDevice(int);
cudaError_t cudaGetDeviceProperties(cudaDeviceProp *, int);
cudaError_t cudaDeviceGetDefaultMemPool(cudaMemPool_t *, int);
cudaError_t cudaMemPoolSetAttribute(cudaMemPool_t, cudaMemPoolAttr, void *);
cudaError_t cudaHostAlloc(void **, size_t, unsigned);
cudaError_t cudaHostGetDevicePointer(void **, void *, unsigned);
cudaError_t cudaFreeHost(void *);
cudaError_t cudaGetLastError(void);
const char *cudaGetErrorString(cudaError_t);
cudaError_t cudaConfigureCall(dim3, dim3, size_t = 0, cudaStream_t = 0);
cudaError_t cudaSetupArgument(const void *, size_t, size_t);
cudaError_t cudaLaunch(const void *);
unsigned __cudaPushCallConfiguration(dim3, dim3, size_t, void *);
cudaError_t cudaLaunchKernel(const void *, dim3, dim3, void **, size_t, cudaStream_t);
}
// __syncthreads is a clang builtin in CUDA mode
__device__ inline void __threadfence(void) { __nvvm_membar_gl(); }
__device__ inline unsigned atomicAdd(unsigned *p, unsigned v) { return (unsigned)__nvvm_atom_add_gen_i((int *)p, (int)v); }
// sm_61+ 4-way int8 dot product with int32 accumulate (the toolkit's
// sm_61_intrinsics.hpp lowers it to the same PTX instruction)
__device__ inline int __dp4a(int a, int b, int c) {
    int d;
    asm("dp4a.s32.s32 %0, %1, %2, %3;" : "=r"(d) : "r"(a), "r"(b), "r"(c));
    return d;
}
