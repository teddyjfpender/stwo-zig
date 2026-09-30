// Compile-check shim for hosts without a CUDA toolkit (circuit_cuda
// `circuit-cuda-compile-check`). It declares only the CUDA runtime surface
// `circuit_grind.cu` and the headers it includes use, so an NVPTX-capable
// Clang can type-check the host code and lower the kernels to PTX. It is
// never linked: GPU builds use the toolkit's own headers through nvcc.
#ifndef STWO_CIRCUIT_CUDA_COMPILE_CHECK_RUNTIME_API_H
#define STWO_CIRCUIT_CUDA_COMPILE_CHECK_RUNTIME_API_H

#include <stddef.h>
#include <stdint.h>

#define __global__ __attribute__((global))
#define __device__ __attribute__((device))
#define __host__ __attribute__((host))
#define __shared__ __attribute__((shared))
#define __constant__ __attribute__((constant))
#define __forceinline__ __inline__ __attribute__((always_inline))
#define __launch_bounds__(...) __attribute__((launch_bounds(__VA_ARGS__)))

#include <__clang_cuda_builtin_vars.h>

struct dim3 {
    unsigned x, y, z;
    __host__ __device__ constexpr dim3(unsigned vx = 1, unsigned vy = 1, unsigned vz = 1)
        : x(vx), y(vy), z(vz) {}
};

typedef enum cudaError {
    cudaSuccess = 0,
    cudaErrorInvalidValue = 1,
    cudaErrorUnknown = 999,
} cudaError_t;
typedef struct CUstream_st *cudaStream_t;
enum cudaMemcpyKind {
    cudaMemcpyHostToDevice = 1,
    cudaMemcpyDeviceToHost = 2,
};
#define cudaStreamNonBlocking 0x01

extern "C" {
unsigned __cudaPushCallConfiguration(dim3 grid, dim3 block, size_t shared = 0, void *stream = 0);
// Clang without a toolkit version lowers `<<<...>>>` to the legacy launch API.
cudaError_t cudaConfigureCall(dim3 grid, dim3 block, size_t shared = 0, cudaStream_t stream = 0);
cudaError_t cudaSetupArgument(const void *argument, size_t size, size_t offset);
cudaError_t cudaLaunch(const void *function);
cudaError_t cudaGetDeviceCount(int *count);
cudaError_t cudaPeekAtLastError(void);
cudaError_t cudaStreamCreateWithFlags(cudaStream_t *stream, unsigned flags);
cudaError_t cudaStreamDestroy(cudaStream_t stream);
cudaError_t cudaStreamSynchronize(cudaStream_t stream);
cudaError_t cudaMalloc(void **pointer, size_t bytes);
cudaError_t cudaFree(void *pointer);
cudaError_t cudaMemcpyAsync(void *destination, const void *source, size_t bytes,
                            enum cudaMemcpyKind kind, cudaStream_t stream);
cudaError_t cudaLaunchKernel(const void *function, dim3 grid, dim3 block, void **args,
                             size_t shared, cudaStream_t stream);
cudaError_t __cudaPopCallConfiguration(dim3 *grid, dim3 *block, size_t *shared, void *stream);
}

// Device intrinsics, lowered with Clang's NVPTX builtins.
__device__ __forceinline__ int __ffs(int value) { return __builtin_ffs(value); }
__device__ __forceinline__ unsigned long long atomicAdd(unsigned long long *address,
                                                        unsigned long long value) {
    return __nvvm_atom_add_gen_ll(reinterpret_cast<long long *>(address),
                                  static_cast<long long>(value));
}
__device__ __forceinline__ unsigned long long atomicMin(unsigned long long *address,
                                                        unsigned long long value) {
    return __nvvm_atom_min_gen_ull(address, value);
}

#endif
