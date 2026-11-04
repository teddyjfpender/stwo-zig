// Tensor-frontend CUDA prelude: one source, two compilers.
//
// Every kernel in this directory is written once against the macros below.
// Under nvcc (__CUDACC__) they expand to ordinary CUDA. Without nvcc
// (TC_EMU, the Mac/CI build used by `zig build test-cuda-emu`) the same
// kernel bodies compile as plain C++ and run on the CPU with the exact
// CUDA indexing: a launch runs its blocks one after another, and inside a
// block every "thread phase" (TC_THREADS ... TC_END_THREADS) loops over
// threadIdx.x = 0 .. blockDim.x - 1. A phase boundary is the block barrier
// (__syncthreads), so phase-structured kernels (shared-memory trees, the
// last-block reduction, in-block FFT layers) are emulated with their real
// data movement, not with a separate reference implementation.
//
// Rules for kernel authors (both compilers enforce them only by convention):
//  - state that crosses a TC_SYNC() lives in TC_SHARED arrays indexed by tid
//    (in CUDA a thread-private variable would also survive, in the emulation
//    it would not);
//  - no warp shuffles / warp-synchronous code (not emulated);
//  - device-wide ordering only via separate launches or the last-block
//    pattern (TC_FENCE + TC_ATOMIC_INC), which the emulation models exactly
//    because blocks run in order.
// The idea of compiling kernel bodies for the host is FlashProve's
// (prover/field/field_lazy.cuh: LAZY_HD is __host__ __device__ under nvcc,
// `inline` otherwise); the phase loop is ours.
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__CUDACC__)

#define TC_HD __host__ __device__ __forceinline__
#define TC_DEV __device__ __forceinline__
#define TC_GLOBAL __global__ void
#define TC_SHARED __shared__
#define TC_CONST __constant__
#define TC_SYNC() __syncthreads()
#define TC_THREADS {                                   \
    const uint32_t tid = threadIdx.x;                  \
    (void)tid;
#define TC_END_THREADS }
#define TC_BLOCK_ID ((uint32_t)blockIdx.x)
#define TC_NBLOCKS ((uint32_t)gridDim.x)
#define TC_BLOCK_DIM ((uint32_t)blockDim.x)
#define TC_FENCE() __threadfence()
#define TC_ATOMIC_INC(p) atomicAdd((unsigned int *)(p), 1u)
// Thread-private state that must survive a TC_SYNC(): registers in CUDA.
#define TC_PRIV(T, name, n) T name[n]
#define TC_P(name) name
#define TC_LAUNCH(kernel, grid, block, stream, ...)                     \
    do {                                                                \
        if ((grid) > 0) kernel<<<(grid), (block), 0, (stream)>>>(__VA_ARGS__); \
        tc_note_launch();                                               \
    } while (0)

#else  // CPU emulation

#define TC_EMU 1
#define TC_HD static inline
#define TC_DEV static inline
#define TC_GLOBAL static void
#define TC_SHARED
#define TC_CONST
#define TC_SYNC() ((void)0)

struct TcEmuDims {
    uint32_t block_id;
    uint32_t n_blocks;
    uint32_t block_dim;
};
inline thread_local TcEmuDims tc_emu_dims = {0, 1, 1};

#define TC_THREADS for (uint32_t tid = 0; tid < tc_emu_dims.block_dim; ++tid) {
#define TC_END_THREADS }
#define TC_BLOCK_ID (tc_emu_dims.block_id)
#define TC_NBLOCKS (tc_emu_dims.n_blocks)
#define TC_BLOCK_DIM (tc_emu_dims.block_dim)
#define TC_FENCE() ((void)0)
static inline uint32_t tc_emu_atomic_inc(uint32_t *p) { return (*p)++; }
#define TC_ATOMIC_INC(p) tc_emu_atomic_inc((uint32_t *)(p))
// Thread-private state that must survive a TC_SYNC(): one row per thread.
#define TC_PRIV(T, name, n) T name##_tc_[TC_TB][n]
#define TC_P(name) name##_tc_[tid]
#define TC_LAUNCH(kernel, grid, block, stream, ...)                     \
    do {                                                                \
        (void)(stream);                                                 \
        const uint32_t tc_g_ = (uint32_t)(grid);                        \
        tc_emu_dims.n_blocks = tc_g_;                                   \
        tc_emu_dims.block_dim = (uint32_t)(block);                      \
        for (uint32_t tc_b_ = 0; tc_b_ < tc_g_; ++tc_b_) {              \
            tc_emu_dims.block_id = tc_b_;                               \
            kernel(__VA_ARGS__);                                        \
        }                                                               \
        tc_note_launch();                                               \
    } while (0)

#endif

// Full unroll of constant-trip loops (keeps small arrays in registers).
#if defined(__CUDACC__)
#define TC_UNROLL _Pragma("unroll")
#else
#define TC_UNROLL
#endif

// 4-way signed int8 dot product with int32 accumulate: the sm_61+ __dp4a
// instruction under nvcc, its exact definition in the emulation
// (c + sum_k (int8)a[k] (int8)b[k] over the four bytes, two's complement).
#if defined(__CUDACC__)
#define TC_DP4A(a, b, c) __dp4a((int)(a), (int)(b), (int)(c))
#else
static inline int32_t tc_dp4a_emu(uint32_t a, uint32_t b, int32_t c) {
    int64_t s = c;
    for (int k = 0; k < 4; ++k) s += (int64_t)(int8_t)(a >> (8 * k)) * (int8_t)(b >> (8 * k));
    return (int32_t)s;
}
#define TC_DP4A(a, b, c) tc_dp4a_emu((uint32_t)(a), (uint32_t)(b), (int32_t)(c))
#endif

// Block size every reduction kernel is launched with (shared arrays are sized
// by it). 256 threads x 3 QM31 x 16 B = 12 KB of shared memory per block.
#define TC_TB 256u
