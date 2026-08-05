#ifndef STWO_ZIG_CUMETAL_CUDA_COMPAT_CUH
#define STWO_ZIG_CUMETAL_CUDA_COMPAT_CUH

// Source compatibility for CUDA constructs that CuMetal intentionally does
// not expose yet.  This header is force-included only by the CuMetal builder;
// the authenticated upstream source projection therefore stays byte-exact.
#if !defined(STWO_CUMETAL)
#error "the CuMetal compatibility header requires STWO_CUMETAL"
#endif

#include <cuda_runtime.h>
#include <cstdio>

static __host__ __device__ __forceinline__ unsigned int
stwo_cumetal_funnelshift_r(
    unsigned int low,
    unsigned int high,
    unsigned int shift) {
    shift &= 31u;
    if (shift == 0u) return low;
    const unsigned int inverse = 32u - shift;
#if defined(__CUDA_ARCH__) && !defined(STWO_CUMETAL_TYPED)
    unsigned int right;
    unsigned int left;
    asm("shr.b32 %0, %1, %2;" : "=r"(right) : "r"(low), "r"(shift));
    asm("shl.b32 %0, %1, %2;" : "=r"(left) : "r"(high), "r"(inverse));
    return right | left;
#else
    return (low >> shift) | (high << inverse);
#endif
}

static __host__ __device__ __forceinline__ unsigned int
stwo_cumetal_funnelshift_rc(
    unsigned int low,
    unsigned int high,
    unsigned int shift) {
    if (shift >= 32u) return high;
    return stwo_cumetal_funnelshift_r(low, high, shift);
}

// A one-lane equivalence class is the conservative semantic fallback for
// match-any: it preserves every exact atomic increment while foregoing only
// the NVIDIA warp aggregation optimization.
static __host__ __device__ __forceinline__ unsigned int
stwo_cumetal_match_any(
    unsigned int active_mask,
    unsigned long long value) {
    (void)active_mask;
    (void)value;
#if defined(__CUDA_ARCH__) && !defined(STWO_CUMETAL_TYPED)
    return 1u << (threadIdx.x & 31u);
#else
    return 1u;
#endif
}

static __host__ __device__ __forceinline__ unsigned int
stwo_cumetal_swap_adjacent_bits(
    unsigned int value,
    unsigned int mask,
    unsigned int shift) {
#if defined(__CUDA_ARCH__) && !defined(STWO_CUMETAL_TYPED)
    unsigned int low;
    unsigned int high;
    unsigned int shifted_low;
    unsigned int shifted_high;
    asm("and.b32 %0, %1, %2;" : "=r"(low) : "r"(value), "r"(mask));
    asm("shr.b32 %0, %1, %2;" : "=r"(high) : "r"(value), "r"(shift));
    asm("and.b32 %0, %1, %2;" : "=r"(high) : "r"(high), "r"(mask));
    asm("shl.b32 %0, %1, %2;" : "=r"(shifted_low) : "r"(low), "r"(shift));
    shifted_high = high;
    return shifted_low | shifted_high;
#else
    return ((value & mask) << shift) | ((value >> shift) & mask);
#endif
}

static __host__ __device__ __forceinline__ unsigned int
stwo_cumetal_bit_reverse(unsigned int value) {
    value = stwo_cumetal_swap_adjacent_bits(value, 0x55555555u, 1u);
    value = stwo_cumetal_swap_adjacent_bits(value, 0x33333333u, 2u);
    value = stwo_cumetal_swap_adjacent_bits(value, 0x0f0f0f0fu, 4u);
    value = stwo_cumetal_swap_adjacent_bits(value, 0x00ff00ffu, 8u);
#if defined(__CUDA_ARCH__) && !defined(STWO_CUMETAL_TYPED)
    unsigned int low;
    unsigned int high;
    asm("shl.b32 %0, %1, 16;" : "=r"(low) : "r"(value));
    asm("shr.b32 %0, %1, 16;" : "=r"(high) : "r"(value));
    return low | high;
#else
    return (value << 16) | (value >> 16);
#endif
}

#define __funnelshift_r(low, high, shift) \
    stwo_cumetal_funnelshift_r((low), (high), (shift))
#define __funnelshift_rc(low, high, shift) \
    stwo_cumetal_funnelshift_rc((low), (high), (shift))
#define __match_any_sync(mask, value) stwo_cumetal_match_any((mask), (value))
#define __brev(value) stwo_cumetal_bit_reverse((value))

#if !defined(unlikely)
#define unlikely(value) __builtin_expect(!!(value), 0)
#endif

#endif
