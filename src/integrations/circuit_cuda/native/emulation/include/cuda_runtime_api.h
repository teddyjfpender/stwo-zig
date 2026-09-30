// Host emulation shim for `circuit_grind.cu` (`STWO_CIRCUIT_GRIND_HOST_EMULATION`).
// The kernel's device functions (the Blake2s candidate hash of
// `backends/cuda/native/pow/candidate.cuh`, the M31 reduction and the
// residue-class scan) compile as ordinary host C++ so the package tests can
// run the device search's own code on a host without a GPU. The atomics are
// single-threaded: the emulation runs the residue classes one after another.
#ifndef STWO_CIRCUIT_CUDA_EMULATION_RUNTIME_API_H
#define STWO_CIRCUIT_CUDA_EMULATION_RUNTIME_API_H

#if !defined(STWO_CIRCUIT_GRIND_HOST_EMULATION) && !defined(STWO_CIRCUIT_BASE_HOST_EMULATION) && !defined(STWO_CIRCUIT_INTERACTION_HOST_EMULATION) && !defined(STWO_CIRCUIT_LOOKUP_SUM_HOST_EMULATION)
#error "the emulation shim requires circuit CUDA host emulation"
#endif

#include <stdint.h>

#define __global__
#define __device__
#define __host__
#define __shared__
#define __constant__ const
#define __forceinline__ inline __attribute__((always_inline))

static inline int __ffs(int value) { return __builtin_ffs(value); }

static inline unsigned long long atomicAdd(unsigned long long *address, unsigned long long value) {
    const unsigned long long old = *address;
    *address = old + value;
    return old;
}

static inline unsigned long long atomicMin(unsigned long long *address, unsigned long long value) {
    const unsigned long long old = *address;
    if (value < old) *address = value;
    return old;
}

static inline unsigned atomicAdd(unsigned *address, unsigned value) {
    const unsigned old = *address;
    *address = old + value;
    return old;
}

static inline unsigned atomicOr(unsigned *address, unsigned value) {
    const unsigned old = *address;
    *address = old | value;
    return old;
}

#endif
