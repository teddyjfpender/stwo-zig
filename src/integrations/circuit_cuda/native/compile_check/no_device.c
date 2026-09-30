/* A no-device stand-in for `circuit_grind.cu`'s host entry points, for
 * hosts without a CUDA toolkit: it lets the device tests, the device rungs
 * and the bench link (`circuit-cuda-compile-check`), and lets `test` check
 * that the provers fail closed. Every call reports `cudaErrorNoDevice` the
 * way the CUDA runtime does on a machine with no NVIDIA GPU. Never part of a
 * GPU build. */
#include <stdint.h>

enum { cuda_error_no_device = 100 };

int stwo_circuit_cuda_device_count(int *count) {
    if (count != 0) *count = 0;
    return cuda_error_no_device;
}

int stwo_circuit_cuda_blake2s_grind(
    const uint32_t *prefix,
    uint32_t pow_bits,
    uint32_t m31_output,
    unsigned long long search_end,
    unsigned long long *nonce_out) {
    (void)prefix;
    (void)pow_bits;
    (void)m31_output;
    (void)search_end;
    if (nonce_out != 0) *nonce_out = ~0ull;
    return cuda_error_no_device;
}
