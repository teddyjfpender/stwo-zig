#ifndef PREFIX_SUM
#define PREFIX_SUM

#include <cstddef>
#include <cuda_runtime.h>

#include "fields.cuh"

__global__ void circle_domain_order_to_coset_order_kernel(const m31* in, m31* out, int n);

__global__ void coset_order_to_circle_domain_order_kernel(const m31* d_in, m31* d_out, int n);

extern "C"
void inclusive_prefix_sum(m31 *device_bit_rev_circle_domain_evals, unsigned len);

size_t inclusive_prefix_sum_temp_bytes(unsigned len);

cudaError_t inclusive_prefix_sum_prepared_on(
    cudaStream_t stream,
    m31 *device_bit_rev_circle_domain_evals,
    m31 *eval_tmp,
    void *temp_storage,
    size_t temp_storage_bytes,
    unsigned len);

extern "C" size_t stwo_relation_scan_temp_bytes(unsigned len);

#endif
