#pragma once
#include <cuda_runtime_api.h>
#include <stddef.h>
#include <stdint.h>
extern "C" cudaError_t stwo_parent_readonly_temp_bytes_v1(uint32_t entries, size_t *bytes);
// input_rows/output_rows are immutable logical row indices compiled from the
// original fixed roster, not values or a CPU-generated sorting permutation.
extern "C" cudaError_t stwo_parent_readonly_gather_v1(
    const uint32_t *input_rows, uint32_t entries, const uint32_t *input_main,
    uint32_t input_log, uint32_t *keys, uint32_t *values, uint32_t *status,
    cudaStream_t stream);
extern "C" cudaError_t stwo_parent_readonly_sort_v1(
    void *temporary, size_t temporary_bytes, const uint32_t *keys_in,
    uint32_t *keys_out, const uint32_t *values_in, uint32_t *values_out,
    uint32_t entries, cudaStream_t stream);
extern "C" cudaError_t stwo_parent_readonly_arguments_v1(
    const uint32_t *output_rows, uint32_t entries, const uint32_t *sorted_keys,
    const uint32_t *sorted_values, uint32_t *arguments, uint32_t argument_rows,
    uint32_t *status, cudaStream_t stream);
