// Product-owned Native XOR trace construction. The caller owns both resident
// slabs and the proof stream; this unit allocates, copies, and synchronizes
// nothing.

#include <stddef.h>
#include <stdint.h>

#if !defined(STWO_CUDA_HOST_TEST)
#include <cuda_runtime_api.h>
#endif

__device__ __forceinline__ uint32_t stwo_xor_trace_reverse_bits(
    uint32_t value) {
#if defined(STWO_CUDA_HOST_TEST)
    value = ((value & 0x55555555u) << 1) | ((value >> 1) & 0x55555555u);
    value = ((value & 0x33333333u) << 2) | ((value >> 2) & 0x33333333u);
    value = ((value & 0x0f0f0f0fu) << 4) | ((value >> 4) & 0x0f0f0f0fu);
    value = ((value & 0x00ff00ffu) << 8) | ((value >> 8) & 0x00ff00ffu);
    return (value << 16) | (value >> 16);
#else
    return __brev(value);
#endif
}

__device__ __forceinline__ uint32_t stwo_xor_trace_logical_row(
    uint32_t storage_index,
    uint32_t row_count,
    uint32_t log_n_rows) {
    const uint32_t circle_index =
        stwo_xor_trace_reverse_bits(storage_index) >> (32u - log_n_rows);
    const uint32_t half = row_count >> 1;
    return circle_index < half
        ? circle_index << 1
        : ((row_count - 1u - circle_index) << 1) + 1u;
}

extern "C" __global__ void __launch_bounds__(256)
stwo_native_xor_trace_kernel(
    uint32_t *preprocessed,
    size_t preprocessed_stride_words,
    uint32_t *main_trace,
    size_t main_stride_words,
    uint32_t row_count,
    uint32_t log_n_rows,
    uint32_t log_step,
    uint64_t offset) {
    const uint32_t storage_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (storage_index >= row_count) return;

    const uint32_t logical_row = stwo_xor_trace_logical_row(
        storage_index,
        row_count,
        log_n_rows);
    const uint32_t step = 1u << log_step;
    const uint32_t normalized_offset = (uint32_t)(offset % (uint64_t)step);

    preprocessed[storage_index] = storage_index == 0u ? 1u : 0u;
    preprocessed[preprocessed_stride_words + storage_index] =
        logical_row % step == normalized_offset ? 1u : 0u;
    main_trace[storage_index] = (logical_row & 1u) == 0u ? 1u : 0u;

    // The main slab is an independent tree and may have a different padded
    // stride. Naming it in the ABI makes that ownership contract explicit.
    (void)main_stride_words;
}

#if !defined(STWO_CUDA_HOST_TEST)
extern "C" int stwo_native_xor_trace_on(
    uint32_t *preprocessed,
    size_t preprocessed_stride_words,
    size_t preprocessed_capacity_words,
    uint32_t *main_trace,
    size_t main_stride_words,
    size_t main_capacity_words,
    uint32_t row_count,
    uint32_t log_n_rows,
    uint32_t log_step,
    uint64_t offset,
    void *stream) {
    if (preprocessed == nullptr || main_trace == nullptr ||
        preprocessed == main_trace || stream == nullptr ||
        log_n_rows == 0u || log_n_rows >= 31u ||
        row_count != (1u << log_n_rows) || log_step > log_n_rows ||
        preprocessed_stride_words < (size_t)row_count ||
        main_stride_words < (size_t)row_count ||
        preprocessed_stride_words > SIZE_MAX / 2u ||
        preprocessed_capacity_words != preprocessed_stride_words * 2u ||
        main_capacity_words != main_stride_words) {
        return 1;
    }

    constexpr uint32_t kThreads = 256u;
    const uint32_t blocks = (row_count + kThreads - 1u) / kThreads;
    stwo_native_xor_trace_kernel<<<
        blocks,
        kThreads,
        0,
        (cudaStream_t)stream>>>(
        preprocessed,
        preprocessed_stride_words,
        main_trace,
        main_stride_words,
        row_count,
        log_n_rows,
        log_step,
        offset);
    return (int)cudaPeekAtLastError();
}
#endif
