// Product-owned Native wide-Fibonacci trace construction. The caller owns the
// device slab and stream; this unit allocates, copies, and synchronizes nothing.

#include <stddef.h>
#include <stdint.h>

#if !defined(STWO_CUDA_HOST_TEST)
#include <cuda_runtime_api.h>
#endif

#define STWO_M31_P 2147483647u
#define STWO_WIDE_FIBONACCI_MAX_COLUMNS 512u

__device__ __forceinline__ uint32_t stwo_trace_m31_add(
    uint32_t lhs,
    uint32_t rhs) {
    const uint32_t sum = lhs + rhs;
    return sum >= STWO_M31_P ? sum - STWO_M31_P : sum;
}

__device__ __forceinline__ uint32_t stwo_trace_m31_mul(
    uint32_t lhs,
    uint32_t rhs) {
    const uint64_t product = (uint64_t)lhs * (uint64_t)rhs;
    const uint64_t reduced =
        (((((product >> 31) + product + 1u) >> 31) + product) &
         (uint64_t)STWO_M31_P);
    return (uint32_t)reduced;
}

__device__ __forceinline__ uint32_t stwo_trace_reverse_bits(uint32_t value) {
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

__device__ __forceinline__ uint32_t stwo_trace_logical_row(
    uint32_t storage_index,
    uint32_t row_count,
    uint32_t log_n_rows) {
    const uint32_t circle_index =
        stwo_trace_reverse_bits(storage_index) >> (32u - log_n_rows);
    const uint32_t half = row_count >> 1;
    return circle_index < half
        ? circle_index << 1
        : ((row_count - 1u - circle_index) << 1) + 1u;
}

extern "C" __global__ void __launch_bounds__(256)
stwo_native_wide_fibonacci_trace_kernel(
    uint32_t *trace,
    size_t column_stride_words,
    uint32_t row_count,
    uint32_t sequence_len,
    uint32_t log_n_rows) {
    const uint32_t storage_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (storage_index >= row_count) return;

    uint32_t previous = 1u;
    uint32_t current = stwo_trace_logical_row(
        storage_index,
        row_count,
        log_n_rows);
    trace[storage_index] = previous;
    trace[column_stride_words + storage_index] = current;

    for (uint32_t column = 2u; column < sequence_len; ++column) {
        const uint32_t next = stwo_trace_m31_add(
            stwo_trace_m31_mul(previous, previous),
            stwo_trace_m31_mul(current, current));
        trace[(size_t)column * column_stride_words + storage_index] = next;
        previous = current;
        current = next;
    }
}

#if !defined(STWO_CUDA_HOST_TEST)
extern "C" int stwo_native_wide_fibonacci_trace_on(
    uint32_t *trace,
    size_t column_stride_words,
    size_t trace_capacity_words,
    uint32_t row_count,
    uint32_t log_n_rows,
    void *stream) {
    if (trace == nullptr || stream == nullptr || log_n_rows == 0u ||
        log_n_rows >= 31u || row_count != (1u << log_n_rows) ||
        column_stride_words < (size_t)row_count ||
        column_stride_words == 0u || trace_capacity_words == 0u ||
        trace_capacity_words % column_stride_words != 0u) {
        return 1;
    }
    const size_t sequence_len_size =
        trace_capacity_words / column_stride_words;
    if (sequence_len_size < 2u ||
        sequence_len_size > STWO_WIDE_FIBONACCI_MAX_COLUMNS ||
        column_stride_words > SIZE_MAX / sequence_len_size ||
        column_stride_words * sequence_len_size != trace_capacity_words) {
        return 1;
    }
    const uint32_t sequence_len = (uint32_t)sequence_len_size;

    constexpr uint32_t kThreads = 256u;
    const uint32_t blocks = (row_count + kThreads - 1u) / kThreads;
    stwo_native_wide_fibonacci_trace_kernel<<<
        blocks,
        kThreads,
        0,
        (cudaStream_t)stream>>>(
        trace,
        column_stride_words,
        row_count,
        sequence_len,
        log_n_rows);
    return (int)cudaPeekAtLastError();
}
#endif
