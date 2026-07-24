// CUDA kernels for generating preprocessed columns directly on GPU
// This avoids CPU->GPU transfer for deterministic columns:
// - Seq: Sequential numbers [0..2^n]
// - RangeCheck: Partitioned enumeration for range checks
// - BitwiseXor: XOR lookup tables

#include "fields.cuh"
#include "utils.cuh"
#include "timer.cuh"
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace {

constexpr uint32_t PREPROCESSED_BLOCK_SIZE = 256;

template <typename T>
cudaError_t allocate_from_default_pool_checked(size_t count, T** output) {
    if (output == nullptr || count == 0 || count > SIZE_MAX / sizeof(T)) {
        return cudaErrorInvalidValue;
    }
    return cuda_default_pool_alloc_checked(
        sizeof(T) * count, reinterpret_cast<void**>(output));
}

template <typename T>
cudaError_t clone_to_device_checked(const T* host, uint32_t count, T** output) {
    if (host == nullptr || output == nullptr || count == 0) {
        return cudaErrorInvalidValue;
    }
    T* device = nullptr;
    cudaError_t status = allocate_from_default_pool_checked(count, &device);
    if (status != cudaSuccess) {
        return status;
    }
    status = cuda_default_pool_copy_h2d_checked(
        host, device, sizeof(T) * static_cast<size_t>(count));
    if (status != cudaSuccess) {
        // Preserve the copy failure as the primary diagnosis; checked free is
        // best-effort rollback when the CUDA context is already unhealthy.
        cuda_default_pool_free_checked(device);
        return status;
    }
    *output = device;
    return cudaSuccess;
}

template <typename T>
cudaError_t release_scratch(T* ptr) {
    return ptr == nullptr ? cudaSuccess : cuda_default_pool_free_checked(ptr);
}

uint32_t block_count(uint32_t elements) {
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(elements) + PREPROCESSED_BLOCK_SIZE - 1) /
        PREPROCESSED_BLOCK_SIZE);
}

}  // namespace

extern "C" cudaError_t stwo_preprocessed_alloc_u32_checked(
    size_t count,
    uint32_t** output
) {
    if (output == nullptr || count == 0 || count > SIZE_MAX / sizeof(uint32_t)) {
        return cudaErrorInvalidValue;
    }
    return allocate_from_default_pool_checked(count, output);
}

extern "C" cudaError_t stwo_preprocessed_copy_h2d_checked(
    const uint32_t* host,
    uint32_t* device,
    size_t count
) {
    if (host == nullptr || device == nullptr || count == 0 ||
        count > SIZE_MAX / sizeof(uint32_t)) {
        return cudaErrorInvalidValue;
    }
    return cuda_default_pool_copy_h2d_checked(
        host, device, count * sizeof(uint32_t));
}

extern "C" cudaError_t stwo_preprocessed_stream_sync_checked() {
    return cuda_default_pool_stream_sync_checked();
}

// ============================================================================
// Seq Column Generation
// ============================================================================
// Generates column with values [0, 1, 2, ..., 2^log_size - 1]

__global__ void gen_seq_column_kernel(
    m31* output,
    uint32_t n_elements
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_elements) return;

    output[idx] = {idx};
}

extern "C" cudaError_t stwo_preprocessed_gen_seq_checked(
    m31* output,
    uint32_t log_size
) {
    if (output == nullptr || log_size >= 32) {
        return cudaErrorInvalidValue;
    }
    uint32_t n_elements = 1u << log_size;
    uint32_t num_blocks = block_count(n_elements);

    gen_seq_column_kernel<<<num_blocks, PREPROCESSED_BLOCK_SIZE>>>(output, n_elements);
    return cudaGetLastError();
}

extern "C" void gen_seq_column_on_gpu(m31* output, uint32_t log_size) {
    ASSERT_CUDA_SUCCESS(stwo_preprocessed_gen_seq_checked(output, log_size));
}

// ============================================================================
// RangeCheck Column Generation
// ============================================================================
// Generates partitioned enumeration for range check columns
// Example: bits_per_segment = [4, 3] generates:
//   column 0: [0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,...]  (4-bit values)
//   column 1: [0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,...]  (3-bit values)

__global__ void gen_range_check_columns_kernel(
    m31** output_columns,
    uint32_t n_columns,
    const uint32_t* bits_per_segment,
    uint32_t n_segments,
    uint32_t n_elements
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_elements) return;

    // Partition idx into segments
    uint32_t value = idx;
    for (int seg = n_segments - 1; seg >= 0; seg--) {
        uint32_t bits = bits_per_segment[seg];
        uint32_t mask = (1u << bits) - 1;
        uint32_t segment_value = value & mask;
        output_columns[seg][idx] = {segment_value};
        value >>= bits;
    }
}

extern "C" cudaError_t stwo_preprocessed_gen_range_checked(
    m31** output_columns,
    uint32_t n_columns,
    const uint32_t* bits_per_segment,
    uint32_t n_segments
) {
    if (output_columns == nullptr || bits_per_segment == nullptr || n_columns == 0 ||
        n_columns != n_segments || n_segments > static_cast<uint32_t>(INT_MAX)) {
        return cudaErrorInvalidValue;
    }

    uint32_t total_bits = 0;
    for (uint32_t i = 0; i < n_segments; i++) {
        if (output_columns[i] == nullptr || bits_per_segment[i] >= 32 ||
            total_bits >= 32 - bits_per_segment[i]) {
            return cudaErrorInvalidValue;
        }
        total_bits += bits_per_segment[i];
    }
    uint32_t n_elements = 1u << total_bits;
    uint32_t num_blocks = block_count(n_elements);

    uint32_t* d_bits_per_segment = nullptr;
    cudaError_t status = clone_to_device_checked(
        bits_per_segment, n_segments, &d_bits_per_segment);
    if (status != cudaSuccess) {
        return status;
    }

    m31** d_columns = nullptr;
    status = clone_to_device_checked(output_columns, n_columns, &d_columns);
    if (status != cudaSuccess) {
        // Keep the allocation failure as the primary diagnosis. The rollback
        // free is best effort when that failure may already reflect a damaged
        // context; the caller's checked fence drains any successful free.
        (void)release_scratch(d_bits_per_segment);
        return status;
    }

    gen_range_check_columns_kernel<<<num_blocks, PREPROCESSED_BLOCK_SIZE>>>(
        d_columns, n_columns, d_bits_per_segment, n_segments, n_elements
    );
    status = cudaGetLastError();

    cudaError_t bits_cleanup = release_scratch(d_bits_per_segment);
    cudaError_t columns_cleanup = release_scratch(d_columns);
    if (status == cudaSuccess) {
        status = bits_cleanup != cudaSuccess ? bits_cleanup : columns_cleanup;
    }
    return status;
}

extern "C" void gen_range_check_columns_on_gpu(
    m31** output_columns,
    uint32_t n_columns,
    const uint32_t* bits_per_segment,
    uint32_t n_segments
) {
    ASSERT_CUDA_SUCCESS(stwo_preprocessed_gen_range_checked(
        output_columns, n_columns, bits_per_segment, n_segments));
}

// ============================================================================
// BitwiseXor Column Generation
// ============================================================================
// Generates XOR lookup table with 3 columns:
// - Column 0: a values (0 to 2^n_bits - 1, each repeated 2^n_bits times)
// - Column 1: b values (0 to 2^n_bits - 1, cycling)
// - Column 2: a ^ b

__global__ void gen_bitwise_xor_columns_kernel(
    m31** output_columns,
    uint32_t n_bits,
    uint32_t n_elements
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_elements) return;

    uint32_t elements_per_a = 1u << n_bits;
    uint32_t a = idx / elements_per_a;
    uint32_t b = idx % elements_per_a;

    output_columns[0][idx] = {a};
    output_columns[1][idx] = {b};
    output_columns[2][idx] = {a ^ b};
}

extern "C" cudaError_t stwo_preprocessed_gen_xor_checked(
    m31** output_columns,
    uint32_t n_bits
) {
    if (output_columns == nullptr || n_bits >= 16 || output_columns[0] == nullptr ||
        output_columns[1] == nullptr || output_columns[2] == nullptr) {
        return cudaErrorInvalidValue;
    }

    uint32_t n_elements = 1u << (2 * n_bits);
    uint32_t num_blocks = block_count(n_elements);

    m31** d_columns = nullptr;
    cudaError_t status = clone_to_device_checked(output_columns, 3, &d_columns);
    if (status != cudaSuccess) {
        return status;
    }

    gen_bitwise_xor_columns_kernel<<<num_blocks, PREPROCESSED_BLOCK_SIZE>>>(
        d_columns, n_bits, n_elements
    );
    status = cudaGetLastError();

    cudaError_t cleanup = release_scratch(d_columns);
    if (status == cudaSuccess) {
        status = cleanup;
    }
    return status;
}

extern "C" void gen_bitwise_xor_columns_on_gpu(m31** output_columns, uint32_t n_bits) {
    ASSERT_CUDA_SUCCESS(stwo_preprocessed_gen_xor_checked(output_columns, n_bits));
}

// ============================================================================
// PedersenPoints Column Generation (alternative to full table generation)
// ============================================================================
// This is handled by gen_pedersen_table_on_gpu.cu for the full table
// Individual column generation can use the same output format
