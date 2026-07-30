#include "cuda_mem_pool.cuh"

#include <cuda_runtime.h>
#include <cstddef>
#include <cstdint>

namespace {

__global__ void batch_gather_column_rows_kernel(
    const uint32_t *const *columns,
    const uint32_t *row_offsets,
    const uint32_t *row_indices,
    uint32_t n_columns,
    uint32_t total_rows,
    uint32_t *output
) {
    uint32_t output_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (output_index >= total_rows) {
        return;
    }

    // Find the greatest column whose starting offset is <= output_index.
    // Repeated offsets (empty columns) select the following non-empty column.
    uint32_t low = 0;
    uint32_t high = n_columns;
    while (low + 1 < high) {
        uint32_t middle = low + (high - low) / 2;
        if (row_offsets[middle] <= output_index) {
            low = middle;
        } else {
            high = middle;
        }
    }
    output[output_index] = columns[low][row_indices[output_index]];
}

template <typename T>
void release_buffer(T *buffer) {
    if (buffer != nullptr) {
        cuda_allocator_free_for_proving(buffer);
    }
}

}  // namespace

// Allocation-free, graph-capturable device launch. Every descriptor and the
// output are caller-owned DEVICE buffers. No synchronization or transfer occurs.
// `stream == nullptr` selects the legacy default stream.
extern "C" int stwo_batch_gather_column_rows_launch(
    const uint32_t *const *columns_device,
    const uint32_t *row_offsets_device,
    const uint32_t *row_indices_device,
    uint32_t n_columns,
    uint32_t total_rows,
    uint32_t *output_device,
    void *stream
) {
    if (total_rows == 0) {
        return cudaSuccess;
    }
    if (n_columns == 0 || columns_device == nullptr || row_offsets_device == nullptr ||
        row_indices_device == nullptr || output_device == nullptr) {
        return cudaErrorInvalidValue;
    }

    constexpr uint32_t BLOCK_SIZE = 256;
    uint32_t grid_size = static_cast<uint32_t>(
        (static_cast<uint64_t>(total_rows) + BLOCK_SIZE - 1) / BLOCK_SIZE
    );
    batch_gather_column_rows_kernel<<<grid_size, BLOCK_SIZE, 0, (cudaStream_t)stream>>>(
        columns_device,
        row_offsets_device,
        row_indices_device,
        n_columns,
        total_rows,
        output_device
    );
    return cudaGetLastError();
}

// Compatibility entry point for host-driven decommitment. Descriptor inputs and
// output are HOST arrays; column entries are DEVICE pointers. It validates the
// complete descriptor, uploads it, performs one gather launch, and issues exactly
// one D2H for the flattened column-major output.
extern "C" int stwo_batch_gather_column_rows_host(
    const uint32_t *const *columns_host,
    const uint32_t *column_lengths_host,
    const uint32_t *row_offsets_host,
    const uint32_t *row_indices_host,
    uint32_t n_columns,
    uint32_t total_rows,
    uint32_t *output_host
) {
    if (n_columns == 0) {
        return total_rows == 0 ? cudaSuccess : cudaErrorInvalidValue;
    }
    if (columns_host == nullptr || column_lengths_host == nullptr ||
        row_offsets_host == nullptr || row_offsets_host[0] != 0 ||
        row_offsets_host[n_columns] != total_rows) {
        return cudaErrorInvalidValue;
    }
    if (total_rows != 0 && (row_indices_host == nullptr || output_host == nullptr)) {
        return cudaErrorInvalidValue;
    }
    for (uint32_t column = 0; column < n_columns; ++column) {
        uint32_t begin = row_offsets_host[column];
        uint32_t end = row_offsets_host[column + 1];
        if (begin > end || end > total_rows ||
            (begin != end && columns_host[column] == nullptr)) {
            return cudaErrorInvalidValue;
        }
        for (uint32_t i = begin; i < end; ++i) {
            if (row_indices_host[i] >= column_lengths_host[column]) {
                return cudaErrorInvalidValue;
            }
        }
    }
    if (total_rows == 0) {
        return cudaSuccess;
    }

    const uint32_t **columns_device =
        cuda_allocator_allocate_for_proving<const uint32_t *>(n_columns);
    uint32_t *row_offsets_device =
        cuda_allocator_allocate_for_proving<uint32_t>((size_t)n_columns + 1);
    uint32_t *row_indices_device =
        cuda_allocator_allocate_for_proving<uint32_t>(total_rows);
    uint32_t *output_device = cuda_allocator_allocate_for_proving<uint32_t>(total_rows);
    if (columns_device == nullptr || row_offsets_device == nullptr ||
        row_indices_device == nullptr || output_device == nullptr) {
        release_buffer(columns_device);
        release_buffer(row_offsets_device);
        release_buffer(row_indices_device);
        release_buffer(output_device);
        return cudaErrorMemoryAllocation;
    }

    cudaError_t status = cudaMemcpy(
        columns_device,
        columns_host,
        (size_t)n_columns * sizeof(uint32_t *),
        cudaMemcpyHostToDevice
    );
    if (status == cudaSuccess) {
        status = cudaMemcpy(
            row_offsets_device,
            row_offsets_host,
            ((size_t)n_columns + 1) * sizeof(uint32_t),
            cudaMemcpyHostToDevice
        );
    }
    if (status == cudaSuccess) {
        status = cudaMemcpy(
            row_indices_device,
            row_indices_host,
            (size_t)total_rows * sizeof(uint32_t),
            cudaMemcpyHostToDevice
        );
    }
    if (status == cudaSuccess) {
        status = static_cast<cudaError_t>(stwo_batch_gather_column_rows_launch(
            columns_device,
            row_offsets_device,
            row_indices_device,
            n_columns,
            total_rows,
            output_device,
            nullptr
        ));
    }
    if (status == cudaSuccess) {
        // The sole device-to-host transfer in this compatibility operation.
        status = cudaMemcpy(
            output_host,
            output_device,
            (size_t)total_rows * sizeof(uint32_t),
            cudaMemcpyDeviceToHost
        );
    }

    release_buffer(columns_device);
    release_buffer(row_offsets_device);
    release_buffer(row_indices_device);
    release_buffer(output_device);
    return status;
}
