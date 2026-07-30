// Ragged relation inverse extracted from the pinned CUDA authority.

#include "batch_inverse.cuh"

namespace stwo::cuda::relation {
namespace {

template <typename T>
__device__ __forceinline__ void forward_parent(
    T *from,
    T *destination,
    int index) {
    destination[index] =
        mul(from[index << 1], from[(index << 1) + 1]);
}

template <typename T>
__device__ __forceinline__ void backward_children(
    T *from,
    T *destination,
    int index) {
    const T temporary = destination[index << 1];
    destination[index << 1] =
        mul(from[index], destination[(index << 1) + 1]);
    destination[(index << 1) + 1] =
        mul(from[index], temporary);
}

template <typename T>
__device__ __forceinline__ void batch_inverse(
    T *from,
    T *destination,
    int size,
    int log_size,
    int block_index,
    T *shared_from,
    T *shared_tree) {
    const int index = threadIdx.x;
    shared_from[index] =
        from[2 * block_index * blockDim.x + index];
    shared_from[index + blockDim.x] =
        from[2 * block_index * blockDim.x + index + blockDim.x];
    __syncthreads();

    destination = &destination[2 * block_index * blockDim.x];
    size >>= 1;
    if (index < size) {
        forward_parent(shared_from, shared_tree, index);
    }

    int from_offset = 0;
    int destination_offset = size;
    size >>= 1;
    int step = 1;
    while (step + 5 < log_size) {
        __syncthreads();
        if (index < size) {
            forward_parent(
                &shared_tree[from_offset],
                &shared_tree[destination_offset],
                index);
        }
        from_offset = destination_offset;
        destination_offset += size;
        size >>= 1;
        ++step;
    }

    __syncthreads();
    if (index < (size << 1)) {
        shared_tree[from_offset + index] =
            inverse(shared_tree[from_offset + index]);
    }

    step = 5;
    size = 32;
    destination_offset = from_offset - (size << 1);
    while (step < log_size - 1) {
        __syncthreads();
        if (index < size) {
            backward_children(
                &shared_tree[from_offset],
                &shared_tree[destination_offset],
                index);
        }
        size <<= 1;
        from_offset = destination_offset;
        destination_offset = from_offset - (size << 1);
        ++step;
    }

    __syncthreads();
    if (index < size) {
        destination[index << 1] =
            mul(shared_tree[index], shared_from[(index << 1) + 1]);
        destination[(index << 1) + 1] =
            mul(shared_tree[index], shared_from[index << 1]);
    }
}

__global__ void batch_inverse_ragged_kernel(
    QM31 *const *slabs,
    const std::uint32_t *geometry,
    std::uint32_t instance_count) {
    const std::uint32_t global_block = blockIdx.x;
    std::uint32_t low = 0u;
    std::uint32_t high = instance_count;
    while (low < high) {
        const std::uint32_t middle = low + (high - low) / 2u;
        if (geometry[middle * kGeometryWords + kInverseFirst] <=
            global_block) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    if (low == 0u) return;

    const std::uint32_t instance = low - 1u;
    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    const std::uint32_t local_block =
        global_block - record[kInverseFirst];
    if (local_block >= record[kInverseBlocks]) return;

    const std::uint32_t rows = record[kRows];
    const std::uint32_t columns = record[kColumns];
    QM31 *slab = slabs[instance];
    const std::uint32_t offset = local_block * 1024u;
    const std::uint32_t total = rows * columns;
    if (rows >= 1024u) {
        extern __shared__ QM31 shared[];
        batch_inverse(
            slab + offset,
            slab + offset,
            1024,
            10,
            0,
            shared,
            &shared[1024]);
        return;
    }

    const std::uint32_t first = offset + threadIdx.x;
    if (first < total) slab[first] = inverse(slab[first]);
    const std::uint32_t second = first + blockDim.x;
    if (second < total) slab[second] = inverse(slab[second]);
}

}  // namespace

cudaError_t batch_inverse_ragged_on(
    cudaStream_t stream,
    QM31 *const *slabs,
    const std::uint32_t *geometry,
    int instances,
    int total_blocks) {
    if (slabs == nullptr || geometry == nullptr ||
        instances <= 0 || total_blocks <= 0) {
        return cudaErrorInvalidValue;
    }
    constexpr int kBlockSize = 512;
    constexpr int kSharedBytes =
        (1024 + 1024 - 32) * 4 * sizeof(std::uint32_t);
    batch_inverse_ragged_kernel<<<
        total_blocks,
        kBlockSize,
        kSharedBytes,
        stream>>>(
            slabs,
            geometry,
            static_cast<std::uint32_t>(instances));
    return cudaGetLastError();
}

}  // namespace stwo::cuda::relation
