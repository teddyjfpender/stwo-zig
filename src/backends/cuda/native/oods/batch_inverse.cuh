#pragma once

#include "field.cuh"

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::oods {

template <typename Field>
__device__ __forceinline__ void inverse_tree_block(
    const Field *input,
    Field *output,
    Field *leaves,
    Field *tree) {
    const int lane = static_cast<int>(threadIdx.x);
    leaves[lane] = input[lane];
    leaves[lane + 512] = input[lane + 512];
    __syncthreads();

    if (lane < 512) {
        tree[lane] = mul(leaves[2 * lane], leaves[2 * lane + 1]);
    }
    int child_offset = 0;
    int parent_offset = 512;
    int nodes = 256;
    for (int level = 1; level < 5; ++level) {
        __syncthreads();
        if (lane < nodes) {
            tree[parent_offset + lane] = mul(
                tree[child_offset + 2 * lane],
                tree[child_offset + 2 * lane + 1]);
        }
        child_offset = parent_offset;
        parent_offset += nodes;
        nodes >>= 1;
    }

    __syncthreads();
    if (lane < 32) {
        tree[child_offset + lane] = inverse(tree[child_offset + lane]);
    }

    nodes = 32;
    parent_offset = child_offset - 64;
    for (int level = 5; level < 9; ++level) {
        __syncthreads();
        if (lane < nodes) {
            const Field left = tree[parent_offset + 2 * lane];
            tree[parent_offset + 2 * lane] =
                mul(tree[child_offset + lane],
                    tree[parent_offset + 2 * lane + 1]);
            tree[parent_offset + 2 * lane + 1] =
                mul(tree[child_offset + lane], left);
        }
        nodes <<= 1;
        child_offset = parent_offset;
        parent_offset -= 2 * nodes;
    }

    __syncthreads();
    if (lane < 512) {
        // The first tree level has one inverse per pair, not per leaf.
        const Field pair_inverse = tree[lane];
        output[2 * lane] =
            mul(pair_inverse, leaves[2 * lane + 1]);
        output[2 * lane + 1] =
            mul(pair_inverse, leaves[2 * lane]);
    }
}

__global__ void inverse_direct_kernel(
    const QM31 *input,
    QM31 *output,
    std::uint32_t size) {
    const std::uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index < size) output[index] = inverse(input[index]);
}

__global__ void inverse_tree_kernel(
    const QM31 *input,
    QM31 *output,
    std::uint32_t size) {
    const std::uint32_t offset = blockIdx.x * 1024u;
    if (offset >= size) return;
    extern __shared__ QM31 shared[];
    inverse_tree_block(
        input + offset,
        output + offset,
        shared,
        shared + 1024);
}

inline cudaError_t batch_inverse_on(
    cudaStream_t stream,
    const QM31 *input,
    QM31 *output,
    std::uint32_t size) {
    if (stream == nullptr || input == nullptr || output == nullptr ||
        !is_power_of_two(size)) {
        return cudaErrorInvalidValue;
    }
    if (size < 1024) {
        constexpr std::uint32_t block_size = 256;
        inverse_direct_kernel<<<
            (size + block_size - 1) / block_size,
            block_size,
            0,
            stream>>>(input, output, size);
    } else {
        constexpr std::size_t shared_elements = 1024 + (1024 - 32);
        inverse_tree_kernel<<<
            size / 1024,
            512,
            shared_elements * sizeof(QM31),
            stream>>>(input, output, size);
    }
    return cudaPeekAtLastError();
}

}  // namespace stwo::cuda::oods
