#include "batch_inverse.cuh"
#include "utils.cuh"

template<typename T>
DEVICE_FORCEINLINE void new_forward_parent(T *from, T *dst, int index) {
    // Computes the value of the parent from the multiplication of two children.
    // dst  : Pointer to the beginning of the parent's level.
    // from : Pointer to the beginning of the children level.
    // index: Index of the computed parent.
    dst[index] = mul(from[index << 1], from[(index << 1) + 1]);
}

template<typename T>
DEVICE_FORCEINLINE void new_backward_children(T *from, T *dst, int index) {
    // Computes the inverse of the two children from the inverse of the parent.
    // dst  : Pointer to the beginning of the children's level.
    // from : Pointer to the beginning of the parent's level.
    // index: Index of the computed children.
    T temp = dst[index << 1];
    dst[index << 1] = mul(from[index], dst[(index << 1) + 1]);
    dst[(index << 1) + 1] = mul(from[index], temp);
}

template<typename T>
DEVICE_FORCEINLINE void batch_inverse(T *from, T *dst, int size, int log_size,
                                      int block_index, T *s_from, T *s_inner_tree) {
    // Input:
    // - from      : array of T representing field elements.
    // - inner_tree: array of T used as an auxiliary variable.
    // - size      : size of "from" and "inner_tree".
    // - log_size  : log(size).
    // Output:
    // - dst       : array of T with the inverses of "from".
    //
    // Variation of Montgomery's trick to leverage GPU parallelization.
    // Construct a binary tree:
    //    - from      : stores the leaves
    //    - inner_tree: stores the inner nodes and the root.
    //
    // The algorithm has three parts:
    //    - Cumulative product: each parent is the product of its children.
    //    - Compute inverse of root node
    //    - Backward pass: compute inverses of children using the fact that
    //          inv_left_child  = inv_parent * right_child
    //          inv_right_child = inv_parent * left_child
    int index = threadIdx.x;

    s_from[index] = from[2 * block_index * blockDim.x + index];
    s_from[index + blockDim.x] = from[2 * block_index * blockDim.x + index + blockDim.x];
    __syncthreads();

    dst = &dst[2 * block_index * blockDim.x];

    // Size tracks the number of threads working.

    size = size >> 1;

    // The first level is a special case because inner_tree and leaves
    // are stored in separate variables.
    if(index < size) {
        new_forward_parent(s_from, s_inner_tree, index);
        // from      : | a_0       | a_1       | ... | a_(n/2 - 1)       |      ...    | a_(n-1)
        // inner_tree: | a_0 * a_1 | a_2 * a_3 | ... | a_(n-2) * a_(n-1) | empty | ... | empty
    }

    int from_offset = 0;   // Offset at inner_tree to get the children.
    int dst_offset = size; // Offset at inner_tree to store the parents.
    size >>= 1;            // Next level is half the size.

    // Each step will compute one level of the inner_tree.
    // If size = 4 inner tree stores:
    // |       Level 1         |        Root           |
    // | a_0 * a_1 | a_2 * a_3 | a_0 * a_1 * a_2 * a_3 |
    // Construct tree up to the level with 32 leaves to leverage
    // SIMD synchronization within a warp
    int step = 1;
    while(step + 5 < log_size) {
        __syncthreads();

        if(index < size) {
            // Each thread computes one parent as the product of left and right children
            new_forward_parent(&s_inner_tree[from_offset], &s_inner_tree[dst_offset], index);
        }

        from_offset = dst_offset;       // Output of this level is input of next one.
        dst_offset = dst_offset + size; // Skip the number of nodes computed.

        size >>= 1; // Next level is half the size.
        step++;
    }

    // Compute inverse of the root.
    __syncthreads();
    if(index < (size << 1)){
        s_inner_tree[from_offset + index] = inv(s_inner_tree[from_offset + index]);
    }

    // Backward Pass: compute the inverses of the children using the parents.
    step = 5;
    size = 32;
    //from_offset = dst_offset - 1;
    dst_offset = from_offset - (size << 1);
    while(step < log_size - 1) {
        __syncthreads();
        if(index < size) {
            // Compute children inverses from parent inverses.
            new_backward_children(&s_inner_tree[from_offset], &s_inner_tree[dst_offset], index);
        }

        size <<= 1; // Each level doubles up its size.

        from_offset = dst_offset;               // Output of this level is input of next one.
        dst_offset = from_offset - (size << 1); // Size threads work but 2*size children are computed.

        step++;
    }

    __syncthreads();
    // The inner_tree has all its inverses computed, now
    // we have to compute the inverses of the leaves:

    if(index < size) {
        dst[index << 1] = mul(s_inner_tree[index], s_from[(index << 1) + 1]);
        dst[(index << 1) + 1] = mul(s_inner_tree[index], s_from[index << 1]);
    }
}

__global__ void batch_inverse_base_field_kernel(m31 *from, m31 *dst, int size, int log_size) {
    // Thread syncing happens within a block.
    // Split the problem to feed them to multiple blocks.
    if(size >= 512) {
        size = 512;
        log_size = 9;
    }

    extern __shared__ m31 shared_basefield[];
    m31 *s_from_basefield = shared_basefield;
    m31 *s_inner_trees_basefield = &shared_basefield[size];

    batch_inverse(from, dst, size, log_size, blockIdx.x, s_from_basefield,
                  s_inner_trees_basefield);
}

__global__ void batch_inverse_secure_field_kernel(qm31 *from, qm31 *dst, int size, int log_size) {
    // Thread syncing happens within a block.
    // Split the problem to feed them to multiple blocks.
    if(size >= 1024) {
        size = 1024;
        log_size = 10;
    }

    extern __shared__ qm31 shared_qm31[];
    qm31 *s_from_qm31 = shared_qm31;
    qm31 *s_inner_trees_qm31 = &shared_qm31[size];

    batch_inverse(from, dst, size, log_size, blockIdx.x, s_from_qm31,
                  s_inner_trees_qm31);
}

// One proof-wide launch over heterogeneous relation denominator slabs. Geometry
// uses the shared relation geometry ABI from batch_inverse.cuh.
// Large power-of-two rows preserve the exact 1024-leaf Montgomery partitions;
// small slabs use direct inverses in 1024-element chunks within the same launch.
__global__ void batch_inverse_secure_field_ragged_kernel(
    qm31 *const *slabs, const uint32_t *geometry, uint32_t n_instances) {
    uint32_t global_block = blockIdx.x;
    uint32_t lo = 0;
    uint32_t hi = n_instances;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        if (geometry[mid * RELATION_GEOMETRY_WORDS + RELATION_INVERSE_FIRST] <= global_block) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    if (lo == 0u) {
        return;
    }
    uint32_t instance = lo - 1u;
    const uint32_t *g = geometry + instance * RELATION_GEOMETRY_WORDS;
    uint32_t local_block = global_block - g[RELATION_INVERSE_FIRST];
    if (local_block >= g[RELATION_INVERSE_BLOCKS]) {
        return;
    }
    uint32_t rows = g[RELATION_ROWS];
    uint32_t columns = g[RELATION_COLUMNS];
    qm31 *slab = slabs[instance];
    uint32_t offset = local_block * 1024u;
    uint32_t total = rows * columns;
    if (rows >= 1024u) {
        extern __shared__ qm31 shared_qm31[];
        qm31 *s_from = shared_qm31;
        qm31 *s_tree = &shared_qm31[1024];
        batch_inverse(slab + offset, slab + offset, 1024, 10, 0, s_from, s_tree);
        return;
    }
    uint32_t first = offset + threadIdx.x;
    if (first < total) {
        slab[first] = inv(slab[first]);
    }
    uint32_t second = first + blockDim.x;
    if (second < total) {
        slab[second] = inv(slab[second]);
    }
}

// Simple element-by-element inverse kernel for small sizes
__global__ void batch_inverse_secure_field_simple_kernel(qm31 *from, qm31 *dst, int size) {
    int index = blockIdx.x * blockDim.x + threadIdx.x;
    if(index < size) {
        dst[index] = inv(from[index]);
    }
}

void batch_inverse_base_field(m31 *from, m31 *dst, int size) {
    int log_size = log_2(size);
    int block_size = 256;
    int half_size = size >> 1;
    int num_blocks = (half_size + block_size - 1) / block_size;
    int shared_memory_bytes = 512 * 4  + (512 - 32) * 4;

    batch_inverse_base_field_kernel<<<num_blocks, block_size, shared_memory_bytes>>>(from, dst, size, log_size);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

cudaError_t batch_inverse_secure_field_on(
    cudaStream_t stream, qm31 *from, qm31 *dst, int size
) {
    if (size <= 0) {
        return cudaErrorInvalidValue;
    }
    int log_size = log_2(size);

    // The tree kernel is fixed at 1024 leaves per block. Smaller and non-power-of-two
    // inputs use the direct kernel rather than reading a partial tree out of bounds.
    bool is_power_of_2 = (size > 0) && ((size & (size - 1)) == 0);
    if(size < 1024 || !is_power_of_2) {
        int block_size = size < 256 ? size : 256;
        int num_blocks = (size + block_size - 1) / block_size;
        batch_inverse_secure_field_simple_kernel<<<num_blocks, block_size, 0, stream>>>(
            from, dst, size);
        return cudaGetLastError();
    }

    int block_size = 512;
    int half_size = size >> 1;
    int num_blocks = (half_size + block_size - 1) / block_size;
    int shared_memory_bytes = 1024 * 4 * 4 + (1024 - 32) * 4 * 4;

    batch_inverse_secure_field_kernel<<<num_blocks, block_size, shared_memory_bytes, stream>>>(
        from, dst, size, log_size);
    return cudaGetLastError();
}

cudaError_t batch_inverse_secure_field_columns_on(
    cudaStream_t stream, qm31 *from, qm31 *dst, int rows, int columns
) {
    if (rows <= 0 || columns <= 0 || rows > 0x7fffffff / columns) {
        return cudaErrorInvalidValue;
    }
    int total = rows * columns;
    int log_rows = log_2(rows);
    bool rows_are_power_of_2 = (rows & (rows - 1)) == 0;

    // Prepared relation extents are powers of two. Small columns use the same
    // element-wise inverse as before, now over one flattened launch.
    if (rows < 1024 || !rows_are_power_of_2) {
        int block_size = total < 256 ? total : 256;
        int num_blocks = (total + block_size - 1) / block_size;
        batch_inverse_secure_field_simple_kernel<<<num_blocks, block_size, 0, stream>>>(
            from, dst, total);
        return cudaGetLastError();
    }

    // `rows` is a multiple of 1024, so flattening the launch preserves the
    // previous per-column 1024-element tree boundaries exactly. `from == dst`
    // is safe: each block loads its disjoint leaves before writing them back.
    int block_size = 512;
    int blocks_per_column = ((rows >> 1) + block_size - 1) / block_size;
    int num_blocks = blocks_per_column * columns;
    int shared_memory_bytes = 1024 * 4 * 4 + (1024 - 32) * 4 * 4;
    batch_inverse_secure_field_kernel<<<num_blocks, block_size, shared_memory_bytes, stream>>>(
        from, dst, rows, log_rows);
    return cudaGetLastError();
}

cudaError_t batch_inverse_secure_field_ragged_on(
    cudaStream_t stream, qm31 *const *slabs, const uint32_t *geometry,
    int instances, int total_blocks
) {
    if (slabs == nullptr || geometry == nullptr || instances <= 0 ||
        total_blocks <= 0) {
        return cudaErrorInvalidValue;
    }
    int block_size = 512;
    int shared_memory_bytes = 1024 * 4 * 4 + (1024 - 32) * 4 * 4;
    batch_inverse_secure_field_ragged_kernel<<<
        total_blocks, block_size, shared_memory_bytes, stream>>>(
        slabs, geometry, static_cast<uint32_t>(instances));
    return cudaGetLastError();
}

void batch_inverse_secure_field(qm31 *from, qm31 *dst, int size) {
    ASSERT_CUDA_SUCCESS(batch_inverse_secure_field_on((cudaStream_t)0, from, dst, size));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}
