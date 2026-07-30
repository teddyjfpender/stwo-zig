#include "barycentric.cuh"

#include "batch_inverse.cuh"
#include "point.cuh"
#include "utils.cuh"

namespace {

constexpr uint32_t BARYCENTRIC_BLOCK_DIM = 256;

// Circle-domain point at `index` for the half-coset parameterization. Copied from
// quotients.cu (where the same routine is byte-equality-proven against the CPU
// reference by the quotient conformance gates); keep the two in sync.
DEVICE_FORCEINLINE point barycentric_domain_at_index(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t index,
    uint32_t domain_size
) {
    uint32_t half_coset_size = domain_size >> 1;
    int modulo_u31_mask = 0x7fffffff;
    if (index < half_coset_size) {
        uint64_t global_index =
            (uint64_t)half_coset_initial_index + (uint64_t)half_coset_step_size * (uint64_t)index;
        return point_pow(m31_circle_gen, (int)(global_index & modulo_u31_mask));
    } else {
        uint64_t global_index = (uint64_t)half_coset_initial_index +
                                (uint64_t)half_coset_step_size * (uint64_t)(index - half_coset_size);
        return point_pow(m31_circle_gen, (int)((2147483648 - global_index) & modulo_u31_mask));
    }
}

DEVICE_FORCEINLINE qm31 qm31_from_m31(m31 value) {
    return qm31{cm31{value, 0}, cm31{0, 0}};
}

// Per bit-reversed domain point i: numerator = (p - d_i).y, denominator = 1 + (p - d_i).x —
// the inversion-free split of `point_vanishing(d_i, p) = h.y / (1 + h.x)`. The division
// happens through one batched inversion (exact field arithmetic: the inverse is unique,
// so the values are identical to the per-point CPU computation).
__global__ void barycentric_point_vanishing_parts_kernel(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    secure_field_point p,
    qm31 *numerators,
    qm31 *denominators
) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= size) {
        return;
    }
    uint32_t domain_index = bit_reverse(i, (int)log_size);
    point d = barycentric_domain_at_index(
        half_coset_initial_index, half_coset_step_size, domain_index, size);
    // h = p - d under the CIRCLE GROUP LAW (p + (-d), with -d = (d.x, -d.y)):
    //   h.x = p.x * d.x + p.y * d.y
    //   h.y = p.y * d.x - p.x * d.y
    // NOT coordinate-wise subtraction — the conformance differential rejects that.
    qm31 dx = qm31_from_m31(d.x);
    qm31 dy = qm31_from_m31(d.y);
    qm31 hx = add(mul(p.x, dx), mul(p.y, dy));
    qm31 hy = sub(mul(p.y, dx), mul(p.x, dy));
    numerators[i] = hy;
    denominators[i] = add(qm31_from_m31(1), hx);
}

__global__ void qm31_mul_elementwise_kernel(
    const qm31 *lhs,
    const qm31 *rhs,
    qm31 *out,
    uint32_t size
) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < size) {
        out[i] = mul(lhs[i], rhs[i]);
    }
}

__global__ void barycentric_scale_weights_kernel(
    const qm31 *point_vanishing_inverses,
    uint32_t size,
    qm31 even_scale,
    qm31 odd_scale,
    qm31 *result_weights
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) {
        return;
    }

    qm31 scale = (index & 1U) == 0 ? even_scale : odd_scale;
    result_weights[index] = mul(point_vanishing_inverses[index], scale);
}

__global__ void barycentric_eval_partial_kernel(
    const m31 *eval_values,
    const qm31 *weights,
    uint32_t size,
    qm31 *partial_sums
) {
    extern __shared__ qm31 shared[];

    qm31 thread_sum = {{0, 0}, {0, 0}};
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t stride = blockDim.x * gridDim.x;

    while (index < size) {
        thread_sum = add(thread_sum, mul(eval_values[index], weights[index]));
        index += stride;
    }

    shared[threadIdx.x] = thread_sum;
    __syncthreads();

    for (uint32_t offset = blockDim.x / 2; offset > 0; offset >>= 1) {
        if (threadIdx.x < offset) {
            shared[threadIdx.x] = add(shared[threadIdx.x], shared[threadIdx.x + offset]);
        }
        __syncthreads();
    }

    if (threadIdx.x == 0) {
        partial_sums[blockIdx.x] = shared[0];
    }
}

__global__ void reduce_qm31_partial_sums_kernel(
    const qm31 *input,
    uint32_t size,
    qm31 *output
) {
    extern __shared__ qm31 shared[];

    qm31 thread_sum = {{0, 0}, {0, 0}};
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t stride = blockDim.x * gridDim.x;

    while (index < size) {
        thread_sum = add(thread_sum, input[index]);
        index += stride;
    }

    shared[threadIdx.x] = thread_sum;
    __syncthreads();

    for (uint32_t offset = blockDim.x / 2; offset > 0; offset >>= 1) {
        if (threadIdx.x < offset) {
            shared[threadIdx.x] = add(shared[threadIdx.x], shared[threadIdx.x + offset]);
        }
        __syncthreads();
    }

    if (threadIdx.x == 0) {
        output[blockIdx.x] = shared[0];
    }
}

__global__ void barycentric_eval_partial_many_kernel(
    const m31 *const *columns,      // n_cols device pointers, same size
    const qm31 *weights,
    uint32_t size,
    qm31 *partial_sums              // [n_cols][gridDim.x] row-major
) {
    extern __shared__ qm31 shared[];

    const m31 *eval_values = columns[blockIdx.y];
    qm31 thread_sum = {{0, 0}, {0, 0}};
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t stride = blockDim.x * gridDim.x;

    while (index < size) {
        thread_sum = add(thread_sum, mul(eval_values[index], weights[index]));
        index += stride;
    }

    shared[threadIdx.x] = thread_sum;
    __syncthreads();

    for (uint32_t offset = blockDim.x / 2; offset > 0; offset >>= 1) {
        if (threadIdx.x < offset) {
            shared[threadIdx.x] = add(shared[threadIdx.x], shared[threadIdx.x + offset]);
        }
        __syncthreads();
    }

    if (threadIdx.x == 0) {
        partial_sums[blockIdx.y * gridDim.x + blockIdx.x] = shared[0];
    }
}

// One block per column: reduce that column's row of partial sums to out[col].
__global__ void reduce_qm31_rows_kernel(
    const qm31 *partials,           // [n_cols][row_width]
    uint32_t row_width,
    qm31 *out                       // [n_cols]
) {
    extern __shared__ qm31 shared[];

    const qm31 *row = partials + (size_t)blockIdx.x * row_width;
    qm31 thread_sum = {{0, 0}, {0, 0}};
    for (uint32_t i = threadIdx.x; i < row_width; i += blockDim.x) {
        thread_sum = add(thread_sum, row[i]);
    }

    shared[threadIdx.x] = thread_sum;
    __syncthreads();

    for (uint32_t offset = blockDim.x / 2; offset > 0; offset >>= 1) {
        if (threadIdx.x < offset) {
            shared[threadIdx.x] = add(shared[threadIdx.x], shared[threadIdx.x + offset]);
        }
        __syncthreads();
    }

    if (threadIdx.x == 0) {
        out[blockIdx.x] = shared[0];
    }
}

} // namespace

// Computes the per-point `point_vanishing(d_i, p)` values for the whole (bit-reversed)
// circle domain ON DEVICE: one parts kernel + one batched inversion + one multiply.
// Replaces a host pass that generated millions of circle points and inverted on the
// CPU per (log_size, point) pair, then uploaded the result.
extern "C"
void barycentric_point_vanishings(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    qm31 p_x,
    qm31 p_y,
    qm31 *result
) {
    qm31 *numerators = cuda_proving_malloc<qm31>(size);
    qm31 *denominators = cuda_proving_malloc<qm31>(size);

    uint32_t num_blocks = (size + BARYCENTRIC_BLOCK_DIM - 1) / BARYCENTRIC_BLOCK_DIM;
    barycentric_point_vanishing_parts_kernel<<<num_blocks, BARYCENTRIC_BLOCK_DIM>>>(
        half_coset_initial_index,
        half_coset_step_size,
        size,
        log_size,
        secure_field_point{p_x, p_y},
        numerators,
        denominators
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    // result = 1 / denominators, then result = numerators * result.
    batch_inverse_secure_field(denominators, result, size);
    qm31_mul_elementwise_kernel<<<num_blocks, BARYCENTRIC_BLOCK_DIM>>>(
        numerators, result, result, size);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    cuda_proving_free(numerators);
    cuda_proving_free(denominators);
}

extern "C"
void barycentric_weights_from_point_vanishings(
    const qm31 *point_vanishings,
    uint32_t size,
    qm31 even_scale,
    qm31 odd_scale,
    qm31 *result_weights
) {
    qm31 *inverses = cuda_proving_malloc<qm31>(size);
    batch_inverse_secure_field(const_cast<qm31 *>(point_vanishings), inverses, size);

    uint32_t num_blocks = (size + BARYCENTRIC_BLOCK_DIM - 1) / BARYCENTRIC_BLOCK_DIM;
    barycentric_scale_weights_kernel<<<num_blocks, BARYCENTRIC_BLOCK_DIM>>>(
        inverses,
        size,
        even_scale,
        odd_scale,
        result_weights
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    cuda_proving_free(inverses);
}

extern "C"
qm31 barycentric_eval_base_field(
    const m31 *eval_values,
    const qm31 *weights,
    uint32_t size
) {
    uint32_t num_blocks = (size + BARYCENTRIC_BLOCK_DIM - 1) / BARYCENTRIC_BLOCK_DIM;
    qm31 *partials = cuda_proving_malloc<qm31>(num_blocks);
    barycentric_eval_partial_kernel<<<num_blocks, BARYCENTRIC_BLOCK_DIM, sizeof(qm31) * BARYCENTRIC_BLOCK_DIM>>>(
        eval_values,
        weights,
        size,
        partials
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    uint32_t current_size = num_blocks;
    qm31 *current = partials;
    while (current_size > 1) {
        uint32_t next_num_blocks = (current_size + BARYCENTRIC_BLOCK_DIM - 1) / BARYCENTRIC_BLOCK_DIM;
        qm31 *next = cuda_proving_malloc<qm31>(next_num_blocks);
        reduce_qm31_partial_sums_kernel<<<next_num_blocks, BARYCENTRIC_BLOCK_DIM, sizeof(qm31) * BARYCENTRIC_BLOCK_DIM>>>(
            current,
            current_size,
            next
        );
        stwo_maybe_debug_sync();
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
        cuda_proving_free(current);
        current = next;
        current_size = next_num_blocks;
    }

    qm31 result = {{0, 0}, {0, 0}};
    cuda_mem_copy_device_to_host(current, &result, 1);

    cuda_proving_free(current);

    return result;
}

// Batched OODS evaluation: MANY same-size base-field columns against ONE weights
// column, one launch pair + one D2H for the whole group (vs a launch+sync round
// trip per column). Exact field sums — values identical to the per-column entry
// regardless of reduction shape.
extern "C"
void barycentric_eval_base_field_many(
    const m31 *const *columns_dev,  // DEVICE array of n_cols column pointers
    uint32_t n_cols,
    const qm31 *weights,
    uint32_t size,
    qm31 *out_host                  // HOST buffer, n_cols results
) {
    uint32_t blocks_per_col = (size + BARYCENTRIC_BLOCK_DIM - 1) / BARYCENTRIC_BLOCK_DIM;
    if (blocks_per_col > 1024) blocks_per_col = 1024;

    qm31 *partials = cuda_proving_malloc<qm31>((size_t)n_cols * blocks_per_col);
    dim3 grid(blocks_per_col, n_cols);
    barycentric_eval_partial_many_kernel<<<grid, BARYCENTRIC_BLOCK_DIM, sizeof(qm31) * BARYCENTRIC_BLOCK_DIM>>>(
        columns_dev,
        weights,
        size,
        partials
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    qm31 *out_dev = cuda_proving_malloc<qm31>(n_cols);
    reduce_qm31_rows_kernel<<<n_cols, BARYCENTRIC_BLOCK_DIM, sizeof(qm31) * BARYCENTRIC_BLOCK_DIM>>>(
        partials,
        blocks_per_col,
        out_dev
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    cuda_mem_copy_device_to_host(out_dev, out_host, n_cols);
    cuda_proving_free(partials);
    cuda_proving_free(out_dev);
}
