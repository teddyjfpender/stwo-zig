#include "accumulate.cuh"
#include "utils.cuh"

__global__
void accumulate_kernel(int size, m31 **left_columns, m31 **right_columns) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < size) {
        left_columns[0][i] = add(left_columns[0][i], right_columns[0][i]);
        left_columns[1][i] = add(left_columns[1][i], right_columns[1][i]);
        left_columns[2][i] = add(left_columns[2][i], right_columns[2][i]);
        left_columns[3][i] = add(left_columns[3][i], right_columns[3][i]);
    }
}

__global__
void lift_accumulate_secure_columns_kernel(
    int size,
    uint32_t log_ratio,
    m31 **previous_columns,
    m31 **current_columns
) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < size) {
        uint32_t lifted_index = (i >> (log_ratio + 1) << 1) + (i & 1);
        current_columns[0][i] = add(current_columns[0][i], previous_columns[0][lifted_index]);
        current_columns[1][i] = add(current_columns[1][i], previous_columns[1][lifted_index]);
        current_columns[2][i] = add(current_columns[2][i], previous_columns[2][lifted_index]);
        current_columns[3][i] = add(current_columns[3][i], previous_columns[3][lifted_index]);
    }
}

void accumulate(int size, m31 **left_columns, m31 **right_columns) {
    m31 **left_columns_device = cuda_proving_clone_to_device<m31*>(left_columns, 4);
    m31 **right_columns_device = cuda_proving_clone_to_device<m31*>(right_columns, 4);

    int block_dim = 1024;
    int num_blocks = (size + block_dim - 1) / block_dim;
    accumulate_kernel<<<num_blocks, block_dim>>>(size, left_columns_device, right_columns_device);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    cuda_proving_free(left_columns_device);
    cuda_proving_free(right_columns_device);
}

void lift_accumulate_secure_columns(
    int size,
    uint32_t log_ratio,
    m31 **previous_columns,
    m31 **current_columns
) {
    m31 **previous_columns_device = cuda_proving_clone_to_device<m31*>(previous_columns, 4);
    m31 **current_columns_device = cuda_proving_clone_to_device<m31*>(current_columns, 4);

    int block_dim = 256;
    int num_blocks = (size + block_dim - 1) / block_dim;
    lift_accumulate_secure_columns_kernel<<<num_blocks, block_dim>>>(
        size,
        log_ratio,
        previous_columns_device,
        current_columns_device
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    cuda_proving_free(previous_columns_device);
    cuda_proving_free(current_columns_device);
}
