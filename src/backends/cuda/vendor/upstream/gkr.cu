#include "utils.cuh"
#include "gkr.cuh"

namespace {

constexpr unsigned int GKR_BLOCK_SIZE = 1024;
constexpr unsigned int GKR_SUM_BLOCK_SIZE = 256;

DEVICE_FORCEINLINE qm31 zero_qm31() {
    return qm31{cm31{0, 0}, cm31{0, 0}};
}

DEVICE_FORCEINLINE qm31 qm31_double(qm31 value) {
    return add(value, value);
}

DEVICE_FORCEINLINE m31 double_value(m31 value) {
    return add(value, value);
}

DEVICE_FORCEINLINE qm31 double_value(qm31 value) {
    return qm31_double(value);
}

template <typename T>
DEVICE_FORCEINLINE qm31 logup_sum_value(
    T numerator0,
    T numerator1,
    qm31 denominator0,
    qm31 denominator1,
    qm31 lambda
) {
    qm31 numerator = add(mul(numerator0, denominator1), mul(numerator1, denominator0));
    qm31 denominator = mul(denominator0, denominator1);
    return add(numerator, mul(lambda, denominator));
}

DEVICE_FORCEINLINE qm31 logup_singles_sum_value(
    qm31 denominator0,
    qm31 denominator1,
    qm31 lambda
) {
    qm31 numerator = add(denominator0, denominator1);
    qm31 denominator = mul(denominator0, denominator1);
    return add(numerator, mul(lambda, denominator));
}

DEVICE_FORCEINLINE void reduce_gkr_sum_block(
    qm31 eval_at_0,
    qm31 eval_at_2,
    m31 *coordinate_sums
) {
    extern __shared__ m31 shared[];

    m31 *s00 = &shared[0 * blockDim.x];
    m31 *s01 = &shared[1 * blockDim.x];
    m31 *s02 = &shared[2 * blockDim.x];
    m31 *s03 = &shared[3 * blockDim.x];
    m31 *s20 = &shared[4 * blockDim.x];
    m31 *s21 = &shared[5 * blockDim.x];
    m31 *s22 = &shared[6 * blockDim.x];
    m31 *s23 = &shared[7 * blockDim.x];

    s00[threadIdx.x] = eval_at_0.a.a;
    s01[threadIdx.x] = eval_at_0.a.b;
    s02[threadIdx.x] = eval_at_0.b.a;
    s03[threadIdx.x] = eval_at_0.b.b;
    s20[threadIdx.x] = eval_at_2.a.a;
    s21[threadIdx.x] = eval_at_2.a.b;
    s22[threadIdx.x] = eval_at_2.b.a;
    s23[threadIdx.x] = eval_at_2.b.b;

    __syncthreads();

    for (unsigned int s = blockDim.x >> 1; s > 0; s >>= 1) {
        if (threadIdx.x < s) {
            s00[threadIdx.x] = add(s00[threadIdx.x], s00[threadIdx.x + s]);
            s01[threadIdx.x] = add(s01[threadIdx.x], s01[threadIdx.x + s]);
            s02[threadIdx.x] = add(s02[threadIdx.x], s02[threadIdx.x + s]);
            s03[threadIdx.x] = add(s03[threadIdx.x], s03[threadIdx.x + s]);
            s20[threadIdx.x] = add(s20[threadIdx.x], s20[threadIdx.x + s]);
            s21[threadIdx.x] = add(s21[threadIdx.x], s21[threadIdx.x + s]);
            s22[threadIdx.x] = add(s22[threadIdx.x], s22[threadIdx.x + s]);
            s23[threadIdx.x] = add(s23[threadIdx.x], s23[threadIdx.x + s]);
        }
        __syncthreads();
    }

    if (threadIdx.x == 0) {
        atomic_add(&coordinate_sums[0], s00[0]);
        atomic_add(&coordinate_sums[1], s01[0]);
        atomic_add(&coordinate_sums[2], s02[0]);
        atomic_add(&coordinate_sums[3], s03[0]);
        atomic_add(&coordinate_sums[4], s20[0]);
        atomic_add(&coordinate_sums[5], s21[0]);
        atomic_add(&coordinate_sums[6], s22[0]);
        atomic_add(&coordinate_sums[7], s23[0]);
    }
}

__global__ void gkr_sum_grand_product_kernel(
    const qm31 *eq_evals,
    const qm31 *input_layer,
    uint32_t n_terms,
    m31 *coordinate_sums
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int grid_size = blockDim.x * gridDim.x;
    qm31 eval_at_0 = zero_qm31();
    qm31 eval_at_2 = zero_qm31();

    for (unsigned int i = index; i < n_terms; i += grid_size) {
        qm31 input_at_r0i0 = input_layer[i * 2];
        qm31 input_at_r0i1 = input_layer[i * 2 + 1];
        qm31 input_at_r1i0 = input_layer[(n_terms + i) * 2];
        qm31 input_at_r1i1 = input_layer[(n_terms + i) * 2 + 1];
        qm31 input_at_r2i0 = sub(qm31_double(input_at_r1i0), input_at_r0i0);
        qm31 input_at_r2i1 = sub(qm31_double(input_at_r1i1), input_at_r0i1);
        qm31 eq_eval = eq_evals[i];

        eval_at_0 = add(
            eval_at_0,
            mul(eq_eval, mul(input_at_r0i0, input_at_r0i1))
        );
        eval_at_2 = add(
            eval_at_2,
            mul(eq_eval, mul(input_at_r2i0, input_at_r2i1))
        );
    }

    reduce_gkr_sum_block(eval_at_0, eval_at_2, coordinate_sums);
}

template <typename T>
__global__ void gkr_sum_logup_kernel(
    const qm31 *eq_evals,
    const T *numerators,
    const qm31 *denominators,
    uint32_t n_terms,
    qm31 lambda,
    m31 *coordinate_sums
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int grid_size = blockDim.x * gridDim.x;
    qm31 eval_at_0 = zero_qm31();
    qm31 eval_at_2 = zero_qm31();

    for (unsigned int i = index; i < n_terms; i += grid_size) {
        T numerator_at_r0i0 = numerators[i * 2];
        T numerator_at_r0i1 = numerators[i * 2 + 1];
        qm31 denominator_at_r0i0 = denominators[i * 2];
        qm31 denominator_at_r0i1 = denominators[i * 2 + 1];
        T numerator_at_r1i0 = numerators[(n_terms + i) * 2];
        T numerator_at_r1i1 = numerators[(n_terms + i) * 2 + 1];
        qm31 denominator_at_r1i0 = denominators[(n_terms + i) * 2];
        qm31 denominator_at_r1i1 = denominators[(n_terms + i) * 2 + 1];
        T numerator_at_r2i0 = sub(double_value(numerator_at_r1i0), numerator_at_r0i0);
        T numerator_at_r2i1 = sub(double_value(numerator_at_r1i1), numerator_at_r0i1);
        qm31 denominator_at_r2i0 = sub(qm31_double(denominator_at_r1i0), denominator_at_r0i0);
        qm31 denominator_at_r2i1 = sub(qm31_double(denominator_at_r1i1), denominator_at_r0i1);
        qm31 eq_eval = eq_evals[i];

        eval_at_0 = add(
            eval_at_0,
            mul(
                eq_eval,
                logup_sum_value(
                    numerator_at_r0i0,
                    numerator_at_r0i1,
                    denominator_at_r0i0,
                    denominator_at_r0i1,
                    lambda
                )
            )
        );
        eval_at_2 = add(
            eval_at_2,
            mul(
                eq_eval,
                logup_sum_value(
                    numerator_at_r2i0,
                    numerator_at_r2i1,
                    denominator_at_r2i0,
                    denominator_at_r2i1,
                    lambda
                )
            )
        );
    }

    reduce_gkr_sum_block(eval_at_0, eval_at_2, coordinate_sums);
}

__global__ void gkr_sum_logup_singles_kernel(
    const qm31 *eq_evals,
    const qm31 *denominators,
    uint32_t n_terms,
    qm31 lambda,
    m31 *coordinate_sums
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int grid_size = blockDim.x * gridDim.x;
    qm31 eval_at_0 = zero_qm31();
    qm31 eval_at_2 = zero_qm31();

    for (unsigned int i = index; i < n_terms; i += grid_size) {
        qm31 denominator_at_r0i0 = denominators[i * 2];
        qm31 denominator_at_r0i1 = denominators[i * 2 + 1];
        qm31 denominator_at_r1i0 = denominators[(n_terms + i) * 2];
        qm31 denominator_at_r1i1 = denominators[(n_terms + i) * 2 + 1];
        qm31 denominator_at_r2i0 = sub(qm31_double(denominator_at_r1i0), denominator_at_r0i0);
        qm31 denominator_at_r2i1 = sub(qm31_double(denominator_at_r1i1), denominator_at_r0i1);
        qm31 eq_eval = eq_evals[i];

        eval_at_0 = add(
            eval_at_0,
            mul(
                eq_eval,
                logup_singles_sum_value(
                    denominator_at_r0i0,
                    denominator_at_r0i1,
                    lambda
                )
            )
        );
        eval_at_2 = add(
            eval_at_2,
            mul(
                eq_eval,
                logup_singles_sum_value(
                    denominator_at_r2i0,
                    denominator_at_r2i1,
                    lambda
                )
            )
        );
    }

    reduce_gkr_sum_block(eval_at_0, eval_at_2, coordinate_sums);
}

template <typename T>
__global__ void next_logup_layer_kernel(
    const T *numerators,
    const qm31 *denominators,
    uint32_t next_layer_size,
    qm31 *next_numerators,
    qm31 *next_denominators
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= next_layer_size) {
        return;
    }

    T numerator0 = numerators[index * 2];
    T numerator1 = numerators[index * 2 + 1];
    qm31 denominator0 = denominators[index * 2];
    qm31 denominator1 = denominators[index * 2 + 1];

    next_numerators[index] = add(
        mul(numerator0, denominator1),
        mul(numerator1, denominator0)
    );
    next_denominators[index] = mul(denominator0, denominator1);
}

__global__ void next_logup_singles_layer_kernel(
    const qm31 *denominators,
    uint32_t next_layer_size,
    qm31 *next_numerators,
    qm31 *next_denominators
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= next_layer_size) {
        return;
    }

    qm31 denominator0 = denominators[index * 2];
    qm31 denominator1 = denominators[index * 2 + 1];

    next_numerators[index] = add(denominator0, denominator1);
    next_denominators[index] = mul(denominator0, denominator1);
}

__global__ void next_grand_product_layer_kernel(
    const qm31 *input_layer,
    uint32_t next_layer_size,
    qm31 *output_layer
) {
    unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= next_layer_size) {
        return;
    }

    output_layer[index] = mul(input_layer[index * 2], input_layer[index * 2 + 1]);
}

void launch_next_grand_product_layer(
    const qm31 *input_layer,
    uint32_t input_size,
    qm31 *output_layer
) {
    uint32_t next_layer_size = input_size >> 1;
    unsigned int number_of_blocks =
        (next_layer_size + GKR_BLOCK_SIZE - 1) / GKR_BLOCK_SIZE;

    next_grand_product_layer_kernel<<<number_of_blocks, GKR_BLOCK_SIZE>>>(
        input_layer,
        next_layer_size,
        output_layer
    );
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

template <typename T>
void launch_next_logup_layer(
    const T *numerators,
    const qm31 *denominators,
    uint32_t input_size,
    qm31 *next_numerators,
    qm31 *next_denominators
) {
    uint32_t next_layer_size = input_size >> 1;
    unsigned int number_of_blocks =
        (next_layer_size + GKR_BLOCK_SIZE - 1) / GKR_BLOCK_SIZE;

    next_logup_layer_kernel<<<number_of_blocks, GKR_BLOCK_SIZE>>>(
        numerators,
        denominators,
        next_layer_size,
        next_numerators,
        next_denominators
    );
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

void launch_next_logup_singles_layer(
    const qm31 *denominators,
    uint32_t input_size,
    qm31 *next_numerators,
    qm31 *next_denominators
) {
    uint32_t next_layer_size = input_size >> 1;
    unsigned int number_of_blocks =
        (next_layer_size + GKR_BLOCK_SIZE - 1) / GKR_BLOCK_SIZE;

    next_logup_singles_layer_kernel<<<number_of_blocks, GKR_BLOCK_SIZE>>>(
        denominators,
        next_layer_size,
        next_numerators,
        next_denominators
    );
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

unsigned int gkr_sum_number_of_blocks(uint32_t n_terms) {
    unsigned int number_of_blocks =
        (n_terms + GKR_SUM_BLOCK_SIZE - 1) / GKR_SUM_BLOCK_SIZE;
    if (number_of_blocks == 0) {
        number_of_blocks = 1;
    }

    return number_of_blocks;
}

size_t gkr_sum_shared_size() {
    return 8 * GKR_SUM_BLOCK_SIZE * sizeof(m31);
}

m31 *alloc_gkr_sum_coordinate_sums() {
    return cuda_proving_alloc_zeroes<m31>(8);
}

void finish_gkr_sum_kernel(
    m31 *device_coordinate_sums,
    qm31 *eval_at_0,
    qm31 *eval_at_2
) {
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    m31 host_coordinate_sums[8];
    cuda_mem_copy_device_to_host<m31>(device_coordinate_sums, host_coordinate_sums, 8);
    cuda_proving_free(device_coordinate_sums);

    *eval_at_0 = qm31{
        cm31{host_coordinate_sums[0], host_coordinate_sums[1]},
        cm31{host_coordinate_sums[2], host_coordinate_sums[3]},
    };
    *eval_at_2 = qm31{
        cm31{host_coordinate_sums[4], host_coordinate_sums[5]},
        cm31{host_coordinate_sums[6], host_coordinate_sums[7]},
    };
}

} // namespace

__global__ void gen_eq_evals_kernel(qm31 v, qm31 *factors, uint32_t y_size, qm31 *evals) {
    // Assumes `factors` holds 1 - y_i at position 2 * i and y_i at position 2 * i + 1
    // for all i = 0, .., y_size - 1.
    // TODO: See if shared memory speeds this up

    unsigned int thread_index = blockIdx.x * blockDim.x + threadIdx.x;

    qm31 eq_eval = v;
    unsigned int shifted_thread_index = thread_index;
    for (int i = 2 * y_size - 2; i >= 0; i -= 2) {
        eq_eval = mul(eq_eval, factors[i + (shifted_thread_index & 1)]);
        shifted_thread_index >>= 1;
    }
    evals[thread_index] = eq_eval;
}

void gen_eq_evals(qm31 v, qm31 *y, uint32_t y_size, qm31 *evals, uint32_t evals_size) {
    const unsigned int BLOCK_SIZE = 1024;
    const unsigned int NUMBER_OF_BLOCKS = (evals_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    int factors_byte_length = sizeof(qm31) * y_size * 2;
    qm31 *factors = (qm31*)malloc(factors_byte_length);
    for(int i = 0; i < y_size; i++) {
        factors[2 * i] = sub(m31{1}, y[i]);
        factors[2 * i + 1] = y[i];
    }

    qm31 *factors_device = cuda_proving_clone_to_device<qm31>(factors, y_size * 2);
    free(factors);

    gen_eq_evals_kernel<<<NUMBER_OF_BLOCKS, min(evals_size, BLOCK_SIZE)>>>(v, factors_device, y_size, evals);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();

    cuda_proving_free(factors_device);
}

void gkr_next_grand_product_layer(
    const qm31 *input_layer,
    uint32_t input_size,
    qm31 *output_layer
) {
    launch_next_grand_product_layer(input_layer, input_size, output_layer);
}

void gkr_next_logup_generic_layer(
    const qm31 *numerators,
    const qm31 *denominators,
    uint32_t input_size,
    qm31 *next_numerators,
    qm31 *next_denominators
) {
    launch_next_logup_layer(numerators, denominators, input_size, next_numerators, next_denominators);
}

void gkr_next_logup_multiplicities_layer(
    const m31 *numerators,
    const qm31 *denominators,
    uint32_t input_size,
    qm31 *next_numerators,
    qm31 *next_denominators
) {
    launch_next_logup_layer(numerators, denominators, input_size, next_numerators, next_denominators);
}

void gkr_next_logup_singles_layer(
    const qm31 *denominators,
    uint32_t input_size,
    qm31 *next_numerators,
    qm31 *next_denominators
) {
    launch_next_logup_singles_layer(denominators, input_size, next_numerators, next_denominators);
}

void gkr_sum_grand_product(
    const qm31 *eq_evals,
    const qm31 *input_layer,
    uint32_t n_terms,
    qm31 *eval_at_0,
    qm31 *eval_at_2
) {
    m31 *device_coordinate_sums = alloc_gkr_sum_coordinate_sums();
    gkr_sum_grand_product_kernel<<<
        gkr_sum_number_of_blocks(n_terms),
        GKR_SUM_BLOCK_SIZE,
        gkr_sum_shared_size()>>>(
        eq_evals,
        input_layer,
        n_terms,
        device_coordinate_sums
    );
    finish_gkr_sum_kernel(device_coordinate_sums, eval_at_0, eval_at_2);
}

void gkr_sum_logup_generic(
    const qm31 *eq_evals,
    const qm31 *numerators,
    const qm31 *denominators,
    uint32_t n_terms,
    qm31 lambda,
    qm31 *eval_at_0,
    qm31 *eval_at_2
) {
    m31 *device_coordinate_sums = alloc_gkr_sum_coordinate_sums();
    gkr_sum_logup_kernel<qm31><<<
        gkr_sum_number_of_blocks(n_terms),
        GKR_SUM_BLOCK_SIZE,
        gkr_sum_shared_size()>>>(
        eq_evals,
        numerators,
        denominators,
        n_terms,
        lambda,
        device_coordinate_sums
    );
    finish_gkr_sum_kernel(device_coordinate_sums, eval_at_0, eval_at_2);
}

void gkr_sum_logup_multiplicities(
    const qm31 *eq_evals,
    const m31 *numerators,
    const qm31 *denominators,
    uint32_t n_terms,
    qm31 lambda,
    qm31 *eval_at_0,
    qm31 *eval_at_2
) {
    m31 *device_coordinate_sums = alloc_gkr_sum_coordinate_sums();
    gkr_sum_logup_kernel<m31><<<
        gkr_sum_number_of_blocks(n_terms),
        GKR_SUM_BLOCK_SIZE,
        gkr_sum_shared_size()>>>(
        eq_evals,
        numerators,
        denominators,
        n_terms,
        lambda,
        device_coordinate_sums
    );
    finish_gkr_sum_kernel(device_coordinate_sums, eval_at_0, eval_at_2);
}

void gkr_sum_logup_singles(
    const qm31 *eq_evals,
    const qm31 *denominators,
    uint32_t n_terms,
    qm31 lambda,
    qm31 *eval_at_0,
    qm31 *eval_at_2
) {
    m31 *device_coordinate_sums = alloc_gkr_sum_coordinate_sums();
    gkr_sum_logup_singles_kernel<<<
        gkr_sum_number_of_blocks(n_terms),
        GKR_SUM_BLOCK_SIZE,
        gkr_sum_shared_size()>>>(
        eq_evals,
        denominators,
        n_terms,
        lambda,
        device_coordinate_sums
    );
    finish_gkr_sum_kernel(device_coordinate_sums, eval_at_0, eval_at_2);
}
