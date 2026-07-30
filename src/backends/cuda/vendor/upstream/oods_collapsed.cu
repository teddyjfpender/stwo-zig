#include "oods.cuh"

#include <cuda_runtime.h>

namespace {

constexpr uint32_t OODS_BLOCK_DIM = 256;

DEVICE_FORCEINLINE qm31 qm31_zero() {
    return qm31{cm31{0, 0}, cm31{0, 0}};
}

DEVICE_FORCEINLINE qm31 qm31_one() {
    return qm31{cm31{1, 0}, cm31{0, 0}};
}

DEVICE_FORCEINLINE secure_field_point secure_point_add_base(
    secure_field_point lhs,
    point rhs
) {
    return secure_field_point{
        sub(mul(rhs.x, lhs.x), mul(rhs.y, lhs.y)),
        add(mul(rhs.y, lhs.x), mul(rhs.x, lhs.y)),
    };
}

DEVICE_FORCEINLINE point domain_at_index(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t index,
    uint32_t domain_size
) {
    uint32_t half_coset_size = domain_size >> 1;
    constexpr uint64_t CIRCLE_ORDER = 2147483648ULL;
    constexpr uint64_t CIRCLE_MASK = CIRCLE_ORDER - 1;
    uint64_t global_index;
    if (index < half_coset_size) {
        global_index = (uint64_t)half_coset_initial_index +
                       (uint64_t)half_coset_step_size * index;
    } else {
        global_index = CIRCLE_ORDER -
                       ((uint64_t)half_coset_initial_index +
                        (uint64_t)half_coset_step_size * (index - half_coset_size));
    }
    return point_pow(m31_circle_gen, (int)(global_index & CIRCLE_MASK));
}

DEVICE_FORCEINLINE void collapsed_barycentric_scale(
    secure_field_point evaluation_point,
    qm31 si0,
    point vanishing_rotation,
    uint32_t log_size,
    qm31 *scales
) {
    secure_field_point rotated =
        secure_point_add_base(evaluation_point, vanishing_rotation);
    qm31 vanishing = rotated.x;
    for (uint32_t i = 1; i < log_size; ++i) {
        vanishing = sub(add(square(vanishing), square(vanishing)), qm31_one());
    }
    scales[0] = mul(si0, vanishing);
    scales[1] = sub(qm31_zero(), scales[0]);
}

DEVICE_FORCEINLINE void collapsed_barycentric_parts(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    uint32_t index,
    secure_field_point evaluation_point,
    qm31 &numerator,
    qm31 &denominator
) {
    point domain_point = domain_at_index(
        half_coset_initial_index,
        half_coset_step_size,
        bit_reverse(index, (int)log_size),
        size);
    qm31 hx = add(
        mul(domain_point.x, evaluation_point.x),
        mul(domain_point.y, evaluation_point.y));
    numerator = sub(
        mul(domain_point.x, evaluation_point.y),
        mul(domain_point.y, evaluation_point.x));
    denominator = add(qm31_one(), hx);
}

// Exact 1024-leaf/512-thread partition used by batch_inverse_secure_field_on.
// In particular, each 1024-row block performs the same 32 root inversions, so
// a zero poisons exactly the same partition as the materialized implementation.
DEVICE_FORCEINLINE void collapsed_batch_inverse_finish_1024(
    qm31 *leaves,
    qm31 *inner_tree,
    qm31 *denominators,
    const qm31 *scales,
    qm31 *weights
) {
    int index = (int)threadIdx.x;
    int size = 512;
    if (index < size) {
        inner_tree[index] = mul(leaves[index << 1], leaves[(index << 1) + 1]);
    }

    int from_offset = 0;
    int dst_offset = size;
    size >>= 1;
    int step = 1;
    while (step + 5 < 10) {
        __syncthreads();
        if (index < size) {
            inner_tree[dst_offset + index] = mul(
                inner_tree[from_offset + (index << 1)],
                inner_tree[from_offset + (index << 1) + 1]);
        }
        from_offset = dst_offset;
        dst_offset += size;
        size >>= 1;
        ++step;
    }

    __syncthreads();
    if (index < (size << 1)) {
        inner_tree[from_offset + index] = inv(inner_tree[from_offset + index]);
    }

    step = 5;
    size = 32;
    dst_offset = from_offset - (size << 1);
    while (step < 9) {
        __syncthreads();
        if (index < size) {
            qm31 temp = inner_tree[dst_offset + (index << 1)];
            inner_tree[dst_offset + (index << 1)] = mul(
                inner_tree[from_offset + index],
                inner_tree[dst_offset + (index << 1) + 1]);
            inner_tree[dst_offset + (index << 1) + 1] =
                mul(inner_tree[from_offset + index], temp);
        }
        size <<= 1;
        from_offset = dst_offset;
        dst_offset = from_offset - (size << 1);
        ++step;
    }

    __syncthreads();
    if (index < size) {
        uint32_t even = (uint32_t)index << 1;
        uint32_t odd = even + 1;
        qm31 inverse_even = mul(inner_tree[index], leaves[odd]);
        qm31 inverse_odd = mul(inner_tree[index], leaves[even]);
        weights[even] = mul(
            mul(denominators[even], inverse_even), scales[even & 1U]);
        weights[odd] = mul(
            mul(denominators[odd], inverse_odd), scales[odd & 1U]);
    }
}

__global__ void barycentric_weights_collapsed_small_kernel(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    const secure_field_point *evaluation_points,
    const uint32_t *descriptor_offsets,
    qm31 si0,
    point vanishing_rotation,
    qm31 *weights
) {
    extern __shared__ qm31 shared[];
    qm31 *scales = shared;
    qm31 *evaluation_point_words = scales + 2;
    __shared__ uint32_t descriptor_offset;
    if (threadIdx.x == 0) {
        descriptor_offset = descriptor_offsets[blockIdx.y];
        secure_field_point evaluation_point = evaluation_points[descriptor_offset];
        evaluation_point_words[0] = evaluation_point.x;
        evaluation_point_words[1] = evaluation_point.y;
        collapsed_barycentric_scale(
            evaluation_point, si0, vanishing_rotation, log_size, scales);
    }
    __syncthreads();

    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) {
        return;
    }
    secure_field_point evaluation_point = {
        evaluation_point_words[0], evaluation_point_words[1]};
    qm31 numerator;
    qm31 denominator;
    collapsed_barycentric_parts(
        half_coset_initial_index,
        half_coset_step_size,
        size,
        log_size,
        index,
        evaluation_point,
        numerator,
        denominator);
    qm31 *group_weights = weights + (size_t)blockIdx.y * size;
    group_weights[index] = mul(
        mul(denominator, inv(numerator)), scales[index & 1U]);
}

__global__ void barycentric_weights_collapsed_1024_kernel(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    const secure_field_point *evaluation_points,
    const uint32_t *descriptor_offsets,
    qm31 si0,
    point vanishing_rotation,
    qm31 *weights
) {
    extern __shared__ qm31 shared[];
    qm31 *leaves = shared;
    qm31 *inner_tree = leaves + 1024;
    qm31 *denominators = inner_tree + 992;
    qm31 *scales = denominators + 1024;
    qm31 *evaluation_point_words = scales + 2;
    __shared__ uint32_t descriptor_offset;
    if (threadIdx.x == 0) {
        descriptor_offset = descriptor_offsets[blockIdx.y];
        secure_field_point evaluation_point = evaluation_points[descriptor_offset];
        evaluation_point_words[0] = evaluation_point.x;
        evaluation_point_words[1] = evaluation_point.y;
        collapsed_barycentric_scale(
            evaluation_point, si0, vanishing_rotation, log_size, scales);
    }
    __syncthreads();

    secure_field_point evaluation_point = {
        evaluation_point_words[0], evaluation_point_words[1]};
    uint32_t first = blockIdx.x * 1024U + threadIdx.x;
    uint32_t second = first + 512U;
    collapsed_barycentric_parts(
        half_coset_initial_index,
        half_coset_step_size,
        size,
        log_size,
        first,
        evaluation_point,
        leaves[first & 1023U],
        denominators[first & 1023U]);
    collapsed_barycentric_parts(
        half_coset_initial_index,
        half_coset_step_size,
        size,
        log_size,
        second,
        evaluation_point,
        leaves[second & 1023U],
        denominators[second & 1023U]);
    __syncthreads();

    qm31 *group_weights = weights + (size_t)blockIdx.y * size +
                          (size_t)blockIdx.x * 1024U;
    collapsed_batch_inverse_finish_1024(
        leaves, inner_tree, denominators, scales, group_weights);
}

} // namespace

extern "C" int stwo_oods_barycentric_weights_collapsed_cohort_on(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    const secure_field_point *evaluation_points,
    const uint32_t *descriptor_offsets,
    uint32_t group_count,
    qm31 si0,
    point vanishing_rotation,
    qm31 *weights,
    void *stream
) {
    if (size < 2 || (size & (size - 1)) != 0 || log_size == 0 ||
        log_size > 30 || size != (1U << log_size) || group_count == 0 ||
        group_count > 65535 || evaluation_points == nullptr ||
        descriptor_offsets == nullptr || weights == nullptr) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    if (size < 1024) {
        uint32_t blocks = (size + OODS_BLOCK_DIM - 1) / OODS_BLOCK_DIM;
        dim3 grid(blocks, group_count);
        constexpr size_t SHARED_BYTES = 4 * sizeof(qm31);
        barycentric_weights_collapsed_small_kernel<<<
            grid, OODS_BLOCK_DIM, SHARED_BYTES, cuda_stream>>>(
            half_coset_initial_index,
            half_coset_step_size,
            size,
            log_size,
            evaluation_points,
            descriptor_offsets,
            si0,
            vanishing_rotation,
            weights);
        return cudaPeekAtLastError();
    }

    constexpr uint32_t BLOCK_DIM = 512;
    constexpr size_t SHARED_QM31 = 1024 + 992 + 1024 + 2 + 2;
    dim3 grid(size / 1024U, group_count);
    barycentric_weights_collapsed_1024_kernel<<<
        grid, BLOCK_DIM, SHARED_QM31 * sizeof(qm31), cuda_stream>>>(
        half_coset_initial_index,
        half_coset_step_size,
        size,
        log_size,
        evaluation_points,
        descriptor_offsets,
        si0,
        vanishing_rotation,
        weights);
    return cudaPeekAtLastError();
}
