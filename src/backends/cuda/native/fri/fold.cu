// Resident FRI folds over contiguous coordinate-major slabs. The circle fold
// intentionally accumulates into prior folded values; line and fused folds
// overwrite their logical destination ranges.

#include "field.cuh"
#include "safety.cuh"
#include "../commitment/blake2s_core.cuh"

#include <cuda_runtime_api.h>

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::fri {

using Blake2sHash = stwo::cuda::blake2s::Hash;

constexpr uint32_t kThreads = 256;
constexpr uint32_t kMaximumLogSize = 30;

__device__ __forceinline__ QM31 squared_alpha(
    const QM31 *alpha,
    uint32_t squarings) {
    QM31 result = *alpha;
    for (uint32_t square = 0; square < squarings; ++square) {
        result = mul(result, result);
    }
    return result;
}

__device__ __forceinline__ QM31 fold_pair(
    QM31 left,
    QM31 right,
    M31 inverse_x,
    QM31 alpha) {
    const QM31 even = add(left, right);
    const QM31 odd = mul(inverse_x, sub(left, right));
    return add(even, mul(alpha, odd));
}

__device__ __forceinline__ void hash_leaf(
    QM31 value,
    Blake2sHash *result) {
    uint32_t hash[8];
    uint32_t message[16] = {
        value.first.real,
        value.first.imag,
        value.second.real,
        value.second.imag,
    };
    stwo::cuda::blake2s::initialize_leaf(hash);
    stwo::cuda::blake2s::compress(hash, message, 80, 0xffffffffu);
#pragma unroll
    for (uint32_t index = 0; index < 8; ++index) {
        result->words[index] = hash[index];
    }
}

template <bool EmitLeaf>
__global__ void fold_circle_kernel(
    const M31 *domain,
    uint32_t twiddle_offset,
    uint32_t size,
    const uint32_t *evaluations,
    uint32_t evaluation_stride,
    const QM31 *alpha_pointer,
    uint32_t alpha_squarings,
    uint32_t *folded,
    uint32_t folded_stride,
    Blake2sHash *leaves) {
    const uint32_t output_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (output_index >= size / 2) return;

    const QM31 alpha = squared_alpha(alpha_pointer, alpha_squarings);
    const QM31 folded_pair = fold_pair(
        load(evaluations, evaluation_stride, 2 * output_index),
        load(evaluations, evaluation_stride, 2 * output_index + 1),
        circle_twiddle(domain + twiddle_offset, output_index),
        alpha);
    const QM31 previous = load(folded, folded_stride, output_index);
    const QM31 result =
        add(mul(mul(alpha, alpha), previous), folded_pair);
    store(folded, folded_stride, output_index, result);
    if constexpr (EmitLeaf) hash_leaf(result, leaves + output_index);
}

template <bool EmitLeaf>
__global__ void fold_line_kernel(
    const M31 *domain,
    uint32_t twiddle_offset,
    uint32_t size,
    const uint32_t *evaluations,
    uint32_t evaluation_stride,
    const QM31 *alpha_pointer,
    uint32_t alpha_squarings,
    uint32_t *folded,
    uint32_t folded_stride,
    Blake2sHash *leaves) {
    const uint32_t output_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (output_index >= size / 2) return;

    const QM31 alpha = squared_alpha(alpha_pointer, alpha_squarings);
    const QM31 result = fold_pair(
        load(evaluations, evaluation_stride, 2 * output_index),
        load(evaluations, evaluation_stride, 2 * output_index + 1),
        domain[twiddle_offset + output_index],
        alpha);
    store(folded, folded_stride, output_index, result);
    if constexpr (EmitLeaf) hash_leaf(result, leaves + output_index);
}

__global__ void fold_three_kernel(
    const M31 *domain,
    uint32_t twiddle_offset_0,
    uint32_t twiddle_offset_1,
    uint32_t twiddle_offset_2,
    uint32_t size,
    uint32_t first_is_circle,
    const uint32_t *evaluations,
    uint32_t evaluation_stride,
    const QM31 *alpha_pointer,
    uint32_t *folded,
    uint32_t folded_stride) {
    const uint32_t output_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (output_index >= size / 8) return;

    const QM31 alpha_0 = *alpha_pointer;
    const QM31 alpha_1 = mul(alpha_0, alpha_0);
    const QM31 alpha_2 = mul(alpha_1, alpha_1);
    QM31 stage_0[4];
#pragma unroll
    for (uint32_t pair = 0; pair < 4; ++pair) {
        const uint32_t index = 4 * output_index + pair;
        const M31 inverse_x = first_is_circle != 0
            ? circle_twiddle(domain + twiddle_offset_0, index)
            : domain[twiddle_offset_0 + index];
        stage_0[pair] = fold_pair(
            load(evaluations, evaluation_stride, 2 * index),
            load(evaluations, evaluation_stride, 2 * index + 1),
            inverse_x,
            alpha_0);
    }

    QM31 stage_1[2];
#pragma unroll
    for (uint32_t pair = 0; pair < 2; ++pair) {
        const uint32_t index = 2 * output_index + pair;
        stage_1[pair] = fold_pair(
            stage_0[2 * pair],
            stage_0[2 * pair + 1],
            domain[twiddle_offset_1 + index],
            alpha_1);
    }
    store(
        folded,
        folded_stride,
        output_index,
        fold_pair(
            stage_1[0],
            stage_1[1],
            domain[twiddle_offset_2 + output_index],
            alpha_2));
}

inline bool valid_fold(
    const uint32_t *domain,
    size_t domain_words,
    uint32_t twiddle_offset,
    uint32_t required_twiddles,
    uint32_t size,
    const uint32_t *evaluations,
    size_t evaluation_words,
    uint32_t evaluation_stride,
    const QM31 *alpha,
    uint32_t alpha_squarings,
    uint32_t *folded,
    size_t folded_words,
    uint32_t folded_stride,
    void *stream) {
    const uint32_t output_count = size / 2;
    size_t evaluation_bytes = 0;
    size_t folded_bytes = 0;
    return domain != nullptr && size >= 2 &&
        size <= (1u << kMaximumLogSize) && is_power_of_two(size) &&
        twiddle_offset <= domain_words &&
        required_twiddles <= domain_words - twiddle_offset &&
        evaluations != nullptr && alpha != nullptr && folded != nullptr &&
        evaluation_words == static_cast<size_t>(4) * evaluation_stride &&
        folded_words == static_cast<size_t>(4) * folded_stride &&
        evaluation_stride >= size && folded_stride >= output_count &&
        alpha_squarings <= kMaximumLogSize && stream != nullptr &&
        checked_bytes(evaluation_words, sizeof(uint32_t), &evaluation_bytes) &&
        checked_bytes(folded_words, sizeof(uint32_t), &folded_bytes) &&
        !ranges_overlap(
            evaluations, evaluation_bytes, folded, folded_bytes);
}

inline bool valid_leaf_output(
    const uint32_t *domain,
    size_t domain_words,
    const uint32_t *evaluations,
    size_t evaluation_words,
    const QM31 *alpha,
    const uint32_t *folded,
    size_t folded_words,
    Blake2sHash *leaves,
    size_t leaf_count,
    uint32_t output_count) {
    size_t domain_bytes = 0, evaluation_bytes = 0;
    size_t folded_bytes = 0, leaf_bytes = 0;
    return leaves != nullptr && leaf_count == output_count &&
        reinterpret_cast<uintptr_t>(leaves) % alignof(Blake2sHash) == 0 &&
        checked_bytes(domain_words, sizeof(uint32_t), &domain_bytes) &&
        checked_bytes(evaluation_words, sizeof(uint32_t), &evaluation_bytes) &&
        checked_bytes(folded_words, sizeof(uint32_t), &folded_bytes) &&
        checked_bytes(leaf_count, sizeof(Blake2sHash), &leaf_bytes) &&
        !stwo::cuda::fri::ranges_overlap(
            domain, domain_bytes, leaves, leaf_bytes) &&
        !stwo::cuda::fri::ranges_overlap(
            alpha, sizeof(QM31), leaves, leaf_bytes) &&
        !stwo::cuda::fri::ranges_overlap(
            evaluations, evaluation_bytes, leaves, leaf_bytes) &&
        !stwo::cuda::fri::ranges_overlap(
            folded, folded_bytes, leaves, leaf_bytes);
}

template <bool EmitLeaf>
int launch_circle(
    const uint32_t *domain,
    size_t domain_words,
    uint32_t twiddle_offset,
    uint32_t size,
    const uint32_t *evaluations,
    size_t evaluation_words,
    uint32_t evaluation_stride,
    const QM31 *alpha,
    uint32_t alpha_squarings,
    uint32_t *folded,
    size_t folded_words,
    uint32_t folded_stride,
    Blake2sHash *leaves,
    size_t leaf_count,
    void *stream) {
    const uint32_t output_count = size / 2;
    const uint32_t required_twiddles = 2 * ((output_count + 3) / 4);
    if (!valid_fold(
            domain, domain_words, twiddle_offset, required_twiddles, size,
            evaluations, evaluation_words, evaluation_stride, alpha,
            alpha_squarings, folded, folded_words, folded_stride, stream) ||
        (EmitLeaf &&
         !valid_leaf_output(
             domain,
             domain_words,
             evaluations,
             evaluation_words,
             alpha,
             folded,
             folded_words,
             leaves,
             leaf_count,
             output_count))) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const uint32_t blocks = (output_count + kThreads - 1) / kThreads;
    fold_circle_kernel<EmitLeaf><<<
        blocks,
        kThreads,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            domain,
            twiddle_offset,
            size,
            evaluations,
            evaluation_stride,
            alpha,
            alpha_squarings,
            folded,
            folded_stride,
            leaves);
    return static_cast<int>(cudaPeekAtLastError());
}

template <bool EmitLeaf>
int launch_line(
    const uint32_t *domain,
    size_t domain_words,
    uint32_t twiddle_offset,
    uint32_t size,
    const uint32_t *evaluations,
    size_t evaluation_words,
    uint32_t evaluation_stride,
    const QM31 *alpha,
    uint32_t alpha_squarings,
    uint32_t *folded,
    size_t folded_words,
    uint32_t folded_stride,
    Blake2sHash *leaves,
    size_t leaf_count,
    void *stream) {
    const uint32_t output_count = size / 2;
    if (!valid_fold(
            domain, domain_words, twiddle_offset, output_count, size,
            evaluations, evaluation_words, evaluation_stride, alpha,
            alpha_squarings, folded, folded_words, folded_stride, stream) ||
        (EmitLeaf &&
         !valid_leaf_output(
             domain,
             domain_words,
             evaluations,
             evaluation_words,
             alpha,
             folded,
             folded_words,
             leaves,
             leaf_count,
             output_count))) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const uint32_t blocks = (output_count + kThreads - 1) / kThreads;
    fold_line_kernel<EmitLeaf><<<
        blocks,
        kThreads,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            domain,
            twiddle_offset,
            size,
            evaluations,
            evaluation_stride,
            alpha,
            alpha_squarings,
            folded,
            folded_stride,
            leaves);
    return static_cast<int>(cudaPeekAtLastError());
}

}  // namespace stwo::cuda::fri

extern "C" int stwo_fold_circle_into_line_on(
    const uint32_t *domain,
    size_t domain_words,
    uint32_t twiddle_offset,
    uint32_t size,
    const uint32_t *evaluations,
    size_t evaluation_words,
    uint32_t evaluation_stride,
    const stwo::cuda::fri::QM31 *alpha,
    uint32_t alpha_squarings,
    uint32_t *folded,
    size_t folded_words,
    uint32_t folded_stride,
    void *stream) {
    return stwo::cuda::fri::launch_circle<false>(
        domain, domain_words, twiddle_offset, size, evaluations,
        evaluation_words, evaluation_stride, alpha, alpha_squarings, folded,
        folded_words, folded_stride, nullptr, 0, stream);
}

extern "C" int stwo_fold_circle_into_line_and_hash_on(
    const uint32_t *domain,
    size_t domain_words,
    uint32_t twiddle_offset,
    uint32_t size,
    const uint32_t *evaluations,
    size_t evaluation_words,
    uint32_t evaluation_stride,
    const stwo::cuda::fri::QM31 *alpha,
    uint32_t alpha_squarings,
    uint32_t *folded,
    size_t folded_words,
    uint32_t folded_stride,
    stwo::cuda::fri::Blake2sHash *leaves,
    size_t leaf_count,
    void *stream) {
    return stwo::cuda::fri::launch_circle<true>(
        domain, domain_words, twiddle_offset, size, evaluations,
        evaluation_words, evaluation_stride, alpha, alpha_squarings, folded,
        folded_words, folded_stride, leaves, leaf_count, stream);
}

extern "C" int stwo_fold_line_on(
    const uint32_t *domain,
    size_t domain_words,
    uint32_t twiddle_offset,
    uint32_t size,
    const uint32_t *evaluations,
    size_t evaluation_words,
    uint32_t evaluation_stride,
    const stwo::cuda::fri::QM31 *alpha,
    uint32_t alpha_squarings,
    uint32_t *folded,
    size_t folded_words,
    uint32_t folded_stride,
    void *stream) {
    return stwo::cuda::fri::launch_line<false>(
        domain, domain_words, twiddle_offset, size, evaluations,
        evaluation_words, evaluation_stride, alpha, alpha_squarings, folded,
        folded_words, folded_stride, nullptr, 0, stream);
}

extern "C" int stwo_fold_line_and_hash_on(
    const uint32_t *domain,
    size_t domain_words,
    uint32_t twiddle_offset,
    uint32_t size,
    const uint32_t *evaluations,
    size_t evaluation_words,
    uint32_t evaluation_stride,
    const stwo::cuda::fri::QM31 *alpha,
    uint32_t alpha_squarings,
    uint32_t *folded,
    size_t folded_words,
    uint32_t folded_stride,
    stwo::cuda::fri::Blake2sHash *leaves,
    size_t leaf_count,
    void *stream) {
    return stwo::cuda::fri::launch_line<true>(
        domain, domain_words, twiddle_offset, size, evaluations,
        evaluation_words, evaluation_stride, alpha, alpha_squarings, folded,
        folded_words, folded_stride, leaves, leaf_count, stream);
}

extern "C" int stwo_fri_fold_fused3_on(
    const uint32_t *domain,
    size_t domain_words,
    uint32_t twiddle_offset_0,
    uint32_t twiddle_offset_1,
    uint32_t twiddle_offset_2,
    uint32_t size,
    uint32_t first_is_circle,
    const uint32_t *evaluations,
    size_t evaluation_words,
    uint32_t evaluation_stride,
    const stwo::cuda::fri::QM31 *alpha,
    uint32_t *folded,
    size_t folded_words,
    uint32_t folded_stride,
    void *stream) {
    const uint32_t stage_0_words =
        first_is_circle != 0 ? size / 4 : size / 2;
    size_t evaluation_bytes = 0;
    size_t folded_bytes = 0;
    if (domain == nullptr || size < 8 ||
        size > (1u << stwo::cuda::fri::kMaximumLogSize) ||
        !stwo::cuda::fri::is_power_of_two(size) || first_is_circle > 1 ||
        twiddle_offset_0 > domain_words ||
        stage_0_words > domain_words - twiddle_offset_0 ||
        twiddle_offset_1 > domain_words ||
        size / 4 > domain_words - twiddle_offset_1 ||
        twiddle_offset_2 > domain_words ||
        size / 8 > domain_words - twiddle_offset_2 ||
        evaluations == nullptr || alpha == nullptr || folded == nullptr ||
        evaluation_words != static_cast<size_t>(4) * evaluation_stride ||
        folded_words != static_cast<size_t>(4) * folded_stride ||
        evaluation_stride < size || folded_stride < size / 8 ||
        stream == nullptr ||
        !stwo::cuda::fri::checked_bytes(
            evaluation_words, sizeof(uint32_t), &evaluation_bytes) ||
        !stwo::cuda::fri::checked_bytes(
            folded_words, sizeof(uint32_t), &folded_bytes) ||
        stwo::cuda::fri::ranges_overlap(
            evaluations, evaluation_bytes, folded, folded_bytes)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const uint32_t output_count = size / 8;
    const uint32_t blocks =
        (output_count + stwo::cuda::fri::kThreads - 1) /
        stwo::cuda::fri::kThreads;
    stwo::cuda::fri::fold_three_kernel<<<
        blocks,
        stwo::cuda::fri::kThreads,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            domain, twiddle_offset_0, twiddle_offset_1, twiddle_offset_2,
            size, first_is_circle, evaluations, evaluation_stride, alpha,
            folded, folded_stride);
    return static_cast<int>(cudaPeekAtLastError());
}
