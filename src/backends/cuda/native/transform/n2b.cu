#include "../common/circle_twiddle.cuh"
#include "transform_internal.cuh"

// Exact stagewise N2B authority from pinned rfft.cu. The column slab and
// twiddles are proof-session resident and every launch stays on its stream.

namespace {

using stwo::cuda::M31;
using stwo::cuda::circle_twiddle;
using stwo::cuda::m31_add;
using stwo::cuda::m31_mul;
using stwo::cuda::m31_sub;

__global__ void n2b_stage(
    M31 *columns,
    size_t column_stride_words,
    uint32_t log_n,
    uint32_t stage,
    const M31 *layer_twiddles) {
    const uint32_t pair_index =
        blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t column_index = blockIdx.y;
    const uint32_t pair_count = 1u << (log_n - 1u);
    if (pair_index >= pair_count) return;

    const uint32_t stride = 1u << (log_n - stage);
    const uint32_t group_index = pair_index & (stride - 1u);
    const uint32_t butterfly_index = pair_index >> (log_n - stage);
    const uint32_t left_index =
        group_index + butterfly_index * 2u * stride;
    const uint32_t right_index = left_index + stride;
    M31 *column =
        columns + static_cast<size_t>(column_index) * column_stride_words;
    const M31 left = column[left_index];
    const M31 product = m31_mul(
        stage == log_n
            ? circle_twiddle(layer_twiddles, butterfly_index)
            : layer_twiddles[butterfly_index],
        column[right_index]);
    column[left_index] = m31_add(left, product);
    column[right_index] = m31_sub(left, product);
}

}  // namespace

namespace stwo::cuda::transform {

cudaError_t n2b_columns_on(
    uint32_t *columns,
    size_t column_stride_words,
    uint32_t log_n,
    uint32_t polynomial_count,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    cudaStream_t stream,
    bool include_circle) {
    auto *field_columns = reinterpret_cast<M31 *>(columns);
    const auto *domain_twiddles = reinterpret_cast<const M31 *>(
        twiddles + twiddle_words - evaluation_domain_size);
    const uint32_t pair_count = 1u << (log_n - 1u);
    const uint32_t blocks =
        (pair_count + kThreadsPerBlock - 1u) / kThreadsPerBlock;
    const uint32_t final_stage = include_circle ? log_n : log_n - 1u;

    for (uint32_t base = 0; base < polynomial_count;
         base += kMaxColumnsPerLaunch) {
        const uint32_t remaining = polynomial_count - base;
        const uint32_t chunk = remaining < kMaxColumnsPerLaunch
            ? remaining
            : kMaxColumnsPerLaunch;
        uint32_t layer_size = 1;
        uint32_t layer_offset = pair_count - 2u;
        for (uint32_t stage = 1; stage <= final_stage; ++stage) {
            n2b_stage<<<
                dim3(blocks, chunk),
                kThreadsPerBlock,
                0,
                stream>>>(
                    field_columns +
                        static_cast<size_t>(base) * column_stride_words,
                    column_stride_words,
                    log_n,
                    stage,
                    stage == log_n
                        ? domain_twiddles
                        : domain_twiddles + layer_offset);
            const cudaError_t status = cudaPeekAtLastError();
            if (status != cudaSuccess) return status;
            if (stage < log_n - 1u) {
                layer_size <<= 1;
                layer_offset -= layer_size;
            }
        }
    }
    return cudaSuccess;
}

}  // namespace stwo::cuda::transform

extern "C" int stwo_ntt_n2b_columns_on(
    uint32_t *columns,
    size_t column_stride_words,
    uint32_t log_n,
    uint32_t polynomial_count,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    void *stream_raw) {
    using namespace stwo::cuda::transform;
    if (!valid_shape(
            log_n,
            polynomial_count,
            twiddle_words,
            evaluation_domain_size) ||
        stream_raw == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const size_t values = static_cast<size_t>(1) << log_n;
    DeviceRange columns_range{};
    DeviceRange twiddle_range{};
    if (!column_range(
            columns,
            column_stride_words,
            polynomial_count,
            values,
            &columns_range) ||
        !word_range(twiddles, twiddle_words, &twiddle_range) ||
        ranges_overlap(columns_range, twiddle_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    return static_cast<int>(n2b_columns_on(
        columns,
        column_stride_words,
        log_n,
        polynomial_count,
        twiddles,
        twiddle_words,
        evaluation_domain_size,
        reinterpret_cast<cudaStream_t>(stream_raw),
        true));
}
