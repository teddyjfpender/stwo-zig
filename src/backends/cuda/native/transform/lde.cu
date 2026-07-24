#include "n2b_fused.cuh"
#include "transform_internal.cuh"

// Production schedules load and zero-extend coefficients in their first N2B
// interval, avoiding a full evaluation-slab pass. Small and unsupported logs
// retain the standalone staging kernel. The product ABI deliberately accepts
// coefficient log sizes: 5 means 2^5 coefficients, never 5 words.

namespace {

using stwo::cuda::M31;

__global__ void stage_lde_columns(
    const uint32_t *coefficients,
    size_t coefficient_column_stride_words,
    const uint32_t *coefficient_log_sizes,
    uint32_t *evaluations,
    size_t evaluation_column_stride_words,
    uint32_t evaluation_domain_size) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t column = blockIdx.y;
    const uint32_t output_size = 2u * evaluation_domain_size;
    if (index >= output_size) return;
    const uint32_t coefficient_log_size = coefficient_log_sizes[column];
    const uint32_t requested_count = coefficient_log_size < 31u
        ? 1u << coefficient_log_size
        : 0u;
    const uint32_t coefficient_count =
        requested_count < evaluation_domain_size
        ? requested_count
        : evaluation_domain_size;
    const uint32_t *coefficient_column =
        coefficients + static_cast<size_t>(column) *
            coefficient_column_stride_words;
    uint32_t *evaluation_column =
        evaluations + static_cast<size_t>(column) *
            evaluation_column_stride_words;
    evaluation_column[index] = index < coefficient_count
        ? coefficient_column[index]
        : 0;
}

int lde_columns_on(
    const uint32_t *coefficients,
    size_t coefficient_column_stride_words,
    const uint32_t *coefficient_log_sizes,
    uint32_t *evaluations,
    size_t evaluation_column_stride_words,
    uint32_t log_n,
    uint32_t polynomial_count,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    void *stream_raw,
    bool include_circle,
    uint32_t *launches_out) {
    using namespace stwo::cuda::transform;
    if (launches_out != nullptr) *launches_out = 0;
    if (!valid_shape(
            log_n,
            polynomial_count,
            twiddle_words,
            evaluation_domain_size) ||
        stream_raw == nullptr ||
        launches_out == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    const size_t output_size =
        static_cast<size_t>(2) * evaluation_domain_size;
    DeviceRange coefficient_range{};
    DeviceRange size_range{};
    DeviceRange evaluation_range{};
    DeviceRange twiddle_range{};
    if (!column_range(
            coefficients,
            coefficient_column_stride_words,
            polynomial_count,
            evaluation_domain_size,
            &coefficient_range) ||
        !word_range(coefficient_log_sizes, polynomial_count, &size_range) ||
        !column_range(
            evaluations,
            evaluation_column_stride_words,
            polynomial_count,
            output_size,
            &evaluation_range) ||
        !word_range(twiddles, twiddle_words, &twiddle_range) ||
        ranges_overlap(evaluation_range, coefficient_range) ||
        ranges_overlap(evaluation_range, size_range) ||
        ranges_overlap(evaluation_range, twiddle_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const cudaStream_t stream =
        reinterpret_cast<cudaStream_t>(stream_raw);
    const auto *domain_twiddles = reinterpret_cast<const M31 *>(
        twiddles + twiddle_words - evaluation_domain_size);
    const bool fuse_first_interval =
        log_n >= kFirstFusedLogN && log_n <= kLastFusedLogN;
    const uint32_t blocks = static_cast<uint32_t>(
        (output_size + kThreadsPerBlock - 1u) / kThreadsPerBlock);
    for (uint32_t base = 0; base < polynomial_count;
         base += kMaxColumnsPerLaunch) {
        const uint32_t remaining = polynomial_count - base;
        const uint32_t chunk = remaining < kMaxColumnsPerLaunch
            ? remaining
            : kMaxColumnsPerLaunch;
        cudaError_t status = cudaSuccess;
        if (fuse_first_interval) {
            const TransformSchedule &schedule =
                kN2bSchedules[log_n - kFirstFusedLogN];
            status = launch_n2b_first_from_coefficients(
                {
                    reinterpret_cast<const M31 *>(coefficients) +
                        static_cast<size_t>(base) *
                            coefficient_column_stride_words,
                    coefficient_column_stride_words,
                },
                coefficient_log_sizes + base,
                {
                    reinterpret_cast<M31 *>(evaluations) +
                        static_cast<size_t>(base) *
                            evaluation_column_stride_words,
                    evaluation_column_stride_words,
                },
                log_n,
                chunk,
                schedule.intervals[0],
                domain_twiddles,
                stream);
        } else {
            stage_lde_columns<<<
                dim3(blocks, chunk),
                kThreadsPerBlock,
                0,
                stream>>>(
                    coefficients +
                        static_cast<size_t>(base) *
                            coefficient_column_stride_words,
                    coefficient_column_stride_words,
                    coefficient_log_sizes + base,
                    evaluations +
                        static_cast<size_t>(base) *
                            evaluation_column_stride_words,
                    evaluation_column_stride_words,
                    evaluation_domain_size);
            status = cudaPeekAtLastError();
        }
        if (status != cudaSuccess) return static_cast<int>(status);
        ++*launches_out;
    }
    if (fuse_first_interval) {
        return static_cast<int>(n2b_columns_after_first_interval_on(
            evaluations,
            evaluation_column_stride_words,
            log_n,
            polynomial_count,
            twiddles,
            twiddle_words,
            evaluation_domain_size,
            stream,
            include_circle,
            launches_out));
    }
    return static_cast<int>(n2b_columns_on(
        evaluations,
        evaluation_column_stride_words,
        log_n,
        polynomial_count,
        twiddles,
        twiddle_words,
        evaluation_domain_size,
        stream,
        include_circle,
        launches_out));
}

}  // namespace

extern "C" int stwo_lde_n2b_columns_on(
    const uint32_t *coefficients,
    size_t coefficient_column_stride_words,
    const uint32_t *coefficient_log_sizes,
    uint32_t *evaluations,
    size_t evaluation_column_stride_words,
    uint32_t log_n,
    uint32_t polynomial_count,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    void *stream_raw,
    uint32_t *launches_out) {
    return lde_columns_on(
        coefficients,
        coefficient_column_stride_words,
        coefficient_log_sizes,
        evaluations,
        evaluation_column_stride_words,
        log_n,
        polynomial_count,
        twiddles,
        twiddle_words,
        evaluation_domain_size,
        stream_raw,
        true,
        launches_out);
}

extern "C" int stwo_lde_n2b_columns_before_circle_on(
    const uint32_t *coefficients,
    size_t coefficient_column_stride_words,
    const uint32_t *coefficient_log_sizes,
    uint32_t *evaluations,
    size_t evaluation_column_stride_words,
    uint32_t log_n,
    uint32_t polynomial_count,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    void *stream_raw,
    uint32_t *launches_out) {
    return lde_columns_on(
        coefficients,
        coefficient_column_stride_words,
        coefficient_log_sizes,
        evaluations,
        evaluation_column_stride_words,
        log_n,
        polynomial_count,
        twiddles,
        twiddle_words,
        evaluation_domain_size,
        stream_raw,
        false,
        launches_out);
}
