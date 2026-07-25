#include "n2b_fused.cuh"
#include "transform_internal.cuh"

// Production schedules load and zero-extend coefficients in their first N2B
// interval, avoiding a full evaluation-slab pass. Small and unsupported logs
// retain the standalone staging kernel. The product ABI deliberately accepts
// coefficient log sizes: 5 means 2^5 coefficients, never 5 words.

namespace {

using stwo::cuda::M31;

struct alignas(8) AddressedLdeDescriptor {
    uint64_t coefficient_offset_words;
    uint64_t evaluation_offset_words;
    uint32_t coefficient_log_size;
    uint32_t reserved;
};

static_assert(sizeof(AddressedLdeDescriptor) == 24);
static_assert(alignof(AddressedLdeDescriptor) == 8);
static_assert(offsetof(AddressedLdeDescriptor, coefficient_log_size) == 16);

__global__ void stage_addressed_lde_columns(
    uint32_t *arena,
    size_t arena_words,
    const AddressedLdeDescriptor *descriptors,
    uint32_t descriptor_count,
    size_t evaluation_tile_offset_words,
    uint32_t log_n) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t column = blockIdx.y;
    if (column >= descriptor_count) return;
    const AddressedLdeDescriptor descriptor = descriptors[column];
    const size_t output_size = static_cast<size_t>(1) << log_n;
    const size_t expected_destination =
        evaluation_tile_offset_words +
        static_cast<size_t>(column) * output_size;
    if (descriptor.reserved != 0 ||
        descriptor.coefficient_log_size >= log_n ||
        descriptor.evaluation_offset_words != expected_destination) {
        return;
    }
    const size_t coefficient_count =
        static_cast<size_t>(1) << descriptor.coefficient_log_size;
    const size_t source_offset =
        static_cast<size_t>(descriptor.coefficient_offset_words);
    const size_t destination_offset =
        static_cast<size_t>(descriptor.evaluation_offset_words);
    const size_t tile_words =
        static_cast<size_t>(descriptor_count) * output_size;
    if (source_offset > arena_words ||
        coefficient_count > arena_words - source_offset ||
        destination_offset > arena_words ||
        output_size > arena_words - destination_offset ||
        evaluation_tile_offset_words > arena_words ||
        tile_words > arena_words - evaluation_tile_offset_words ||
        (source_offset < evaluation_tile_offset_words + tile_words &&
         evaluation_tile_offset_words < source_offset + coefficient_count)) {
        return;
    }
    if (index < output_size) {
        arena[destination_offset + index] =
            index < coefficient_count ? arena[source_offset + index] : 0;
    }
}

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

extern "C" int stwo_lde_n2b_addressed_on(
    uint32_t *arena,
    size_t arena_words,
    const AddressedLdeDescriptor *descriptors,
    uint32_t descriptor_count,
    size_t evaluation_tile_offset_words,
    uint32_t log_n,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    void *stream_raw,
    uint32_t include_circle,
    uint32_t *launches_out) {
    using namespace stwo::cuda::transform;
    if (launches_out != nullptr) *launches_out = 0;
    if (!valid_shape(
            log_n,
            descriptor_count,
            twiddle_words,
            evaluation_domain_size) ||
        stream_raw == nullptr ||
        launches_out == nullptr ||
        include_circle > 1u ||
        descriptor_count > kMaxColumnsPerLaunch) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const size_t output_size =
        static_cast<size_t>(2) * evaluation_domain_size;
    if (descriptor_count > SIZE_MAX / output_size) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const size_t tile_words =
        static_cast<size_t>(descriptor_count) * output_size;
    if (evaluation_tile_offset_words > arena_words ||
        tile_words > arena_words - evaluation_tile_offset_words) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    DeviceRange arena_range{};
    DeviceRange descriptor_range{};
    DeviceRange twiddle_range{};
    DeviceRange tile_range{};
    if (!word_range(arena, arena_words, &arena_range) ||
        !word_range(descriptors, descriptor_count * 6u, &descriptor_range) ||
        !word_range(twiddles, twiddle_words, &twiddle_range) ||
        !word_range(
            arena + evaluation_tile_offset_words,
            tile_words,
            &tile_range) ||
        descriptor_range.start < arena_range.start ||
        descriptor_range.end > arena_range.end ||
        twiddle_range.start < arena_range.start ||
        twiddle_range.end > arena_range.end ||
        ranges_overlap(tile_range, descriptor_range) ||
        ranges_overlap(tile_range, twiddle_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    const cudaStream_t stream =
        reinterpret_cast<cudaStream_t>(stream_raw);
    const uint32_t blocks = static_cast<uint32_t>(
        (output_size + kThreadsPerBlock - 1u) / kThreadsPerBlock);
    stage_addressed_lde_columns<<<
        dim3(blocks, descriptor_count),
        kThreadsPerBlock,
        0,
        stream>>>(
            arena,
            arena_words,
            descriptors,
            descriptor_count,
            evaluation_tile_offset_words,
            log_n);
    cudaError_t status = cudaPeekAtLastError();
    if (status != cudaSuccess) return static_cast<int>(status);
    ++*launches_out;
    return static_cast<int>(n2b_columns_on(
        arena + evaluation_tile_offset_words,
        output_size,
        log_n,
        descriptor_count,
        twiddles,
        twiddle_words,
        evaluation_domain_size,
        stream,
        include_circle != 0,
        launches_out));
}

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
