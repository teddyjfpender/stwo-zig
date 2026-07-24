#include "quotient_numerator_single_write.cuh"
#include "m31_fast32.cuh"
#include "resource_attestation.cuh"

#include <cstdint>
#include <cuda_runtime.h>

namespace {

constexpr uint32_t TERM_WORDS = 3;
constexpr uint32_t PREPACKED_TERM_WORDS = 7;
constexpr uint32_t PREPACKED_GROUP_WORDS = 4;
constexpr uint32_t PREPACKED_STATUS_WORDS = 1;
constexpr uint32_t BLOCK_THREADS = 256;
constexpr uint64_t MAX_GRID_X = 2147483647ull;

__device__ __forceinline__ qm31 prepacked_load_qm31(const uint32_t *words) {
    return qm31{cm31{words[0], words[1]}, cm31{words[2], words[3]}};
}

__device__ __forceinline__ void prepacked_store_qm31(
        uint32_t *words,
        qm31 value
) {
    words[0] = value.a.a;
    words[1] = value.a.b;
    words[2] = value.b.a;
    words[3] = value.b.b;
}

__device__ __forceinline__ qm31 prepacked_add(qm31 lhs, qm31 rhs) {
    return qm31{
        cm31{
            stwo_m31_add_fast32(lhs.a.a, rhs.a.a),
            stwo_m31_add_fast32(lhs.a.b, rhs.a.b),
        },
        cm31{
            stwo_m31_add_fast32(lhs.b.a, rhs.b.a),
            stwo_m31_add_fast32(lhs.b.b, rhs.b.b),
        },
    };
}

__device__ __forceinline__ qm31 prepacked_sub(qm31 lhs, qm31 rhs) {
    return qm31{
        cm31{
            stwo_m31_sub_fast32(lhs.a.a, rhs.a.a),
            stwo_m31_sub_fast32(lhs.a.b, rhs.a.b),
        },
        cm31{
            stwo_m31_sub_fast32(lhs.b.a, rhs.b.a),
            stwo_m31_sub_fast32(lhs.b.b, rhs.b.b),
        },
    };
}

__device__ __forceinline__ qm31 prepacked_mul_by_scalar(
        qm31 value,
        m31 scalar
) {
    return qm31{
        cm31{
            stwo_m31_mul_fast32(value.a.a, scalar),
            stwo_m31_mul_fast32(value.a.b, scalar),
        },
        cm31{
            stwo_m31_mul_fast32(value.b.a, scalar),
            stwo_m31_mul_fast32(value.b.b, scalar),
        },
    };
}

__device__ __forceinline__ uint32_t *prepacked_status(
        uint32_t *storage,
        uint32_t term_count,
        uint32_t group_count
) {
    return storage +
        static_cast<size_t>(term_count) * PREPACKED_TERM_WORDS +
        static_cast<size_t>(group_count) * PREPACKED_GROUP_WORDS;
}

__device__ __forceinline__ void prepacked_record_status(
        uint32_t *status,
        StwoQuotientNumeratorPrepackedStatus code
) {
    const uint32_t requested = static_cast<uint32_t>(code);
    uint32_t current = atomicCAS(status, 0, 0);
    while (current == 0 || requested < current) {
        const uint32_t observed = atomicCAS(status, current, requested);
        if (observed == current) {
            return;
        }
        current = observed;
    }
}

} // namespace

// One thread owns one (group, row) numerator. The descriptor builder preserves
// the legacy batch order inside every group, so this changes memory ownership,
// not field semantics: no zero pass and no global read/modify/write cascade.
extern "C" __global__ void stwo_quotient_numerator_single_write_kernel(
        const uint32_t *group_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint32_t max_output_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t group = blockIdx.y;
    if (group >= group_count || row >= max_output_size) {
        return;
    }
    const uint32_t group_log_size = group_log_sizes[group];
    if (row >= (1u << group_log_size)) {
        return;
    }

    qm31 numerator = qm31{cm31{0, 0}, cm31{0, 0}};
    for (uint32_t index = group_offsets[group];
         index < group_offsets[group + 1]; ++index) {
        const uint32_t *descriptor =
            term_descriptors + static_cast<size_t>(index) * TERM_WORDS;
        const uint32_t source = descriptor[0];
        const uint32_t term = descriptor[1];
        const uint32_t source_log_size = descriptor[2];
        const uint32_t log_ratio = group_log_size - source_log_size;
        const uint32_t source_row =
            (row >> (log_ratio + 1) << 1) + (row & 1);
        const qm31 b = line_coefficients[static_cast<size_t>(term) * 3 + 1];
        const qm31 c = line_coefficients[static_cast<size_t>(term) * 3 + 2];
        numerator = add(
            numerator,
            sub(mul_by_scalar(c, source_evaluations[source][source_row]), b));
    }

    outputs_0[group][row] = numerator.a.a;
    outputs_1[group][row] = numerator.a.b;
    outputs_2[group][row] = numerator.b.a;
    outputs_3[group][row] = numerator.b.b;
}

extern "C" int stwo_accumulate_quotient_numerator_single_write_on(
        const uint32_t *group_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint32_t max_output_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3,
        void *stream) {
    if (group_offsets == nullptr || term_descriptors == nullptr ||
        group_count == 0 || group_count > 65535 || max_output_size == 0 ||
        source_evaluations == nullptr || line_coefficients == nullptr ||
        group_log_sizes == nullptr || outputs_0 == nullptr ||
        outputs_1 == nullptr || outputs_2 == nullptr ||
        outputs_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint32_t blocks =
        (max_output_size + BLOCK_THREADS - 1) / BLOCK_THREADS;
    stwo_quotient_numerator_single_write_kernel<<<
        dim3(blocks, group_count), BLOCK_THREADS, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            group_offsets, term_descriptors, group_count, max_output_size,
            source_evaluations, line_coefficients, group_log_sizes, outputs_0,
            outputs_1, outputs_2, outputs_3);
    return cudaGetLastError();
}

// One exact packed row owns one canonical (group, row) numerator. The binary
// search mirrors QuotientNumeratorStagedSingleWritePlan::packed_row_location.
extern "C" __global__ void stwo_quotient_numerator_packed_single_write_kernel(
        const uint64_t *group_row_offsets,
        const uint32_t *group_term_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint64_t packed_output_rows,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3) {
    const uint64_t packed_row =
        static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (packed_row >= packed_output_rows || group_row_offsets[0] != 0 ||
        group_row_offsets[group_count] != packed_output_rows) {
        return;
    }

    uint32_t low = 0;
    uint32_t high = group_count;
    while (low < high) {
        const uint32_t middle = low + (high - low) / 2;
        if (packed_row < group_row_offsets[middle + 1]) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    const uint32_t group = low;
    if (group >= group_count) {
        return;
    }
    const uint64_t group_begin = group_row_offsets[group];
    const uint64_t group_end = group_row_offsets[group + 1];
    const uint32_t group_log_size = group_log_sizes[group];
    if (group_begin > packed_row || group_end <= packed_row ||
        group_log_size >= 31 ||
        group_end - group_begin != (1ull << group_log_size)) {
        return;
    }
    const uint32_t row = static_cast<uint32_t>(packed_row - group_begin);

    qm31 numerator = qm31{cm31{0, 0}, cm31{0, 0}};
    for (uint32_t index = group_term_offsets[group];
         index < group_term_offsets[group + 1]; ++index) {
        const uint32_t *descriptor =
            term_descriptors + static_cast<size_t>(index) * TERM_WORDS;
        const uint32_t source = descriptor[0];
        const uint32_t term = descriptor[1];
        const uint32_t source_log_size = descriptor[2];
        const uint32_t log_ratio = group_log_size - source_log_size;
        const uint32_t source_row =
            (row >> (log_ratio + 1) << 1) + (row & 1);
        const qm31 b = line_coefficients[static_cast<size_t>(term) * 3 + 1];
        const qm31 c = line_coefficients[static_cast<size_t>(term) * 3 + 2];
        numerator = add(
            numerator,
            sub(mul_by_scalar(c, source_evaluations[source][source_row]), b));
    }

    outputs_0[group][row] = numerator.a.a;
    outputs_1[group][row] = numerator.a.b;
    outputs_2[group][row] = numerator.b.a;
    outputs_3[group][row] = numerator.b.b;
}

extern "C" int stwo_accumulate_quotient_numerator_packed_single_write_on(
        const uint64_t *group_row_offsets,
        const uint32_t *group_term_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint64_t packed_output_rows,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3,
        void *stream) {
    if (group_row_offsets == nullptr || group_term_offsets == nullptr ||
        term_descriptors == nullptr || group_count == 0 ||
        packed_output_rows == 0 || source_evaluations == nullptr ||
        line_coefficients == nullptr || group_log_sizes == nullptr ||
        outputs_0 == nullptr || outputs_1 == nullptr || outputs_2 == nullptr ||
        outputs_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint64_t blocks =
        (packed_output_rows + BLOCK_THREADS - 1) / BLOCK_THREADS;
    if (blocks == 0 || blocks > MAX_GRID_X) {
        return cudaErrorInvalidConfiguration;
    }
    stwo_quotient_numerator_packed_single_write_kernel<<<
        static_cast<uint32_t>(blocks), BLOCK_THREADS, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            group_row_offsets, group_term_offsets, term_descriptors,
            group_count, packed_output_rows, source_evaluations,
            line_coefficients, group_log_sizes, outputs_0, outputs_1,
            outputs_2, outputs_3);
    return cudaGetLastError();
}

namespace {

__device__ __forceinline__ uint32_t group_direct_source_row(
        uint32_t row,
        uint32_t group_log_size,
        uint32_t source_log_size
) {
    const uint32_t log_ratio = group_log_size - source_log_size;
    return (row >> (log_ratio + 1) << 1) + (row & 1);
}

template<bool TWO_ROWS>
__device__ __forceinline__ void accumulate_group_direct_rows(
        const uint32_t *term_descriptors,
        uint32_t term_begin,
        uint32_t term_end,
        uint32_t group_log_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const qm31 *group_b,
        uint32_t *output_0,
        uint32_t *output_1,
        uint32_t *output_2,
        uint32_t *output_3,
        uint32_t row_0,
        uint32_t row_1
) {
    qm31 numerator_0 = qm31{cm31{0, 0}, cm31{0, 0}};
    qm31 numerator_1 = qm31{cm31{0, 0}, cm31{0, 0}};
    uint32_t index = term_begin;
    uint32_t source_log_size =
        term_descriptors[static_cast<size_t>(index) * TERM_WORDS + 2];
    while (index < term_end) {
        const uint32_t source_row_0 = group_direct_source_row(
            row_0, group_log_size, source_log_size);
        const uint32_t source_row_1 = TWO_ROWS
            ? group_direct_source_row(row_1, group_log_size, source_log_size)
            : 0;
        while (true) {
            const uint32_t *descriptor =
                term_descriptors + static_cast<size_t>(index) * TERM_WORDS;
            const uint32_t source = descriptor[0];
            const uint32_t term = descriptor[1];
            const qm31 c =
                line_coefficients[static_cast<size_t>(term) * 3 + 2];
            const uint32_t *source_values = source_evaluations[source];
            numerator_0 = prepacked_add(
                numerator_0,
                prepacked_mul_by_scalar(c, source_values[source_row_0]));
            if constexpr (TWO_ROWS) {
                numerator_1 = prepacked_add(
                    numerator_1,
                    prepacked_mul_by_scalar(c, source_values[source_row_1]));
            }

            ++index;
            if (index == term_end) {
                break;
            }
            const uint32_t next_source_log_size =
                term_descriptors[static_cast<size_t>(index) * TERM_WORDS + 2];
            if (next_source_log_size != source_log_size) {
                source_log_size = next_source_log_size;
                break;
            }
        }
    }

    const qm31 b = *group_b;
    numerator_0 = prepacked_sub(numerator_0, b);
    output_0[row_0] = numerator_0.a.a;
    output_1[row_0] = numerator_0.a.b;
    output_2[row_0] = numerator_0.b.a;
    output_3[row_0] = numerator_0.b.b;
    if constexpr (TWO_ROWS) {
        numerator_1 = prepacked_sub(numerator_1, b);
        output_0[row_1] = numerator_1.a.a;
        output_1[row_1] = numerator_1.a.b;
        output_2[row_1] = numerator_1.b.a;
        output_3[row_1] = numerator_1.b.b;
    }
}

} // namespace

// One launch owns one canonical numerator group. One thread owns two rows in
// opposite halves, sharing descriptor, coefficient, and source-pointer loads.
// The prepared plan seals nondecreasing source-log runs and canonical backend
// field inputs; TU-local fast32 operations normalize every result exactly.
extern "C" __global__ void stwo_quotient_numerator_group_direct_kernel(
        const uint32_t *term_descriptors,
        uint32_t term_begin,
        uint32_t term_end,
        uint32_t group_log_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const qm31 *group_b,
        uint32_t *output_0,
        uint32_t *output_1,
        uint32_t *output_2,
        uint32_t *output_3
) {
    const uint32_t owner = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t row_count = 1u << group_log_size;
    const uint32_t half_rows = row_count >> 1;
    if (owner >= half_rows) {
        return;
    }
    accumulate_group_direct_rows<true>(
        term_descriptors, term_begin, term_end, group_log_size,
        source_evaluations, line_coefficients, group_b, output_0, output_1,
        output_2, output_3, owner, owner + half_rows);
}

namespace {

__global__ void stwo_quotient_numerator_group_direct_scalar_kernel(
        const uint32_t *term_descriptors,
        uint32_t term_begin,
        uint32_t term_end,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const qm31 *group_b,
        uint32_t *output_0,
        uint32_t *output_1,
        uint32_t *output_2,
        uint32_t *output_3
) {
    accumulate_group_direct_rows<false>(
        term_descriptors, term_begin, term_end, 0, source_evaluations,
        line_coefficients, group_b, output_0, output_1, output_2, output_3, 0,
        0);
}

} // namespace

extern "C" int stwo_accumulate_quotient_numerator_group_direct_on(
        const uint32_t *term_descriptors,
        uint32_t term_begin,
        uint32_t term_end,
        uint32_t group_log_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const qm31 *group_b,
        uint32_t *output_0,
        uint32_t *output_1,
        uint32_t *output_2,
        uint32_t *output_3,
        void *stream
) {
    if (term_descriptors == nullptr || term_begin >= term_end ||
        group_log_size >= 31 || source_evaluations == nullptr ||
        line_coefficients == nullptr || group_b == nullptr ||
        output_0 == nullptr ||
        output_1 == nullptr || output_2 == nullptr || output_3 == nullptr ||
        stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint32_t row_count = 1u << group_log_size;
    const cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    if (group_log_size == 0) {
        stwo_quotient_numerator_group_direct_scalar_kernel<<<
            1, 1, 0, cuda_stream>>>(
                term_descriptors, term_begin, term_end, source_evaluations,
                line_coefficients, group_b, output_0, output_1, output_2,
                output_3);
        return cudaGetLastError();
    }
    const uint32_t row_pairs = row_count >> 1;
    const uint32_t blocks =
        (row_pairs + BLOCK_THREADS - 1) / BLOCK_THREADS;
    stwo_quotient_numerator_group_direct_kernel<<<
        blocks, BLOCK_THREADS, 0, cuda_stream>>>(
            term_descriptors, term_begin, term_end, group_log_size,
            source_evaluations, line_coefficients, group_b, output_0, output_1,
            output_2, output_3);
    return cudaGetLastError();
}

// Candidate-only preparation after finalize_quotient_numerator_groups has
// consumed term_points. The same storage becomes descriptor-ordered records:
// [source pointer lo/hi, four c words, source log], followed by one B_g per
// group and one status word.
extern "C" __global__ void stwo_prepare_quotient_numerator_prepacked_terms_kernel(
        const uint32_t *group_term_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint32_t term_count,
        const uint32_t *const *source_evaluations,
        uint32_t source_count,
        const qm31 *line_coefficients,
        uint32_t *prepacked_storage
) {
    const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t *status =
        prepacked_status(prepacked_storage, term_count, group_count);
    if (index == 0 &&
        (group_term_offsets[0] != 0 ||
         group_term_offsets[group_count] != term_count)) {
        prepacked_record_status(
            status,
            STWO_QUOTIENT_PREPACKED_PREPARE_GROUP_OFFSETS_NOT_CANONICAL);
        return;
    }
    if (index < term_count) {
        const uint32_t *descriptor =
            term_descriptors + static_cast<size_t>(index) * TERM_WORDS;
        const uint32_t source = descriptor[0];
        const uint32_t term = descriptor[1];
        const uint32_t source_log_size = descriptor[2];
        if (source >= source_count) {
            prepacked_record_status(
                status,
                STWO_QUOTIENT_PREPACKED_PREPARE_SOURCE_OUT_OF_BOUNDS);
            return;
        }
        if (term >= term_count) {
            prepacked_record_status(
                status,
                STWO_QUOTIENT_PREPACKED_PREPARE_TERM_OUT_OF_BOUNDS);
            return;
        }
        if (source_log_size >= 31) {
            prepacked_record_status(
                status,
                STWO_QUOTIENT_PREPACKED_PREPARE_SOURCE_LOG_OUT_OF_BOUNDS);
            return;
        }
        if (source_evaluations[source] == nullptr) {
            prepacked_record_status(
                status,
                STWO_QUOTIENT_PREPACKED_PREPARE_NULL_SOURCE);
            return;
        }
        const uintptr_t source_address =
            reinterpret_cast<uintptr_t>(source_evaluations[source]);
        uint32_t *record =
            prepacked_storage + static_cast<size_t>(index) * PREPACKED_TERM_WORDS;
        record[0] = static_cast<uint32_t>(source_address);
        record[1] = static_cast<uint32_t>(
            static_cast<uint64_t>(source_address) >> 32);
        prepacked_store_qm31(
            record + 2,
            line_coefficients[static_cast<size_t>(term) * 3 + 2]);
        record[6] = source_log_size;
    }

    if (index < group_count) {
        const uint32_t begin = group_term_offsets[index];
        const uint32_t end = group_term_offsets[index + 1];
        if (begin >= end || end > term_count) {
            prepacked_record_status(
                status,
                STWO_QUOTIENT_PREPACKED_PREPARE_GROUP_RANGE_OUT_OF_BOUNDS);
            return;
        }
        qm31 group_b = qm31{cm31{0, 0}, cm31{0, 0}};
        for (uint32_t descriptor_index = begin;
             descriptor_index < end; ++descriptor_index) {
            const uint32_t term = term_descriptors[
                static_cast<size_t>(descriptor_index) * TERM_WORDS + 1];
            if (term >= term_count) {
                prepacked_record_status(
                    status,
                    STWO_QUOTIENT_PREPACKED_PREPARE_GROUP_TERM_OUT_OF_BOUNDS);
                return;
            }
            group_b = prepacked_add(
                group_b,
                line_coefficients[static_cast<size_t>(term) * 3 + 1]);
        }
        uint32_t *group_words =
            prepacked_storage +
            static_cast<size_t>(term_count) * PREPACKED_TERM_WORDS +
            static_cast<size_t>(index) * PREPACKED_GROUP_WORDS;
        prepacked_store_qm31(group_words, group_b);
    }
}

extern "C" int stwo_prepare_quotient_numerator_prepacked_terms_on(
        const uint32_t *group_term_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint32_t term_count,
        const uint32_t *const *source_evaluations,
        uint32_t source_count,
        const qm31 *line_coefficients,
        uint32_t *prepacked_storage,
        uint64_t prepacked_storage_words,
        void *stream
) {
    const uint64_t required_words =
        static_cast<uint64_t>(term_count) * PREPACKED_TERM_WORDS +
        static_cast<uint64_t>(group_count) * PREPACKED_GROUP_WORDS +
        PREPACKED_STATUS_WORDS;
    if (group_term_offsets == nullptr || term_descriptors == nullptr ||
        group_count == 0 || term_count == 0 ||
        source_evaluations == nullptr || source_count == 0 ||
        line_coefficients == nullptr || prepacked_storage == nullptr ||
        prepacked_storage_words < required_words || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    uint32_t *status =
        prepacked_storage +
        static_cast<size_t>(term_count) * PREPACKED_TERM_WORDS +
        static_cast<size_t>(group_count) * PREPACKED_GROUP_WORDS;
    const cudaError_t reset = cudaMemsetAsync(
        status, 0, sizeof(*status), reinterpret_cast<cudaStream_t>(stream));
    if (reset != cudaSuccess) {
        return reset;
    }
    const uint32_t work = term_count > group_count ? term_count : group_count;
    const uint32_t blocks = static_cast<uint32_t>(
        (static_cast<uint64_t>(work) + BLOCK_THREADS - 1) / BLOCK_THREADS);
    stwo_prepare_quotient_numerator_prepacked_terms_kernel<<<
        blocks, BLOCK_THREADS, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            group_term_offsets, term_descriptors, group_count, term_count,
            source_evaluations, source_count, line_coefficients,
            prepacked_storage);
    return cudaGetLastError();
}

extern "C" __global__ void stwo_validate_quotient_numerator_prepacked_terms_kernel(
        const uint64_t *group_row_offsets,
        const uint32_t *group_term_offsets,
        uint32_t group_count,
        uint32_t term_count,
        uint64_t packed_output_rows,
        uint32_t *prepacked_storage,
        const uint32_t *group_log_sizes
) {
    const uint32_t group = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t *status =
        prepacked_status(prepacked_storage, term_count, group_count);
    if (group >= group_count) {
        return;
    }
    if (group == 0 &&
        (group_row_offsets[0] != 0 ||
         group_row_offsets[group_count] != packed_output_rows)) {
        prepacked_record_status(
            status,
            STWO_QUOTIENT_PREPACKED_HOT_ROW_OFFSETS_NOT_CANONICAL);
        return;
    }

    const uint64_t row_begin = group_row_offsets[group];
    const uint64_t row_end = group_row_offsets[group + 1];
    const uint32_t group_log_size = group_log_sizes[group];
    if (row_begin >= row_end || group_log_size >= 31 ||
        row_end - row_begin != (1ull << group_log_size)) {
        prepacked_record_status(
            status,
            STWO_QUOTIENT_PREPACKED_HOT_GROUP_ROW_SHAPE_INVALID);
        return;
    }
    const uint32_t term_begin = group_term_offsets[group];
    const uint32_t term_end = group_term_offsets[group + 1];
    if ((group == 0 &&
         (group_term_offsets[0] != 0 ||
          group_term_offsets[group_count] != term_count)) ||
        term_begin >= term_end || term_end > term_count) {
        prepacked_record_status(
            status,
            STWO_QUOTIENT_PREPACKED_HOT_GROUP_TERM_RANGE_INVALID);
        return;
    }
    for (uint32_t index = term_begin; index < term_end; ++index) {
        const uint32_t *record =
            prepacked_storage + static_cast<size_t>(index) * PREPACKED_TERM_WORDS;
        if (record[6] > group_log_size) {
            prepacked_record_status(
                status,
                STWO_QUOTIENT_PREPACKED_HOT_SOURCE_LOG_OUT_OF_BOUNDS);
            return;
        }
        if ((static_cast<uint64_t>(record[0]) |
             (static_cast<uint64_t>(record[1]) << 32)) == 0) {
            prepacked_record_status(
                status,
                STWO_QUOTIENT_PREPACKED_HOT_NULL_SOURCE);
            return;
        }
    }
}

// The hot candidate performs one sequential record read per canonical term and
// subtracts the pre-summed group constant once after all c*source products.
extern "C" __global__ void stwo_quotient_numerator_prepacked_single_write_kernel(
        const uint64_t *group_row_offsets,
        const uint32_t *group_term_offsets,
        uint32_t group_count,
        uint32_t term_count,
        uint64_t packed_output_rows,
        uint32_t *prepacked_storage,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3
) {
    const uint64_t packed_row =
        static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    uint32_t *status =
        prepacked_status(prepacked_storage, term_count, group_count);
    if (packed_row >= packed_output_rows || atomicCAS(status, 0, 0) != 0) {
        return;
    }
    if (group_row_offsets[0] != 0 ||
        group_row_offsets[group_count] != packed_output_rows) {
        prepacked_record_status(
            status,
            STWO_QUOTIENT_PREPACKED_HOT_ROW_OFFSETS_NOT_CANONICAL);
        return;
    }

    uint32_t low = 0;
    uint32_t high = group_count;
    while (low < high) {
        const uint32_t middle = low + (high - low) / 2;
        if (packed_row < group_row_offsets[middle + 1]) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    const uint32_t group = low;
    if (group >= group_count) {
        prepacked_record_status(
            status,
            STWO_QUOTIENT_PREPACKED_HOT_GROUP_ROW_SHAPE_INVALID);
        return;
    }
    const uint64_t group_begin = group_row_offsets[group];
    const uint64_t group_end = group_row_offsets[group + 1];
    const uint32_t group_log_size = group_log_sizes[group];
    if (group_begin > packed_row || group_end <= packed_row ||
        group_log_size >= 31 ||
        group_end - group_begin != (1ull << group_log_size)) {
        prepacked_record_status(
            status,
            STWO_QUOTIENT_PREPACKED_HOT_GROUP_ROW_SHAPE_INVALID);
        return;
    }
    const uint32_t row = static_cast<uint32_t>(packed_row - group_begin);
    const uint32_t term_begin = group_term_offsets[group];
    const uint32_t term_end = group_term_offsets[group + 1];
    if (term_begin >= term_end || term_end > term_count) {
        prepacked_record_status(
            status,
            STWO_QUOTIENT_PREPACKED_HOT_GROUP_TERM_RANGE_INVALID);
        return;
    }

    qm31 numerator = qm31{cm31{0, 0}, cm31{0, 0}};
    for (uint32_t index = term_begin; index < term_end; ++index) {
        const uint32_t *record =
            prepacked_storage + static_cast<size_t>(index) * PREPACKED_TERM_WORDS;
        const uint32_t source_log_size = record[6];
        if (source_log_size > group_log_size) {
            prepacked_record_status(
                status,
                STWO_QUOTIENT_PREPACKED_HOT_SOURCE_LOG_OUT_OF_BOUNDS);
            return;
        }
        const uint64_t source_address =
            static_cast<uint64_t>(record[0]) |
            (static_cast<uint64_t>(record[1]) << 32);
        const uint32_t *source_evaluations =
            reinterpret_cast<const uint32_t *>(
                static_cast<uintptr_t>(source_address));
        if (source_evaluations == nullptr) {
            prepacked_record_status(
                status,
                STWO_QUOTIENT_PREPACKED_HOT_NULL_SOURCE);
            return;
        }
        const uint32_t log_ratio = group_log_size - source_log_size;
        const uint32_t source_row =
            (row >> (log_ratio + 1) << 1) + (row & 1);
        numerator = prepacked_add(
            numerator,
            prepacked_mul_by_scalar(
                prepacked_load_qm31(record + 2),
                source_evaluations[source_row]));
    }

    const uint32_t *group_words =
        prepacked_storage +
        static_cast<size_t>(term_count) * PREPACKED_TERM_WORDS +
        static_cast<size_t>(group) * PREPACKED_GROUP_WORDS;
    numerator = prepacked_sub(numerator, prepacked_load_qm31(group_words));
    if (atomicCAS(status, 0, 0) != 0) {
        return;
    }
    outputs_0[group][row] = numerator.a.a;
    outputs_1[group][row] = numerator.a.b;
    outputs_2[group][row] = numerator.b.a;
    outputs_3[group][row] = numerator.b.b;
}

extern "C" int stwo_accumulate_quotient_numerator_prepacked_single_write_on(
        const uint64_t *group_row_offsets,
        const uint32_t *group_term_offsets,
        uint32_t group_count,
        uint32_t term_count,
        uint64_t packed_output_rows,
        uint32_t *prepacked_storage,
        uint64_t prepacked_storage_words,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3,
        void *stream
) {
    const uint64_t required_words =
        static_cast<uint64_t>(term_count) * PREPACKED_TERM_WORDS +
        static_cast<uint64_t>(group_count) * PREPACKED_GROUP_WORDS +
        PREPACKED_STATUS_WORDS;
    if (group_row_offsets == nullptr || group_term_offsets == nullptr ||
        group_count == 0 || term_count == 0 || packed_output_rows == 0 ||
        prepacked_storage == nullptr ||
        prepacked_storage_words < required_words ||
        group_log_sizes == nullptr || outputs_0 == nullptr ||
        outputs_1 == nullptr || outputs_2 == nullptr ||
        outputs_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint64_t blocks =
        (packed_output_rows + BLOCK_THREADS - 1) / BLOCK_THREADS;
    if (blocks == 0 || blocks > MAX_GRID_X) {
        return cudaErrorInvalidConfiguration;
    }
    const uint32_t validation_blocks = static_cast<uint32_t>(
        (static_cast<uint64_t>(group_count) + BLOCK_THREADS - 1) /
        BLOCK_THREADS);
    stwo_validate_quotient_numerator_prepacked_terms_kernel<<<
        validation_blocks, BLOCK_THREADS, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            group_row_offsets, group_term_offsets, group_count, term_count,
            packed_output_rows, prepacked_storage, group_log_sizes);
    const cudaError_t validation_launch = cudaGetLastError();
    if (validation_launch != cudaSuccess) {
        return validation_launch;
    }
    stwo_quotient_numerator_prepacked_single_write_kernel<<<
        static_cast<uint32_t>(blocks), BLOCK_THREADS, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            group_row_offsets, group_term_offsets, group_count, term_count,
            packed_output_rows, prepacked_storage, group_log_sizes, outputs_0,
            outputs_1, outputs_2, outputs_3);
    return cudaGetLastError();
}

extern "C" int stwo_quotient_numerator_single_write_function_attributes(
        uint32_t role,
        StwoCudaFunctionAttributes *out
) {
    switch (role) {
    case STWO_QUOTIENT_NUMERATOR_STAGED_PACKED:
        return stwo_cuda_function_attributes(
            stwo_quotient_numerator_packed_single_write_kernel, out);
    case STWO_QUOTIENT_NUMERATOR_PREPACKED_PREPARE:
        return stwo_cuda_function_attributes(
            stwo_prepare_quotient_numerator_prepacked_terms_kernel, out);
    case STWO_QUOTIENT_NUMERATOR_PREPACKED_VALIDATE:
        return stwo_cuda_function_attributes(
            stwo_validate_quotient_numerator_prepacked_terms_kernel, out);
    case STWO_QUOTIENT_NUMERATOR_PREPACKED_HOT:
        return stwo_cuda_function_attributes(
            stwo_quotient_numerator_prepacked_single_write_kernel, out);
    case STWO_QUOTIENT_NUMERATOR_GROUP_DIRECT:
        return stwo_cuda_function_attributes(
            stwo_quotient_numerator_group_direct_kernel, out);
    default:
        return cudaErrorInvalidValue;
    }
}
