#include "fields.cuh"
#include "m31_fast32.cuh"
#include "resource_attestation.cuh"

#include <cstdint>
#include <cuda_runtime.h>

namespace {

constexpr uint32_t TERM_WORDS = 3;
constexpr uint32_t BLOCK_THREADS = 256;
constexpr uint32_t COOPERATIVE_LOG_MIN = 9;
constexpr uint32_t ROWS_PER_CTA = 512;
constexpr uint32_t SECOND_ROW_OFFSET = 256;
constexpr uint32_t TILE_WORDS_4_KIB = 1024;
constexpr uint32_t TILE_WORDS_16_KIB = 4096;
constexpr uint32_t CONTRIBUTION_TILE_ENTRIES = 1024;
constexpr uint32_t MAX_TERMS_PER_BATCH = 1024;

static_assert(alignof(uint4) == 16);

__device__ __forceinline__ qm31 tiled_add(qm31 lhs, qm31 rhs) {
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

__device__ __forceinline__ qm31 tiled_sub(qm31 lhs, qm31 rhs) {
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

__device__ __forceinline__ qm31 tiled_mul_by_scalar(
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

__device__ __forceinline__ uint32_t source_row(
        uint32_t row,
        uint32_t group_log_size,
        uint32_t source_log_size
) {
    const uint32_t log_ratio = group_log_size - source_log_size;
    return (row >> (log_ratio + 1) << 1) + (row & 1);
}

__device__ __forceinline__ uint32_t unique_row_log(
        uint32_t group_log_size,
        uint32_t source_log_size
) {
    const uint32_t log_ratio = group_log_size - source_log_size;
    return log_ratio >= 8 ? 1 : 9 - log_ratio;
}

__device__ __forceinline__ uint32_t source_log_run_end(
        const uint32_t *term_descriptors,
        uint32_t begin,
        uint32_t end,
        uint32_t source_log_size
) {
    uint32_t low = begin + 1;
    uint32_t high = end;
    if ((threadIdx.x & 31) == 0) {
        while (low < high) {
            const uint32_t middle = low + (high - low) / 2;
            const uint32_t middle_log =
                term_descriptors[
                    static_cast<size_t>(middle) * TERM_WORDS + 2];
            if (middle_log == source_log_size) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
    }
    return __shfl_sync(0xffffffffu, low, 0);
}

template<uint32_t TILE_WORDS>
__device__ __forceinline__ void accumulate_tiled_rows(
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
        uint32_t row_base,
        uint32_t *tile
) {
    const uint32_t row_0 = row_base + threadIdx.x;
    const uint32_t row_1 = row_0 + SECOND_ROW_OFFSET;
    qm31 numerator_0 = qm31{cm31{0, 0}, cm31{0, 0}};
    qm31 numerator_1 = qm31{cm31{0, 0}, cm31{0, 0}};
    uint32_t index = term_begin;

    while (index < term_end) {
        const uint32_t run_log =
            term_descriptors[static_cast<size_t>(index) * TERM_WORDS + 2];
        if (group_log_size - run_log < 3) {
            // Source logs are sealed nondecreasing. At d < 3 the original
            // warp-coalesced loads already request the minimum 32-byte sectors,
            // so the complete remaining tail stays direct.
            while (index < term_end) {
                const uint32_t *descriptor =
                    term_descriptors + static_cast<size_t>(index) * TERM_WORDS;
                const uint32_t source_log_size = descriptor[2];
                const qm31 c = line_coefficients[
                    static_cast<size_t>(descriptor[1]) * 3 + 2];
                const uint32_t *values =
                    source_evaluations[descriptor[0]];
                numerator_0 = tiled_add(
                    numerator_0,
                    tiled_mul_by_scalar(
                        c,
                        values[source_row(
                            row_0, group_log_size, source_log_size)]));
                numerator_1 = tiled_add(
                    numerator_1,
                    tiled_mul_by_scalar(
                        c,
                        values[source_row(
                            row_1, group_log_size, source_log_size)]));
                ++index;
            }
            break;
        }

        const uint32_t run_end = source_log_run_end(
            term_descriptors, index, term_end, run_log);
        const uint32_t row_log = unique_row_log(group_log_size, run_log);
        const uint32_t unique_rows = 1u << row_log;
        const uint32_t batch_capacity =
            min(MAX_TERMS_PER_BATCH, TILE_WORDS >> row_log);
        const uint32_t batch_terms = min(batch_capacity, run_end - index);
        const uint32_t staged_words = batch_terms << row_log;
        const uint32_t source_base =
            source_row(row_base, group_log_size, run_log);

        for (uint32_t linear = threadIdx.x;
             linear < staged_words; linear += blockDim.x) {
            const uint32_t slot = linear >> row_log;
            const uint32_t local_row = linear & (unique_rows - 1);
            const uint32_t *descriptor = term_descriptors +
                static_cast<size_t>(index + slot) * TERM_WORDS;
            tile[linear] =
                source_evaluations[descriptor[0]][source_base + local_row];
        }
        __syncthreads();

        const uint32_t local_row_0 =
            source_row(row_0, group_log_size, run_log) - source_base;
        const uint32_t local_row_1 =
            source_row(row_1, group_log_size, run_log) - source_base;
        for (uint32_t slot = 0; slot < batch_terms; ++slot) {
            const uint32_t *descriptor = term_descriptors +
                static_cast<size_t>(index + slot) * TERM_WORDS;
            const qm31 c =
                line_coefficients[static_cast<size_t>(descriptor[1]) * 3 + 2];
            const uint32_t tile_offset = slot << row_log;
            numerator_0 = tiled_add(
                numerator_0,
                tiled_mul_by_scalar(c, tile[tile_offset + local_row_0]));
            numerator_1 = tiled_add(
                numerator_1,
                tiled_mul_by_scalar(c, tile[tile_offset + local_row_1]));
        }
        __syncthreads();
        index += batch_terms;
    }

    const qm31 b = *group_b;
    numerator_0 = tiled_sub(numerator_0, b);
    output_0[row_0] = numerator_0.a.a;
    output_1[row_0] = numerator_0.a.b;
    output_2[row_0] = numerator_0.b.a;
    output_3[row_0] = numerator_0.b.b;
    numerator_1 = tiled_sub(numerator_1, b);
    output_0[row_1] = numerator_1.a.a;
    output_1[row_1] = numerator_1.a.b;
    output_2[row_1] = numerator_1.b.a;
    output_3[row_1] = numerator_1.b.b;
}

__device__ __forceinline__ qm31 contribution_from_words(uint4 words) {
    return qm31{
        cm31{words.x, words.y},
        cm31{words.z, words.w},
    };
}

__device__ __forceinline__ void accumulate_contribution_tiled_rows(
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
        uint32_t row_base,
        uint4 *tile
) {
    const uint32_t row_0 = row_base + threadIdx.x;
    const uint32_t row_1 = row_0 + SECOND_ROW_OFFSET;
    qm31 numerator_0 = qm31{cm31{0, 0}, cm31{0, 0}};
    qm31 numerator_1 = qm31{cm31{0, 0}, cm31{0, 0}};
    uint32_t index = term_begin;

    while (index < term_end) {
        const uint32_t run_log =
            term_descriptors[static_cast<size_t>(index) * TERM_WORDS + 2];
        if (group_log_size - run_log < 3) {
            while (index < term_end) {
                const uint32_t *descriptor =
                    term_descriptors + static_cast<size_t>(index) * TERM_WORDS;
                const uint32_t source_log_size = descriptor[2];
                const qm31 c = line_coefficients[
                    static_cast<size_t>(descriptor[1]) * 3 + 2];
                const uint32_t *values =
                    source_evaluations[descriptor[0]];
                numerator_0 = tiled_add(
                    numerator_0,
                    tiled_mul_by_scalar(
                        c,
                        values[source_row(
                            row_0, group_log_size, source_log_size)]));
                numerator_1 = tiled_add(
                    numerator_1,
                    tiled_mul_by_scalar(
                        c,
                        values[source_row(
                            row_1, group_log_size, source_log_size)]));
                ++index;
            }
            break;
        }

        const uint32_t run_end = source_log_run_end(
            term_descriptors, index, term_end, run_log);
        const uint32_t row_log = unique_row_log(group_log_size, run_log);
        const uint32_t unique_rows = 1u << row_log;
        const uint32_t batch_capacity =
            min(MAX_TERMS_PER_BATCH, CONTRIBUTION_TILE_ENTRIES >> row_log);
        const uint32_t batch_terms = min(batch_capacity, run_end - index);
        const uint32_t staged_entries = batch_terms << row_log;
        const uint32_t source_base =
            source_row(row_base, group_log_size, run_log);

        for (uint32_t linear = threadIdx.x;
             linear < staged_entries; linear += blockDim.x) {
            const uint32_t slot = linear >> row_log;
            const uint32_t local_row = linear & (unique_rows - 1);
            const uint32_t *descriptor = term_descriptors +
                static_cast<size_t>(index + slot) * TERM_WORDS;
            const qm31 c =
                line_coefficients[static_cast<size_t>(descriptor[1]) * 3 + 2];
            const qm31 contribution = tiled_mul_by_scalar(
                c,
                source_evaluations[descriptor[0]][source_base + local_row]);
            tile[linear] = uint4{
                contribution.a.a,
                contribution.a.b,
                contribution.b.a,
                contribution.b.b,
            };
        }
        __syncthreads();

        const uint32_t local_row_0 =
            source_row(row_0, group_log_size, run_log) - source_base;
        const uint32_t local_row_1 =
            source_row(row_1, group_log_size, run_log) - source_base;
        for (uint32_t slot = 0; slot < batch_terms; ++slot) {
            const uint32_t tile_offset = slot << row_log;
            numerator_0 = tiled_add(
                numerator_0,
                contribution_from_words(tile[tile_offset + local_row_0]));
            numerator_1 = tiled_add(
                numerator_1,
                contribution_from_words(tile[tile_offset + local_row_1]));
        }
        __syncthreads();
        index += batch_terms;
    }

    const qm31 b = *group_b;
    numerator_0 = tiled_sub(numerator_0, b);
    output_0[row_0] = numerator_0.a.a;
    output_1[row_0] = numerator_0.a.b;
    output_2[row_0] = numerator_0.b.a;
    output_3[row_0] = numerator_0.b.b;
    numerator_1 = tiled_sub(numerator_1, b);
    output_0[row_1] = numerator_1.a.a;
    output_1[row_1] = numerator_1.a.b;
    output_2[row_1] = numerator_1.b.a;
    output_3[row_1] = numerator_1.b.b;
}

} // namespace

template<uint32_t TILE_WORDS>
__global__ void stwo_quotient_numerator_group_direct_tiled_kernel(
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
    __shared__ uint32_t tile[TILE_WORDS];
    const uint32_t row_base = blockIdx.x * ROWS_PER_CTA;
    accumulate_tiled_rows<TILE_WORDS>(
        term_descriptors, term_begin, term_end, group_log_size,
        source_evaluations, line_coefficients, group_b, output_0, output_1,
        output_2, output_3, row_base, tile);
}

__global__ void stwo_quotient_numerator_group_direct_contribution_tiled_kernel(
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
    __shared__ uint4 tile[CONTRIBUTION_TILE_ENTRIES];
    const uint32_t row_base = blockIdx.x * ROWS_PER_CTA;
    accumulate_contribution_tiled_rows(
        term_descriptors, term_begin, term_end, group_log_size,
        source_evaluations, line_coefficients, group_b, output_0, output_1,
        output_2, output_3, row_base, tile);
}

extern "C" int stwo_accumulate_quotient_numerator_group_direct_on(
        const uint32_t *, uint32_t, uint32_t, uint32_t,
        const uint32_t *const *, const qm31 *, const qm31 *,
        uint32_t *, uint32_t *, uint32_t *, uint32_t *, void *);

// Keep candidate ABI declarations local: quotient_numerator_single_write.cuh
// fingerprints every CUDA translation unit, so extending it would force a
// whole-archive rebuild. raw.rs is the Rust-side ABI authority, and its exact
// raw/stub signatures are compile-checked together in lib.rs.
extern "C" int stwo_accumulate_quotient_numerator_group_direct_tiled_on(
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
        uint32_t tile_words,
        void *stream
) {
    if (tile_words != TILE_WORDS_4_KIB &&
        tile_words != TILE_WORDS_16_KIB) {
        return cudaErrorInvalidValue;
    }
    if (group_log_size < COOPERATIVE_LOG_MIN) {
        return stwo_accumulate_quotient_numerator_group_direct_on(
            term_descriptors, term_begin, term_end, group_log_size,
            source_evaluations, line_coefficients, group_b, output_0, output_1,
            output_2, output_3, stream);
    }
    if (term_descriptors == nullptr || term_begin >= term_end ||
        group_log_size >= 31 || source_evaluations == nullptr ||
        line_coefficients == nullptr || group_b == nullptr ||
        output_0 == nullptr || output_1 == nullptr ||
        output_2 == nullptr || output_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint32_t blocks = (1u << group_log_size) / ROWS_PER_CTA;
    if (tile_words == TILE_WORDS_4_KIB) {
        stwo_quotient_numerator_group_direct_tiled_kernel<
            TILE_WORDS_4_KIB><<<
                blocks, BLOCK_THREADS, 0,
                reinterpret_cast<cudaStream_t>(stream)>>>(
                    term_descriptors, term_begin, term_end, group_log_size,
                    source_evaluations, line_coefficients, group_b, output_0,
                    output_1, output_2, output_3);
    } else {
        stwo_quotient_numerator_group_direct_tiled_kernel<
            TILE_WORDS_16_KIB><<<
                blocks, BLOCK_THREADS, 0,
                reinterpret_cast<cudaStream_t>(stream)>>>(
                    term_descriptors, term_begin, term_end, group_log_size,
                    source_evaluations, line_coefficients, group_b, output_0,
                    output_1, output_2, output_3);
    }
    return cudaGetLastError();
}

extern "C" int
stwo_accumulate_quotient_numerator_group_direct_contribution_tiled_on(
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
    if (group_log_size < COOPERATIVE_LOG_MIN) {
        return stwo_accumulate_quotient_numerator_group_direct_on(
            term_descriptors, term_begin, term_end, group_log_size,
            source_evaluations, line_coefficients, group_b, output_0, output_1,
            output_2, output_3, stream);
    }
    if (term_descriptors == nullptr || term_begin >= term_end ||
        group_log_size >= 31 || source_evaluations == nullptr ||
        line_coefficients == nullptr || group_b == nullptr ||
        output_0 == nullptr || output_1 == nullptr ||
        output_2 == nullptr || output_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint32_t blocks = (1u << group_log_size) / ROWS_PER_CTA;
    stwo_quotient_numerator_group_direct_contribution_tiled_kernel<<<
        blocks, BLOCK_THREADS, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            term_descriptors, term_begin, term_end, group_log_size,
            source_evaluations, line_coefficients, group_b, output_0, output_1,
            output_2, output_3);
    return cudaGetLastError();
}

extern "C" int stwo_quotient_numerator_group_direct_tiled_function_attributes(
        uint32_t tile_words,
        StwoCudaFunctionAttributes *out
) {
    if (tile_words == TILE_WORDS_4_KIB) {
        return stwo_cuda_function_attributes(
            stwo_quotient_numerator_group_direct_tiled_kernel<
                TILE_WORDS_4_KIB>,
            out);
    }
    if (tile_words == TILE_WORDS_16_KIB) {
        return stwo_cuda_function_attributes(
            stwo_quotient_numerator_group_direct_tiled_kernel<
                TILE_WORDS_16_KIB>,
            out);
    }
    return cudaErrorInvalidValue;
}

extern "C" int
stwo_quotient_numerator_group_direct_contribution_tiled_function_attributes(
        StwoCudaFunctionAttributes *out
) {
    return stwo_cuda_function_attributes(
        stwo_quotient_numerator_group_direct_contribution_tiled_kernel,
        out);
}
