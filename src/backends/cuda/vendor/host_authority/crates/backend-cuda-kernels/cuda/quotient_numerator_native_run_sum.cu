#include "fields.cuh"
#include "m31_fast32.cuh"
#include "resource_attestation.cuh"

#include <cstddef>
#include <cstdint>
#include <cuda_runtime.h>

namespace {

constexpr uint32_t TERM_WORDS = 3;
constexpr uint32_t LINE_COEFFICIENTS_PER_TERM = 3;
constexpr uint32_t C_COEFFICIENT_INDEX = 2;
constexpr uint32_t BLOCK_THREADS = 256;
constexpr uint32_t MAX_RUNS = 24;
// At log zero the canonical lifted-row map selects indices 0 and 1 by parity,
// while a 2^0 native buffer has one word. Supporting that shape requires an
// explicit two-word minimum-domain contract; this focused candidate rejects it.
constexpr uint32_t MIN_NATIVE_RUN_LOG = 1;

struct StwoQuotientNativeRunEntry {
    uint32_t term_begin;
    uint32_t term_end;
    uint32_t source_log_size;
    uint32_t scratch_offset_words;
};

struct StwoQuotientNativeRunManifest {
    uint32_t run_count;
    uint32_t direct_term_begin;
    uint32_t direct_term_end;
    uint32_t target_log_size;
    StwoQuotientNativeRunEntry runs[MAX_RUNS];
};

static_assert(sizeof(StwoQuotientNativeRunEntry) == 16);
static_assert(alignof(StwoQuotientNativeRunEntry) == 4);
static_assert(sizeof(StwoQuotientNativeRunManifest) == 400);
static_assert(alignof(StwoQuotientNativeRunManifest) == 4);
static_assert(offsetof(StwoQuotientNativeRunManifest, runs) == 16);
// The expansion kernel receives the manifest as a true value parameter.
// Its complete parameter block is 400 manifest bytes plus twelve pointers.
static_assert(sizeof(StwoQuotientNativeRunManifest) + 12 * sizeof(void *) == 496);

__device__ __forceinline__ qm31 run_sum_add(qm31 lhs, qm31 rhs) {
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

__device__ __forceinline__ qm31 run_sum_sub(qm31 lhs, qm31 rhs) {
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

__device__ __forceinline__ qm31 run_sum_mul_by_scalar(
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

__device__ __forceinline__ uint32_t run_sum_source_row(
        uint32_t row,
        uint32_t target_log_size,
        uint32_t source_log_size
) {
    const uint32_t log_ratio = target_log_size - source_log_size;
    return (row >> (log_ratio + 1) << 1) + (row & 1);
}

__device__ __forceinline__ qm31 load_run_sum(
        const uint32_t *scratch_0,
        const uint32_t *scratch_1,
        const uint32_t *scratch_2,
        const uint32_t *scratch_3,
        uint32_t index
) {
    return qm31{
        cm31{scratch_0[index], scratch_1[index]},
        cm31{scratch_2[index], scratch_3[index]},
    };
}

__device__ __forceinline__ void store_run_sum(
        qm31 value,
        uint32_t *destination_0,
        uint32_t *destination_1,
        uint32_t *destination_2,
        uint32_t *destination_3,
        uint32_t index
) {
    destination_0[index] = value.a.a;
    destination_1[index] = value.a.b;
    destination_2[index] = value.b.a;
    destination_3[index] = value.b.b;
}

bool run_sum_manifest_is_canonical(
        const StwoQuotientNativeRunManifest &manifest
) {
    if (manifest.run_count == 0 || manifest.run_count > MAX_RUNS ||
        manifest.direct_term_begin >= manifest.direct_term_end ||
        manifest.target_log_size == 0 || manifest.target_log_size >= 31) {
        return false;
    }

    uint64_t expected_offset = 0;
    uint32_t previous_end = 0;
    uint32_t previous_log = 0;
    for (uint32_t index = 0; index < manifest.run_count; ++index) {
        const StwoQuotientNativeRunEntry &run = manifest.runs[index];
        if (run.term_begin >= run.term_end ||
            run.source_log_size < MIN_NATIVE_RUN_LOG ||
            run.source_log_size >= manifest.target_log_size ||
            run.scratch_offset_words != expected_offset) {
            return false;
        }
        if (index != 0 &&
            (run.term_begin != previous_end ||
             run.source_log_size <= previous_log)) {
            return false;
        }
        expected_offset += uint64_t{1} << run.source_log_size;
        if (expected_offset > (uint64_t{1} << manifest.target_log_size)) {
            return false;
        }
        previous_end = run.term_end;
        previous_log = run.source_log_size;
    }
    if (previous_end != manifest.direct_term_begin) {
        return false;
    }
    for (uint32_t index = manifest.run_count; index < MAX_RUNS; ++index) {
        const StwoQuotientNativeRunEntry &run = manifest.runs[index];
        if (run.term_begin != 0 || run.term_end != 0 ||
            run.source_log_size != 0 || run.scratch_offset_words != 0) {
            return false;
        }
    }
    return true;
}

} // namespace

extern "C" __global__ void
stwo_quotient_numerator_native_run_precompute_kernel(
        const uint32_t *term_descriptors,
        uint32_t term_begin,
        uint32_t term_end,
        uint32_t native_row_count,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        uint32_t *scratch_0,
        uint32_t *scratch_1,
        uint32_t *scratch_2,
        uint32_t *scratch_3,
        uint32_t scratch_offset_words
) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= native_row_count) {
        return;
    }

    qm31 sum = qm31{cm31{0, 0}, cm31{0, 0}};
    for (uint32_t term = term_begin; term < term_end; ++term) {
        const uint32_t *descriptor =
            term_descriptors + static_cast<size_t>(term) * TERM_WORDS;
        const qm31 c = line_coefficients[
            static_cast<size_t>(descriptor[1]) *
                LINE_COEFFICIENTS_PER_TERM +
            C_COEFFICIENT_INDEX];
        const m31 value = source_evaluations[descriptor[0]][row];
        sum = run_sum_add(sum, run_sum_mul_by_scalar(c, value));
    }
    store_run_sum(
        sum, scratch_0, scratch_1, scratch_2, scratch_3,
        scratch_offset_words + row);
}

extern "C" __global__ void
stwo_quotient_numerator_run_sum_expand_kernel(
        StwoQuotientNativeRunManifest manifest,
        const uint32_t *term_descriptors,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const qm31 *group_b,
        const uint32_t *scratch_0,
        const uint32_t *scratch_1,
        const uint32_t *scratch_2,
        const uint32_t *scratch_3,
        uint32_t *output_0,
        uint32_t *output_1,
        uint32_t *output_2,
        uint32_t *output_3
) {
    const uint32_t owner = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t half_rows = 1u << (manifest.target_log_size - 1);
    if (owner >= half_rows) {
        return;
    }

    const uint32_t row_0 = owner;
    const uint32_t row_1 = owner + half_rows;
    qm31 numerator_0 = qm31{cm31{0, 0}, cm31{0, 0}};
    qm31 numerator_1 = qm31{cm31{0, 0}, cm31{0, 0}};

    for (uint32_t run_index = 0;
         run_index < manifest.run_count; ++run_index) {
        const StwoQuotientNativeRunEntry run = manifest.runs[run_index];
        const uint32_t scratch_row_0 =
            run.scratch_offset_words +
            run_sum_source_row(
                row_0, manifest.target_log_size, run.source_log_size);
        const uint32_t scratch_row_1 =
            run.scratch_offset_words +
            run_sum_source_row(
                row_1, manifest.target_log_size, run.source_log_size);
        numerator_0 = run_sum_add(
            numerator_0,
            load_run_sum(
                scratch_0, scratch_1, scratch_2, scratch_3, scratch_row_0));
        numerator_1 = run_sum_add(
            numerator_1,
            load_run_sum(
                scratch_0, scratch_1, scratch_2, scratch_3, scratch_row_1));
    }

    for (uint32_t term = manifest.direct_term_begin;
         term < manifest.direct_term_end; ++term) {
        const uint32_t *descriptor =
            term_descriptors + static_cast<size_t>(term) * TERM_WORDS;
        const uint32_t source_log_size = descriptor[2];
        const qm31 c = line_coefficients[
            static_cast<size_t>(descriptor[1]) *
                LINE_COEFFICIENTS_PER_TERM +
            C_COEFFICIENT_INDEX];
        const uint32_t *values = source_evaluations[descriptor[0]];
        numerator_0 = run_sum_add(
            numerator_0,
            run_sum_mul_by_scalar(
                c,
                values[run_sum_source_row(
                    row_0, manifest.target_log_size, source_log_size)]));
        numerator_1 = run_sum_add(
            numerator_1,
            run_sum_mul_by_scalar(
                c,
                values[run_sum_source_row(
                    row_1, manifest.target_log_size, source_log_size)]));
    }

    const qm31 b = *group_b;
    numerator_0 = run_sum_sub(numerator_0, b);
    numerator_1 = run_sum_sub(numerator_1, b);
    store_run_sum(
        numerator_0, output_0, output_1, output_2, output_3, row_0);
    store_run_sum(
        numerator_1, output_0, output_1, output_2, output_3, row_1);
}

extern "C" int stwo_precompute_quotient_numerator_native_run_on(
        const uint32_t *term_descriptors,
        uint32_t term_begin,
        uint32_t term_end,
        uint32_t source_log_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        uint32_t *scratch_0,
        uint32_t *scratch_1,
        uint32_t *scratch_2,
        uint32_t *scratch_3,
        uint32_t scratch_offset_words,
        void *stream
) {
    if (term_descriptors == nullptr || term_begin >= term_end ||
        source_log_size < MIN_NATIVE_RUN_LOG || source_log_size >= 31 ||
        source_evaluations == nullptr || line_coefficients == nullptr ||
        scratch_0 == nullptr || scratch_1 == nullptr ||
        scratch_2 == nullptr || scratch_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    const uint32_t native_rows = 1u << source_log_size;
    if (scratch_offset_words > UINT32_MAX - native_rows) {
        return cudaErrorInvalidValue;
    }
    const uint32_t blocks =
        (native_rows + BLOCK_THREADS - 1) / BLOCK_THREADS;
    stwo_quotient_numerator_native_run_precompute_kernel<<<
        blocks, BLOCK_THREADS, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            term_descriptors, term_begin, term_end, native_rows,
            source_evaluations, line_coefficients, scratch_0, scratch_1,
            scratch_2, scratch_3, scratch_offset_words);
    return cudaGetLastError();
}

extern "C" int stwo_expand_quotient_numerator_native_run_sums_on(
        const StwoQuotientNativeRunManifest *manifest,
        const uint32_t *term_descriptors,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const qm31 *group_b,
        const uint32_t *scratch_0,
        const uint32_t *scratch_1,
        const uint32_t *scratch_2,
        const uint32_t *scratch_3,
        uint32_t *output_0,
        uint32_t *output_1,
        uint32_t *output_2,
        uint32_t *output_3,
        void *stream
) {
    if (manifest == nullptr || !run_sum_manifest_is_canonical(*manifest) ||
        term_descriptors == nullptr || source_evaluations == nullptr ||
        line_coefficients == nullptr || group_b == nullptr ||
        scratch_0 == nullptr || scratch_1 == nullptr ||
        scratch_2 == nullptr || scratch_3 == nullptr ||
        output_0 == nullptr || output_1 == nullptr ||
        output_2 == nullptr || output_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }

    const StwoQuotientNativeRunManifest manifest_value = *manifest;
    const uint32_t half_rows =
        1u << (manifest_value.target_log_size - 1);
    const uint32_t blocks =
        (half_rows + BLOCK_THREADS - 1) / BLOCK_THREADS;
    // cudaLaunchKernel copies by-value argument bytes when the node is added,
    // including during stream capture; no host-manifest lifetime escapes here.
    stwo_quotient_numerator_run_sum_expand_kernel<<<
        blocks, BLOCK_THREADS, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            manifest_value, term_descriptors, source_evaluations,
            line_coefficients, group_b, scratch_0, scratch_1, scratch_2,
            scratch_3, output_0, output_1, output_2, output_3);
    return cudaGetLastError();
}

extern "C" int
stwo_quotient_numerator_native_run_precompute_function_attributes(
        StwoCudaFunctionAttributes *out
) {
    return stwo_cuda_function_attributes(
        stwo_quotient_numerator_native_run_precompute_kernel, out);
}

extern "C" int
stwo_quotient_numerator_native_run_sum_expand_function_attributes(
        StwoCudaFunctionAttributes *out
) {
    return stwo_cuda_function_attributes(
        stwo_quotient_numerator_run_sum_expand_kernel, out);
}
