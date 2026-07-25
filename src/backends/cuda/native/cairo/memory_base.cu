// Resident Cairo memory base traces and range-check multiplicity feed.
//
// These kernels preserve the imported memory_witness.cu formulas while
// exposing only exact, explicit-stream Zig product ABIs.

#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>

namespace {

constexpr std::uint32_t kBlockThreads = 256;
constexpr std::uint32_t kMaximumColumns = 32;
constexpr std::uint32_t kMaximumLimbs = 28;

struct Columns {
    std::uint32_t *values[kMaximumColumns];
};

struct Sources {
    const std::uint32_t *values[kMaximumLimbs];
};

__global__ void address_base(
    const std::uint32_t *address_ids,
    std::uint32_t address_id_words,
    const std::uint32_t *multiplicities,
    std::uint32_t row_count,
    Columns outputs) {
    const std::uint32_t row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) return;
    for (std::uint32_t chunk = 0; chunk < 16; ++chunk) {
        const std::uint32_t index = chunk * row_count + row;
        outputs.values[2 * chunk][row] =
            index < address_id_words ? address_ids[index] : 0u;
        outputs.values[2 * chunk + 1][row] = multiplicities[index];
    }
}

__global__ void value_base(
    Sources sources,
    std::uint32_t limb_count,
    std::uint32_t source_words,
    const std::uint32_t *multiplicities,
    std::uint32_t row_count,
    Columns outputs) {
    const std::uint32_t row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) return;
    for (std::uint32_t limb = 0; limb < limb_count; ++limb) {
        outputs.values[limb][row] =
            row < source_words ? sources.values[limb][row] : 0u;
    }
    outputs.values[limb_count][row] = multiplicities[row];
}

__global__ void range_check_9_9_counts(
    Sources limbs,
    std::uint32_t pair_count,
    std::uint32_t row_count,
    const std::uint32_t *input_to_row,
    std::uint32_t table_rows,
    std::uint32_t *counts) {
    const std::uint32_t row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) return;
    for (std::uint32_t pair = 0; pair < pair_count; ++pair) {
        const std::uint32_t low = limbs.values[2 * pair][row];
        const std::uint32_t high = limbs.values[2 * pair + 1][row];
        const std::uint32_t table_row =
            input_to_row[(low << 9u) | high];
        atomicAdd(
            &counts[(pair % 8u) *
                static_cast<std::size_t>(table_rows) + table_row],
            1u);
    }
}

bool bind_outputs(
    std::uint32_t *const *source,
    std::uint32_t count,
    Columns *outputs) {
    if (source == nullptr || outputs == nullptr ||
        count == 0 || count > kMaximumColumns) {
        return false;
    }
    for (std::uint32_t index = 0; index < count; ++index) {
        if (source[index] == nullptr) return false;
        outputs->values[index] = source[index];
    }
    return true;
}

bool bind_sources(
    const std::uint32_t *const *source,
    std::uint32_t count,
    Sources *outputs) {
    if (source == nullptr || outputs == nullptr ||
        count == 0 || count > kMaximumLimbs) {
        return false;
    }
    for (std::uint32_t index = 0; index < count; ++index) {
        if (source[index] == nullptr) return false;
        outputs->values[index] = source[index];
    }
    return true;
}

}  // namespace

extern "C" int stwo_cairo_memory_address_base_on(
    const std::uint32_t *address_ids,
    std::uint32_t address_id_words,
    const std::uint32_t *multiplicities,
    std::uint32_t multiplicity_words,
    std::uint32_t row_count,
    std::uint32_t *const *outputs_host,
    void *stream) {
    Columns outputs{};
    if (address_ids == nullptr || multiplicities == nullptr ||
        stream == nullptr || row_count == 0 ||
        row_count > UINT32_MAX / 16u ||
        multiplicity_words != 16u * row_count ||
        address_id_words > multiplicity_words ||
        !bind_outputs(outputs_host, 32, &outputs)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const std::uint32_t blocks =
        1u + (row_count - 1u) / kBlockThreads;
    address_base<<<blocks, kBlockThreads, 0,
        static_cast<cudaStream_t>(stream)>>>(
            address_ids,
            address_id_words,
            multiplicities,
            row_count,
            outputs);
    return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_cairo_memory_value_base_on(
    const std::uint32_t *const *sources_host,
    std::uint32_t limb_count,
    std::uint32_t source_words,
    const std::uint32_t *multiplicities,
    std::uint32_t multiplicity_words,
    std::uint32_t row_count,
    std::uint32_t *const *outputs_host,
    void *stream) {
    Sources sources{};
    Columns outputs{};
    if (multiplicities == nullptr || stream == nullptr ||
        row_count == 0 || source_words > row_count ||
        multiplicity_words != row_count ||
        !bind_sources(sources_host, limb_count, &sources) ||
        !bind_outputs(outputs_host, limb_count + 1u, &outputs)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const std::uint32_t blocks =
        1u + (row_count - 1u) / kBlockThreads;
    value_base<<<blocks, kBlockThreads, 0,
        static_cast<cudaStream_t>(stream)>>>(
            sources,
            limb_count,
            source_words,
            multiplicities,
            row_count,
            outputs);
    return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_cairo_memory_range_check_9_9_on(
    const std::uint32_t *const *limbs_host,
    std::uint32_t pair_count,
    std::uint32_t row_count,
    const std::uint32_t *input_to_row,
    std::uint32_t table_rows,
    std::uint32_t *counts,
    std::uint32_t count_words,
    void *stream) {
    Sources limbs{};
    if (input_to_row == nullptr || counts == nullptr || stream == nullptr ||
        row_count == 0 || pair_count == 0 ||
        pair_count > kMaximumLimbs / 2u ||
        table_rows != (1u << 18u) ||
        count_words != 8u * table_rows ||
        !bind_sources(limbs_host, 2u * pair_count, &limbs)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const std::uint32_t blocks =
        1u + (row_count - 1u) / kBlockThreads;
    range_check_9_9_counts<<<blocks, kBlockThreads, 0,
        static_cast<cudaStream_t>(stream)>>>(
            limbs,
            pair_count,
            row_count,
            input_to_row,
            table_rows,
            counts);
    return static_cast<int>(cudaGetLastError());
}
