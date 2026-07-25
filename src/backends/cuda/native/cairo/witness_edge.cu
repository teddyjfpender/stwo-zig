#include <cuda_runtime_api.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "safety.cuh"

namespace stwo::cuda::cairo {

__global__ void gather_witness_edge(
    const std::uint32_t *producer,
    std::uint32_t producer_rows,
    std::uint32_t word_base,
    std::uint32_t words_per_instance,
    std::uint32_t real_rows,
    std::uint32_t consumer_rows,
    std::uint32_t *outputs,
    std::size_t output_stride_words,
    std::size_t total_cells,
    std::uint32_t include_enabler) {
    const std::size_t first =
        static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const std::size_t step =
        static_cast<std::size_t>(blockDim.x) * gridDim.x;
    for (std::size_t cell = first; cell < total_cells; cell += step) {
        const std::size_t column = cell / consumer_rows;
        const std::uint32_t row =
            static_cast<std::uint32_t>(cell % consumer_rows);
        std::uint32_t value;
        if (column < words_per_instance) {
            const std::uint32_t source_row =
                row < real_rows ? row : (row & 15u);
            const std::uint32_t instance = source_row / producer_rows;
            const std::uint32_t producer_row = source_row % producer_rows;
            const std::size_t source_word =
                static_cast<std::size_t>(word_base) +
                static_cast<std::size_t>(instance) * words_per_instance +
                column;
            value = producer[source_word * producer_rows + producer_row];
        } else if (include_enabler != 0 && column == words_per_instance) {
            value = static_cast<std::uint32_t>(row < real_rows);
        } else {
            value = row;
        }
        outputs[column * output_stride_words + row] = value;
    }
}

}  // namespace stwo::cuda::cairo

extern "C" int stwo_witness_edge_gather_contiguous_on(
    const std::uint32_t *producer,
    std::size_t producer_capacity_words,
    std::uint32_t producer_rows,
    std::uint32_t word_base,
    std::uint32_t words_per_instance,
    std::uint32_t instance_count,
    std::uint32_t consumer_rows,
    std::uint32_t *outputs,
    std::size_t output_stride_words,
    std::size_t output_capacity_words,
    std::uint32_t include_enabler,
    std::uint32_t include_iota,
    void *stream_pointer) {
    using namespace stwo::cuda::cairo;
    std::size_t real_rows;
    if (producer_rows == 0 || producer_rows % 16 != 0 ||
        words_per_instance == 0 || instance_count == 0 ||
        !checked_product(producer_rows, instance_count, &real_rows) ||
        real_rows > (std::size_t{1} << 31) ||
        consumer_rows < real_rows || stream_pointer == nullptr ||
        include_enabler > 1 || include_iota > 1) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::uint32_t canonical_rows = 16;
    while (canonical_rows < real_rows) canonical_rows *= 2;
    if (consumer_rows != canonical_rows ||
        output_stride_words < consumer_rows) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    std::size_t instance_words;
    std::size_t source_word_end;
    std::size_t required_source_words;
    std::size_t output_columns =
        static_cast<std::size_t>(words_per_instance) +
        include_enabler + include_iota;
    std::size_t expected_output_capacity;
    std::size_t total_cells;
    if (!checked_product(words_per_instance, instance_count, &instance_words) ||
        !checked_sum(word_base, instance_words, &source_word_end) ||
        !checked_product(
            source_word_end, producer_rows, &required_source_words) ||
        required_source_words > producer_capacity_words ||
        !checked_product(
            output_stride_words, output_columns, &expected_output_capacity) ||
        expected_output_capacity != output_capacity_words ||
        !checked_product(consumer_rows, output_columns, &total_cells)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ByteRange producer_range;
    ByteRange output_range;
    if (!element_range(
            producer, producer_capacity_words, &producer_range) ||
        !element_range(outputs, output_capacity_words, &output_range) ||
        overlaps(producer_range, output_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    constexpr std::uint32_t block_size = 256;
    constexpr std::uint32_t maximum_blocks = 65535;
    const std::size_t requested_blocks =
        1 + (total_cells - 1) / block_size;
    const std::uint32_t grid_size = static_cast<std::uint32_t>(
        std::min<std::size_t>(requested_blocks, maximum_blocks));
    gather_witness_edge<<<
        grid_size,
        block_size,
        0,
        reinterpret_cast<cudaStream_t>(stream_pointer)>>>(
        producer,
        producer_rows,
        word_base,
        words_per_instance,
        static_cast<std::uint32_t>(real_rows),
        consumer_rows,
        outputs,
        output_stride_words,
        total_cells,
        include_enabler);
    return static_cast<int>(cudaPeekAtLastError());
}
