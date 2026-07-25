#include <cuda_runtime_api.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "safety.cuh"

namespace stwo::cuda::cairo {

__global__ void expand_witness_seed(
    const std::uint32_t *scalars,
    std::uint32_t scalar_count,
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
        if (column < scalar_count) {
            value = scalars[column];
        } else if (include_enabler != 0 && column == scalar_count) {
            value = static_cast<std::uint32_t>(row < real_rows);
        } else {
            value = row;
        }
        outputs[column * output_stride_words + row] = value;
    }
}

}  // namespace stwo::cuda::cairo

extern "C" int stwo_witness_input_seed_contiguous_on(
    const std::uint32_t *scalars,
    std::uint32_t scalar_count,
    std::uint32_t real_rows,
    std::uint32_t consumer_rows,
    std::uint32_t *outputs,
    std::size_t output_stride_words,
    std::size_t output_capacity_words,
    std::uint32_t include_enabler,
    std::uint32_t include_iota,
    void *stream_pointer) {
    using namespace stwo::cuda::cairo;
    if (scalar_count == 0 || real_rows == 0 || real_rows > consumer_rows ||
        consumer_rows == 0 || consumer_rows % 16 != 0 ||
        output_stride_words < consumer_rows ||
        include_enabler > 1 || include_iota > 1 ||
        stream_pointer == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::size_t output_columns;
    std::size_t expected_capacity;
    std::size_t total_cells;
    if (!checked_product(1, static_cast<std::size_t>(scalar_count) +
            include_enabler + include_iota, &output_columns) ||
        !checked_product(
            output_stride_words, output_columns, &expected_capacity) ||
        expected_capacity != output_capacity_words ||
        !checked_product(
            static_cast<std::size_t>(consumer_rows),
            output_columns,
            &total_cells)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ByteRange scalar_range;
    ByteRange output_range;
    if (!element_range(scalars, scalar_count, &scalar_range) ||
        !element_range(outputs, output_capacity_words, &output_range) ||
        overlaps(scalar_range, output_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    constexpr std::uint32_t block_size = 256;
    constexpr std::uint32_t maximum_blocks = 65535;
    const std::size_t requested_blocks =
        1 + (total_cells - 1) / block_size;
    const std::uint32_t grid_size = static_cast<std::uint32_t>(
        std::min<std::size_t>(requested_blocks, maximum_blocks));
    expand_witness_seed<<<
        grid_size,
        block_size,
        0,
        reinterpret_cast<cudaStream_t>(stream_pointer)>>>(
        scalars,
        scalar_count,
        real_rows,
        consumer_rows,
        outputs,
        output_stride_words,
        total_cells,
        include_enabler);
    return static_cast<int>(cudaPeekAtLastError());
}
