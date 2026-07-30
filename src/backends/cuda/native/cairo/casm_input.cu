#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

#include "safety.cuh"

namespace stwo::cuda::cairo {

__global__ void scatter_casm_input(
    const std::uint32_t *rows,
    std::uint32_t real_rows,
    std::uint32_t consumer_rows,
    std::uint32_t *pc,
    std::uint32_t *ap,
    std::uint32_t *fp,
    std::uint32_t *enabler,
    std::uint32_t *iota) {
    const std::uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= consumer_rows) return;

    const std::uint32_t source_row = row < real_rows ? row : 0;
    const std::uint32_t *state =
        rows + static_cast<std::size_t>(source_row) * 3;
    pc[row] = state[0];
    ap[row] = state[1];
    fp[row] = state[2];
    enabler[row] = static_cast<std::uint32_t>(row < real_rows);
    if (iota != nullptr) iota[row] = row;
}

inline bool valid_ranges(
    const std::uint32_t *rows,
    std::size_t input_words,
    std::uint32_t *pc,
    std::uint32_t *ap,
    std::uint32_t *fp,
    std::uint32_t *enabler,
    std::uint32_t *iota,
    std::size_t output_words) {
    ByteRange input;
    ByteRange outputs[5];
    if (!element_range(rows, input_words, &input) ||
        !element_range(pc, output_words, &outputs[0]) ||
        !element_range(ap, output_words, &outputs[1]) ||
        !element_range(fp, output_words, &outputs[2]) ||
        !element_range(enabler, output_words, &outputs[3]) ||
        (iota != nullptr && !element_range(iota, output_words, &outputs[4]))) {
        return false;
    }
    const std::size_t output_count = iota == nullptr ? 4 : 5;
    for (std::size_t index = 0; index < output_count; ++index) {
        if (overlaps(input, outputs[index])) return false;
        for (std::size_t other = index + 1; other < output_count; ++other) {
            if (overlaps(outputs[index], outputs[other])) return false;
        }
    }
    return true;
}

}  // namespace stwo::cuda::cairo

extern "C" int stwo_witness_casm_input_scatter_on(
    const std::uint32_t *rows,
    std::uint32_t real_rows,
    std::uint32_t consumer_rows,
    std::uint32_t *pc,
    std::uint32_t *ap,
    std::uint32_t *fp,
    std::uint32_t *enabler,
    std::uint32_t *iota,
    void *stream_pointer) {
    using namespace stwo::cuda::cairo;
    if (real_rows == 0 || consumer_rows < 16 ||
        (consumer_rows & (consumer_rows - 1)) != 0 ||
        consumer_rows > (std::uint32_t{1} << 31) ||
        real_rows > consumer_rows || stream_pointer == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::uint32_t canonical_rows = 16;
    while (canonical_rows < real_rows) canonical_rows *= 2;
    if (consumer_rows != canonical_rows) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    std::size_t input_words;
    if (!checked_product(static_cast<std::size_t>(real_rows), 3, &input_words) ||
        !valid_ranges(
            rows,
            input_words,
            pc,
            ap,
            fp,
            enabler,
            iota,
            consumer_rows)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    constexpr std::uint32_t block_size = 256;
    const std::uint32_t grid_size = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(consumer_rows) + block_size - 1) /
        block_size);
    scatter_casm_input<<<
        grid_size,
        block_size,
        0,
        reinterpret_cast<cudaStream_t>(stream_pointer)>>>(
        rows,
        real_rows,
        consumer_rows,
        pc,
        ap,
        fp,
        enabler,
        iota);
    return static_cast<int>(cudaPeekAtLastError());
}
