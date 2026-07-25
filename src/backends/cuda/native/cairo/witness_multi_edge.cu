#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

#include "safety.cuh"

namespace stwo::cuda::cairo {

struct alignas(8) MultiEdgeDescriptor {
    std::uint64_t source_offset_words;
    std::uint32_t producer_rows;
    std::uint32_t word_base;
    std::uint32_t words_per_instance;
    std::uint32_t instance_count;
    std::uint32_t destination_row_offset;
    std::uint32_t reserved;
};

static_assert(sizeof(MultiEdgeDescriptor) == 32);
static_assert(alignof(MultiEdgeDescriptor) == 8);
static_assert(offsetof(MultiEdgeDescriptor, producer_rows) == 8);
static_assert(offsetof(MultiEdgeDescriptor, destination_row_offset) == 24);

__device__ const MultiEdgeDescriptor *edge_for_row(
    const MultiEdgeDescriptor *descriptors,
    std::uint32_t edge_count,
    std::uint32_t row) {
    std::uint32_t low = 0;
    std::uint32_t high = edge_count;
    while (low + 1 < high) {
        const std::uint32_t middle = low + (high - low) / 2;
        if (descriptors[middle].destination_row_offset <= row) {
            low = middle;
        } else {
            high = middle;
        }
    }
    return &descriptors[low];
}

__global__ void gather_witness_edges(
    const std::uint32_t *producer_arena,
    std::size_t producer_word_count,
    const MultiEdgeDescriptor *descriptors,
    std::uint32_t edge_count,
    std::uint32_t input_width,
    std::uint32_t total_real_rows,
    std::uint32_t consumer_rows,
    std::uint32_t *outputs,
    std::size_t output_stride_words,
    std::uint32_t include_enabler,
    std::uint32_t include_iota) {
    const std::uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= consumer_rows) return;
    const std::uint32_t source_global_row =
        row < total_real_rows ? row : (row & 15u);
    const MultiEdgeDescriptor *edge =
        edge_for_row(descriptors, edge_count, source_global_row);

    const std::uint64_t edge_rows =
        static_cast<std::uint64_t>(edge->producer_rows) *
        edge->instance_count;
    const bool structurally_valid =
        edge->reserved == 0 && edge->producer_rows != 0 &&
        edge->producer_rows % 16 == 0 &&
        edge->words_per_instance == input_width &&
        edge->instance_count != 0 &&
        source_global_row >= edge->destination_row_offset &&
        static_cast<std::uint64_t>(source_global_row) <
            static_cast<std::uint64_t>(edge->destination_row_offset) +
                edge_rows;
    const std::uint32_t local_row = structurally_valid
        ? source_global_row - edge->destination_row_offset
        : 0;
    const std::uint32_t instance = structurally_valid
        ? local_row / edge->producer_rows
        : 0;
    const std::uint32_t producer_row = structurally_valid
        ? local_row % edge->producer_rows
        : 0;
    for (std::uint32_t word = 0; word < input_width; ++word) {
        const std::uint64_t source_word =
            static_cast<std::uint64_t>(edge->word_base) +
            static_cast<std::uint64_t>(instance) * input_width + word;
        std::uint64_t source_index = producer_word_count;
        if (structurally_valid &&
            edge->source_offset_words <=
                UINT64_MAX - producer_row) {
            const std::uint64_t available =
                UINT64_MAX - edge->source_offset_words - producer_row;
            if (source_word <= available / edge->producer_rows) {
                source_index =
                    edge->source_offset_words +
                    source_word * edge->producer_rows + producer_row;
            }
        }
        outputs[static_cast<std::size_t>(word) * output_stride_words + row] =
            structurally_valid && source_index < producer_word_count
                ? producer_arena[source_index]
                : 0;
    }
    std::uint32_t tail = input_width;
    if (include_enabler != 0) {
        outputs[static_cast<std::size_t>(tail++) * output_stride_words + row] =
            static_cast<std::uint32_t>(row < total_real_rows);
    }
    if (include_iota != 0) {
        outputs[static_cast<std::size_t>(tail) * output_stride_words + row] =
            row;
    }
}

}  // namespace stwo::cuda::cairo

extern "C" int stwo_witness_multi_edge_gather_contiguous_on(
    const std::uint32_t *producer_arena,
    std::size_t producer_word_count,
    const stwo::cuda::cairo::MultiEdgeDescriptor *descriptors,
    std::uint32_t edge_count,
    std::uint32_t input_width,
    std::uint32_t total_real_rows,
    std::uint32_t consumer_rows,
    std::uint32_t *outputs,
    std::size_t output_stride_words,
    std::size_t output_capacity_words,
    std::uint32_t include_enabler,
    std::uint32_t include_iota,
    void *stream_pointer) {
    using namespace stwo::cuda::cairo;
    if (producer_word_count == 0 || edge_count == 0 || input_width == 0 ||
        total_real_rows == 0 || total_real_rows > consumer_rows ||
        consumer_rows < 16 || (consumer_rows & (consumer_rows - 1)) != 0 ||
        output_stride_words < consumer_rows ||
        include_enabler > 1 || include_iota > 1 ||
        stream_pointer == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::uint32_t canonical_rows = 16;
    while (canonical_rows < total_real_rows) canonical_rows *= 2;
    if (consumer_rows != canonical_rows) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    const std::size_t output_columns =
        static_cast<std::size_t>(input_width) +
        include_enabler + include_iota;
    std::size_t expected_output_capacity;
    if (!checked_product(
            output_stride_words,
            output_columns,
            &expected_output_capacity) ||
        expected_output_capacity != output_capacity_words) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ByteRange producer_range;
    ByteRange descriptor_range;
    ByteRange output_range;
    if (!element_range(
            producer_arena, producer_word_count, &producer_range) ||
        !element_range(descriptors, edge_count, &descriptor_range) ||
        !element_range(outputs, output_capacity_words, &output_range) ||
        overlaps(output_range, producer_range) ||
        overlaps(output_range, descriptor_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    constexpr std::uint32_t block_size = 256;
    const std::uint32_t grid_size =
        1 + (consumer_rows - 1) / block_size;
    gather_witness_edges<<<
        grid_size,
        block_size,
        0,
        reinterpret_cast<cudaStream_t>(stream_pointer)>>>(
        producer_arena,
        producer_word_count,
        descriptors,
        edge_count,
        input_width,
        total_real_rows,
        consumer_rows,
        outputs,
        output_stride_words,
        include_enabler,
        include_iota);
    return static_cast<int>(cudaPeekAtLastError());
}
