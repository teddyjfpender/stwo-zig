#include <cuda_runtime_api.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int stwo_witness_input_compact_sort_temp_bytes(
    std::uint32_t rows,
    std::size_t *out_bytes);
extern "C" int stwo_witness_input_compact_scan_temp_bytes(
    std::uint32_t rows,
    std::size_t *out_bytes);
extern "C" int stwo_witness_input_compact_v2_on(
    const std::uint32_t *const *producer_pointer_table,
    const std::uint32_t *edge_descriptors,
    std::uint32_t edge_count,
    std::uint32_t tuple_words,
    std::uint32_t key_words,
    std::uint32_t total_rows,
    std::uint32_t sort_rows,
    std::uint32_t consumer_rows,
    std::uint32_t input_count,
    std::uint32_t *const *consumer_pointer_table,
    std::uint32_t enabler_slot,
    std::uint32_t iota_slot,
    std::uint32_t multiplicity_slot,
    std::uint32_t *tuples,
    std::uint32_t *keys_a,
    std::uint32_t *keys_b,
    std::uint32_t *indices_a,
    std::uint32_t *indices_b,
    std::uint32_t *heads,
    std::uint32_t *positions,
    std::uint32_t *unique_count,
    void *sort_temp,
    std::size_t sort_temp_bytes,
    void *scan_temp,
    std::size_t scan_temp_bytes,
    void *stream);

namespace {

constexpr std::uint32_t kStrideRows = 32;
constexpr std::uint32_t kRealRows = 17;
constexpr std::uint32_t kSortRows = 32;
constexpr std::uint32_t kConsumerRows = 16;
constexpr std::uint32_t kTupleWords = 3;
constexpr std::uint32_t kInputCount = 6;

bool cuda_ok(cudaError_t status, const char *operation) {
    if (status == cudaSuccess) return true;
    std::fprintf(
        stderr,
        "%s failed: %s\n",
        operation,
        cudaGetErrorString(status));
    return false;
}

template <typename T>
T *allocate(std::size_t count, std::vector<void *> *allocations) {
    T *pointer = nullptr;
    if (!cuda_ok(
            cudaMalloc(reinterpret_cast<void **>(&pointer), count * sizeof(T)),
            "cudaMalloc")) {
        return nullptr;
    }
    allocations->push_back(pointer);
    return pointer;
}

bool run() {
    cudaStream_t stream = nullptr;
    if (!cuda_ok(cudaStreamCreate(&stream), "create stream")) return false;
    std::vector<void *> allocations;
    auto release = [&]() {
        for (auto iterator = allocations.rbegin();
             iterator != allocations.rend();
             ++iterator) {
            cudaFree(*iterator);
        }
        cudaStreamDestroy(stream);
    };

    std::array<std::uint32_t, kStrideRows * kTupleWords> source{};
    for (std::uint32_t row = 0; row < kStrideRows; ++row) {
        const bool active = row < 16;
        const std::uint32_t value =
            active ? row : (row == 16 ? 0 : 1000 + row);
        source[row] = value;
        source[kStrideRows + row] = value + 100;
        source[2 * kStrideRows + row] = value + 200;
    }
    const std::array<std::uint32_t, 6> descriptor{
        kStrideRows,
        kRealRows,
        0,
        kTupleWords,
        1,
        0,
    };

    auto *device_source =
        allocate<std::uint32_t>(source.size(), &allocations);
    auto *device_descriptor =
        allocate<std::uint32_t>(descriptor.size(), &allocations);
    auto *device_outputs = allocate<std::uint32_t>(
        kInputCount * kConsumerRows,
        &allocations);
    auto *device_producer_table =
        allocate<const std::uint32_t *>(1, &allocations);
    auto *device_consumer_table =
        allocate<std::uint32_t *>(kInputCount, &allocations);
    auto *tuples = allocate<std::uint32_t>(
        kSortRows * kTupleWords,
        &allocations);
    auto *keys_a = allocate<std::uint32_t>(kSortRows, &allocations);
    auto *keys_b = allocate<std::uint32_t>(kSortRows, &allocations);
    auto *indices_a = allocate<std::uint32_t>(kSortRows, &allocations);
    auto *indices_b = allocate<std::uint32_t>(kSortRows, &allocations);
    auto *heads = allocate<std::uint32_t>(kSortRows, &allocations);
    auto *positions = allocate<std::uint32_t>(kSortRows, &allocations);
    auto *unique_count = allocate<std::uint32_t>(1, &allocations);
    if (device_source == nullptr || device_descriptor == nullptr ||
        device_outputs == nullptr || device_producer_table == nullptr ||
        device_consumer_table == nullptr || tuples == nullptr ||
        keys_a == nullptr || keys_b == nullptr || indices_a == nullptr ||
        indices_b == nullptr || heads == nullptr || positions == nullptr ||
        unique_count == nullptr) {
        release();
        return false;
    }

    const std::array<const std::uint32_t *, 1> producer_table{device_source};
    std::array<std::uint32_t *, kInputCount> consumer_table{};
    for (std::size_t column = 0; column < consumer_table.size(); ++column) {
        consumer_table[column] =
            device_outputs + column * kConsumerRows;
    }
    if (!cuda_ok(
            cudaMemcpyAsync(
                device_source,
                source.data(),
                sizeof(source),
                cudaMemcpyHostToDevice,
                stream),
            "upload padded producer") ||
        !cuda_ok(
            cudaMemcpyAsync(
                device_descriptor,
                descriptor.data(),
                sizeof(descriptor),
                cudaMemcpyHostToDevice,
                stream),
            "upload v2 descriptor") ||
        !cuda_ok(
            cudaMemcpyAsync(
                device_producer_table,
                producer_table.data(),
                sizeof(producer_table),
                cudaMemcpyHostToDevice,
                stream),
            "upload producer table") ||
        !cuda_ok(
            cudaMemcpyAsync(
                device_consumer_table,
                consumer_table.data(),
                sizeof(consumer_table),
                cudaMemcpyHostToDevice,
                stream),
            "upload consumer table")) {
        release();
        return false;
    }

    std::size_t sort_temp_bytes = 0;
    std::size_t scan_temp_bytes = 0;
    if (stwo_witness_input_compact_sort_temp_bytes(
            kSortRows, &sort_temp_bytes) != 0 ||
        stwo_witness_input_compact_scan_temp_bytes(
            kSortRows, &scan_temp_bytes) != 0) {
        std::fprintf(stderr, "compact scratch query failed\n");
        release();
        return false;
    }
    auto *sort_temp =
        allocate<std::uint8_t>(sort_temp_bytes, &allocations);
    auto *scan_temp =
        allocate<std::uint8_t>(scan_temp_bytes, &allocations);
    if (sort_temp == nullptr || scan_temp == nullptr) {
        release();
        return false;
    }

    const int status = stwo_witness_input_compact_v2_on(
        device_producer_table,
        device_descriptor,
        1,
        kTupleWords,
        kTupleWords,
        kRealRows,
        kSortRows,
        kConsumerRows,
        kInputCount,
        device_consumer_table,
        3,
        4,
        5,
        tuples,
        keys_a,
        keys_b,
        indices_a,
        indices_b,
        heads,
        positions,
        unique_count,
        sort_temp,
        sort_temp_bytes,
        scan_temp,
        scan_temp_bytes,
        stream);
    if (status != 0 ||
        !cuda_ok(cudaStreamSynchronize(stream), "compact v2")) {
        release();
        return false;
    }

    std::array<std::uint32_t, kInputCount * kConsumerRows> output{};
    std::uint32_t unique = 0;
    if (!cuda_ok(
            cudaMemcpy(
                output.data(),
                device_outputs,
                sizeof(output),
                cudaMemcpyDeviceToHost),
            "download compact output") ||
        !cuda_ok(
            cudaMemcpy(
                &unique,
                unique_count,
                sizeof(unique),
                cudaMemcpyDeviceToHost),
            "download unique count")) {
        release();
        return false;
    }
    if (unique != kConsumerRows) {
        std::fprintf(stderr, "unique count mismatch: %u\n", unique);
        release();
        return false;
    }
    for (std::uint32_t row = 0; row < kConsumerRows; ++row) {
        const std::uint32_t expected_multiplicity = row == 0 ? 2 : 1;
        if (output[row] != row ||
            output[kConsumerRows + row] != row + 100 ||
            output[2 * kConsumerRows + row] != row + 200 ||
            output[3 * kConsumerRows + row] != 1 ||
            output[4 * kConsumerRows + row] != row ||
            output[5 * kConsumerRows + row] != expected_multiplicity) {
            std::fprintf(stderr, "compact v2 mismatch at row %u\n", row);
            release();
            return false;
        }
    }

    release();
    return true;
}

}  // namespace

int main() {
    if (!run()) return 1;
    std::printf("native CUDA witness compact v2 smoke passed\n");
    return 0;
}
