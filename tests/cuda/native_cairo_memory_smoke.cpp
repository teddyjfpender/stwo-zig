#include <cuda_runtime_api.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle,
    std::size_t count,
    std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(
    void *handle,
    std::uint32_t *pointer);
extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *handle,
    void *destination,
    const void *source,
    std::size_t bytes);
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle,
    void *destination,
    const void *source,
    std::size_t bytes);
extern "C" int stwo_exec_context_pool_current(
    void *handle,
    std::size_t *used_current,
    std::size_t *reserved_current);

extern "C" int stwo_cairo_memory_split_big_on(
    const std::uint32_t *values,
    std::uint32_t value_count,
    std::uint32_t row_count,
    std::uint32_t *const *outputs,
    void *stream);
extern "C" int stwo_cairo_memory_split_small_on(
    const std::uint32_t *values,
    std::uint32_t value_count,
    std::uint32_t row_count,
    std::uint32_t *const *outputs,
    void *stream);
extern "C" int stwo_cairo_memory_address_base_on(
    const std::uint32_t *address_ids,
    std::uint32_t address_id_words,
    const std::uint32_t *multiplicities,
    std::uint32_t multiplicity_words,
    std::uint32_t row_count,
    std::uint32_t *const *outputs,
    void *stream);
extern "C" int stwo_cairo_memory_value_base_on(
    const std::uint32_t *const *sources,
    std::uint32_t limb_count,
    std::uint32_t source_words,
    const std::uint32_t *multiplicities,
    std::uint32_t multiplicity_words,
    std::uint32_t row_count,
    std::uint32_t *const *outputs,
    void *stream);
extern "C" int stwo_cairo_memory_range_check_9_9_on(
    const std::uint32_t *const *limbs,
    std::uint32_t pair_count,
    std::uint32_t row_count,
    const std::uint32_t *input_to_row,
    std::uint32_t table_rows,
    std::uint32_t *counts,
    std::uint32_t count_words,
    void *stream);

namespace {

constexpr std::uint32_t kRows = 16;
constexpr std::uint32_t kBigLimbs = 28;
constexpr std::uint32_t kSmallLimbs = 8;
constexpr std::uint32_t kRangeRows = 1u << 18u;

bool check(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(
        stderr,
        "%s: status=%d (%s)\n",
        operation,
        status,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

class Arena {
  public:
    bool create() {
        return check(stwo_exec_context_create(&context_), "create context") &&
               check(stwo_exec_context_stream(context_, &stream_), "get stream");
    }

    std::uint32_t *allocate(std::size_t words) {
        std::uint32_t *pointer = nullptr;
        if (!check(
                stwo_exec_context_alloc_u32(
                    context_,
                    std::max<std::size_t>(words, 1),
                    &pointer),
                "allocate memory smoke words")) {
            return nullptr;
        }
        allocations_.push_back(pointer);
        return pointer;
    }

    std::uint32_t *upload(const std::vector<std::uint32_t> &source) {
        auto *destination = allocate(source.size());
        if (destination == nullptr ||
            !check(
                stwo_exec_context_memcpy_h2d_async(
                    context_,
                    destination,
                    source.data(),
                    source.size() * sizeof(std::uint32_t)),
                "upload memory smoke words")) {
            return nullptr;
        }
        return destination;
    }

    bool download(
        std::vector<std::uint32_t> *destination,
        const std::uint32_t *source) {
        return check(
            stwo_exec_context_memcpy_d2h_async(
                context_,
                destination->data(),
                source,
                destination->size() * sizeof(std::uint32_t)),
            "download memory smoke words");
    }

    bool sync(const char *operation) {
        return check(stwo_exec_context_sync(context_), operation);
    }

    bool destroy() {
        bool passed = true;
        for (auto iterator = allocations_.rbegin();
             iterator != allocations_.rend();
             ++iterator) {
            passed =
                check(
                    stwo_exec_context_free_u32(context_, *iterator),
                    "free memory smoke words") &&
                passed;
        }
        passed = sync("wait for memory smoke frees") && passed;
        std::size_t used = 1;
        std::size_t reserved = 0;
        passed =
            check(
                stwo_exec_context_pool_current(
                    context_,
                    &used,
                    &reserved),
                "query memory smoke pool") &&
            passed;
        passed = used == 0 && passed;
        passed =
            check(stwo_exec_context_destroy(context_), "destroy context") &&
            passed;
        context_ = nullptr;
        return passed;
    }

    void *stream() const { return stream_; }

  private:
    void *context_ = nullptr;
    void *stream_ = nullptr;
    std::vector<std::uint32_t *> allocations_;
};

std::vector<std::uint32_t> splitReference(
    const std::vector<std::uint32_t> &words,
    std::uint32_t word_count,
    std::uint32_t value_count,
    std::uint32_t limb_count) {
    std::vector<std::uint32_t> output(limb_count * kRows);
    for (std::uint32_t row = 0; row < kRows; ++row) {
        std::uint32_t bit = 0;
        for (std::uint32_t limb = 0; limb < limb_count; ++limb) {
            std::uint32_t value = 0;
            if (row < value_count) {
                const std::uint32_t word = bit / 32;
                const std::uint32_t shift = bit % 32;
                value = words[row * word_count + word] >> shift;
                if (shift > 23 && word + 1 < word_count) {
                    value |= words[row * word_count + word + 1] <<
                        (32 - shift);
                }
                value &= 0x1ffu;
            }
            output[limb * kRows + row] = value;
            bit += 9;
        }
    }
    return output;
}

bool equal(
    const std::vector<std::uint32_t> &actual,
    const std::vector<std::uint32_t> &expected,
    const char *label) {
    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (actual[index] == expected[index]) continue;
        std::fprintf(
            stderr,
            "%s mismatch at %zu: actual=%u expected=%u\n",
            label,
            index,
            actual[index],
            expected[index]);
        return false;
    }
    return true;
}

bool run() {
    Arena arena;
    if (!arena.create()) return false;
    bool passed = true;

    std::vector<std::uint32_t> big_values(3 * 8);
    for (std::size_t index = 0; index < big_values.size(); ++index) {
        big_values[index] =
            static_cast<std::uint32_t>(0xf00d1234u + 0x1020304u * index);
    }
    auto *big_input = arena.upload(big_values);
    std::array<std::uint32_t *, kBigLimbs> big_columns{};
    for (auto &column : big_columns) column = arena.allocate(kRows);
    passed =
        big_input != nullptr &&
        std::all_of(
            big_columns.begin(),
            big_columns.end(),
            [](const auto *pointer) { return pointer != nullptr; }) &&
        check(
            stwo_cairo_memory_split_big_on(
                big_input,
                3,
                kRows,
                big_columns.data(),
                arena.stream()),
            "split big memory") &&
        passed;

    std::vector<std::uint32_t> big_actual(kBigLimbs * kRows);
    for (std::uint32_t limb = 0; limb < kBigLimbs; ++limb) {
        std::vector<std::uint32_t> column(kRows);
        passed = arena.download(&column, big_columns[limb]) && passed;
        std::copy(
            column.begin(),
            column.end(),
            big_actual.begin() + limb * kRows);
    }
    passed = arena.sync("wait for big split") && passed;
    const auto big_expected =
        splitReference(big_values, 8, 3, kBigLimbs);
    passed = equal(big_actual, big_expected, "big split") && passed;

    std::vector<std::uint32_t> small_values(5 * 4);
    for (std::size_t index = 0; index < small_values.size(); ++index) {
        small_values[index] =
            static_cast<std::uint32_t>(0x89abcdefu ^ (0x11111111u * index));
    }
    auto *small_input = arena.upload(small_values);
    std::array<std::uint32_t *, kSmallLimbs> small_columns{};
    for (auto &column : small_columns) column = arena.allocate(kRows);
    passed =
        check(
            stwo_cairo_memory_split_small_on(
                small_input,
                5,
                kRows,
                small_columns.data(),
                arena.stream()),
            "split small memory") &&
        passed;
    std::vector<std::uint32_t> small_actual(kSmallLimbs * kRows);
    for (std::uint32_t limb = 0; limb < kSmallLimbs; ++limb) {
        std::vector<std::uint32_t> column(kRows);
        passed = arena.download(&column, small_columns[limb]) && passed;
        std::copy(
            column.begin(),
            column.end(),
            small_actual.begin() + limb * kRows);
    }
    passed = arena.sync("wait for small split") && passed;
    passed =
        equal(
            small_actual,
            splitReference(small_values, 4, 5, kSmallLimbs),
            "small split") &&
        passed;

    std::vector<std::uint32_t> address_ids(37);
    std::vector<std::uint32_t> address_counts(16 * kRows);
    for (std::size_t index = 0; index < address_ids.size(); ++index)
        address_ids[index] = static_cast<std::uint32_t>(1000 + index);
    for (std::size_t index = 0; index < address_counts.size(); ++index)
        address_counts[index] = static_cast<std::uint32_t>(17 + index);
    auto *address_input = arena.upload(address_ids);
    auto *address_count_input = arena.upload(address_counts);
    std::array<std::uint32_t *, 32> address_outputs{};
    for (auto &column : address_outputs) column = arena.allocate(kRows);
    passed =
        check(
            stwo_cairo_memory_address_base_on(
                address_input,
                address_ids.size(),
                address_count_input,
                address_counts.size(),
                kRows,
                address_outputs.data(),
                arena.stream()),
            "build address memory trace") &&
        passed;
    for (std::uint32_t column = 0; column < 32; ++column) {
        std::vector<std::uint32_t> actual(kRows);
        passed = arena.download(&actual, address_outputs[column]) && passed;
        std::vector<std::uint32_t> expected(kRows);
        const std::uint32_t chunk = column / 2;
        for (std::uint32_t row = 0; row < kRows; ++row) {
            const std::uint32_t index = chunk * kRows + row;
            expected[row] = column % 2 == 0
                ? (index < address_ids.size() ? address_ids[index] : 0u)
                : address_counts[index];
        }
        passed = equal(actual, expected, "address trace") && passed;
    }

    std::vector<std::uint32_t> value_counts(kRows);
    for (std::uint32_t row = 0; row < kRows; ++row)
        value_counts[row] = 0x700u + row;
    auto *value_count_input = arena.upload(value_counts);
    std::array<std::uint32_t *, kBigLimbs + 1> value_outputs{};
    for (auto &column : value_outputs) column = arena.allocate(kRows);
    passed =
        check(
            stwo_cairo_memory_value_base_on(
                big_columns.data(),
                kBigLimbs,
                kRows,
                value_count_input,
                kRows,
                kRows,
                value_outputs.data(),
                arena.stream()),
            "build value memory trace") &&
        passed;
    for (std::uint32_t column = 0; column <= kBigLimbs; ++column) {
        std::vector<std::uint32_t> actual(kRows);
        passed = arena.download(&actual, value_outputs[column]) && passed;
        const auto begin = column == kBigLimbs
            ? value_counts.begin()
            : big_expected.begin() + column * kRows;
        std::vector<std::uint32_t> expected(begin, begin + kRows);
        passed = equal(actual, expected, "value trace") && passed;
    }

    std::vector<std::uint32_t> input_to_row(kRangeRows);
    for (std::uint32_t index = 0; index < kRangeRows; ++index)
        input_to_row[index] = index;
    std::vector<std::uint32_t> zero_counts(8 * kRangeRows, 0);
    auto *range_lut = arena.upload(input_to_row);
    auto *range_counts = arena.upload(zero_counts);
    passed =
        check(
            stwo_cairo_memory_range_check_9_9_on(
                big_columns.data(),
                kBigLimbs / 2,
                kRows,
                range_lut,
                kRangeRows,
                range_counts,
                zero_counts.size(),
                arena.stream()),
            "feed memory range checks") &&
        passed;
    std::vector<std::uint32_t> range_actual(zero_counts.size());
    passed = arena.download(&range_actual, range_counts) && passed;
    passed = arena.sync("wait for memory graph") && passed;
    std::vector<std::uint32_t> range_expected(zero_counts.size(), 0);
    for (std::uint32_t pair = 0; pair < kBigLimbs / 2; ++pair) {
        for (std::uint32_t row = 0; row < kRows; ++row) {
            const auto key =
                (big_expected[(2 * pair) * kRows + row] << 9u) |
                big_expected[(2 * pair + 1) * kRows + row];
            ++range_expected[(pair % 8) * kRangeRows + key];
        }
    }
    passed = equal(range_actual, range_expected, "range-check feed") && passed;
    return arena.destroy() && passed;
}

}  // namespace

int main() {
    if (!run()) return 1;
    std::printf(
        "native CUDA Cairo memory passed: big/small split, "
        "address/value base, range-check feed, exact resident outputs\n");
    return 0;
}
