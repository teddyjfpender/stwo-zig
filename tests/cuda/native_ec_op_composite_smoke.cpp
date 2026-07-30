#include "../../src/backends/cuda/native/aot_loader.h"

#include <cuda_runtime_api.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle, std::size_t count, std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(
    void *handle, std::uint32_t *pointer);
extern "C" int stwo_exec_context_memset_async(
    void *handle, void *destination, int value, std::size_t bytes);
extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *handle, void *destination, const void *source, std::size_t bytes);
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle, void *destination, const void *source, std::size_t bytes);
extern "C" int ec_op_builtin_witness_on(
    const std::uint32_t *const *execution_tables,
    std::uint32_t n_addresses,
    std::uint32_t n_big,
    std::uint32_t n_small,
    const std::uint32_t *segment_start_source,
    std::uint32_t row_count,
    std::uint32_t *const *trace_columns_host,
    std::uint32_t *lookup_words,
    std::uint32_t *const *partial_input_columns_host,
    std::uint32_t partial_row_count,
    std::uint32_t *address_counts,
    std::uint32_t address_count_words,
    std::uint32_t *big_counts,
    std::uint32_t big_count_words,
    std::uint32_t *small_counts,
    std::uint32_t small_count_words,
    std::uint32_t *range_check_8_counts,
    std::uint32_t range_check_8_count_words,
    cudaStream_t stream);

namespace {

constexpr std::size_t kExecutionColumns = 37;
constexpr std::size_t kTraceColumns = 273;
constexpr std::size_t kLookupWordsPerRow = 488;
constexpr std::size_t kPartialColumns = 127;
constexpr std::size_t kPartialRounds = 256;
constexpr std::size_t kGenericInputColumns = 126;
constexpr std::size_t kGenericOutputColumns = 624;
constexpr std::size_t kGenericLookupWords = 990;
constexpr std::size_t kGenericSubWords = 424;
constexpr std::uint64_t kGenericCacheKey = 0xd6628b6f40a95659ull;
constexpr const char *kGenericKernel =
    "stwo_jit_witness_945de91f8879d0ac";
constexpr std::array<std::uint8_t, SHA256_DIGEST_LENGTH>
    kGenericOutputDigest = {
        0x64, 0xa9, 0x13, 0x4c, 0xc2, 0x8a, 0x5d, 0xd3,
        0x53, 0xa8, 0x64, 0x34, 0x66, 0x0c, 0x5d, 0xfb,
        0xe8, 0xbb, 0x7d, 0xce, 0xb9, 0xe5, 0x10, 0xa3,
        0x5a, 0x2e, 0xd4, 0xce, 0x59, 0x3b, 0x4e, 0xdb,
    };
constexpr std::array<std::uint8_t, SHA256_DIGEST_LENGTH>
    kGenericLookupDigest = {
        0x94, 0x6e, 0x0c, 0x8b, 0xd1, 0xcc, 0xa0, 0x26,
        0x86, 0xac, 0x24, 0xd5, 0x5a, 0x06, 0x56, 0x8e,
        0x31, 0x7a, 0xbc, 0xda, 0x7f, 0x20, 0xcc, 0x0d,
        0x0e, 0xa8, 0xf2, 0xff, 0xc6, 0xd3, 0x63, 0x87,
    };
constexpr std::array<std::uint8_t, SHA256_DIGEST_LENGTH>
    kGenericSubDigest = {
        0x1a, 0xe0, 0xd9, 0xfa, 0x6a, 0x59, 0x3c, 0x19,
        0xa1, 0xe3, 0xe8, 0x3c, 0x33, 0xfe, 0x3a, 0x02,
        0xc0, 0xcf, 0x7d, 0xc1, 0xa2, 0xd5, 0x81, 0xf0,
        0xba, 0xb9, 0x05, 0xad, 0xfe, 0xf3, 0xfe, 0x79,
    };

struct Fixture {
    std::uint32_t rows;
    std::uint32_t segment;
    std::uint32_t n_addresses;
    std::uint32_t n_big;
    std::uint32_t n_small;
    std::vector<std::uint32_t> addresses;
    std::vector<std::uint32_t> big_words;
    std::vector<std::uint32_t> small_words;
    std::vector<std::uint32_t> trace;
    std::vector<std::uint32_t> lookup;
    std::vector<std::uint32_t> partial;
};

bool check(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(stderr, "%s failed: CUDA status %d\n", operation, status);
    return false;
}

std::uint32_t take(const std::vector<std::uint8_t> &bytes, std::size_t &cursor) {
    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data() + cursor, sizeof(value));
    cursor += sizeof(value);
    return value;
}

bool take_words(
    const std::vector<std::uint8_t> &bytes,
    std::size_t &cursor,
    std::size_t count,
    std::vector<std::uint32_t> &out) {
    const std::size_t byte_count = count * sizeof(std::uint32_t);
    if (cursor > bytes.size() || byte_count > bytes.size() - cursor) {
        return false;
    }
    out.resize(count);
    std::memcpy(out.data(), bytes.data() + cursor, byte_count);
    cursor += byte_count;
    return true;
}

bool read_fixture(const char *path, Fixture &fixture) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    const std::vector<std::uint8_t> bytes{
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>()};
    constexpr std::uint8_t magic[8] = {
        'S', 'T', 'W', 'Z', 'E', 'C', 'O', 0};
    if (bytes.size() < 32 ||
        std::memcmp(bytes.data(), magic, sizeof(magic)) != 0) {
        return false;
    }
    std::size_t cursor = 8;
    if (take(bytes, cursor) != 1) return false;
    fixture.rows = take(bytes, cursor);
    fixture.segment = take(bytes, cursor);
    fixture.n_addresses = take(bytes, cursor);
    fixture.n_big = take(bytes, cursor);
    fixture.n_small = take(bytes, cursor);
    if (fixture.rows < 16 ||
        (fixture.rows & (fixture.rows - 1)) != 0) {
        return false;
    }
    const std::size_t rows = fixture.rows;
    const std::size_t partial_rows = rows * kPartialRounds;
    return take_words(
               bytes, cursor, fixture.n_addresses, fixture.addresses) &&
        take_words(
            bytes, cursor, static_cast<std::size_t>(fixture.n_big) * 8,
            fixture.big_words) &&
        take_words(
            bytes, cursor, static_cast<std::size_t>(fixture.n_small) * 4,
            fixture.small_words) &&
        take_words(bytes, cursor, rows * kTraceColumns, fixture.trace) &&
        take_words(
            bytes, cursor, rows * kLookupWordsPerRow, fixture.lookup) &&
        take_words(
            bytes, cursor, partial_rows * kPartialColumns,
            fixture.partial) &&
        cursor == bytes.size();
}

std::uint32_t extract_limb(
    const std::uint32_t *source,
    std::size_t source_words,
    std::size_t limb) {
    const std::size_t bit = limb * 9;
    const std::size_t source_limb = bit / 32;
    const std::uint32_t shift = static_cast<std::uint32_t>(bit % 32);
    std::uint32_t value = source[source_limb] >> shift;
    if (shift > 23 && source_limb + 1 < source_words) {
        value |= source[source_limb + 1] << (32 - shift);
    }
    return value & 0x1ff;
}

std::array<std::vector<std::uint32_t>, kExecutionColumns>
execution_columns(const Fixture &fixture) {
    std::array<std::vector<std::uint32_t>, kExecutionColumns> columns;
    columns[0] = fixture.addresses;
    for (std::size_t limb = 0; limb < 28; ++limb) {
        columns[1 + limb].resize(fixture.n_big);
        for (std::size_t row = 0; row < fixture.n_big; ++row) {
            columns[1 + limb][row] = extract_limb(
                fixture.big_words.data() + row * 8, 8, limb);
        }
    }
    for (std::size_t limb = 0; limb < 8; ++limb) {
        columns[29 + limb].resize(fixture.n_small);
        for (std::size_t row = 0; row < fixture.n_small; ++row) {
            columns[29 + limb][row] = extract_limb(
                fixture.small_words.data() + row * 4, 4, limb);
        }
    }
    return columns;
}

std::uint32_t memory_limb(
    const std::array<std::vector<std::uint32_t>, kExecutionColumns> &tables,
    std::uint32_t id,
    std::size_t limb) {
    const std::uint32_t tag = id >> 30;
    const std::uint32_t index = id & 0x3fffffffu;
    if (tag == 1 && index < tables[1 + limb].size()) {
        return tables[1 + limb][index];
    }
    if (tag == 0 && limb < 8 && index < tables[29 + limb].size()) {
        return tables[29 + limb][index];
    }
    return 0;
}

std::array<std::vector<std::uint32_t>, 4> expected_multiplicities(
    const Fixture &fixture,
    const std::array<std::vector<std::uint32_t>, kExecutionColumns> &tables) {
    std::array<std::vector<std::uint32_t>, 4> result = {
        std::vector<std::uint32_t>(fixture.n_addresses),
        std::vector<std::uint32_t>(fixture.n_big),
        std::vector<std::uint32_t>(fixture.n_small),
        std::vector<std::uint32_t>(256),
    };
    for (std::uint32_t row = 0; row < fixture.rows; ++row) {
        const std::uint32_t base = fixture.segment + 7 * row;
        for (std::uint32_t cell = 0; cell < 7; ++cell) {
            const std::uint32_t address = base + cell;
            const std::uint32_t id = fixture.addresses[address];
            ++result[0][address - 1];
            const std::uint32_t tag = id >> 30;
            const std::uint32_t index = id & 0x3fffffffu;
            if (tag == 1) {
                ++result[1][index];
            } else if (tag == 0) {
                ++result[2][index];
            }
        }
        const std::uint32_t scalar_id = fixture.addresses[base + 4];
        const std::uint32_t high = memory_limb(tables, scalar_id, 27);
        const std::uint32_t middle = memory_limb(tables, scalar_id, 21);
        const std::uint32_t high_is_max = high == 256;
        const std::uint32_t high_middle_are_max =
            high_is_max && middle == 136;
        const std::uint32_t rc0 = high - high_is_max;
        const std::uint32_t rc1 =
            high_is_max * (120 + middle - high_middle_are_max);
        ++result[3][rc0];
        ++result[3][rc1];
    }
    return result;
}

bool compare(
    const char *role,
    const std::vector<std::uint32_t> &expected,
    const std::vector<std::uint32_t> &actual,
    std::size_t rows) {
    if (expected.size() != actual.size()) return false;
    for (std::size_t word = 0; word < expected.size(); ++word) {
        if (expected[word] == actual[word]) continue;
        std::fprintf(
            stderr,
            "%s mismatch word=%zu column=%zu row=%zu expected=%u actual=%u\n",
            role,
            word,
            rows == 0 ? 0 : word / rows,
            rows == 0 ? word : word % rows,
            expected[word],
            actual[word]);
        return false;
    }
    return true;
}

bool compare_digest(
    const char *role,
    const std::vector<std::uint32_t> &words,
    const std::array<std::uint8_t, SHA256_DIGEST_LENGTH> &expected) {
    std::array<std::uint8_t, SHA256_DIGEST_LENGTH> actual{};
    SHA256(
        reinterpret_cast<const unsigned char *>(words.data()),
        words.size() * sizeof(std::uint32_t),
        actual.data());
    if (actual == expected) return true;
    std::fprintf(stderr, "%s SHA-256 mismatch expected=", role);
    for (const auto value : expected) std::fprintf(stderr, "%02x", value);
    std::fprintf(stderr, " actual=");
    for (const auto value : actual) std::fprintf(stderr, "%02x", value);
    std::fprintf(stderr, "\n");
    return false;
}

std::vector<std::uint32_t> column_major_trace(const Fixture &fixture) {
    std::vector<std::uint32_t> result(fixture.trace.size());
    for (std::size_t row = 0; row < fixture.rows; ++row) {
        for (std::size_t column = 0; column < kTraceColumns; ++column) {
            result[column * fixture.rows + row] =
                fixture.trace[row * kTraceColumns + column];
        }
    }
    return result;
}

bool run(const Fixture &fixture) {
    void *context = nullptr;
    void *raw_stream = nullptr;
    if (!check(stwo_exec_context_create(&context), "create context") ||
        !check(stwo_exec_context_stream(context, &raw_stream), "get stream")) {
        return false;
    }
    auto tables = execution_columns(fixture);
    const auto expected_counts = expected_multiplicities(fixture, tables);
    std::vector<std::uint32_t *> allocations;
    auto allocate = [&](std::size_t words) -> std::uint32_t * {
        std::uint32_t *pointer = nullptr;
        if (!check(
                stwo_exec_context_alloc_u32(context, words, &pointer),
                "allocate resident range")) {
            return nullptr;
        }
        allocations.push_back(pointer);
        return pointer;
    };
    auto upload = [&](std::uint32_t *destination, const void *source,
                      std::size_t words) {
        return check(
            stwo_exec_context_memcpy_h2d_async(
                context, destination, source, words * sizeof(std::uint32_t)),
            "upload resident range");
    };

    std::array<std::uint32_t *, kExecutionColumns> device_tables{};
    bool passed = true;
    for (std::size_t index = 0; index < device_tables.size(); ++index) {
        device_tables[index] = allocate(tables[index].size());
        passed = passed && device_tables[index] != nullptr &&
            upload(
                device_tables[index], tables[index].data(),
                tables[index].size());
    }
    const std::size_t table_pointer_words =
        (sizeof(device_tables) + sizeof(std::uint32_t) - 1) /
        sizeof(std::uint32_t);
    std::uint32_t *device_table_pointers = allocate(table_pointer_words);
    passed = passed && device_table_pointers != nullptr &&
        upload(
            device_table_pointers, device_tables.data(),
            table_pointer_words);
    std::uint32_t *segment = allocate(1);
    passed = passed && segment != nullptr &&
        upload(segment, &fixture.segment, 1);

    std::array<std::uint32_t *, kTraceColumns> trace{};
    for (auto &column : trace) column = allocate(fixture.rows);
    std::uint32_t *lookup =
        allocate(static_cast<std::size_t>(fixture.rows) * kLookupWordsPerRow);
    const std::size_t partial_rows =
        static_cast<std::size_t>(fixture.rows) * kPartialRounds;
    std::array<std::uint32_t *, kPartialColumns> partial{};
    for (auto &column : partial) column = allocate(partial_rows);
    std::array<std::uint32_t *, 4> counts{};
    for (std::size_t index = 0; index < counts.size(); ++index) {
        counts[index] = allocate(expected_counts[index].size());
    }
    std::array<std::uint32_t *, kGenericInputColumns> generic_inputs{};
    std::copy_n(partial.begin(), generic_inputs.size(), generic_inputs.begin());
    std::uint32_t *generic_input_pointers = allocate(
        (sizeof(generic_inputs) + sizeof(std::uint32_t) - 1) /
        sizeof(std::uint32_t));
    passed = passed && generic_input_pointers != nullptr &&
        upload(
            generic_input_pointers,
            generic_inputs.data(),
            (sizeof(generic_inputs) + sizeof(std::uint32_t) - 1) /
                sizeof(std::uint32_t));
    const std::size_t generic_output_words =
        kGenericOutputColumns * partial_rows;
    std::uint32_t *generic_output = allocate(generic_output_words);
    std::array<std::uint32_t *, kGenericOutputColumns> generic_outputs{};
    if (generic_output != nullptr) {
        for (std::size_t column = 0;
             column < generic_outputs.size(); ++column) {
            generic_outputs[column] =
                generic_output + column * partial_rows;
        }
    }
    std::uint32_t *generic_output_pointers = allocate(
        (sizeof(generic_outputs) + sizeof(std::uint32_t) - 1) /
        sizeof(std::uint32_t));
    passed = passed && generic_output != nullptr &&
        generic_output_pointers != nullptr &&
        upload(
            generic_output_pointers,
            generic_outputs.data(),
            (sizeof(generic_outputs) + sizeof(std::uint32_t) - 1) /
                sizeof(std::uint32_t));
    const std::array<std::uint32_t, 3> execution_strides = {
        fixture.n_addresses,
        fixture.n_big,
        fixture.n_small,
    };
    std::uint32_t *generic_strides = allocate(execution_strides.size());
    passed = passed && generic_strides != nullptr &&
        upload(
            generic_strides,
            execution_strides.data(),
            execution_strides.size());
    std::uint32_t *generic_multiplicity_pointers = allocate(2);
    std::uint32_t *generic_lookup =
        allocate(kGenericLookupWords * partial_rows);
    std::uint32_t *generic_sub =
        allocate(kGenericSubWords * partial_rows);
    passed = passed && generic_multiplicity_pointers != nullptr &&
        generic_lookup != nullptr && generic_sub != nullptr;
    for (std::uint32_t *pointer : trace) passed = passed && pointer != nullptr;
    for (std::uint32_t *pointer : partial) passed = passed && pointer != nullptr;
    passed = passed && lookup != nullptr;
    for (std::uint32_t *pointer : counts) passed = passed && pointer != nullptr;
    for (std::uint32_t *pointer : trace) {
        passed = passed && check(stwo_exec_context_memset_async(
            context, pointer, 0xa5, fixture.rows * sizeof(std::uint32_t)),
            "poison trace");
    }
    passed = passed && check(stwo_exec_context_memset_async(
        context, lookup, 0xa5,
        static_cast<std::size_t>(fixture.rows) * kLookupWordsPerRow *
            sizeof(std::uint32_t)), "poison lookup");
    for (std::uint32_t *pointer : partial) {
        passed = passed && check(stwo_exec_context_memset_async(
            context, pointer, 0xa5, partial_rows * sizeof(std::uint32_t)),
            "poison partial input");
    }
    for (std::size_t index = 0; index < counts.size(); ++index) {
        passed = passed && check(stwo_exec_context_memset_async(
            context, counts[index], 0,
            expected_counts[index].size() * sizeof(std::uint32_t)),
            "zero multiplicity");
    }
    passed = passed && check(stwo_exec_context_memset_async(
        context, generic_output, 0xa5,
        generic_output_words * sizeof(std::uint32_t)),
        "poison generic output");
    passed = passed && check(stwo_exec_context_memset_async(
        context, generic_lookup, 0xa5,
        kGenericLookupWords * partial_rows * sizeof(std::uint32_t)),
        "poison generic lookup");
    passed = passed && check(stwo_exec_context_memset_async(
        context, generic_sub, 0xa5,
        kGenericSubWords * partial_rows * sizeof(std::uint32_t)),
        "poison generic sub");
    passed = passed && check(stwo_exec_context_memset_async(
        context, generic_multiplicity_pointers, 0,
        2 * sizeof(std::uint32_t)),
        "zero empty generic multiplicity table");

    void *loader = nullptr;
    void *generic_function = nullptr;
    passed = passed && check(
        stwo_native_aot_loader_create(context, &loader),
        "create authenticated AOT loader");
    const std::uint32_t generic_grid[3] = {
        static_cast<std::uint32_t>(
            (partial_rows + 255) / 256),
        1,
        1,
    };
    const std::uint32_t generic_block[3] = {256, 1, 1};
    StwoNativeAotFunctionReceipt generic_receipt{};
    passed = passed && check(
        stwo_native_aot_function_bind(
            loader,
            kGenericCacheKey,
            2,
            kGenericKernel,
            generic_grid,
            generic_block,
            0,
            8,
            &generic_function,
            &generic_receipt),
        "bind authenticated partial-EC consumer");
    passed = passed &&
        generic_receipt.verification.verified == 1 &&
        generic_receipt.cache_key == kGenericCacheKey &&
        generic_receipt.argument_count == 8;

    cudaEvent_t begin = nullptr;
    cudaEvent_t end = nullptr;
    passed = passed &&
        check(cudaEventCreate(&begin), "create begin event") &&
        check(cudaEventCreate(&end), "create end event") &&
        check(
            cudaEventRecord(begin, static_cast<cudaStream_t>(raw_stream)),
            "record begin");
    if (passed) {
        passed = check(
            ec_op_builtin_witness_on(
                reinterpret_cast<const std::uint32_t *const *>(
                    device_table_pointers),
                fixture.n_addresses,
                fixture.n_big,
                fixture.n_small,
                segment,
                fixture.rows,
                trace.data(),
                lookup,
                partial.data(),
                static_cast<std::uint32_t>(partial_rows),
                counts[0],
                fixture.n_addresses,
                counts[1],
                fixture.n_big,
                counts[2],
                fixture.n_small,
                counts[3],
                256,
                static_cast<cudaStream_t>(raw_stream)),
            "launch native EC-op");
    }
    std::uint32_t generic_rows = static_cast<std::uint32_t>(partial_rows);
    auto *generic_input_table =
        reinterpret_cast<std::uint32_t **>(generic_input_pointers);
    auto *generic_execution_table =
        reinterpret_cast<std::uint32_t **>(device_table_pointers);
    auto *generic_output_table =
        reinterpret_cast<std::uint32_t **>(generic_output_pointers);
    auto *generic_multiplicity_table =
        reinterpret_cast<std::uint32_t **>(
            generic_multiplicity_pointers);
    void *generic_arguments[8] = {
        &generic_input_table,
        &generic_execution_table,
        &generic_strides,
        &generic_output_table,
        &generic_multiplicity_table,
        &generic_lookup,
        &generic_sub,
        &generic_rows,
    };
    if (passed) {
        passed = check(
            stwo_native_aot_function_launch(
                generic_function,
                generic_arguments,
                8),
            "launch authenticated partial-EC consumer");
    }
    passed = passed && check(
        cudaEventRecord(end, static_cast<cudaStream_t>(raw_stream)),
        "record end");

    std::vector<std::uint32_t> trace_output(fixture.trace.size());
    for (std::size_t column = 0; column < trace.size(); ++column) {
        passed = passed && check(stwo_exec_context_memcpy_d2h_async(
            context,
            trace_output.data() + column * fixture.rows,
            trace[column],
            fixture.rows * sizeof(std::uint32_t)), "read trace");
    }
    std::vector<std::uint32_t> lookup_output(fixture.lookup.size());
    passed = passed && check(stwo_exec_context_memcpy_d2h_async(
        context, lookup_output.data(), lookup,
        lookup_output.size() * sizeof(std::uint32_t)), "read lookup");
    std::vector<std::uint32_t> partial_output(fixture.partial.size());
    for (std::size_t column = 0; column < partial.size(); ++column) {
        passed = passed && check(stwo_exec_context_memcpy_d2h_async(
            context,
            partial_output.data() + column * partial_rows,
            partial[column],
            partial_rows * sizeof(std::uint32_t)), "read partial input");
    }
    std::array<std::vector<std::uint32_t>, 4> count_outputs;
    for (std::size_t index = 0; index < counts.size(); ++index) {
        count_outputs[index].resize(expected_counts[index].size());
        passed = passed && check(stwo_exec_context_memcpy_d2h_async(
            context, count_outputs[index].data(), counts[index],
            count_outputs[index].size() * sizeof(std::uint32_t)),
            "read multiplicity");
    }
    std::vector<std::uint32_t> generic_output_words_host(
        generic_output_words);
    std::vector<std::uint32_t> generic_lookup_host(
        kGenericLookupWords * partial_rows);
    std::vector<std::uint32_t> generic_sub_host(
        kGenericSubWords * partial_rows);
    passed = passed && check(stwo_exec_context_memcpy_d2h_async(
        context,
        generic_output_words_host.data(),
        generic_output,
        generic_output_words_host.size() * sizeof(std::uint32_t)),
        "read generic output");
    passed = passed && check(stwo_exec_context_memcpy_d2h_async(
        context,
        generic_lookup_host.data(),
        generic_lookup,
        generic_lookup_host.size() * sizeof(std::uint32_t)),
        "read generic lookup");
    passed = passed && check(stwo_exec_context_memcpy_d2h_async(
        context,
        generic_sub_host.data(),
        generic_sub,
        generic_sub_host.size() * sizeof(std::uint32_t)),
        "read generic sub");
    passed = passed && check(stwo_exec_context_sync(context), "sync graph");
    float device_ms = 0;
    if (passed) {
        passed = check(
            cudaEventElapsedTime(&device_ms, begin, end),
            "measure graph");
    }
    const auto expected_trace = column_major_trace(fixture);
    passed = passed &&
        compare("trace", expected_trace, trace_output, fixture.rows) &&
        compare("lookup", fixture.lookup, lookup_output, fixture.rows) &&
        compare(
            "partial", fixture.partial, partial_output, partial_rows);
    constexpr const char *count_names[4] = {
        "address multiplicity",
        "big multiplicity",
        "small multiplicity",
        "range-check-8 multiplicity",
    };
    for (std::size_t index = 0; index < counts.size(); ++index) {
        passed = passed && compare(
            count_names[index],
            expected_counts[index],
            count_outputs[index],
            0);
    }
    passed = passed &&
        compare_digest(
            "generic output",
            generic_output_words_host,
            kGenericOutputDigest) &&
        compare_digest(
            "generic lookup",
            generic_lookup_host,
            kGenericLookupDigest) &&
        compare_digest(
            "generic sub",
            generic_sub_host,
            kGenericSubDigest);
    StwoNativeAotStats aot_stats{};
    passed = passed && check(
        stwo_native_aot_loader_stats(loader, &aot_stats),
        "read AOT telemetry");
    passed = passed &&
        aot_stats.aot_loads == 1 &&
        aot_stats.aot_misses == 0 &&
        aot_stats.launches == 1 &&
        aot_stats.launch_failures == 0;
    if (begin != nullptr) cudaEventDestroy(begin);
    if (end != nullptr) cudaEventDestroy(end);
    if (generic_function != nullptr) {
        passed = check(
            stwo_native_aot_function_destroy(generic_function),
            "destroy partial-EC function") && passed;
    }
    if (loader != nullptr) {
        passed = check(
            stwo_native_aot_loader_destroy(loader),
            "destroy authenticated AOT loader") && passed;
    }
    for (auto iterator = allocations.rbegin();
         iterator != allocations.rend(); ++iterator) {
        passed = check(
            stwo_exec_context_free_u32(context, *iterator),
            "free resident range") && passed;
    }
    passed = check(stwo_exec_context_sync(context), "sync frees") && passed;
    passed = check(stwo_exec_context_destroy(context), "destroy context") &&
        passed;
    if (passed) {
        std::printf(
            "native CUDA EC composite passed: rows=%u partial_rows=%zu "
            "trace_words=%zu lookup_words=%zu partial_words=%zu "
            "multiplicity_words=%zu generic_output_words=%zu "
            "generic_lookup_words=%zu generic_sub_words=%zu "
            "launches=4 device_ms=%.3f "
            "hot_allocations=0 hot_copies=0 hot_syncs=0 jit=0 fallbacks=0\n",
            fixture.rows,
            partial_rows,
            fixture.trace.size(),
            fixture.lookup.size(),
            fixture.partial.size(),
            expected_counts[0].size() + expected_counts[1].size() +
                expected_counts[2].size() + expected_counts[3].size(),
            generic_output_words_host.size(),
            generic_lookup_host.size(),
            generic_sub_host.size(),
            device_ms);
    }
    return passed;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <ec_op_parity.bin>\n", argv[0]);
        return 2;
    }
    Fixture fixture{};
    if (!read_fixture(argv[1], fixture)) {
        std::fprintf(stderr, "invalid EC-op parity fixture\n");
        return 1;
    }
    return run(fixture) ? 0 : 1;
}
