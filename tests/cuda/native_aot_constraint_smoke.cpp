#include "../../src/backends/cuda/native/aot_loader.h"

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle,
    std::size_t count,
    std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(
    void *handle,
    std::uint32_t *pointer);
extern "C" int stwo_exec_context_fill_u32_async(
    void *handle,
    std::uint32_t *destination,
    std::uint32_t value,
    std::size_t count);
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

namespace {

constexpr std::uint64_t kCacheKey = 0xb0108a05e4de93caull;
constexpr std::uint32_t kConstraintSchema = 1;
constexpr std::uint32_t kArgumentCount = 13;
constexpr const char *kKernelName = "stwo_jit_fused_4a5dad552ce2c7ae";

bool check_status(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(
        stderr,
        "%s: status=%d (%s)\n",
        operation,
        status,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

std::uint32_t *allocate(void *context, std::size_t words) {
    std::uint32_t *result = nullptr;
    if (!check_status(
            stwo_exec_context_alloc_u32(context, words, &result),
            "allocate device words")) {
        return nullptr;
    }
    return result;
}

bool upload(
    void *context,
    void *destination,
    const void *source,
    std::size_t bytes) {
    return check_status(
        stwo_exec_context_memcpy_h2d_async(
            context,
            destination,
            source,
            bytes),
        "upload device words");
}

}  // namespace

int main() {
    void *context = nullptr;
    void *loader = nullptr;
    void *function = nullptr;
    if (!check_status(stwo_exec_context_create(&context), "create context") ||
        !check_status(
            stwo_native_aot_loader_create(context, &loader),
            "create AOT loader")) {
        return 1;
    }

    constexpr std::uint32_t row_count = 2;
    constexpr std::uint32_t sequence_len = 5;
    constexpr std::uint32_t trace_log_size = 0;
    constexpr std::uint32_t random_coefficient_base = 0;
    const std::uint32_t host_columns[sequence_len][row_count] = {
        {3, 3},
        {4, 4},
        {26, 26},
        {694, 694},
        {482315, 482315},
    };
    std::uint32_t *columns[sequence_len] = {};
    for (std::uint32_t index = 0; index < sequence_len; ++index) {
        columns[index] = allocate(context, row_count);
        if (columns[index] == nullptr ||
            !upload(
                context,
                columns[index],
                host_columns[index],
                sizeof(host_columns[index]))) {
            return 1;
        }
    }

    const std::size_t pointer_table_words =
        (sizeof(columns) + sizeof(std::uint32_t) - 1) / sizeof(std::uint32_t);
    std::uint32_t *trace_table = allocate(context, pointer_table_words);
    std::uint32_t *offsets = allocate(context, 3);
    std::uint32_t *base_parameters = allocate(context, 1);
    std::uint32_t *extension_parameters = allocate(context, 1);
    std::uint32_t *powers = allocate(context, 12);
    std::uint32_t *denominators = allocate(context, 2);
    std::uint32_t *coordinates[4] = {
        allocate(context, row_count),
        allocate(context, row_count),
        allocate(context, row_count),
        allocate(context, row_count),
    };
    if (trace_table == nullptr || offsets == nullptr ||
        base_parameters == nullptr || extension_parameters == nullptr ||
        powers == nullptr || denominators == nullptr ||
        coordinates[0] == nullptr || coordinates[1] == nullptr ||
        coordinates[2] == nullptr || coordinates[3] == nullptr) {
        return 1;
    }

    const std::uint32_t host_offsets[3] = {0, 0, sequence_len};
    const std::uint32_t host_base[1] = {sequence_len};
    const std::uint32_t host_extension[1] = {0};
    const std::uint32_t host_powers[12] = {
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
    };
    const std::uint32_t host_denominators[2] = {2, 3};
    if (!upload(context, trace_table, columns, sizeof(columns)) ||
        !upload(context, offsets, host_offsets, sizeof(host_offsets)) ||
        !upload(context, base_parameters, host_base, sizeof(host_base)) ||
        !upload(
            context,
            extension_parameters,
            host_extension,
            sizeof(host_extension)) ||
        !upload(context, powers, host_powers, sizeof(host_powers)) ||
        !upload(
            context,
            denominators,
            host_denominators,
            sizeof(host_denominators))) {
        return 1;
    }
    for (std::uint32_t *coordinate : coordinates) {
        if (!check_status(
                stwo_exec_context_fill_u32_async(
                    context,
                    coordinate,
                    0,
                    row_count),
                "zero constraint coordinate")) {
            return 1;
        }
    }

    const std::uint32_t grid[3] = {1, 1, 1};
    const std::uint32_t block[3] = {128, 1, 1};
    StwoNativeAotFunctionReceipt receipt{};
    if (!check_status(
            stwo_native_aot_function_bind(
                loader,
                kCacheKey,
                kConstraintSchema,
                kKernelName,
                grid,
                block,
                0,
                kArgumentCount,
                &function,
                &receipt),
            "bind AOT constraint")) {
        return 1;
    }
    if (receipt.abi_version != 1 ||
        receipt.abi_schema != kConstraintSchema ||
        receipt.cache_key != kCacheKey ||
        receipt.argument_count != kArgumentCount ||
        receipt.stream_token == 0) {
        std::fprintf(stderr, "invalid AOT binding receipt\n");
        return 1;
    }

    void *arguments[kArgumentCount] = {
        &trace_table,
        &offsets,
        &base_parameters,
        &extension_parameters,
        &powers,
        &denominators,
        &coordinates[0],
        &coordinates[1],
        &coordinates[2],
        &coordinates[3],
        const_cast<std::uint32_t *>(&row_count),
        const_cast<std::uint32_t *>(&trace_log_size),
        const_cast<std::uint32_t *>(&random_coefficient_base),
    };
    if (!check_status(
            stwo_native_aot_function_launch(
                function,
                arguments,
                kArgumentCount),
            "launch AOT constraint") ||
        !check_status(stwo_exec_context_sync(context), "wait for AOT constraint")) {
        return 1;
    }

    const std::uint32_t expected[4][row_count] = {
        {76, 114},
        {88, 132},
        {100, 150},
        {112, 168},
    };
    std::uint32_t actual[4][row_count] = {};
    for (std::uint32_t index = 0; index < 4; ++index) {
        if (!check_status(
                stwo_exec_context_memcpy_d2h_async(
                    context,
                    actual[index],
                    coordinates[index],
                    sizeof(actual[index])),
                "read constraint coordinate")) {
            return 1;
        }
    }
    if (!check_status(stwo_exec_context_sync(context), "wait for constraint read")) {
        return 1;
    }
    for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        for (std::uint32_t row = 0; row < row_count; ++row) {
            if (actual[coordinate][row] != expected[coordinate][row]) {
                std::fprintf(
                    stderr,
                    "constraint mismatch coordinate=%u row=%u expected=%u actual=%u\n",
                    coordinate,
                    row,
                    expected[coordinate][row],
                    actual[coordinate][row]);
                return 1;
            }
        }
    }

    StwoNativeAotStats stats{};
    if (!check_status(
            stwo_native_aot_loader_stats(loader, &stats),
            "read AOT stats") ||
        stats.aot_loads != 1 || stats.aot_misses != 0 ||
        stats.launches != 1 || stats.launch_failures != 0) {
        std::fprintf(stderr, "invalid AOT telemetry\n");
        return 1;
    }

    if (!check_status(
            stwo_native_aot_function_destroy(function),
            "destroy AOT function") ||
        !check_status(stwo_native_aot_loader_destroy(loader), "destroy AOT loader")) {
        return 1;
    }
    std::vector<std::uint32_t *> allocations(
        columns,
        columns + sequence_len);
    allocations.insert(
        allocations.end(),
        {trace_table, offsets, base_parameters, extension_parameters,
         powers, denominators, coordinates[0], coordinates[1],
         coordinates[2], coordinates[3]});
    for (std::uint32_t *allocation : allocations) {
        if (!check_status(
                stwo_exec_context_free_u32(context, allocation),
                "free AOT workspace")) {
            return 1;
        }
    }
    if (!check_status(stwo_exec_context_sync(context), "wait for AOT frees") ||
        !check_status(stwo_exec_context_destroy(context), "destroy context")) {
        return 1;
    }
    std::printf("native CUDA AOT constraint smoke passed\n");
    return 0;
}
