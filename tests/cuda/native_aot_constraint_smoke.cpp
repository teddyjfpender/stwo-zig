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

constexpr std::uint64_t kCacheKey = 0x7a6ba68d80b91b07ull;
constexpr std::uint32_t kConstraintSchema = 4;
constexpr std::uint32_t kArgumentCount = 14;
constexpr const char *kKernelName =
    "stwo_native_constraint_wide_fibonacci_slab_v1_6f60dbf6e15716eb";

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
    constexpr std::uint64_t trace_stride_words = 4;
    constexpr std::uint64_t trace_slab_words =
        (sequence_len - 1) * trace_stride_words + row_count;
    constexpr std::uint64_t random_coefficient_words = 12;
    constexpr std::uint64_t denominator_words = 2;
    constexpr std::uint64_t coordinate_stride_words = 4;
    constexpr std::uint64_t coordinate_slab_words =
        3 * coordinate_stride_words + row_count;
    const std::uint32_t host_columns[sequence_len][row_count] = {
        {3, 3},
        {4, 4},
        {26, 26},
        {694, 694},
        {482315, 482315},
    };
    std::uint32_t host_trace_slab[trace_slab_words] = {};
    for (std::uint32_t column = 0; column < sequence_len; ++column) {
        for (std::uint32_t row = 0; row < row_count; ++row) {
            host_trace_slab[column * trace_stride_words + row] =
                host_columns[column][row];
        }
    }

    std::uint32_t *trace_slab = allocate(context, trace_slab_words);
    std::uint32_t *powers = allocate(context, random_coefficient_words);
    std::uint32_t *denominators = allocate(context, denominator_words);
    std::uint32_t *coordinate_slab =
        allocate(context, coordinate_slab_words);
    if (trace_slab == nullptr || powers == nullptr || denominators == nullptr ||
        coordinate_slab == nullptr) {
        return 1;
    }

    const std::uint32_t host_powers[12] = {
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
    };
    const std::uint32_t host_denominators[2] = {2, 3};
    if (!upload(context, trace_slab, host_trace_slab, sizeof(host_trace_slab)) ||
        !upload(context, powers, host_powers, sizeof(host_powers)) ||
        !upload(
            context,
            denominators,
            host_denominators,
            sizeof(host_denominators))) {
        return 1;
    }
    if (!check_status(
            stwo_exec_context_fill_u32_async(
                context,
                coordinate_slab,
                0,
                coordinate_slab_words),
            "zero constraint coordinates")) {
        return 1;
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
        &trace_slab,
        const_cast<std::uint64_t *>(&trace_slab_words),
        const_cast<std::uint64_t *>(&trace_stride_words),
        const_cast<std::uint32_t *>(&sequence_len),
        &powers,
        const_cast<std::uint64_t *>(&random_coefficient_words),
        &denominators,
        const_cast<std::uint64_t *>(&denominator_words),
        &coordinate_slab,
        const_cast<std::uint64_t *>(&coordinate_slab_words),
        const_cast<std::uint64_t *>(&coordinate_stride_words),
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
        {44, 66},
        {56, 84},
        {68, 102},
        {80, 120},
    };
    std::uint32_t actual[4][row_count] = {};
    for (std::uint32_t index = 0; index < 4; ++index) {
        if (!check_status(
                stwo_exec_context_memcpy_d2h_async(
                    context,
                    actual[index],
                    coordinate_slab + index * coordinate_stride_words,
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
    const std::vector<std::uint32_t *> allocations = {
        trace_slab, powers, denominators, coordinate_slab,
    };
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
