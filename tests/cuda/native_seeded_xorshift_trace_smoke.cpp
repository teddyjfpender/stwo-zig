#include "../../src/backends/cuda/native/aot_loader.h"

#include <cuda_runtime_api.h>

#include <algorithm>
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
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle,
    void *destination,
    const void *source,
    std::size_t bytes);
extern "C" int stwo_exec_context_pool_current(
    void *handle,
    std::size_t *used_current,
    std::size_t *reserved_current);

namespace {

constexpr std::uint64_t kCacheKey = 0x1888a1a02b4e35b5ull;
constexpr std::uint32_t kTraceSchema = 6;
constexpr std::uint32_t kArgumentCount = 13;
constexpr const char *kKernelName =
    "stwo_native_trace_seeded_xorshift_slab_v1_21cc1d6d9728809e";
constexpr std::uint32_t kColumnsPerRound = 96;
constexpr std::uint64_t kSeedOffset = 1;
constexpr std::uint32_t kLeftShift = 13;
constexpr std::uint32_t kRightShift = 7;
constexpr std::uint32_t kFinalLeftShift = 17;
constexpr std::uint64_t kRoundMix = 0x9e3779b97f4a7c15ull;
constexpr std::uint64_t kCellMix = 0x517cc1b727220a95ull;
constexpr std::uint32_t kM31Prime = 2147483647u;
constexpr std::uint32_t kSentinel = 0xa5a5a5a5u;

struct Case {
    const char *name;
    std::uint32_t log_n_rows;
    std::uint32_t rounds;
};

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

std::uint64_t next_seed(std::uint64_t seed) {
    seed ^= seed << kLeftShift;
    seed ^= seed >> kRightShift;
    seed ^= seed << kFinalLeftShift;
    return seed;
}

std::uint32_t m31_from_u64(std::uint64_t value) {
    constexpr std::uint64_t prime = kM31Prime;
    std::uint64_t reduced = (value & prime) + (value >> 31u);
    reduced = (reduced & prime) + (reduced >> 31u);
    return reduced >= prime
        ? static_cast<std::uint32_t>(reduced - prime)
        : static_cast<std::uint32_t>(reduced);
}

bool run_case(
    void *context,
    void *loader,
    Case test_case,
    std::size_t *peak_used_bytes,
    std::size_t *peak_reserved_bytes) {
    const std::uint32_t row_count = 1u << test_case.log_n_rows;
    const std::uint32_t column_count =
        test_case.rounds * kColumnsPerRound;
    const std::uint64_t stride = row_count + 3u;
    const std::uint64_t trace_words = stride * column_count;
    std::uint32_t *device_trace = nullptr;
    if (!check_status(
            stwo_exec_context_alloc_u32(
                context,
                trace_words,
                &device_trace),
            "allocate seeded-xorshift trace") ||
        !check_status(
            stwo_exec_context_fill_u32_async(
                context,
                device_trace,
                kSentinel,
                trace_words),
            "poison seeded-xorshift trace")) {
        return false;
    }
    std::size_t used_bytes = 0;
    std::size_t reserved_bytes = 0;
    if (!check_status(
            stwo_exec_context_pool_current(
                context,
                &used_bytes,
                &reserved_bytes),
            "read seeded-xorshift pool counters")) {
        return false;
    }
    *peak_used_bytes = std::max(*peak_used_bytes, used_bytes);
    *peak_reserved_bytes = std::max(*peak_reserved_bytes, reserved_bytes);

    const std::uint32_t grid[3] = {
        (row_count + 255u) / 256u,
        1,
        1,
    };
    const std::uint32_t block[3] = {256, 1, 1};
    void *function = nullptr;
    StwoNativeAotFunctionReceipt receipt{};
    if (!check_status(
            stwo_native_aot_function_bind(
                loader,
                kCacheKey,
                kTraceSchema,
                kKernelName,
                grid,
                block,
                0,
                kArgumentCount,
                &function,
                &receipt),
            "bind seeded-xorshift trace") ||
        receipt.abi_version != 1 ||
        receipt.abi_schema != kTraceSchema ||
        receipt.cache_key != kCacheKey ||
        receipt.argument_count != kArgumentCount) {
        std::fprintf(stderr, "invalid seeded-xorshift AOT receipt\n");
        return false;
    }

    std::uint32_t log_n_rows = test_case.log_n_rows;
    std::uint32_t group_count = test_case.rounds;
    std::uint32_t columns_per_group = kColumnsPerRound;
    std::uint64_t seed_offset = kSeedOffset;
    std::uint32_t left_shift = kLeftShift;
    std::uint32_t right_shift = kRightShift;
    std::uint32_t final_left_shift = kFinalLeftShift;
    std::uint64_t group_mix = kRoundMix;
    std::uint64_t item_mix = kCellMix;
    std::uint64_t column_stride = stride;
    std::uint64_t capacity = trace_words;
    std::uint32_t rows = row_count;
    void *arguments[kArgumentCount] = {
        &device_trace,
        &capacity,
        &column_stride,
        &rows,
        &log_n_rows,
        &group_count,
        &columns_per_group,
        &seed_offset,
        &left_shift,
        &right_shift,
        &final_left_shift,
        &group_mix,
        &item_mix,
    };
    if (!check_status(
            stwo_native_aot_function_launch(
                function,
                arguments,
                kArgumentCount),
            "launch seeded-xorshift trace") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for seeded-xorshift trace")) {
        return false;
    }

    std::vector<std::uint32_t> actual(trace_words);
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual.data(),
                device_trace,
                trace_words * sizeof(std::uint32_t)),
            "read seeded-xorshift trace") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for seeded-xorshift read")) {
        return false;
    }
    for (std::uint32_t row = 0; row < row_count; ++row) {
        std::uint64_t seed = static_cast<std::uint64_t>(row) + 1u;
        std::uint32_t column = 0;
        for (std::uint32_t round = 0; round < test_case.rounds; ++round) {
            for (std::uint32_t cell = 0; cell < kColumnsPerRound; ++cell) {
                seed = next_seed(seed);
                const std::uint64_t mixed =
                    seed ^
                    (static_cast<std::uint64_t>(round) * kRoundMix) ^
                    (static_cast<std::uint64_t>(cell + 1u) * kCellMix);
                const std::uint32_t expected = m31_from_u64(mixed);
                const std::uint32_t observed =
                    actual[static_cast<std::uint64_t>(column) * stride + row];
                if (observed != expected) {
                    std::fprintf(
                        stderr,
                        "%s mismatch row=%u column=%u expected=%u actual=%u\n",
                        test_case.name,
                        row,
                        column,
                        expected,
                        observed);
                    return false;
                }
                ++column;
            }
        }
    }
    for (std::uint32_t column = 0; column < column_count; ++column) {
        for (std::uint64_t row = row_count; row < stride; ++row) {
            if (actual[static_cast<std::uint64_t>(column) * stride + row] !=
                kSentinel) {
                std::fprintf(stderr, "%s wrote trace padding\n", test_case.name);
                return false;
            }
        }
    }

    if (!check_status(
            stwo_native_aot_function_destroy(function),
            "destroy seeded-xorshift function") ||
        !check_status(
            stwo_exec_context_free_u32(context, device_trace),
            "free seeded-xorshift trace") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for seeded-xorshift free")) {
        return false;
    }
    used_bytes = 1;
    if (!check_status(
            stwo_exec_context_pool_current(
                context,
                &used_bytes,
                &reserved_bytes),
            "read final seeded-xorshift pool counters") ||
        used_bytes != 0) {
        std::fprintf(stderr, "seeded-xorshift pool retains %zu bytes\n", used_bytes);
        return false;
    }
    return true;
}

}  // namespace

int main() {
    void *context = nullptr;
    void *loader = nullptr;
    if (!check_status(stwo_exec_context_create(&context), "create context") ||
        !check_status(
            stwo_native_aot_loader_create(context, &loader),
            "create AOT loader")) {
        return 1;
    }

    std::size_t peak_used_bytes = 0;
    std::size_t peak_reserved_bytes = 0;
    const Case cases[] = {
        {"target", 10, 10},
        {"non-target", 7, 3},
    };
    for (const Case &test_case : cases) {
        if (!run_case(
                context,
                loader,
                test_case,
                &peak_used_bytes,
                &peak_reserved_bytes)) {
            return 1;
        }
    }

    StwoNativeAotStats stats{};
    if (!check_status(
            stwo_native_aot_loader_stats(loader, &stats),
            "read seeded-xorshift stats") ||
        stats.aot_loads != 1 || stats.aot_cache_hits != 1 ||
        stats.aot_misses != 0 || stats.launches != 2 ||
        stats.launch_failures != 0) {
        std::fprintf(
            stderr,
            "invalid seeded-xorshift telemetry loads=%llu hits=%llu "
            "misses=%llu launches=%llu failures=%llu\n",
            static_cast<unsigned long long>(stats.aot_loads),
            static_cast<unsigned long long>(stats.aot_cache_hits),
            static_cast<unsigned long long>(stats.aot_misses),
            static_cast<unsigned long long>(stats.launches),
            static_cast<unsigned long long>(stats.launch_failures));
        return 1;
    }
    if (!check_status(
            stwo_native_aot_loader_destroy(loader),
            "destroy AOT loader") ||
        !check_status(stwo_exec_context_destroy(context), "destroy context")) {
        return 1;
    }
    std::printf(
        "native CUDA seeded-xorshift trace smoke passed: 2 launches, "
        "peak_used=%zu peak_reserved=%zu bytes\n",
        peak_used_bytes,
        peak_reserved_bytes);
    return 0;
}
