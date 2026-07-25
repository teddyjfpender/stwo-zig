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

constexpr std::uint64_t kCacheKey = 0xbfa4f42232b92676ull;
constexpr std::uint32_t kConstraintSchema = 12;
constexpr std::uint32_t kArgumentCount = 17;
constexpr const char *kKernelName =
    "stwo_native_constraint_plonk_logup_slab_v1_1aeccc54c43f17c3";
constexpr std::uint32_t kRows = 4;
constexpr std::uint32_t kTraceLogSize = 1;
constexpr std::uint32_t kInverseRows = 1u << 30u;
constexpr std::uint64_t kStride = kRows;
constexpr std::uint64_t kSourceWords = 16 * kRows;
constexpr std::uint64_t kPowerWords = 12;
constexpr std::uint64_t kDenominatorWords = 2;
constexpr std::uint64_t kLookupWords = 8;
constexpr std::uint64_t kClaimedSumWords = 4;
constexpr std::uint64_t kCoordinateWords = 4 * kRows;

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
        "upload Plonk/LogUp input");
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

    std::uint32_t *sources = allocate(context, kSourceWords);
    std::uint32_t *powers = allocate(context, kPowerWords);
    std::uint32_t *denominators = allocate(context, kDenominatorWords);
    std::uint32_t *lookup = allocate(context, kLookupWords);
    std::uint32_t *claimed_sum = allocate(context, kClaimedSumWords);
    std::uint32_t *coordinates = allocate(context, kCoordinateWords);
    if (sources == nullptr || powers == nullptr || denominators == nullptr ||
        lookup == nullptr || claimed_sum == nullptr ||
        coordinates == nullptr) {
        return 1;
    }

    const std::uint32_t host_sources[kSourceWords] = {
        3, 5, 7, 9, 8, 10, 12, 14,
        13, 15, 17, 19, 18, 20, 22, 24,
        23, 25, 27, 29, 28, 30, 32, 34,
        33, 35, 37, 39, 38, 40, 42, 44,
        43, 45, 47, 49, 48, 50, 52, 54,
        53, 55, 57, 59, 58, 60, 62, 64,
        63, 65, 67, 69, 68, 70, 72, 74,
        73, 75, 77, 79, 78, 80, 82, 84,
    };
    const std::uint32_t host_powers[kPowerWords] = {
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
    };
    const std::uint32_t host_denominators[kDenominatorWords] = {61, 67};
    const std::uint32_t host_lookup[kLookupWords] = {
        13, 17, 19, 23,
        29, 31, 37, 41,
    };
    const std::uint32_t host_claimed_sum[kClaimedSumWords] = {
        43, 47, 53, 59,
    };
    if (!upload(context, sources, host_sources, sizeof(host_sources)) ||
        !upload(context, powers, host_powers, sizeof(host_powers)) ||
        !upload(
            context,
            denominators,
            host_denominators,
            sizeof(host_denominators)) ||
        !upload(context, lookup, host_lookup, sizeof(host_lookup)) ||
        !upload(
            context,
            claimed_sum,
            host_claimed_sum,
            sizeof(host_claimed_sum)) ||
        !check_status(
            stwo_exec_context_fill_u32_async(
                context,
                coordinates,
                0,
                kCoordinateWords),
            "zero composition coordinates")) {
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
            "bind Plonk/LogUp constraint") ||
        receipt.abi_version != STWO_NATIVE_AOT_FUNCTION_RECEIPT_ABI_VERSION ||
        receipt.abi_schema != kConstraintSchema ||
        receipt.cache_key != kCacheKey ||
        receipt.argument_count != kArgumentCount ||
        receipt.stream_token == 0) {
        std::fprintf(stderr, "invalid Plonk/LogUp AOT binding receipt\n");
        return 1;
    }

    std::uint32_t row_count = kRows;
    std::uint32_t trace_log_size = kTraceLogSize;
    std::uint32_t inverse_rows = kInverseRows;
    std::uint64_t source_words = kSourceWords;
    std::uint64_t source_stride = kStride;
    std::uint64_t power_words = kPowerWords;
    std::uint64_t denominator_words = kDenominatorWords;
    std::uint64_t lookup_words = kLookupWords;
    std::uint64_t claimed_sum_words = kClaimedSumWords;
    std::uint64_t coordinate_words = kCoordinateWords;
    std::uint64_t coordinate_stride = kStride;
    void *arguments[kArgumentCount] = {
        &sources,
        &source_words,
        &source_stride,
        &powers,
        &power_words,
        &denominators,
        &denominator_words,
        &lookup,
        &lookup_words,
        &claimed_sum,
        &claimed_sum_words,
        &coordinates,
        &coordinate_words,
        &coordinate_stride,
        &row_count,
        &trace_log_size,
        &inverse_rows,
    };
    if (!check_status(
            stwo_native_aot_function_launch(
                function,
                arguments,
                kArgumentCount),
            "launch Plonk/LogUp constraint") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for Plonk/LogUp constraint")) {
        return 1;
    }

    const std::uint32_t expected[4][kRows] = {
        {606176109, 1787302443, 1959867894, 1887363615},
        {1462550668, 1874025832, 1351282746, 649544424},
        {1293323832, 2115446679, 1386711407, 773983380},
        {1938565058, 1503624160, 1250970379, 1817175278},
    };
    std::uint32_t actual[4][kRows] = {};
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual,
                coordinates,
                sizeof(actual)),
            "read Plonk/LogUp coordinates") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for Plonk/LogUp read")) {
        return 1;
    }
    for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        for (std::uint32_t row = 0; row < kRows; ++row) {
            if (actual[coordinate][row] != expected[coordinate][row]) {
                std::fprintf(
                    stderr,
                    "Plonk/LogUp mismatch coordinate=%u row=%u "
                    "expected=%u actual=%u\n",
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
            "read Plonk/LogUp AOT stats") ||
        stats.aot_loads != 1 || stats.aot_misses != 0 ||
        stats.launches != 1 || stats.launch_failures != 0) {
        std::fprintf(stderr, "invalid Plonk/LogUp AOT telemetry\n");
        return 1;
    }
    if (!check_status(
            stwo_native_aot_function_destroy(function),
            "destroy Plonk/LogUp function") ||
        !check_status(
            stwo_native_aot_loader_destroy(loader),
            "destroy Plonk/LogUp loader")) {
        return 1;
    }
    const std::vector<std::uint32_t *> allocations = {
        sources,
        powers,
        denominators,
        lookup,
        claimed_sum,
        coordinates,
    };
    for (std::uint32_t *allocation : allocations) {
        if (!check_status(
                stwo_exec_context_free_u32(context, allocation),
                "free Plonk/LogUp workspace")) {
            return 1;
        }
    }
    if (!check_status(
            stwo_exec_context_sync(context),
            "wait for Plonk/LogUp frees") ||
        !check_status(stwo_exec_context_destroy(context), "destroy context")) {
        return 1;
    }
    std::printf("native CUDA Plonk/LogUp constraint smoke passed\n");
    return 0;
}
