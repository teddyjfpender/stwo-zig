#include "../../src/backends/cuda/native/aot_loader.h"

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

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

constexpr std::uint64_t kCacheKey = 0xd363e2a1d1c6b31dull;
constexpr std::uint32_t kConstraintSchema = 5;
constexpr std::uint32_t kArgumentCount = 15;
constexpr const char *kKernelName =
    "stwo_native_constraint_constant_qm31_slab_v1_578d333ea30082f5";
constexpr std::uint32_t kRows = 8;
constexpr std::uint64_t kStride = 11;
constexpr std::uint64_t kCoordinateWords = 3 * kStride + kRows;
constexpr std::uint32_t kSentinel = 0xa5a5a5a5u;

struct Qm31 {
    std::uint32_t a;
    std::uint32_t b;
    std::uint32_t c;
    std::uint32_t d;
};

struct Shape {
    std::uint32_t component_index;
    std::uint32_t component_count;
    std::uint32_t evaluation_log_size;
    std::uint32_t trace_log_size;
    std::uint32_t preprocessed_columns;
    std::uint32_t main_columns;
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

std::uint32_t *allocate(void *context, std::size_t words) {
    std::uint32_t *result = nullptr;
    if (!check_status(
            stwo_exec_context_alloc_u32(context, words, &result),
            "allocate device words")) {
        return nullptr;
    }
    return result;
}

bool run_case(
    void *context,
    void *function,
    std::uint32_t *statement_storage,
    std::uint32_t *challenge_storage,
    std::uint32_t *coordinates,
    Shape shape,
    std::uint64_t statement_word_count,
    std::uint64_t challenge_word_count,
    Qm31 constant) {
    std::uint32_t *statement_words =
        statement_word_count == 0 ? nullptr : statement_storage;
    std::uint32_t *challenge_words =
        challenge_word_count == 0 ? nullptr : challenge_storage;
    std::uint32_t row_count = kRows;
    std::uint64_t coordinate_words = kCoordinateWords;
    std::uint64_t coordinate_stride = kStride;
    void *arguments[kArgumentCount] = {
        &shape.component_index,
        &shape.component_count,
        &shape.evaluation_log_size,
        &shape.trace_log_size,
        &shape.preprocessed_columns,
        &shape.main_columns,
        &statement_words,
        &statement_word_count,
        &challenge_words,
        &challenge_word_count,
        &constant,
        &coordinates,
        &coordinate_words,
        &coordinate_stride,
        &row_count,
    };
    if (!check_status(
            stwo_exec_context_fill_u32_async(
                context,
                coordinates,
                kSentinel,
                kCoordinateWords),
            "initialize constant-QM31 output") ||
        !check_status(
            stwo_native_aot_function_launch(
                function,
                arguments,
                kArgumentCount),
            "launch constant-QM31 constraint") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for constant-QM31 constraint")) {
        return false;
    }

    std::uint32_t actual[kCoordinateWords] = {};
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual,
                coordinates,
                sizeof(actual)),
            "read constant-QM31 coordinates") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for constant-QM31 read")) {
        return false;
    }
    const std::uint32_t expected[4] = {
        constant.a,
        constant.b,
        constant.c,
        constant.d,
    };
    for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        for (std::uint32_t row = 0; row < kRows; ++row) {
            const std::uint64_t index = coordinate * kStride + row;
            if (actual[index] != expected[coordinate]) {
                std::fprintf(
                    stderr,
                    "constant-QM31 mismatch coordinate=%u row=%u "
                    "expected=%u actual=%u\n",
                    coordinate,
                    row,
                    expected[coordinate],
                    actual[index]);
                return false;
            }
        }
        if (coordinate == 3) continue;
        for (std::uint64_t row = kRows; row < kStride; ++row) {
            if (actual[coordinate * kStride + row] != kSentinel) {
                std::fprintf(stderr, "constant-QM31 wrote destination padding\n");
                return false;
            }
        }
    }
    return true;
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

    std::uint32_t *statement = allocate(context, 4);
    std::uint32_t *challenges = allocate(context, 4);
    std::uint32_t *coordinates = allocate(context, kCoordinateWords);
    if (statement == nullptr || challenges == nullptr || coordinates == nullptr) {
        return 1;
    }
    const std::uint32_t host_statement[4] = {3, 5, 8, 13};
    const std::uint32_t host_challenges[4] = {21, 34, 55, 89};
    if (!check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                statement,
                host_statement,
                sizeof(host_statement)),
            "upload statement") ||
        !check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                challenges,
                host_challenges,
                sizeof(host_challenges)),
            "upload challenges")) {
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
            "bind constant-QM31 AOT constraint") ||
        receipt.abi_version != STWO_NATIVE_AOT_FUNCTION_RECEIPT_ABI_VERSION ||
        receipt.abi_schema != kConstraintSchema ||
        receipt.cache_key != kCacheKey ||
        receipt.argument_count != kArgumentCount ||
        receipt.stream_token == 0) {
        std::fprintf(stderr, "invalid constant-QM31 AOT binding receipt\n");
        return 1;
    }

    if (!run_case(
            context,
            function,
            statement,
            challenges,
            coordinates,
            {0, 1, 3, 2, 0, 37},
            4,
            0,
            {7, 11, 13, 17}) ||
        !run_case(
            context,
            function,
            statement,
            challenges,
            coordinates,
            {2, 4, 3, 3, 5, 32},
            0,
            4,
            {19, 23, 29, 31})) {
        return 1;
    }

    StwoNativeAotStats stats{};
    if (!check_status(
            stwo_native_aot_loader_stats(loader, &stats),
            "read constant-QM31 AOT stats") ||
        stats.aot_loads != 1 || stats.aot_misses != 0 ||
        stats.launches != 2 || stats.launch_failures != 0) {
        std::fprintf(stderr, "invalid constant-QM31 AOT telemetry\n");
        return 1;
    }

    if (!check_status(
            stwo_native_aot_function_destroy(function),
            "destroy constant-QM31 function") ||
        !check_status(stwo_native_aot_loader_destroy(loader), "destroy AOT loader") ||
        !check_status(stwo_exec_context_free_u32(context, statement), "free statement") ||
        !check_status(stwo_exec_context_free_u32(context, challenges), "free challenges") ||
        !check_status(stwo_exec_context_free_u32(context, coordinates), "free coordinates") ||
        !check_status(stwo_exec_context_sync(context), "wait for frees") ||
        !check_status(stwo_exec_context_destroy(context), "destroy context")) {
        return 1;
    }
    std::printf("native CUDA constant-QM31 constraint smoke passed\n");
    return 0;
}
