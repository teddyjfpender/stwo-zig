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

constexpr std::uint64_t kCacheKey = 0x6af438997e7d2cefull;
constexpr std::uint32_t kTraceSchema = 8;
constexpr std::uint32_t kArgumentCount = 16;
constexpr const char *kKernelName =
    "stwo_native_trace_indexed_recurrence_slabs_v1_ad484862f20d700c";
constexpr std::uint32_t kColumns = 4;
constexpr std::uint64_t kM31Prime = 2147483647ull;
constexpr std::uint32_t kSentinel = 0xa5a5a5a5u;

struct Case {
    const char *name;
    std::uint32_t log_n_rows;
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

std::uint32_t m31_from_u64(std::uint64_t value) {
    std::uint64_t reduced = (value & kM31Prime) + (value >> 31u);
    reduced = (reduced & kM31Prime) + (reduced >> 31u);
    return reduced >= kM31Prime
        ? static_cast<std::uint32_t>(reduced - kM31Prime)
        : static_cast<std::uint32_t>(reduced);
}

std::uint32_t m31_add(std::uint32_t lhs, std::uint32_t rhs) {
    const std::uint64_t sum = static_cast<std::uint64_t>(lhs) + rhs;
    return static_cast<std::uint32_t>(
        sum >= kM31Prime ? sum - kM31Prime : sum);
}

void fill_oracle(
    std::uint32_t rows,
    std::uint64_t preprocessed_stride,
    std::uint64_t main_stride,
    std::vector<std::uint32_t> *preprocessed,
    std::vector<std::uint32_t> *main) {
    std::vector<std::uint32_t> fib(rows + 2);
    fib[0] = 1;
    fib[1] = 1;
    for (std::uint32_t index = 2; index < fib.size(); ++index) {
        fib[index] = m31_add(fib[index - 1], fib[index - 2]);
    }
    for (std::uint32_t row = 0; row < rows; ++row) {
        (*preprocessed)[row] = m31_from_u64(row);
        (*preprocessed)[preprocessed_stride + row] = m31_from_u64(row + 1);
        (*preprocessed)[2 * preprocessed_stride + row] =
            m31_from_u64(row + 2);
        (*preprocessed)[3 * preprocessed_stride + row] = 1;

        (*main)[row] = row + 1 == rows ? 0 : 1;
        (*main)[main_stride + row] = fib[row];
        (*main)[2 * main_stride + row] = fib[row + 1];
        (*main)[3 * main_stride + row] = fib[row + 2];
    }
}

bool compare_words(
    const char *case_name,
    const char *tree,
    const std::vector<std::uint32_t> &actual,
    const std::vector<std::uint32_t> &oracle,
    std::uint64_t stride) {
    for (std::uint64_t index = 0; index < actual.size(); ++index) {
        if (actual[index] == oracle[index]) continue;
        std::fprintf(
            stderr,
            "%s %s mismatch row=%llu column=%llu expected=%u actual=%u\n",
            case_name,
            tree,
            static_cast<unsigned long long>(index % stride),
            static_cast<unsigned long long>(index / stride),
            oracle[index],
            actual[index]);
        return false;
    }
    return true;
}

bool run_case(
    void *context,
    void *loader,
    Case test_case,
    std::size_t *peak_used_bytes,
    std::size_t *peak_reserved_bytes) {
    const std::uint32_t rows = 1u << test_case.log_n_rows;
    std::uint64_t preprocessed_stride = rows + 3u;
    std::uint64_t main_stride = rows + 5u;
    const std::uint64_t preprocessed_words =
        preprocessed_stride * kColumns;
    const std::uint64_t main_words = main_stride * kColumns;
    std::uint32_t *device_preprocessed = nullptr;
    std::uint32_t *device_main = nullptr;
    if (!check_status(
            stwo_exec_context_alloc_u32(
                context,
                preprocessed_words,
                &device_preprocessed),
            "allocate indexed preprocessed trace") ||
        !check_status(
            stwo_exec_context_alloc_u32(
                context,
                main_words,
                &device_main),
            "allocate recurrence main trace") ||
        !check_status(
            stwo_exec_context_fill_u32_async(
                context,
                device_preprocessed,
                kSentinel,
                preprocessed_words),
            "poison indexed preprocessed trace") ||
        !check_status(
            stwo_exec_context_fill_u32_async(
                context,
                device_main,
                kSentinel,
                main_words),
            "poison recurrence main trace")) {
        return false;
    }

    std::size_t used_bytes = 0;
    std::size_t reserved_bytes = 0;
    if (!check_status(
            stwo_exec_context_pool_current(
                context,
                &used_bytes,
                &reserved_bytes),
            "read indexed recurrence pool counters")) {
        return false;
    }
    *peak_used_bytes = std::max(*peak_used_bytes, used_bytes);
    *peak_reserved_bytes = std::max(*peak_reserved_bytes, reserved_bytes);

    const std::uint32_t grid[3] = {
        (rows + 255u) / 256u,
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
            "bind indexed recurrence trace") ||
        receipt.abi_version != 1 ||
        receipt.abi_schema != kTraceSchema ||
        receipt.cache_key != kCacheKey ||
        receipt.argument_count != kArgumentCount) {
        std::fprintf(stderr, "invalid indexed recurrence AOT receipt\n");
        return false;
    }

    std::uint64_t preprocessed_capacity = preprocessed_words;
    std::uint64_t main_capacity = main_words;
    std::uint32_t row_count = rows;
    std::uint32_t log_n_rows = test_case.log_n_rows;
    std::uint64_t index_base = 0;
    std::uint64_t index_step = 1;
    std::uint64_t preprocessed_constant = 1;
    std::uint64_t recurrence_seed0 = 1;
    std::uint64_t recurrence_seed1 = 1;
    std::uint64_t selector_default = 1;
    std::uint64_t selector_last = 0;
    std::uint64_t selector_penultimate = 1;
    void *arguments[kArgumentCount] = {
        &device_preprocessed,
        &preprocessed_capacity,
        &preprocessed_stride,
        &device_main,
        &main_capacity,
        &main_stride,
        &row_count,
        &log_n_rows,
        &index_base,
        &index_step,
        &preprocessed_constant,
        &recurrence_seed0,
        &recurrence_seed1,
        &selector_default,
        &selector_last,
        &selector_penultimate,
    };
    if (!check_status(
            stwo_native_aot_function_launch(
                function,
                arguments,
                kArgumentCount),
            "launch indexed recurrence trace") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for indexed recurrence trace")) {
        return false;
    }

    std::vector<std::uint32_t> actual_preprocessed(preprocessed_words);
    std::vector<std::uint32_t> actual_main(main_words);
    std::vector<std::uint32_t> oracle_preprocessed(
        preprocessed_words,
        kSentinel);
    std::vector<std::uint32_t> oracle_main(main_words, kSentinel);
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual_preprocessed.data(),
                device_preprocessed,
                preprocessed_words * sizeof(std::uint32_t)),
            "read indexed preprocessed trace") ||
        !check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual_main.data(),
                device_main,
                main_words * sizeof(std::uint32_t)),
            "read recurrence main trace") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for indexed recurrence read")) {
        return false;
    }
    fill_oracle(
        rows,
        preprocessed_stride,
        main_stride,
        &oracle_preprocessed,
        &oracle_main);
    if (!compare_words(
            test_case.name,
            "preprocessed",
            actual_preprocessed,
            oracle_preprocessed,
            preprocessed_stride) ||
        !compare_words(
            test_case.name,
            "main",
            actual_main,
            oracle_main,
            main_stride)) {
        return false;
    }

    if (!check_status(
            stwo_native_aot_function_destroy(function),
            "destroy indexed recurrence function") ||
        !check_status(
            stwo_exec_context_free_u32(context, device_preprocessed),
            "free indexed preprocessed trace") ||
        !check_status(
            stwo_exec_context_free_u32(context, device_main),
            "free recurrence main trace") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for indexed recurrence free")) {
        return false;
    }
    used_bytes = 1;
    if (!check_status(
            stwo_exec_context_pool_current(
                context,
                &used_bytes,
                &reserved_bytes),
            "read final indexed recurrence pool counters") ||
        used_bytes != 0) {
        std::fprintf(
            stderr,
            "indexed recurrence pool retains %zu bytes\n",
            used_bytes);
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
        {"guard-log14", 14},
        {"guard-log16", 16},
        {"non-target-log5", 5},
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
            "read indexed recurrence stats") ||
        stats.aot_loads != 1 || stats.aot_cache_hits != 2 ||
        stats.aot_misses != 0 || stats.launches != 3 ||
        stats.launch_failures != 0) {
        std::fprintf(
            stderr,
            "invalid indexed recurrence telemetry loads=%llu hits=%llu "
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
        "native CUDA indexed recurrence trace smoke passed: 3 launches, "
        "logs=14,16,5 full_cell_parity=pass padding=pass "
        "peak_used=%zu peak_reserved=%zu residual=0 bytes\n",
        peak_used_bytes,
        peak_reserved_bytes);
    return 0;
}
