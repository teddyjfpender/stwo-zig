#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int stwo_native_wide_fibonacci_trace_on(
    std::uint32_t *trace,
    std::size_t column_stride_words,
    std::size_t trace_capacity_words,
    std::uint32_t row_count,
    std::uint32_t log_n_rows,
    void *stream);
extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle,
    std::size_t count,
    std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(
    void *handle,
    std::uint32_t *pointer);
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

constexpr std::uint32_t kM31Prime = 2147483647u;

std::uint32_t reverse_bits(std::uint32_t value) {
    value = ((value & 0x55555555u) << 1) | ((value >> 1) & 0x55555555u);
    value = ((value & 0x33333333u) << 2) | ((value >> 2) & 0x33333333u);
    value = ((value & 0x0f0f0f0fu) << 4) | ((value >> 4) & 0x0f0f0f0fu);
    value = ((value & 0x00ff00ffu) << 8) | ((value >> 8) & 0x00ff00ffu);
    return (value << 16) | (value >> 16);
}

std::uint32_t logical_row(
    std::uint32_t storage_index,
    std::uint32_t row_count,
    std::uint32_t log_n_rows) {
    const std::uint32_t circle =
        reverse_bits(storage_index) >> (32u - log_n_rows);
    return circle < row_count / 2u
        ? circle * 2u
        : (row_count - 1u - circle) * 2u + 1u;
}

std::uint32_t mul(std::uint32_t lhs, std::uint32_t rhs) {
    const std::uint64_t product =
        static_cast<std::uint64_t>(lhs) * static_cast<std::uint64_t>(rhs);
    const std::uint64_t reduced =
        (((((product >> 31) + product + 1u) >> 31) + product) &
         static_cast<std::uint64_t>(kM31Prime));
    return static_cast<std::uint32_t>(reduced);
}

std::uint32_t add(std::uint32_t lhs, std::uint32_t rhs) {
    const std::uint32_t sum = lhs + rhs;
    return sum >= kM31Prime ? sum - kM31Prime : sum;
}

bool check(cudaError_t status, const char *operation) {
    if (status == cudaSuccess) return true;
    std::fprintf(stderr, "%s: %s\n", operation, cudaGetErrorString(status));
    return false;
}

bool check_status(int status, const char *operation) {
    return check(static_cast<cudaError_t>(status), operation);
}

}  // namespace

int main() {
    constexpr std::uint32_t log_n_rows = 10;
    constexpr std::uint32_t row_count = 1u << log_n_rows;
    constexpr std::uint32_t sequence_len = 37;
    constexpr std::size_t column_stride_words =
        static_cast<std::size_t>(row_count) * 2u;
    constexpr std::size_t trace_words =
        column_stride_words * sequence_len;

    void *context = nullptr;
    void *stream = nullptr;
    std::uint32_t *device_trace = nullptr;
    if (!check_status(stwo_exec_context_create(&context), "create context") ||
        !check_status(
            stwo_exec_context_stream(context, &stream),
            "get proof stream") ||
        !check_status(
            stwo_exec_context_alloc_u32(
                context,
                trace_words,
                &device_trace),
            "allocate trace")) {
        return 1;
    }

    if (!check(
            cudaMemsetAsync(
                device_trace,
                0xa5,
                trace_words * sizeof(std::uint32_t),
                static_cast<cudaStream_t>(stream)),
            "poison retained trace upper halves")) {
        return 1;
    }
    const int launch_status = stwo_native_wide_fibonacci_trace_on(
        device_trace,
        column_stride_words,
        trace_words,
        row_count,
        log_n_rows,
        stream);
    if (launch_status != 0) {
        std::fprintf(stderr, "trace launch: %s\n", cudaGetErrorString(
            static_cast<cudaError_t>(launch_status)));
        return 1;
    }

    std::vector<std::uint32_t> trace(trace_words);
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                trace.data(),
                device_trace,
                trace_words * sizeof(std::uint32_t)),
            "read trace") ||
        !check_status(stwo_exec_context_sync(context), "wait for trace")) {
        return 1;
    }

    for (std::uint32_t row = 0; row < row_count; ++row) {
        std::uint32_t previous = 1u;
        std::uint32_t current = logical_row(row, row_count, log_n_rows);
        for (std::uint32_t column = 0; column < sequence_len; ++column) {
            const std::uint32_t expected =
                column == 0 ? previous : column == 1 ? current
                : add(mul(previous, previous), mul(current, current));
            const std::uint32_t actual =
                trace[
                    static_cast<std::size_t>(column) *
                        column_stride_words +
                    row];
            if (actual != expected) {
                std::fprintf(
                    stderr,
                    "mismatch row=%u column=%u expected=%u actual=%u\n",
                    row,
                    column,
                    expected,
                    actual);
                return 1;
            }
            if (column >= 2) {
                previous = current;
                current = expected;
            }
        }
    }
    for (std::uint32_t column = 0; column < sequence_len; ++column) {
        for (std::uint32_t row = row_count; row < column_stride_words; ++row) {
            const std::uint32_t actual =
                trace[
                    static_cast<std::size_t>(column) *
                        column_stride_words +
                    row];
            if (actual != 0xa5a5a5a5u) {
                std::fprintf(
                    stderr,
                    "upper-half write column=%u row=%u actual=%u\n",
                    column,
                    row,
                    actual);
                return 1;
            }
        }
    }
    if (stwo_native_wide_fibonacci_trace_on(
            device_trace,
            column_stride_words,
            trace_words - 1u,
            row_count,
            log_n_rows,
            stream) == 0 ||
        stwo_native_wide_fibonacci_trace_on(
            device_trace,
            row_count - 1u,
            (row_count - 1u) * sequence_len,
            row_count,
            log_n_rows,
            stream) == 0 ||
        stwo_native_wide_fibonacci_trace_on(
            device_trace,
            column_stride_words,
            trace_words,
            row_count,
            log_n_rows,
            nullptr) == 0) {
        std::fprintf(stderr, "trace ABI admitted an invalid resident layout\n");
        return 1;
    }

    if (!check_status(
            stwo_exec_context_free_u32(context, device_trace),
            "free trace") ||
        !check_status(stwo_exec_context_sync(context), "wait for free")) {
        return 1;
    }
    std::size_t used = 1;
    std::size_t reserved = 0;
    if (!check_status(
            stwo_exec_context_pool_current(context, &used, &reserved),
            "read pool counters") ||
        used != 0) {
        std::fprintf(stderr, "pool has %zu live bytes\n", used);
        return 1;
    }
    if (!check_status(stwo_exec_context_destroy(context), "destroy context")) {
        return 1;
    }
    std::printf(
        "native CUDA wide-Fibonacci trace smoke passed: %u rows x %u columns\n",
        row_count,
        sequence_len);
    return 0;
}
