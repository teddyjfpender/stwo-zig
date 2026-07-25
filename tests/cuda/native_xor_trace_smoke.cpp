#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int stwo_native_xor_trace_on(
    std::uint32_t *preprocessed,
    std::size_t preprocessed_stride_words,
    std::size_t preprocessed_capacity_words,
    std::uint32_t *main_trace,
    std::size_t main_stride_words,
    std::size_t main_capacity_words,
    std::uint32_t row_count,
    std::uint32_t log_n_rows,
    std::uint32_t log_step,
    std::uint64_t offset,
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

namespace {

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

bool check(cudaError_t status, const char *operation) {
    if (status == cudaSuccess) return true;
    std::fprintf(stderr, "%s: %s\n", operation, cudaGetErrorString(status));
    return false;
}

bool check_status(int status, const char *operation) {
    return check(static_cast<cudaError_t>(status), operation);
}

bool exercise(
    void *context,
    void *stream,
    std::uint32_t log_n_rows,
    std::uint32_t log_step,
    std::uint64_t offset) {
    const std::uint32_t row_count = 1u << log_n_rows;
    const std::size_t preprocessed_stride = row_count + 19u;
    const std::size_t main_stride = row_count + 31u;
    const std::size_t preprocessed_words = preprocessed_stride * 2u;
    const std::size_t main_words = main_stride;
    std::uint32_t *device_preprocessed = nullptr;
    std::uint32_t *device_main = nullptr;
    if (!check_status(
            stwo_exec_context_alloc_u32(
                context,
                preprocessed_words,
                &device_preprocessed),
            "allocate preprocessed") ||
        !check_status(
            stwo_exec_context_alloc_u32(context, main_words, &device_main),
            "allocate main") ||
        !check(
            cudaMemsetAsync(
                device_preprocessed,
                0xa5,
                preprocessed_words * sizeof(std::uint32_t),
                static_cast<cudaStream_t>(stream)),
            "poison preprocessed") ||
        !check(
            cudaMemsetAsync(
                device_main,
                0xa5,
                main_words * sizeof(std::uint32_t),
                static_cast<cudaStream_t>(stream)),
            "poison main")) {
        return false;
    }
    if (!check_status(
            stwo_native_xor_trace_on(
                device_preprocessed,
                preprocessed_stride,
                preprocessed_words,
                device_main,
                main_stride,
                main_words,
                row_count,
                log_n_rows,
                log_step,
                offset,
                stream),
            "launch XOR trace")) {
        return false;
    }
    std::vector<std::uint32_t> preprocessed(preprocessed_words);
    std::vector<std::uint32_t> main_trace(main_words);
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                preprocessed.data(),
                device_preprocessed,
                preprocessed_words * sizeof(std::uint32_t)),
            "read preprocessed") ||
        !check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                main_trace.data(),
                device_main,
                main_words * sizeof(std::uint32_t)),
            "read main") ||
        !check_status(stwo_exec_context_sync(context), "wait for trace")) {
        return false;
    }

    const std::uint32_t step = 1u << log_step;
    const std::uint32_t normalized_offset =
        static_cast<std::uint32_t>(offset % step);
    for (std::uint32_t row = 0; row < row_count; ++row) {
        const std::uint32_t logical =
            logical_row(row, row_count, log_n_rows);
        if (preprocessed[row] != (row == 0u ? 1u : 0u) ||
            preprocessed[preprocessed_stride + row] !=
                (logical % step == normalized_offset ? 1u : 0u) ||
            main_trace[row] != ((logical & 1u) == 0u ? 1u : 0u)) {
            std::fprintf(
                stderr,
                "XOR mismatch log=%u step=%u offset=%llu row=%u\n",
                log_n_rows,
                log_step,
                static_cast<unsigned long long>(offset),
                row);
            return false;
        }
    }
    for (std::size_t row = row_count; row < preprocessed_stride; ++row) {
        if (preprocessed[row] != 0xa5a5a5a5u ||
            preprocessed[preprocessed_stride + row] != 0xa5a5a5a5u) {
            std::fprintf(stderr, "XOR preprocessed padding was overwritten\n");
            return false;
        }
    }
    for (std::size_t row = row_count; row < main_stride; ++row) {
        if (main_trace[row] != 0xa5a5a5a5u) {
            std::fprintf(stderr, "XOR main padding was overwritten\n");
            return false;
        }
    }
    if (stwo_native_xor_trace_on(
            device_preprocessed,
            preprocessed_stride,
            preprocessed_words - 1u,
            device_main,
            main_stride,
            main_words,
            row_count,
            log_n_rows,
            log_step,
            offset,
            stream) == 0 ||
        stwo_native_xor_trace_on(
            device_preprocessed,
            preprocessed_stride,
            preprocessed_words,
            device_main,
            main_stride,
            main_words,
            row_count,
            log_n_rows,
            log_n_rows + 1u,
            offset,
            stream) == 0 ||
        stwo_native_xor_trace_on(
            device_preprocessed,
            preprocessed_stride,
            preprocessed_words,
            device_preprocessed,
            main_stride,
            main_words,
            row_count,
            log_n_rows,
            log_step,
            offset,
            stream) == 0 ||
        stwo_native_xor_trace_on(
            device_preprocessed,
            preprocessed_stride,
            preprocessed_words,
            device_main,
            main_stride,
            main_words,
            row_count,
            log_n_rows,
            log_step,
            offset,
            nullptr) == 0) {
        std::fprintf(stderr, "XOR trace ABI admitted an invalid descriptor\n");
        return false;
    }
    return check_status(
               stwo_exec_context_free_u32(context, device_preprocessed),
               "free preprocessed") &&
        check_status(
               stwo_exec_context_free_u32(context, device_main),
               "free main") &&
        check_status(stwo_exec_context_sync(context), "wait for free");
}

}  // namespace

int main() {
    void *context = nullptr;
    void *stream = nullptr;
    if (!check_status(stwo_exec_context_create(&context), "create context") ||
        !check_status(
            stwo_exec_context_stream(context, &stream),
            "get proof stream")) {
        return 1;
    }

    const struct {
        std::uint32_t log_n_rows;
        std::uint32_t log_step;
        std::uint64_t offset;
    } cases[] = {
        {5, 0, 0},
        {7, 3, 5},
        {10, 10, 1023},
        {14, 6, 0x1'0000'0041ull},
        {16, 11, 0xfeed'face'1234'5678ull},
    };
    for (const auto &test : cases) {
        if (!exercise(
                context,
                stream,
                test.log_n_rows,
                test.log_step,
                test.offset)) {
            return 1;
        }
    }
    if (!check_status(stwo_exec_context_destroy(context), "destroy context")) {
        return 1;
    }
    std::printf("native CUDA XOR trace smoke passed: 5 exact geometries\n");
    return 0;
}
