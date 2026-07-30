#include "../../src/backends/cuda/native/aot_loader.h"

#include <cuda.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);

namespace {

constexpr std::uint64_t kCacheKey = 0xcfd5cd0b51ed26c6ull;
constexpr std::uint32_t kRecordedWitnessSchema = 2;
constexpr std::uint32_t kArgumentCount = 8;
constexpr const char *kKernelName =
    "stwo_jit_witness_d14e690e89d48795";
constexpr std::array<std::uint8_t, 32> kSmokeTableIdentity = {
    0xe5, 0x13, 0x86, 0x24, 0x9a, 0xb7, 0xd7, 0xe0,
    0x68, 0x56, 0x69, 0x64, 0x9f, 0x98, 0x0d, 0xad,
    0xde, 0x74, 0x04, 0x3e, 0x23, 0xdb, 0x70, 0x65,
    0x1c, 0x0f, 0xfb, 0xe1, 0x84, 0xbd, 0xb0, 0xe7,
};

bool check(CUresult status, const char *operation) {
    if (status == CUDA_SUCCESS) return true;
    const char *name = nullptr;
    cuGetErrorName(status, &name);
    std::fprintf(
        stderr,
        "%s failed: %s (%d)\n",
        operation,
        name == nullptr ? "unknown" : name,
        static_cast<int>(status));
    return false;
}

bool run() {
    void *context = nullptr;
    if (!check(
            static_cast<CUresult>(stwo_exec_context_create(&context)),
            "create execution context")) {
        return false;
    }

    constexpr std::size_t column_bytes =
        static_cast<std::size_t>(STWO_NATIVE_PEDERSEN_W18_ROW_COUNT) *
        sizeof(std::uint32_t);
    std::array<CUdeviceptr, STWO_NATIVE_PEDERSEN_W18_COLUMN_COUNT>
        allocations{};
    std::array<std::uint64_t, STWO_NATIVE_PEDERSEN_W18_COLUMN_COUNT>
        columns{};
    std::size_t allocated = 0;
    for (; allocated < allocations.size(); ++allocated) {
        if (!check(
                cuMemAlloc(&allocations[allocated], column_bytes),
                "allocate Pedersen column")) {
            break;
        }
        columns[allocated] = allocations[allocated];
    }

    void *loader = nullptr;
    void *function = nullptr;
    bool passed = allocated == allocations.size();
    if (passed) {
        passed = check(
            static_cast<CUresult>(
                stwo_native_aot_loader_create(context, &loader)),
            "create AOT loader");
    }
    const std::uint32_t grid[3] = {1, 1, 1};
    const std::uint32_t block[3] = {32, 1, 1};
    StwoNativeAotFunctionReceipt function_receipt{};
    if (passed) {
        passed = check(
            static_cast<CUresult>(
                stwo_native_aot_function_bind_with_globals(
                    loader,
                    kCacheKey,
                    kRecordedWitnessSchema,
                    STWO_NATIVE_AOT_MODULE_GLOBALS_PEDERSEN_W18_COLUMNS_ROWS_V1,
                    kKernelName,
                    grid,
                    block,
                    0,
                    kArgumentCount,
                    &function,
                    &function_receipt)),
            "bind Pedersen recorded witness");
    }

    StwoNativeAotModuleGlobalsReceipt globals_receipt{};
    if (passed) {
        passed = check(
            static_cast<CUresult>(
                stwo_native_aot_function_publish_pedersen_w18(
                    function,
                    columns.data(),
                    STWO_NATIVE_PEDERSEN_W18_ROW_COUNT,
                    kSmokeTableIdentity.data(),
                    &globals_receipt)),
            "publish Pedersen globals");
    }
    if (passed) {
        passed =
            globals_receipt.abi_version == 1 &&
            globals_receipt.verified == 1 &&
            globals_receipt.module_globals ==
                STWO_NATIVE_AOT_MODULE_GLOBALS_PEDERSEN_W18_COLUMNS_ROWS_V1 &&
            globals_receipt.column_count ==
                STWO_NATIVE_PEDERSEN_W18_COLUMN_COUNT &&
            globals_receipt.row_count == STWO_NATIVE_PEDERSEN_W18_ROW_COUNT &&
            globals_receipt.columns_symbol_bytes ==
                columns.size() * sizeof(CUdeviceptr) &&
            globals_receipt.row_count_symbol_bytes == sizeof(std::uint32_t) &&
            globals_receipt.module_token == function_receipt.module_token &&
            globals_receipt.stream_token == function_receipt.stream_token;
    }
    if (passed) {
        passed = check(
            static_cast<CUresult>(
                stwo_native_aot_function_publish_pedersen_w18(
                    function,
                    columns.data(),
                    STWO_NATIVE_PEDERSEN_W18_ROW_COUNT,
                    kSmokeTableIdentity.data(),
                    &globals_receipt)),
            "reuse Pedersen globals");
    }

    if (function != nullptr) {
        passed = check(
            static_cast<CUresult>(
                stwo_native_aot_function_destroy(function)),
            "destroy AOT function") && passed;
    }
    if (loader != nullptr) {
        passed = check(
            static_cast<CUresult>(
                stwo_native_aot_loader_destroy(loader)),
            "destroy AOT loader") && passed;
    }
    while (allocated != 0) {
        --allocated;
        passed = check(
            cuMemFree(allocations[allocated]),
            "free Pedersen column") && passed;
    }
    passed = check(
        static_cast<CUresult>(stwo_exec_context_destroy(context)),
        "destroy execution context") && passed;
    return passed;
}

}  // namespace

int main() {
    if (!run()) return 1;
    std::printf(
        "native CUDA Pedersen module globals passed: "
        "56 columns x 8388608 rows, authenticated AOT, exact readback\n");
    return 0;
}
