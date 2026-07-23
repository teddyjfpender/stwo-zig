// Strict AOT-only CUDA module loading for the Zig-owned resident proof runtime.
//
// This is deliberately smaller than the copied dynamic-loader authority:
// it has no runtime compiler, filesystem cache, environment policy, Cairo
// publication, compatibility stream, or alternate host path. A missing module
// is a proof error.

#include "aot_loader.h"

#include <cuda.h>
#include <cuda_runtime_api.h>

#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <thread>
#include <unordered_map>

extern "C" bool stwo_aot_lookup(
    uint64_t cache_key,
    uint32_t sm_major,
    uint32_t sm_minor,
    const unsigned char **out_data,
    size_t *out_len);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_device(void *handle, int *out_device);

namespace {

constexpr uint32_t kReceiptAbiVersion = 1;

struct ModuleKey {
    uint64_t cache_key;
    std::string kernel_name;

    bool operator==(const ModuleKey &other) const {
        return cache_key == other.cache_key && kernel_name == other.kernel_name;
    }
};

struct ModuleKeyHash {
    size_t operator()(const ModuleKey &key) const {
        const size_t left = std::hash<uint64_t>{}(key.cache_key);
        const size_t right = std::hash<std::string>{}(key.kernel_name);
        return left ^ (right + 0x9e3779b97f4a7c15ULL + (left << 6) + (left >> 2));
    }
};

struct Module {
    CUmodule module = nullptr;
    CUfunction function = nullptr;
};

struct Loader {
    void *exec_context = nullptr;
    CUcontext driver_context = nullptr;
    CUstream stream = nullptr;
    uint32_t device = 0;
    uint32_t sm_major = 0;
    uint32_t sm_minor = 0;
    std::thread::id owner;
    std::unordered_map<ModuleKey, Module, ModuleKeyHash> modules;
    StwoNativeAotStats stats = {};
    uint32_t live_functions = 0;
};

struct BoundFunction {
    Loader *loader = nullptr;
    Module *module = nullptr;
    uint64_t cache_key = 0;
    uint32_t grid[3] = {};
    uint32_t block[3] = {};
    uint32_t dynamic_shared_bytes = 0;
    uint32_t argument_count = 0;
};

int runtime_status(cudaError_t status) {
    return status == cudaSuccess ? CUDA_SUCCESS : static_cast<int>(status);
}

int require_owner(Loader *loader) {
    if (loader == nullptr) return CUDA_ERROR_INVALID_HANDLE;
    if (loader->owner != std::this_thread::get_id()) return CUDA_ERROR_INVALID_CONTEXT;
    CUcontext current = nullptr;
    if (cuCtxGetCurrent(&current) != CUDA_SUCCESS ||
        current == nullptr || current != loader->driver_context) {
        return CUDA_ERROR_INVALID_CONTEXT;
    }
    return CUDA_SUCCESS;
}

int current_binding(
    void *exec_context,
    CUcontext *out_context,
    CUstream *out_stream,
    uint32_t *out_device,
    uint32_t *out_sm_major,
    uint32_t *out_sm_minor) {
    if (exec_context == nullptr || out_context == nullptr || out_stream == nullptr ||
        out_device == nullptr || out_sm_major == nullptr || out_sm_minor == nullptr) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    const int runtime = runtime_status(cudaFree(nullptr));
    if (runtime != CUDA_SUCCESS) return runtime;

    CUcontext context = nullptr;
    CUdevice device = 0;
    int context_device = -1;
    int sm_major = 0;
    int sm_minor = 0;
    void *stream = nullptr;
    if (cuCtxGetCurrent(&context) != CUDA_SUCCESS || context == nullptr ||
        cuCtxGetDevice(&device) != CUDA_SUCCESS || device < 0 ||
        stwo_exec_context_device(exec_context, &context_device) != CUDA_SUCCESS ||
        context_device != static_cast<int>(device) ||
        stwo_exec_context_stream(exec_context, &stream) != CUDA_SUCCESS ||
        stream == nullptr ||
        cuDeviceGetAttribute(
            &sm_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, device) !=
            CUDA_SUCCESS ||
        cuDeviceGetAttribute(
            &sm_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, device) !=
            CUDA_SUCCESS ||
        sm_major < 0 || sm_minor < 0) {
        return CUDA_ERROR_INVALID_CONTEXT;
    }
    *out_context = context;
    *out_stream = reinterpret_cast<CUstream>(stream);
    *out_device = static_cast<uint32_t>(device);
    *out_sm_major = static_cast<uint32_t>(sm_major);
    *out_sm_minor = static_cast<uint32_t>(sm_minor);
    return CUDA_SUCCESS;
}

int validate_launch(
    Loader *loader,
    CUfunction function,
    const uint32_t grid[3],
    const uint32_t block[3],
    uint32_t dynamic_shared_bytes,
    StwoNativeAotFunctionReceipt *receipt) {
    if (grid == nullptr || block == nullptr || receipt == nullptr ||
        grid[0] == 0 || grid[1] == 0 || grid[2] == 0 ||
        block[0] == 0 || block[1] == 0 || block[2] == 0) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    const uint64_t threads =
        static_cast<uint64_t>(block[0]) * block[1] * block[2];
    int max_threads = 0;
    int registers = 0;
    int binary_version = 0;
    int max_dynamic_shared = 0;
    if (cuFuncGetAttribute(
            &max_threads, CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK, function) !=
            CUDA_SUCCESS ||
        cuFuncGetAttribute(
            &registers, CU_FUNC_ATTRIBUTE_NUM_REGS, function) != CUDA_SUCCESS ||
        cuFuncGetAttribute(
            &binary_version, CU_FUNC_ATTRIBUTE_BINARY_VERSION, function) !=
            CUDA_SUCCESS ||
        cuFuncGetAttribute(
            &max_dynamic_shared,
            CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES,
            function) != CUDA_SUCCESS ||
        max_threads <= 0 || threads > static_cast<uint64_t>(max_threads) ||
        dynamic_shared_bytes > static_cast<uint32_t>(max_dynamic_shared)) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    receipt->registers_per_thread = static_cast<uint32_t>(registers);
    receipt->max_threads_per_block = static_cast<uint32_t>(max_threads);
    receipt->binary_version = static_cast<uint32_t>(binary_version);
    return CUDA_SUCCESS;
}

void unload_modules(Loader *loader) {
    for (auto &item : loader->modules) {
        if (item.second.module != nullptr) {
            cuModuleUnload(item.second.module);
            item.second.module = nullptr;
            item.second.function = nullptr;
        }
    }
}

}  // namespace

extern "C" int stwo_native_aot_loader_create(
    void *exec_context,
    void **out_loader) {
    if (out_loader == nullptr) return CUDA_ERROR_INVALID_VALUE;
    *out_loader = nullptr;

    std::unique_ptr<Loader> loader(new (std::nothrow) Loader());
    if (!loader) return CUDA_ERROR_OUT_OF_MEMORY;
    const int status = current_binding(
        exec_context,
        &loader->driver_context,
        &loader->stream,
        &loader->device,
        &loader->sm_major,
        &loader->sm_minor);
    if (status != CUDA_SUCCESS) return status;
    loader->exec_context = exec_context;
    loader->owner = std::this_thread::get_id();
    *out_loader = loader.release();
    return CUDA_SUCCESS;
}

extern "C" int stwo_native_aot_loader_destroy(void *raw_loader) {
    Loader *loader = static_cast<Loader *>(raw_loader);
    const int status = require_owner(loader);
    if (status != CUDA_SUCCESS) return status;
    if (loader->live_functions != 0) return CUDA_ERROR_INVALID_HANDLE;
    unload_modules(loader);
    delete loader;
    return CUDA_SUCCESS;
}

extern "C" int stwo_native_aot_function_bind(
    void *raw_loader,
    uint64_t cache_key,
    const char *kernel_name,
    const uint32_t grid[3],
    const uint32_t block[3],
    uint32_t dynamic_shared_bytes,
    uint32_t argument_count,
    void **out_function,
    StwoNativeAotFunctionReceipt *out_receipt) {
    Loader *loader = static_cast<Loader *>(raw_loader);
    if (out_function == nullptr || out_receipt == nullptr) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    *out_function = nullptr;
    std::memset(out_receipt, 0, sizeof(*out_receipt));
    const int owner = require_owner(loader);
    if (owner != CUDA_SUCCESS) return owner;
    if (cache_key == 0 || kernel_name == nullptr || kernel_name[0] == '\0' ||
        argument_count == 0) {
        return CUDA_ERROR_INVALID_VALUE;
    }

    ModuleKey key{cache_key, kernel_name};
    auto found = loader->modules.find(key);
    if (found == loader->modules.end()) {
        const unsigned char *image = nullptr;
        size_t image_bytes = 0;
        if (!stwo_aot_lookup(
                cache_key,
                loader->sm_major,
                loader->sm_minor,
                &image,
                &image_bytes) ||
            image == nullptr || image_bytes == 0) {
            loader->stats.aot_misses += 1;
            return CUDA_ERROR_NOT_FOUND;
        }
        Module module;
        CUresult status = cuModuleLoadData(&module.module, image);
        if (status != CUDA_SUCCESS) return status;
        status = cuModuleGetFunction(&module.function, module.module, kernel_name);
        if (status != CUDA_SUCCESS || module.function == nullptr) {
            cuModuleUnload(module.module);
            return status == CUDA_SUCCESS ? CUDA_ERROR_NOT_FOUND : status;
        }
        auto inserted = loader->modules.emplace(std::move(key), module);
        found = inserted.first;
        loader->stats.aot_loads += 1;
    } else {
        loader->stats.aot_cache_hits += 1;
    }

    std::unique_ptr<BoundFunction> function(new (std::nothrow) BoundFunction());
    if (!function) return CUDA_ERROR_OUT_OF_MEMORY;
    function->loader = loader;
    function->module = &found->second;
    function->cache_key = cache_key;
    std::memcpy(function->grid, grid, sizeof(function->grid));
    std::memcpy(function->block, block, sizeof(function->block));
    function->dynamic_shared_bytes = dynamic_shared_bytes;
    function->argument_count = argument_count;

    out_receipt->abi_version = kReceiptAbiVersion;
    out_receipt->device_ordinal = loader->device;
    out_receipt->sm_major = loader->sm_major;
    out_receipt->sm_minor = loader->sm_minor;
    out_receipt->argument_count = argument_count;
    std::memcpy(out_receipt->grid, grid, sizeof(out_receipt->grid));
    std::memcpy(out_receipt->block, block, sizeof(out_receipt->block));
    out_receipt->dynamic_shared_bytes = dynamic_shared_bytes;
    const int launch_status = validate_launch(
        loader,
        found->second.function,
        grid,
        block,
        dynamic_shared_bytes,
        out_receipt);
    if (launch_status != CUDA_SUCCESS) return launch_status;
    out_receipt->cache_key = cache_key;
    out_receipt->context_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(loader->driver_context));
    out_receipt->module_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(found->second.module));
    out_receipt->function_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(found->second.function));
    out_receipt->stream_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(loader->stream));

    loader->live_functions += 1;
    *out_function = function.release();
    return CUDA_SUCCESS;
}

extern "C" int stwo_native_aot_function_launch(
    void *raw_function,
    void *const *arguments,
    uint32_t argument_count) {
    BoundFunction *function = static_cast<BoundFunction *>(raw_function);
    if (function == nullptr || function->loader == nullptr ||
        function->module == nullptr || arguments == nullptr ||
        argument_count != function->argument_count) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    Loader *loader = function->loader;
    const int owner = require_owner(loader);
    if (owner != CUDA_SUCCESS) return owner;
    CUresult status = cuLaunchKernel(
        function->module->function,
        function->grid[0],
        function->grid[1],
        function->grid[2],
        function->block[0],
        function->block[1],
        function->block[2],
        function->dynamic_shared_bytes,
        loader->stream,
        const_cast<void **>(arguments),
        nullptr);
    if (status == CUDA_SUCCESS) {
        loader->stats.launches += 1;
    } else {
        loader->stats.launch_failures += 1;
    }
    return status;
}

extern "C" int stwo_native_aot_function_destroy(void *raw_function) {
    BoundFunction *function = static_cast<BoundFunction *>(raw_function);
    if (function == nullptr || function->loader == nullptr) {
        return CUDA_ERROR_INVALID_HANDLE;
    }
    const int owner = require_owner(function->loader);
    if (owner != CUDA_SUCCESS) return owner;
    if (function->loader->live_functions == 0) return CUDA_ERROR_INVALID_HANDLE;
    function->loader->live_functions -= 1;
    delete function;
    return CUDA_SUCCESS;
}

extern "C" int stwo_native_aot_loader_stats(
    void *raw_loader,
    StwoNativeAotStats *out_stats) {
    Loader *loader = static_cast<Loader *>(raw_loader);
    if (out_stats == nullptr) return CUDA_ERROR_INVALID_VALUE;
    const int owner = require_owner(loader);
    if (owner != CUDA_SUCCESS) return owner;
    *out_stats = loader->stats;
    return CUDA_SUCCESS;
}
