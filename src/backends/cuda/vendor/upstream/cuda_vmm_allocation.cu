#include <cuda.h>
#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>
#include <new>

// Whole-allocation CUDA VMM storage for the replacement prover. A handle owns
// one stable virtual address and at most one physical allocation at a time.
// Physical backing may be reclaimed and replaced across strictly consecutive
// generations. Stream quiescence remains a checked Rust-side prerequisite.

extern "C" int stwo_exec_context_device(void *handle, int *out_device);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);

namespace {

struct StwoVmmAllocation {
    CUdeviceptr address;
    size_t bytes;
    size_t granularity;
    CUmemGenericAllocationHandle physical;
    CUcontext cuda_context;
    CUdevice device;
    void *owner_context;
    uint32_t generation;
    bool mapped;
    bool physical_live;
    bool primary_retained;
    bool poisoned;
};

int status(CUresult result) {
    return static_cast<int>(result);
}

int first_status(int current, int candidate) {
    return current == static_cast<int>(CUDA_SUCCESS) ? candidate : current;
}

int poison_and_return(StwoVmmAllocation *allocation, int result) {
    if (allocation != nullptr) {
        allocation->poisoned = true;
    }
    return result;
}

constexpr bool valid_generation_step(uint32_t current, uint32_t next) {
    return current != UINT32_MAX && next == current + 1u;
}

static_assert(valid_generation_step(0u, 1u));
static_assert(!valid_generation_step(0u, 2u));
static_assert(!valid_generation_step(UINT32_MAX, 0u));

CUmemAllocationProp allocation_properties(CUdevice device) {
    CUmemAllocationProp properties = {};
    properties.type = CU_MEM_ALLOCATION_TYPE_PINNED;
    properties.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
    properties.location.id = static_cast<int>(device);
    properties.requestedHandleTypes = CU_MEM_HANDLE_TYPE_NONE;
    return properties;
}

int require_not_capturing(void *context_handle) {
    void *raw_stream = nullptr;
    int result = stwo_exec_context_stream(context_handle, &raw_stream);
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }
    cudaStreamCaptureStatus capture_status = cudaStreamCaptureStatusNone;
    cudaError_t error = cudaStreamIsCapturing(
        reinterpret_cast<cudaStream_t>(raw_stream), &capture_status);
    if (error != cudaSuccess) {
        return static_cast<int>(error);
    }
    return capture_status == cudaStreamCaptureStatusNone
        ? static_cast<int>(cudaSuccess)
        : static_cast<int>(cudaErrorStreamCaptureUnsupported);
}

int require_owner_current(
    const StwoVmmAllocation *allocation,
    void *context_handle
) {
    if (allocation == nullptr || context_handle == nullptr ||
        context_handle != allocation->owner_context) {
        return static_cast<int>(CUDA_ERROR_INVALID_CONTEXT);
    }

    int owner_device = -1;
    int result = stwo_exec_context_device(context_handle, &owner_device);
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }
    int runtime_device = -1;
    cudaError_t runtime_error = cudaGetDevice(&runtime_device);
    if (runtime_error != cudaSuccess) {
        return static_cast<int>(runtime_error);
    }
    if (owner_device != static_cast<int>(allocation->device) ||
        runtime_device != owner_device) {
        return static_cast<int>(CUDA_ERROR_INVALID_DEVICE);
    }

    CUcontext current_context = nullptr;
    CUresult driver_error = cuCtxGetCurrent(&current_context);
    if (driver_error != CUDA_SUCCESS) {
        return status(driver_error);
    }
    CUdevice current_device = 0;
    driver_error = cuCtxGetDevice(&current_device);
    if (driver_error != CUDA_SUCCESS) {
        return status(driver_error);
    }
    if (current_context != allocation->cuda_context ||
        current_device != allocation->device) {
        return static_cast<int>(CUDA_ERROR_INVALID_CONTEXT);
    }
    return static_cast<int>(CUDA_SUCCESS);
}

int unmap_and_release(StwoVmmAllocation *allocation);

int create_and_map_physical(StwoVmmAllocation *allocation) {
    CUmemGenericAllocationHandle physical = 0;
    CUmemAllocationProp properties = allocation_properties(allocation->device);
    CUresult error = cuMemCreate(
        &physical, allocation->bytes, &properties, 0);
    if (error != CUDA_SUCCESS) {
        return status(error);
    }
    allocation->physical = physical;
    allocation->physical_live = true;

    error = cuMemMap(
        allocation->address, allocation->bytes, 0, physical, 0);
    if (error != CUDA_SUCCESS) {
        if (cuMemRelease(physical) == CUDA_SUCCESS) {
            allocation->physical = 0;
            allocation->physical_live = false;
        }
        return status(error);
    }
    allocation->mapped = true;

    CUmemAccessDesc access = {};
    access.location = properties.location;
    access.flags = CU_MEM_ACCESS_FLAGS_PROT_READWRITE;
    error = cuMemSetAccess(
        allocation->address, allocation->bytes, &access, 1);
    if (error != CUDA_SUCCESS) {
        unmap_and_release(allocation);
        return status(error);
    }
    return static_cast<int>(CUDA_SUCCESS);
}

int unmap_and_release(StwoVmmAllocation *allocation) {
    int result = static_cast<int>(CUDA_SUCCESS);
    if (allocation->mapped) {
        CUresult error = cuMemUnmap(allocation->address, allocation->bytes);
        result = first_status(result, status(error));
        if (error != CUDA_SUCCESS) {
            return result;
        }
        allocation->mapped = false;
    }
    if (allocation->physical_live) {
        CUresult error = cuMemRelease(allocation->physical);
        result = first_status(result, status(error));
        if (error == CUDA_SUCCESS) {
            allocation->physical = 0;
            allocation->physical_live = false;
        }
    }
    return result;
}

}  // namespace

extern "C" int stwo_vmm_allocation_create(
    void *context_handle,
    size_t requested_bytes,
    void **out_handle,
    void **out_ptr,
    size_t *out_mapped_bytes,
    size_t *out_granularity
) {
    if (context_handle == nullptr || requested_bytes == 0 || out_handle == nullptr ||
        out_ptr == nullptr || out_mapped_bytes == nullptr || out_granularity == nullptr) {
        return static_cast<int>(CUDA_ERROR_INVALID_VALUE);
    }
    *out_handle = nullptr;
    *out_ptr = nullptr;
    *out_mapped_bytes = 0;
    *out_granularity = 0;

    int result = require_not_capturing(context_handle);
    if (result != static_cast<int>(CUDA_SUCCESS)) {
        return result;
    }

    int owner_device = -1;
    result = stwo_exec_context_device(context_handle, &owner_device);
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }
    int runtime_device = -1;
    cudaError_t runtime_error = cudaGetDevice(&runtime_device);
    if (runtime_error != cudaSuccess) {
        return static_cast<int>(runtime_error);
    }
    if (runtime_device != owner_device) {
        return static_cast<int>(CUDA_ERROR_INVALID_DEVICE);
    }

    CUcontext current_context = nullptr;
    CUresult driver_error = cuCtxGetCurrent(&current_context);
    if (driver_error != CUDA_SUCCESS) {
        return status(driver_error);
    }
    if (current_context == nullptr) {
        return static_cast<int>(CUDA_ERROR_INVALID_CONTEXT);
    }
    CUdevice device = 0;
    driver_error = cuCtxGetDevice(&device);
    if (driver_error != CUDA_SUCCESS) {
        return status(driver_error);
    }
    if (static_cast<int>(device) != owner_device) {
        return static_cast<int>(CUDA_ERROR_INVALID_DEVICE);
    }

    int vmm_supported = 0;
    driver_error = cuDeviceGetAttribute(
        &vmm_supported,
        CU_DEVICE_ATTRIBUTE_VIRTUAL_MEMORY_MANAGEMENT_SUPPORTED,
        device);
    if (driver_error != CUDA_SUCCESS) {
        return status(driver_error);
    }
    if (vmm_supported == 0) {
        return static_cast<int>(CUDA_ERROR_NOT_SUPPORTED);
    }

    CUcontext retained_context = nullptr;
    driver_error = cuDevicePrimaryCtxRetain(&retained_context, device);
    if (driver_error != CUDA_SUCCESS) {
        return status(driver_error);
    }
    if (retained_context != current_context) {
        cuDevicePrimaryCtxRelease(device);
        return static_cast<int>(CUDA_ERROR_INVALID_CONTEXT);
    }

    StwoVmmAllocation *allocation = new (std::nothrow) StwoVmmAllocation{};
    if (allocation == nullptr) {
        cuDevicePrimaryCtxRelease(device);
        return static_cast<int>(CUDA_ERROR_OUT_OF_MEMORY);
    }
    allocation->cuda_context = retained_context;
    allocation->device = device;
    allocation->owner_context = context_handle;
    allocation->bytes = requested_bytes;
    allocation->generation = 0;
    allocation->primary_retained = true;

    CUmemAllocationProp properties = allocation_properties(device);
    driver_error = cuMemGetAllocationGranularity(
        &allocation->granularity,
        &properties,
        CU_MEM_ALLOC_GRANULARITY_MINIMUM);
    if (driver_error != CUDA_SUCCESS || allocation->granularity == 0 ||
        (allocation->granularity & (allocation->granularity - 1)) != 0 ||
        requested_bytes % allocation->granularity != 0) {
        result = driver_error == CUDA_SUCCESS
            ? static_cast<int>(CUDA_ERROR_INVALID_VALUE)
            : status(driver_error);
        cuDevicePrimaryCtxRelease(device);
        delete allocation;
        return result;
    }

    driver_error = cuMemAddressReserve(
        &allocation->address,
        allocation->bytes,
        allocation->granularity,
        0,
        0);
    if (driver_error != CUDA_SUCCESS) {
        cuDevicePrimaryCtxRelease(device);
        delete allocation;
        return status(driver_error);
    }

    result = create_and_map_physical(allocation);
    if (result != static_cast<int>(CUDA_SUCCESS)) {
        int cleanup = unmap_and_release(allocation);
        if (!allocation->mapped && allocation->address != 0) {
            CUresult free_error = cuMemAddressFree(
                allocation->address, allocation->bytes);
            cleanup = first_status(cleanup, status(free_error));
            if (free_error == CUDA_SUCCESS) {
                allocation->address = 0;
            }
        }
        if (cleanup != static_cast<int>(CUDA_SUCCESS)) {
            // The Rust wrapper destroys a non-null error handle, giving failed
            // rollback operations one deterministic cleanup retry.
            *out_handle = allocation;
            return result;
        }
        CUresult release_error = cuDevicePrimaryCtxRelease(device);
        if (release_error != CUDA_SUCCESS) {
            *out_handle = allocation;
            return result;
        }
        allocation->primary_retained = false;
        delete allocation;
        return result;
    }

    *out_handle = allocation;
    *out_ptr = reinterpret_cast<void *>(allocation->address);
    *out_mapped_bytes = allocation->bytes;
    *out_granularity = allocation->granularity;
    return static_cast<int>(CUDA_SUCCESS);
}

extern "C" int stwo_vmm_allocation_unmap_release(
    void *handle,
    void *context_handle,
    uint32_t expected_generation
) {
    StwoVmmAllocation *allocation = static_cast<StwoVmmAllocation *>(handle);
    int result = require_owner_current(allocation, context_handle);
    if (result != static_cast<int>(CUDA_SUCCESS)) {
        return poison_and_return(allocation, result);
    }
    result = require_not_capturing(context_handle);
    if (result != static_cast<int>(CUDA_SUCCESS)) {
        return poison_and_return(allocation, result);
    }
    if (allocation->poisoned || !allocation->mapped ||
        !allocation->physical_live ||
        allocation->generation != expected_generation) {
        return poison_and_return(
            allocation, static_cast<int>(CUDA_ERROR_INVALID_VALUE));
    }
    result = unmap_and_release(allocation);
    return result == static_cast<int>(CUDA_SUCCESS)
        ? result
        : poison_and_return(allocation, result);
}

extern "C" int stwo_vmm_allocation_remap_next(
    void *handle,
    void *context_handle,
    uint32_t current_generation,
    uint32_t next_generation
) {
    StwoVmmAllocation *allocation = static_cast<StwoVmmAllocation *>(handle);
    int result = require_owner_current(allocation, context_handle);
    if (result != static_cast<int>(CUDA_SUCCESS)) {
        return poison_and_return(allocation, result);
    }
    result = require_not_capturing(context_handle);
    if (result != static_cast<int>(CUDA_SUCCESS)) {
        return poison_and_return(allocation, result);
    }
    if (allocation->poisoned || allocation->mapped ||
        allocation->physical_live ||
        allocation->generation != current_generation ||
        !valid_generation_step(current_generation, next_generation)) {
        return poison_and_return(
            allocation, static_cast<int>(CUDA_ERROR_INVALID_VALUE));
    }
    result = create_and_map_physical(allocation);
    if (result == static_cast<int>(CUDA_SUCCESS)) {
        allocation->generation = next_generation;
        return result;
    }
    return poison_and_return(allocation, result);
}

// Drop fallback only. Normal spill/reclaim has no global synchronization: it
// joins every proof lane and fences the owner main stream before unmapping.
extern "C" int stwo_vmm_allocation_destroy(void *handle) {
    if (handle == nullptr) {
        return static_cast<int>(CUDA_SUCCESS);
    }
    StwoVmmAllocation *allocation = static_cast<StwoVmmAllocation *>(handle);
    int result = static_cast<int>(CUDA_SUCCESS);

    CUresult driver_error = cuCtxPushCurrent(allocation->cuda_context);
    result = first_status(result, status(driver_error));
    if (driver_error == CUDA_SUCCESS) {
        result = first_status(result, status(cuCtxSynchronize()));
        result = first_status(result, unmap_and_release(allocation));
        if (!allocation->mapped && allocation->address != 0) {
            CUresult free_error = cuMemAddressFree(
                allocation->address, allocation->bytes);
            result = first_status(result, status(free_error));
            if (free_error == CUDA_SUCCESS) {
                allocation->address = 0;
            }
        }
        CUcontext popped_context = nullptr;
        CUresult pop_error = cuCtxPopCurrent(&popped_context);
        result = first_status(result, status(pop_error));
        if (pop_error == CUDA_SUCCESS &&
            popped_context != allocation->cuda_context) {
            result = first_status(
                result, static_cast<int>(CUDA_ERROR_INVALID_CONTEXT));
        }
    }
    if (allocation->primary_retained) {
        result = first_status(
            result, status(cuDevicePrimaryCtxRelease(allocation->device)));
        allocation->primary_retained = false;
    }
    delete allocation;
    return result;
}
