#include <cuda.h>
#include <cuda_runtime.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
// One-rank-per-GPU Track-A exchange storage. Classic CUDA IPC can export only
// cudaMalloc allocations, so this file deliberately owns a dedicated buffer;
// it never exports the proof arena or its stream-ordered pool.
extern "C" int stwo_exec_context_device(void *handle, int *out_device);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
namespace {
constexpr size_t kIpcHandleBytes = 64;
constexpr size_t kIpcAllocationAlignment = 2u * 1024u * 1024u;
static_assert(sizeof(void *) == 8, "CUDA IPC requires a 64-bit process");
static_assert(sizeof(cudaIpcMemHandle_t) == kIpcHandleBytes);
static_assert(sizeof(cudaIpcEventHandle_t) == kIpcHandleBytes);
enum class OwnerState : uint32_t {
    Idle,
    Published,
    Poisoned,
};
enum class ImportState : uint32_t {
    Awaiting,
    Consumed,
    Poisoned,
};
struct ContextIdentity {
    int device;
    CUcontext driver_context;
    cudaStream_t stream;
};
struct StwoIpcExchangeOwner {
    void *allocation;
    size_t logical_bytes;
    size_t allocation_bytes;
    cudaEvent_t ready;
    cudaEvent_t consumed;
    ContextIdentity identity;
    void *owner_context;
    uint64_t generation;
    OwnerState state;
    bool peer_closed;
};
struct StwoIpcExchangeImport {
    void *remote_allocation;
    size_t logical_bytes;
    size_t allocation_bytes;
    cudaEvent_t ready;
    cudaEvent_t consumed;
    ContextIdentity identity;
    void *owner_context;
    uint64_t generation;
    ImportState state;
};
int context_identity(void *context_handle, ContextIdentity *out) {
    if (context_handle == nullptr || out == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    int device = -1;
    int result = stwo_exec_context_device(context_handle, &device);
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }
    int current_device = -1;
    cudaError_t runtime_error = cudaGetDevice(&current_device);
    if (runtime_error != cudaSuccess) {
        return static_cast<int>(runtime_error);
    }
    if (device != current_device) {
        return static_cast<int>(cudaErrorInvalidDevice);
    }
    void *raw_stream = nullptr;
    result = stwo_exec_context_stream(context_handle, &raw_stream);
    if (result != static_cast<int>(cudaSuccess) || raw_stream == nullptr) {
        return result == static_cast<int>(cudaSuccess)
            ? static_cast<int>(cudaErrorInvalidResourceHandle)
            : result;
    }
    CUcontext driver_context = nullptr;
    CUresult driver_error = cuCtxGetCurrent(&driver_context);
    if (driver_error != CUDA_SUCCESS) {
        return static_cast<int>(driver_error);
    }
    CUdevice driver_device = 0;
    driver_error = cuCtxGetDevice(&driver_device);
    if (driver_error != CUDA_SUCCESS) {
        return static_cast<int>(driver_error);
    }
    if (driver_context == nullptr || static_cast<int>(driver_device) != device) {
        return static_cast<int>(CUDA_ERROR_INVALID_CONTEXT);
    }
    *out = ContextIdentity{
        device,
        driver_context,
        reinterpret_cast<cudaStream_t>(raw_stream),
    };
    return static_cast<int>(cudaSuccess);
}
int require_context(
    void *context_handle,
    void *expected_handle,
    const ContextIdentity &expected,
    ContextIdentity *out
) {
    if (context_handle != expected_handle) {
        return static_cast<int>(CUDA_ERROR_INVALID_CONTEXT);
    }
    ContextIdentity actual{};
    int result = context_identity(context_handle, &actual);
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }
    if (actual.device != expected.device ||
        actual.driver_context != expected.driver_context ||
        actual.stream != expected.stream) {
        return static_cast<int>(CUDA_ERROR_INVALID_CONTEXT);
    }
    if (out != nullptr) {
        *out = actual;
    }
    return static_cast<int>(cudaSuccess);
}
int require_uuid(int device, const uint8_t *expected_uuid) {
    if (expected_uuid == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    cudaUUID_t actual{};
    CUresult error = cuDeviceGetUuid_v2(&actual, device);
    if (error != CUDA_SUCCESS) {
        return static_cast<int>(error);
    }
    return std::memcmp(actual.bytes, expected_uuid, sizeof(actual.bytes)) == 0
        ? static_cast<int>(cudaSuccess)
        : static_cast<int>(cudaErrorInvalidDevice);
}
int require_not_capturing(cudaStream_t stream) {
    cudaStreamCaptureStatus capture = cudaStreamCaptureStatusNone;
    cudaError_t error = cudaStreamIsCapturing(stream, &capture);
    if (error != cudaSuccess) {
        return static_cast<int>(error);
    }
    return capture == cudaStreamCaptureStatusNone
        ? static_cast<int>(cudaSuccess)
        : static_cast<int>(cudaErrorStreamCaptureUnsupported);
}
bool round_allocation(size_t logical_bytes, size_t *allocation_bytes) {
    if (logical_bytes == 0 || allocation_bytes == nullptr ||
        logical_bytes > std::numeric_limits<size_t>::max() -
            (kIpcAllocationAlignment - 1)) {
        return false;
    }
    *allocation_bytes =
        (logical_bytes + kIpcAllocationAlignment - 1) &
        ~(kIpcAllocationAlignment - 1);
    return true;
}
int require_exact_allocation(
    void *pointer,
    size_t expected_bytes,
    bool require_exportable
) {
    CUdeviceptr base = 0;
    size_t bytes = 0;
    CUdeviceptr address = reinterpret_cast<CUdeviceptr>(pointer);
    CUresult error = cuPointerGetAttribute(
        &base, CU_POINTER_ATTRIBUTE_RANGE_START_ADDR, address);
    if (error == CUDA_SUCCESS) {
        error = cuPointerGetAttribute(
            &bytes, CU_POINTER_ATTRIBUTE_RANGE_SIZE, address);
    }
    if (error != CUDA_SUCCESS) {
        return static_cast<int>(error);
    }
    if (base != address || bytes != expected_bytes) {
        return static_cast<int>(CUDA_ERROR_INVALID_VALUE);
    }
    if (require_exportable) {
        unsigned int legacy_ipc_capable = 0;
        error = cuPointerGetAttribute(
            &legacy_ipc_capable,
            CU_POINTER_ATTRIBUTE_IS_LEGACY_CUDA_IPC_CAPABLE,
            address);
        if (error != CUDA_SUCCESS) {
            return static_cast<int>(error);
        }
        if (legacy_ipc_capable == 0) {
            return static_cast<int>(CUDA_ERROR_NOT_SUPPORTED);
        }
    }
    return static_cast<int>(CUDA_SUCCESS);
}
bool ranges_overlap(
    const void *left,
    size_t left_bytes,
    const void *right,
    size_t right_bytes
) {
    const uintptr_t left_start = reinterpret_cast<uintptr_t>(left);
    const uintptr_t right_start = reinterpret_cast<uintptr_t>(right);
    if (left_start > std::numeric_limits<uintptr_t>::max() - left_bytes ||
        right_start > std::numeric_limits<uintptr_t>::max() - right_bytes) {
        return true;
    }
    return left_start < right_start + right_bytes &&
        right_start < left_start + left_bytes;
}
int require_local_device_range(const void *pointer, int device, size_t bytes) {
    if (pointer == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    cudaPointerAttributes attributes{};
    cudaError_t error = cudaPointerGetAttributes(&attributes, pointer);
    if (error != cudaSuccess) {
        return static_cast<int>(error);
    }
    if (attributes.type != cudaMemoryTypeDevice || attributes.device != device) {
        return static_cast<int>(cudaErrorInvalidDevicePointer);
    }
    const CUdeviceptr address = reinterpret_cast<CUdeviceptr>(pointer);
    CUdeviceptr base = 0;
    size_t range_bytes = 0;
    CUresult driver_error = cuPointerGetAttribute(
        &base, CU_POINTER_ATTRIBUTE_RANGE_START_ADDR, address);
    if (driver_error == CUDA_SUCCESS) {
        driver_error = cuPointerGetAttribute(
            &range_bytes, CU_POINTER_ATTRIBUTE_RANGE_SIZE, address);
    }
    if (driver_error != CUDA_SUCCESS) {
        return static_cast<int>(driver_error);
    }
    if (address < base) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const size_t offset = static_cast<size_t>(address - base);
    return offset <= range_bytes && bytes <= range_bytes - offset
        ? static_cast<int>(cudaSuccess)
        : static_cast<int>(cudaErrorInvalidValue);
}
int cleanup_owner(StwoIpcExchangeOwner *owner) {
    if (owner->consumed != nullptr) {
        cudaError_t error = cudaEventDestroy(owner->consumed);
        if (error != cudaSuccess) {
            return static_cast<int>(error);
        }
        owner->consumed = nullptr;
    }
    if (owner->ready != nullptr) {
        cudaError_t error = cudaEventDestroy(owner->ready);
        if (error != cudaSuccess) {
            return static_cast<int>(error);
        }
        owner->ready = nullptr;
    }
    if (owner->allocation != nullptr) {
        cudaError_t error = cudaFree(owner->allocation);
        if (error != cudaSuccess) {
            return static_cast<int>(error);
        }
        owner->allocation = nullptr;
    }
    return static_cast<int>(cudaSuccess);
}
int cleanup_import(StwoIpcExchangeImport *imported) {
    if (imported->consumed != nullptr) {
        cudaError_t error = cudaEventDestroy(imported->consumed);
        if (error != cudaSuccess) {
            return static_cast<int>(error);
        }
        imported->consumed = nullptr;
    }
    if (imported->ready != nullptr) {
        cudaError_t error = cudaEventDestroy(imported->ready);
        if (error != cudaSuccess) {
            return static_cast<int>(error);
        }
        imported->ready = nullptr;
    }
    if (imported->remote_allocation != nullptr) {
        cudaError_t error = cudaIpcCloseMemHandle(imported->remote_allocation);
        if (error != cudaSuccess) {
            return static_cast<int>(error);
        }
        imported->remote_allocation = nullptr;
    }
    return static_cast<int>(cudaSuccess);
}

}  // namespace
extern "C" int stwo_ipc_exchange_context_uuid(
    void *context_handle,
    uint8_t *out_uuid
) {
    if (out_uuid == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ContextIdentity identity{};
    int result = context_identity(context_handle, &identity);
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }
    cudaUUID_t uuid{};
    CUresult error = cuDeviceGetUuid_v2(&uuid, identity.device);
    if (error != CUDA_SUCCESS) {
        return static_cast<int>(error);
    }
    std::memcpy(out_uuid, uuid.bytes, sizeof(uuid.bytes));
    return static_cast<int>(cudaSuccess);
}
extern "C" int stwo_ipc_exchange_owner_create(
    void *context_handle,
    size_t logical_bytes,
    uint64_t initial_generation,
    const uint8_t *expected_owner_uuid,
    void **out_handle,
    void **out_pointer,
    size_t *out_allocation_bytes,
    uint8_t *out_memory_handle,
    uint8_t *out_ready_event_handle,
    uint8_t *out_consumed_event_handle
) {
#if !defined(__linux__)
    return static_cast<int>(cudaErrorNotSupported);
#else
    if (out_handle == nullptr || out_pointer == nullptr ||
        out_allocation_bytes == nullptr || out_memory_handle == nullptr ||
        out_ready_event_handle == nullptr || out_consumed_event_handle == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    *out_handle = nullptr;
    *out_pointer = nullptr;
    *out_allocation_bytes = 0;
    std::memset(out_memory_handle, 0, kIpcHandleBytes);
    std::memset(out_ready_event_handle, 0, kIpcHandleBytes);
    std::memset(out_consumed_event_handle, 0, kIpcHandleBytes);

    ContextIdentity identity{};
    int result = context_identity(context_handle, &identity);
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }
    result = require_not_capturing(identity.stream);
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }
    result = require_uuid(identity.device, expected_owner_uuid);
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }
    size_t allocation_bytes = 0;
    if (!round_allocation(logical_bytes, &allocation_bytes)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    StwoIpcExchangeOwner *owner = new (std::nothrow) StwoIpcExchangeOwner{};
    if (owner == nullptr) {
        return static_cast<int>(cudaErrorMemoryAllocation);
    }
    owner->logical_bytes = logical_bytes;
    owner->allocation_bytes = allocation_bytes;
    owner->identity = identity;
    owner->owner_context = context_handle;
    owner->generation = initial_generation;
    owner->state = OwnerState::Idle;

    cudaError_t error = cudaMalloc(&owner->allocation, allocation_bytes);
    if (error == cudaSuccess) {
        result = require_exact_allocation(
            owner->allocation, allocation_bytes, true);
        error = result == static_cast<int>(cudaSuccess)
            ? cudaMemsetAsync(owner->allocation, 0, allocation_bytes, identity.stream)
            : static_cast<cudaError_t>(result);
    }
    if (error == cudaSuccess) {
        error = cudaStreamSynchronize(identity.stream);
    }
    if (error == cudaSuccess) {
        error = cudaEventCreateWithFlags(
            &owner->ready, cudaEventInterprocess | cudaEventDisableTiming);
    }
    if (error == cudaSuccess) {
        error = cudaEventCreateWithFlags(
            &owner->consumed, cudaEventInterprocess | cudaEventDisableTiming);
    }
    cudaIpcMemHandle_t memory_handle{};
    cudaIpcEventHandle_t ready_handle{};
    cudaIpcEventHandle_t consumed_handle{};
    if (error == cudaSuccess) {
        error = cudaIpcGetMemHandle(&memory_handle, owner->allocation);
    }
    if (error == cudaSuccess) {
        error = cudaIpcGetEventHandle(&ready_handle, owner->ready);
    }
    if (error == cudaSuccess) {
        error = cudaIpcGetEventHandle(&consumed_handle, owner->consumed);
    }
    if (error != cudaSuccess) {
        cleanup_owner(owner);
        delete owner;
        return static_cast<int>(error);
    }

    std::memcpy(out_memory_handle, &memory_handle, kIpcHandleBytes);
    std::memcpy(out_ready_event_handle, &ready_handle, kIpcHandleBytes);
    std::memcpy(out_consumed_event_handle, &consumed_handle, kIpcHandleBytes);
    *out_handle = owner;
    *out_pointer = owner->allocation;
    *out_allocation_bytes = allocation_bytes;
    return static_cast<int>(cudaSuccess);
#endif
}

extern "C" int stwo_ipc_exchange_owner_publish(
    void *handle,
    void *context_handle,
    const void *source,
    size_t bytes,
    uint64_t generation
) {
    StwoIpcExchangeOwner *owner = static_cast<StwoIpcExchangeOwner *>(handle);
    if (owner == nullptr || bytes != owner->logical_bytes ||
        generation != owner->generation || owner->state != OwnerState::Idle) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    int result = require_context(
        context_handle, owner->owner_context, owner->identity, nullptr);
    if (result == static_cast<int>(cudaSuccess)) {
        result = require_local_device_range(source, owner->identity.device, bytes);
    }
    if (result == static_cast<int>(cudaSuccess) &&
        ranges_overlap(
            source,
            bytes,
            owner->allocation,
            owner->allocation_bytes)) {
        result = static_cast<int>(cudaErrorInvalidValue);
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = static_cast<int>(cudaMemcpyAsync(
            owner->allocation,
            source,
            bytes,
            cudaMemcpyDeviceToDevice,
            owner->identity.stream));
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = static_cast<int>(cudaEventRecordWithFlags(
            owner->ready, owner->identity.stream, cudaEventRecordExternal));
    }
    if (result != static_cast<int>(cudaSuccess)) {
        owner->state = OwnerState::Poisoned;
        return result;
    }
    owner->state = OwnerState::Published;
    return static_cast<int>(cudaSuccess);
}

extern "C" int stwo_ipc_exchange_owner_reclaim(
    void *handle,
    void *context_handle,
    uint64_t generation
) {
    StwoIpcExchangeOwner *owner = static_cast<StwoIpcExchangeOwner *>(handle);
    if (owner == nullptr || generation != owner->generation ||
        owner->state != OwnerState::Published ||
        generation == std::numeric_limits<uint64_t>::max()) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    int result = require_context(
        context_handle, owner->owner_context, owner->identity, nullptr);
    if (result == static_cast<int>(cudaSuccess)) {
        result = static_cast<int>(cudaStreamWaitEvent(
            owner->identity.stream, owner->consumed, cudaEventWaitExternal));
    }
    if (result != static_cast<int>(cudaSuccess)) {
        owner->state = OwnerState::Poisoned;
        return result;
    }
    owner->generation += 1;
    owner->state = OwnerState::Idle;
    return static_cast<int>(cudaSuccess);
}

extern "C" int stwo_ipc_exchange_owner_mark_peer_closed(
    void *handle,
    void *context_handle,
    uint64_t generation
) {
    StwoIpcExchangeOwner *owner = static_cast<StwoIpcExchangeOwner *>(handle);
    if (owner == nullptr || owner->state != OwnerState::Idle ||
        owner->generation != generation) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    int result = require_context(
        context_handle, owner->owner_context, owner->identity, nullptr);
    if (result == static_cast<int>(cudaSuccess)) {
        owner->peer_closed = true;
    }
    return result;
}

extern "C" int stwo_ipc_exchange_owner_close(
    void *handle,
    void *context_handle
) {
    StwoIpcExchangeOwner *owner = static_cast<StwoIpcExchangeOwner *>(handle);
    if (owner == nullptr || !owner->peer_closed || owner->state != OwnerState::Idle) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ContextIdentity identity{};
    int result = require_context(
        context_handle, owner->owner_context, owner->identity, &identity);
    if (result == static_cast<int>(cudaSuccess)) {
        result = require_not_capturing(identity.stream);
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = static_cast<int>(cudaStreamSynchronize(identity.stream));
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = cleanup_owner(owner);
    }
    if (result == static_cast<int>(cudaSuccess)) {
        delete owner;
    } else {
        owner->state = OwnerState::Poisoned;
    }
    return result;
}

extern "C" int stwo_ipc_exchange_import_open(
    void *context_handle,
    size_t logical_bytes,
    size_t allocation_bytes,
    uint64_t initial_generation,
    const uint8_t *expected_peer_uuid,
    const uint8_t *memory_handle_bytes,
    const uint8_t *ready_event_handle_bytes,
    const uint8_t *consumed_event_handle_bytes,
    void **out_handle,
    void **out_remote_pointer
) {
#if !defined(__linux__)
    return static_cast<int>(cudaErrorNotSupported);
#else
    if (out_handle == nullptr || out_remote_pointer == nullptr ||
        memory_handle_bytes == nullptr || ready_event_handle_bytes == nullptr ||
        consumed_event_handle_bytes == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    *out_handle = nullptr;
    *out_remote_pointer = nullptr;
    size_t expected_allocation_bytes = 0;
    if (!round_allocation(logical_bytes, &expected_allocation_bytes) ||
        allocation_bytes != expected_allocation_bytes) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ContextIdentity identity{};
    int result = context_identity(context_handle, &identity);
    if (result == static_cast<int>(cudaSuccess)) {
        result = require_not_capturing(identity.stream);
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = require_uuid(identity.device, expected_peer_uuid);
    }
    if (result != static_cast<int>(cudaSuccess)) {
        return result;
    }

    cudaIpcMemHandle_t memory_handle{};
    cudaIpcEventHandle_t ready_handle{};
    cudaIpcEventHandle_t consumed_handle{};
    std::memcpy(&memory_handle, memory_handle_bytes, kIpcHandleBytes);
    std::memcpy(&ready_handle, ready_event_handle_bytes, kIpcHandleBytes);
    std::memcpy(&consumed_handle, consumed_event_handle_bytes, kIpcHandleBytes);

    StwoIpcExchangeImport *imported = new (std::nothrow) StwoIpcExchangeImport{};
    if (imported == nullptr) {
        return static_cast<int>(cudaErrorMemoryAllocation);
    }
    imported->logical_bytes = logical_bytes;
    imported->allocation_bytes = allocation_bytes;
    imported->identity = identity;
    imported->owner_context = context_handle;
    imported->generation = initial_generation;
    imported->state = ImportState::Awaiting;

    cudaError_t error = cudaIpcOpenMemHandle(
        &imported->remote_allocation,
        memory_handle,
        cudaIpcMemLazyEnablePeerAccess);
    if (error == cudaSuccess) {
        result = require_exact_allocation(
            imported->remote_allocation, allocation_bytes, false);
        error = result == static_cast<int>(cudaSuccess)
            ? cudaSuccess
            : static_cast<cudaError_t>(result);
    }
    if (error == cudaSuccess) {
        error = cudaIpcOpenEventHandle(&imported->ready, ready_handle);
    }
    if (error == cudaSuccess) {
        error = cudaIpcOpenEventHandle(&imported->consumed, consumed_handle);
    }
    if (error != cudaSuccess) {
        cleanup_import(imported);
        delete imported;
        return static_cast<int>(error);
    }
    *out_handle = imported;
    *out_remote_pointer = imported->remote_allocation;
    return static_cast<int>(cudaSuccess);
#endif
}

extern "C" int stwo_ipc_exchange_import_consume(
    void *handle,
    void *context_handle,
    void *destination,
    size_t bytes,
    uint64_t generation
) {
    StwoIpcExchangeImport *imported =
        static_cast<StwoIpcExchangeImport *>(handle);
    if (imported == nullptr || bytes != imported->logical_bytes ||
        generation != imported->generation ||
        imported->state != ImportState::Awaiting) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    int result = require_context(
        context_handle, imported->owner_context, imported->identity, nullptr);
    if (result == static_cast<int>(cudaSuccess)) {
        result = require_local_device_range(
            destination, imported->identity.device, bytes);
    }
    if (result == static_cast<int>(cudaSuccess) &&
        ranges_overlap(
            destination,
            bytes,
            imported->remote_allocation,
            imported->allocation_bytes)) {
        result = static_cast<int>(cudaErrorInvalidValue);
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = static_cast<int>(cudaStreamWaitEvent(
            imported->identity.stream, imported->ready, cudaEventWaitExternal));
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = static_cast<int>(cudaMemcpyAsync(
            destination,
            imported->remote_allocation,
            bytes,
            cudaMemcpyDeviceToDevice,
            imported->identity.stream));
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = static_cast<int>(cudaEventRecordWithFlags(
            imported->consumed,
            imported->identity.stream,
            cudaEventRecordExternal));
    }
    if (result != static_cast<int>(cudaSuccess)) {
        imported->state = ImportState::Poisoned;
        return result;
    }
    imported->state = ImportState::Consumed;
    return static_cast<int>(cudaSuccess);
}

extern "C" int stwo_ipc_exchange_import_arm_next(
    void *handle,
    void *context_handle,
    uint64_t next_generation
) {
    StwoIpcExchangeImport *imported =
        static_cast<StwoIpcExchangeImport *>(handle);
    if (imported == nullptr || imported->state != ImportState::Consumed ||
        imported->generation == std::numeric_limits<uint64_t>::max() ||
        next_generation != imported->generation + 1) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    int result = require_context(
        context_handle, imported->owner_context, imported->identity, nullptr);
    if (result == static_cast<int>(cudaSuccess)) {
        imported->generation = next_generation;
        imported->state = ImportState::Awaiting;
    }
    return result;
}

extern "C" int stwo_ipc_exchange_import_close(
    void *handle,
    void *context_handle,
    uint64_t generation
) {
    StwoIpcExchangeImport *imported =
        static_cast<StwoIpcExchangeImport *>(handle);
    if (imported == nullptr || imported->state != ImportState::Awaiting ||
        imported->generation != generation) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ContextIdentity identity{};
    int result = require_context(
        context_handle, imported->owner_context, imported->identity, &identity);
    if (result == static_cast<int>(cudaSuccess)) {
        result = require_not_capturing(identity.stream);
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = static_cast<int>(cudaStreamSynchronize(identity.stream));
    }
    if (result == static_cast<int>(cudaSuccess)) {
        result = cleanup_import(imported);
    }
    if (result == static_cast<int>(cudaSuccess)) {
        delete imported;
    } else {
        imported->state = ImportState::Poisoned;
    }
    return result;
}

// Importer-only drop fallback. It drains its stream before closing the imported
// event views and memory mapping; it never frees the exporting allocation.
extern "C" int stwo_ipc_exchange_import_destroy(void *handle) {
    if (handle == nullptr) {
        return static_cast<int>(cudaSuccess);
    }
    StwoIpcExchangeImport *imported =
        static_cast<StwoIpcExchangeImport *>(handle);
    int result = static_cast<int>(cuCtxPushCurrent(imported->identity.driver_context));
    if (result == static_cast<int>(CUDA_SUCCESS)) {
        result = static_cast<int>(cuCtxSynchronize());
        if (result == static_cast<int>(CUDA_SUCCESS)) {
            result = cleanup_import(imported);
        }
        CUcontext popped = nullptr;
        CUresult pop_result = cuCtxPopCurrent(&popped);
        if (result == static_cast<int>(CUDA_SUCCESS)) {
            result = static_cast<int>(pop_result);
        }
        if (pop_result == CUDA_SUCCESS && popped != imported->identity.driver_context &&
            result == static_cast<int>(CUDA_SUCCESS)) {
            result = static_cast<int>(CUDA_ERROR_INVALID_CONTEXT);
        }
    }
    if (result == static_cast<int>(CUDA_SUCCESS)) {
        delete imported;
    }
    return result;
}
