// M8 job runtime addon (libstwo-rv64-jobs.so): the few stream/event/host-fn
// primitives the frozen base image does not export with an explicit stream.
// Linked against the base image; never rebuilds it. Every function except the
// fenced host wait only enqueues work or manages a handle.
//
// Handles are driver objects (CUstream/CUevent), so a stream created here and
// the base image's exec-context lanes interoperate within one process.
#include <cuda_runtime_api.h>
#include <stdint.h>
#include <stddef.h>

#define STWO_RV64_JOBS_ABI_VERSION 2u  // 2: + stwo_rv64_jobs_channel_draw_raw_on (channel_ops.cu)

namespace {
inline int status(cudaError_t s) { return static_cast<int>(s); }
}  // namespace

extern "C" uint32_t stwo_rv64_jobs_abi_version(void) { return STWO_RV64_JOBS_ABI_VERSION; }

// Non-blocking h2d stream on `device`, called first on the worker thread
// (after the exec context is created there).
extern "C" int stwo_rv64_jobs_stream_create(uint32_t device, void **out) {
    if (out == nullptr) return status(cudaErrorInvalidValue);
    *out = nullptr;
    // This addon links its own static cudart, whose per-thread current device
    // is independent of the base image's: select the worker's device here so
    // the events created next on this thread belong to the same device.
    cudaError_t s = cudaSetDevice(static_cast<int>(device));
    cudaStream_t stream = nullptr;
    if (s == cudaSuccess) s = cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking);
    if (s == cudaSuccess) *out = stream;
    return status(s);
}

extern "C" int stwo_rv64_jobs_stream_destroy(void *stream) {
    if (stream == nullptr) return status(cudaErrorInvalidValue);
    return status(cudaStreamDestroy(static_cast<cudaStream_t>(stream)));
}

extern "C" int stwo_rv64_jobs_event_create(void **out) {
    if (out == nullptr) return status(cudaErrorInvalidValue);
    cudaEvent_t event = nullptr;
    // Blocking-sync events: the worker's single wait sleeps instead of spinning.
    const cudaError_t s = cudaEventCreateWithFlags(&event, cudaEventDisableTiming | cudaEventBlockingSync);
    *out = s == cudaSuccess ? event : nullptr;
    return status(s);
}

extern "C" int stwo_rv64_jobs_event_destroy(void *event) {
    if (event == nullptr) return status(cudaErrorInvalidValue);
    return status(cudaEventDestroy(static_cast<cudaEvent_t>(event)));
}

extern "C" int stwo_rv64_jobs_event_record(void *event, void *stream) {
    if (event == nullptr || stream == nullptr) return status(cudaErrorInvalidValue);
    return status(cudaEventRecord(static_cast<cudaEvent_t>(event), static_cast<cudaStream_t>(stream)));
}

// Device-side ordering only: `stream` waits for `event`; the host never blocks.
extern "C" int stwo_rv64_jobs_stream_wait(void *stream, void *event) {
    if (event == nullptr || stream == nullptr) return status(cudaErrorInvalidValue);
    return status(cudaStreamWaitEvent(static_cast<cudaStream_t>(stream), static_cast<cudaEvent_t>(event), 0));
}

// lint:host-wait-begin — the worker's one host wait per job.
extern "C" int stwo_rv64_jobs_event_wait_host(void *event) {
    if (event == nullptr) return status(cudaErrorInvalidValue);
    return status(cudaEventSynchronize(static_cast<cudaEvent_t>(event)));
}
// lint:host-wait-end

// Explicit-stream async copy: kind 1 = h2d, 2 = d2h (into pinned), 3 = d2d.
extern "C" int stwo_rv64_jobs_copy_async(void *dst, const void *src, size_t bytes, uint32_t kind, void *stream) {
    if (dst == nullptr || src == nullptr || bytes == 0 || stream == nullptr) return status(cudaErrorInvalidValue);
    cudaMemcpyKind k;
    switch (kind) {
        case 1: k = cudaMemcpyHostToDevice; break;
        case 2: k = cudaMemcpyDeviceToHost; break;
        case 3: k = cudaMemcpyDeviceToDevice; break;
        default: return status(cudaErrorInvalidValue);
    }
    return status(cudaMemcpyAsync(dst, src, bytes, k, static_cast<cudaStream_t>(stream)));
}

// cudaLaunchHostFunc: `fn` runs on a driver thread after prior stream work; it
// must not call CUDA (CUDA rule) and touches pinned memory only (job rule).
extern "C" int stwo_rv64_jobs_host_fn(void *stream, void (*fn)(void *), void *user) {
    if (stream == nullptr || fn == nullptr) return status(cudaErrorInvalidValue);
    return status(cudaLaunchHostFunc(static_cast<cudaStream_t>(stream), fn, user));
}

// Portable pinned host memory for the worker's three pipeline slots.
extern "C" int stwo_rv64_jobs_host_alloc(size_t bytes, void **out) {
    if (out == nullptr || bytes == 0) return status(cudaErrorInvalidValue);
    *out = nullptr;
    return status(cudaHostAlloc(out, bytes, cudaHostAllocPortable));
}

extern "C" int stwo_rv64_jobs_host_free(void *pointer) {
    if (pointer == nullptr) return status(cudaErrorInvalidValue);
    return status(cudaFreeHost(pointer));
}
