// M8 GPU-native driver: peer exchange, slab fills, device flag checks and
// timing events (design/riscv-proving-stack/rv64-m8-gpu-native.md §3.4-§3.6).
//
// Additive to libstwo-rv64-jobs.so: the Zig side looks these symbols up only
// when the GPU-native driver is installed (ops.zig Peer.open), so the ABI
// version and every existing caller are unchanged. Every function only
// enqueues work or manages a handle; none blocks the host (the elapsed-time
// query reads two events the caller already waited past).
#include <cuda_runtime_api.h>
#include <stdint.h>
#include <stddef.h>

namespace {
inline int status(cudaError_t s) { return static_cast<int>(s); }

__global__ void fill_u32(uint32_t *dst, uint32_t value, size_t words) {
    for (size_t i = blockIdx.x * static_cast<size_t>(blockDim.x) + threadIdx.x; i < words; i += static_cast<size_t>(gridDim.x) * blockDim.x)
        dst[i] = value;
}

// One verdict word from `count` flag words: accepted (0) when every flag
// equals `expected` (the request's Exchange.flagTag: replicas are never zeroed
// per request, so a stale flag of an earlier request carries another tag),
// else reject_code with the low half = 1 + index of the first unset flag
// (capped at 0xffff). One block; the flag table is < 64 words per request.
__global__ void flags_verdict(const uint32_t *flags, uint32_t count, uint32_t expected, uint32_t *verdict, uint32_t reject_code) {
    __shared__ uint32_t first;
    if (threadIdx.x == 0) first = 0xffffffffu;
    __syncthreads();
    for (uint32_t i = threadIdx.x; i < count; i += blockDim.x)
        if (flags[i] != expected) atomicMin(&first, i);
    __syncthreads();
    if (threadIdx.x == 0) {
        if (first == 0xffffffffu) {
            *verdict = 0u;
        } else {
            const uint32_t detail = first + 1u > 0xffffu ? 0xffffu : first + 1u;
            *verdict = (reject_code & 0xffff0000u) | detail;
        }
    }
}
}  // namespace

// Enable peer access both ways between every pair of `devices` (install time,
// any thread). `*direct` := 1 when every pair maps the other's memory, else 0
// (e.g. RTX 5090 pairs behind a chipset that refuses P2P: nvidia-smi topo
// -p2p r shows CNS on the M8 pod [M]). Peer COPIES work either way
// (cudaMemcpyPeerAsync stages through the host without peer access); only
// direct peer pointer dereference needs `direct`. Already-enabled pairs are
// not an error.
extern "C" int stwo_rv64_jobs_peer_enable(const uint32_t *devices, uint32_t count, uint32_t *direct) {
    if ((devices == nullptr && count != 0) || direct == nullptr) return status(cudaErrorInvalidValue);
    *direct = 1u;
    int previous = 0;
    cudaError_t s = cudaGetDevice(&previous);
    if (s != cudaSuccess) return status(s);
    for (uint32_t i = 0; i < count && s == cudaSuccess; ++i) {
        for (uint32_t j = 0; j < count && s == cudaSuccess; ++j) {
            if (i == j) continue;
            int can = 0;
            s = cudaDeviceCanAccessPeer(&can, static_cast<int>(devices[i]), static_cast<int>(devices[j]));
            if (s != cudaSuccess) break;
            if (!can) {
                *direct = 0u;
                continue;
            }
            s = cudaSetDevice(static_cast<int>(devices[i]));
            if (s != cudaSuccess) break;
            s = cudaDeviceEnablePeerAccess(static_cast<int>(devices[j]), 0);
            if (s == cudaErrorPeerAccessAlreadyEnabled) {
                (void)cudaGetLastError();
                s = cudaSuccess;
            }
        }
    }
    const cudaError_t r = cudaSetDevice(previous);
    return status(s != cudaSuccess ? s : r);
}

// Async peer copy on the SOURCE device's stream (the producer's exec stream).
extern "C" int stwo_rv64_jobs_peer_copy_async(void *dst, uint32_t dst_device, const void *src, uint32_t src_device, size_t bytes, void *stream) {
    if (bytes == 0) return 0;
    if (dst == nullptr || src == nullptr || stream == nullptr) return status(cudaErrorInvalidValue);
    return status(cudaMemcpyPeerAsync(dst, static_cast<int>(dst_device), src, static_cast<int>(src_device), bytes, static_cast<cudaStream_t>(stream)));
}

// dst[0..words) = value on `stream` (slab unset memset, exchange reset, flags).
extern "C" int stwo_rv64_jobs_fill_u32(uint32_t *dst, uint32_t value, size_t words, void *stream) {
    if (words == 0) return 0;
    if (dst == nullptr || stream == nullptr) return status(cudaErrorInvalidValue);
    const unsigned threads = 256;
    size_t blocks = (words + threads - 1) / threads;
    if (blocks > 1024) blocks = 1024;
    fill_u32<<<static_cast<unsigned>(blocks), threads, 0, static_cast<cudaStream_t>(stream)>>>(dst, value, words);
    return status(cudaGetLastError());
}

// Check.exchange_complete (and any "every flag set" check) as a device kernel.
// (Renamed from stwo_rv64_jobs_flags_verdict when `expected` was added, so a
// stale addon fails the symbol lookup instead of mis-reading arguments.)
extern "C" int stwo_rv64_jobs_flags_verdict_tag(const uint32_t *flags, uint32_t count, uint32_t expected, uint32_t *verdict, uint32_t reject_code, void *stream) {
    if (flags == nullptr || verdict == nullptr || stream == nullptr) return status(cudaErrorInvalidValue);
    flags_verdict<<<1, 64, 0, static_cast<cudaStream_t>(stream)>>>(flags, count, expected, verdict, reject_code);
    return status(cudaGetLastError());
}

// Timing events (CUDA-event GPU time of a request's device span; the request's
// single wait happens before the elapsed query).
extern "C" int stwo_rv64_jobs_event_create_timed(void **out) {
    if (out == nullptr) return status(cudaErrorInvalidValue);
    cudaEvent_t event = nullptr;
    const cudaError_t s = cudaEventCreateWithFlags(&event, cudaEventBlockingSync);
    *out = s == cudaSuccess ? event : nullptr;
    return status(s);
}

extern "C" int stwo_rv64_jobs_event_elapsed_us(void *start, void *end, uint64_t *out_us) {
    if (start == nullptr || end == nullptr || out_us == nullptr) return status(cudaErrorInvalidValue);
    float ms = 0.0f;
    const cudaError_t s = cudaEventElapsedTime(&ms, static_cast<cudaEvent_t>(start), static_cast<cudaEvent_t>(end));
    *out_us = s == cudaSuccess ? static_cast<uint64_t>(ms * 1000.0f) : 0;
    return status(s);
}
