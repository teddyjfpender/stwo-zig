// Deterministic Blake2s proof-of-work search for the circuit recursion
// channels (design 02-design.md §4.7, §9.2 item 7, milestone M12).
//
// Both `proving_5a7c5ed` channel profiles grind with Rust Stwo's
// `SimdBackend` order: the smallest valid nonce `(hi << 32) | lo`,
// `lo < 2^20`, searched hi-major (`core/channel/blake2s_pow_order.zig`).
// This translation unit reuses the backend's PoW lattice kernel pieces
// (`backends/cuda/native/pow/candidate.cuh`: the fixed 40-byte Blake2s
// compression and `trailing_zeros`) and repeats `pow/search.cu`'s
// NVIDIA search loop (dense index walk, per-thread ascending residue class,
// device atomic minimum). It adds only what the circuit lane needs and the
// authenticated `search.cu` does not have:
//
//  * an M31 output policy. `Blake2sM31Channel` reduces every output word of
//    both the prefix hash and the candidate hash modulo P = 2^31 - 1 before
//    counting trailing zeros. The host passes the (already reduced) prefix
//    from the channel's own `computePowPrefix`; the kernel reduces the
//    candidate's first word. For `pow_bits <= 32` the first word decides the
//    predicate: a zero word has at least 32 trailing zeros on both sides.
//  * a host-supplied prefix, so the circuit prover does not need a resident
//    transcript session. The host computes the prefix with the same code the
//    CPU grind uses, and the engine revalidates every returned nonce.
//
// `search.cu` is left untouched: its bytes are pinned by qualified CUDA
// source snapshots.

// The runtime API first: under the compile-check and emulation shims it also
// supplies the `__device__`-family qualifiers the backend headers use.
#include <cuda_runtime_api.h>

#include "../../../backends/cuda/native/pow/candidate.cuh"

#include <stddef.h>
#include <stdint.h>

namespace stwo::circuit_cuda::grind {

using stwo::cuda::pow::Prefix;
using stwo::cuda::pow::candidate_hash_word;
using stwo::cuda::pow::trailing_zeros;

constexpr uint32_t kLowBits = 20;
constexpr unsigned long long kLowMask = (1ull << kLowBits) - 1ull;
constexpr unsigned long long kIndexLimit =
    static_cast<unsigned long long>(0x7fffffffu) << kLowBits;
constexpr unsigned long long kNoNonce = ~0ull;
constexpr uint32_t kModulus = 0x7fffffffu;
#if !defined(STWO_CIRCUIT_GRIND_HOST_EMULATION)
// `pow/search.cu`'s NVIDIA grid.
constexpr uint32_t kThreads = 256;
constexpr uint32_t kBlocks = 1024;
constexpr uint32_t kMinimumBlocksPerMultiprocessor = 6;
#endif

__device__ __forceinline__ unsigned long long index_to_nonce(
    unsigned long long index) {
    return ((index >> kLowBits) << 32) | (index & kLowMask);
}

// `core/vcs/blake2_hash.zig` `reduceToM31`, one word.
__device__ __forceinline__ uint32_t reduce_m31(uint32_t word) {
    const uint32_t folded = (word & kModulus) + (word >> 31);
    return folded >= kModulus ? folded - kModulus : folded;
}

template <bool kM31Output>
__device__ __forceinline__ bool candidate_valid(
    const Prefix &prefix,
    unsigned long long nonce,
    uint32_t pow_bits) {
    uint32_t word = candidate_hash_word(prefix, nonce);
    if constexpr (kM31Output) word = reduce_m31(word);
    return trailing_zeros(word) >= pow_bits;
}

// One worker's share of the search: the residue class `worker + k * stride`
// of the index space, ascending, stopping at its first hit or once it
// passes the current best. The minimum over every class's first hit is the
// global minimum valid index, whatever the grid shape or scheduling. The
// host emulation (`STWO_CIRCUIT_GRIND_HOST_EMULATION`) runs this exact
// function sequentially over the classes against the CPU grind.
template <bool kM31Output>
__device__ __forceinline__ void scan_residue_class(
    const Prefix &prefix,
    uint32_t pow_bits,
    unsigned long long worker,
    unsigned long long stride,
    unsigned long long search_end,
    unsigned long long *best_nonce) {
    unsigned long long index = worker;
    while (index < search_end) {
        const unsigned long long candidate = index_to_nonce(index);
        if (candidate >= atomicAdd(best_nonce, 0ull)) return;
        if (candidate_valid<kM31Output>(prefix, candidate, pow_bits)) {
            atomicMin(best_nonce, candidate);
            return;
        }
        if (stride >= search_end - index) return;
        index += stride;
    }
}

#if !defined(STWO_CIRCUIT_GRIND_HOST_EMULATION)
__global__ void initialize_kernel(unsigned long long *best_nonce) {
    if (blockIdx.x == 0 && threadIdx.x == 0) *best_nonce = kNoNonce;
}

template <bool kM31Output>
__global__ __launch_bounds__(kThreads, kMinimumBlocksPerMultiprocessor)
void search_kernel(
    const uint32_t *prefix_words,
    uint32_t pow_bits,
    unsigned long long search_end,
    unsigned long long *best_nonce) {
    __shared__ Prefix prefix;
    if (threadIdx.x < 8) prefix.words[threadIdx.x] = prefix_words[threadIdx.x];
    __syncthreads();
    scan_residue_class<kM31Output>(
        prefix,
        pow_bits,
        static_cast<unsigned long long>(blockIdx.x) * blockDim.x + threadIdx.x,
        static_cast<unsigned long long>(gridDim.x) * blockDim.x,
        search_end,
        best_nonce);
}

template <bool kM31Output>
cudaError_t launch(
    const uint32_t *prefix_words,
    uint32_t pow_bits,
    unsigned long long search_end,
    unsigned long long *best_nonce,
    cudaStream_t stream) {
    initialize_kernel<<<1, 1, 0, stream>>>(best_nonce);
    cudaError_t status = cudaPeekAtLastError();
    if (status != cudaSuccess) return status;
    search_kernel<kM31Output><<<kBlocks, kThreads, 0, stream>>>(
        prefix_words, pow_bits, search_end, best_nonce);
    return cudaPeekAtLastError();
}

// Device workspace: the prefix words, then the best nonce (8-byte aligned).
struct Workspace {
    uint32_t prefix[8];
    unsigned long long best_nonce;
};

#endif  // !STWO_CIRCUIT_GRIND_HOST_EMULATION

}  // namespace stwo::circuit_cuda::grind

#if !defined(STWO_CIRCUIT_GRIND_HOST_EMULATION)

// Number of visible CUDA devices; the Zig side fails closed on zero.
extern "C" int stwo_circuit_cuda_device_count(int *count) {
    if (count == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    *count = 0;
    return static_cast<int>(cudaGetDeviceCount(count));
}

// Grinds one canonical nonce. `prefix` is the channel's PoW prefix digest as
// eight little-endian words; `m31_output` selects `Blake2sM31Channel`.
// Writes `~0` to `nonce_out` when no index below `search_end` is valid.
// Synchronous: returns once the nonce is on the host.
extern "C" int stwo_circuit_cuda_blake2s_grind(
    const uint32_t *prefix,
    uint32_t pow_bits,
    uint32_t m31_output,
    unsigned long long search_end,
    unsigned long long *nonce_out) {
    using namespace stwo::circuit_cuda::grind;
    if (prefix == nullptr || nonce_out == nullptr || pow_bits == 0 ||
        pow_bits > 32 || m31_output > 1 || search_end == 0 ||
        search_end > kIndexLimit) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    *nonce_out = kNoNonce;

    cudaStream_t stream = nullptr;
    Workspace *workspace = nullptr;
    unsigned long long best = kNoNonce;
    cudaError_t status =
        cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking);
    if (status != cudaSuccess) return static_cast<int>(status);
    status = cudaMalloc(reinterpret_cast<void **>(&workspace), sizeof(Workspace));
    if (status == cudaSuccess) {
        status = cudaMemcpyAsync(
            workspace->prefix, prefix, sizeof(workspace->prefix),
            cudaMemcpyHostToDevice, stream);
    }
    if (status == cudaSuccess) {
        status = m31_output != 0
            ? launch<true>(workspace->prefix, pow_bits, search_end,
                           &workspace->best_nonce, stream)
            : launch<false>(workspace->prefix, pow_bits, search_end,
                            &workspace->best_nonce, stream);
    }
    if (status == cudaSuccess) {
        status = cudaMemcpyAsync(
            &best, &workspace->best_nonce, sizeof(best),
            cudaMemcpyDeviceToHost, stream);
    }
    if (status == cudaSuccess) status = cudaStreamSynchronize(stream);
    if (status == cudaSuccess) *nonce_out = best;

    // Teardown errors surface only when the search itself succeeded.
    if (workspace != nullptr) {
        const cudaError_t freed = cudaFree(workspace);
        if (status == cudaSuccess) status = freed;
    }
    const cudaError_t destroyed = cudaStreamDestroy(stream);
    if (status == cudaSuccess) status = destroyed;
    return static_cast<int>(status);
}
#endif  // !STWO_CIRCUIT_GRIND_HOST_EMULATION

#if defined(STWO_CIRCUIT_GRIND_HOST_EMULATION)
// Host emulation of the device search for hosts without a GPU: the kernel's
// own predicate and residue-class scan, run on the CPU over `workers`
// classes in order (a stand-in for `kBlocks * kThreads` concurrent threads;
// the result does not depend on the class count). Same contract as
// `stwo_circuit_cuda_blake2s_grind`; returns 0 or 1 (invalid argument).
extern "C" int stwo_circuit_cuda_grind_emulate(
    const uint32_t *prefix,
    uint32_t pow_bits,
    uint32_t m31_output,
    unsigned long long search_end,
    unsigned long long workers,
    unsigned long long *nonce_out) {
    using namespace stwo::circuit_cuda::grind;
    if (prefix == nullptr || nonce_out == nullptr || pow_bits == 0 ||
        pow_bits > 32 || m31_output > 1 || search_end == 0 ||
        search_end > kIndexLimit || workers == 0) {
        return 1;
    }
    Prefix words;
    for (uint32_t word = 0; word < 8; ++word) words.words[word] = prefix[word];
    unsigned long long best = kNoNonce;
    for (unsigned long long worker = 0; worker < workers; ++worker) {
        if (m31_output != 0) {
            scan_residue_class<true>(words, pow_bits, worker, workers, search_end, &best);
        } else {
            scan_residue_class<false>(words, pow_bits, worker, workers, search_end, &best);
        }
    }
    *nonce_out = best;
    return 0;
}
#endif
