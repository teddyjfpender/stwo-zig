// Deterministic bounded Blake2s PoW search over Stwo's SIMD nonce lattice.

#include "candidate.cuh"
#include "safety.cuh"

#include <cuda_runtime_api.h>

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::pow {

constexpr uint32_t kLowBits = 20;
constexpr unsigned long long kLowMask = (1ull << kLowBits) - 1ull;
constexpr unsigned long long kIndexLimit =
    static_cast<unsigned long long>(0x7fffffffu) << kLowBits;
constexpr uint32_t kThreads = 256;
constexpr uint32_t kBlocks = 1024;
constexpr uint32_t kMinimumBlocksPerMultiprocessor = 6;

__device__ __forceinline__ unsigned long long index_to_nonce(
    unsigned long long index) {
    return ((index >> kLowBits) << 32) | (index & kLowMask);
}

__global__ void initialize_kernel(
    unsigned long long *best_nonce,
    uint32_t *completed_blocks,
    uint32_t *transcript_nonce) {
    if (blockIdx.x == 0 && threadIdx.x == 0) {
        *best_nonce = ~0ull;
        *completed_blocks = 0;
        transcript_nonce[0] = UINT32_MAX;
        transcript_nonce[1] = UINT32_MAX;
    }
}

__global__ void prefix_kernel(
    const uint32_t *transcript_state,
    uint32_t pow_bits,
    uint32_t *prefix_digest) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    const blake2s::Hash value =
        transcript::pow_prefix(transcript_state, pow_bits);
#pragma unroll
    for (uint32_t word = 0; word < 8; ++word) {
        prefix_digest[word] = value.words[word];
    }
}

__global__ __launch_bounds__(
    kThreads,
    kMinimumBlocksPerMultiprocessor)
void search_kernel(
    const uint32_t *prefix_digest,
    uint32_t pow_bits,
    unsigned long long search_end,
    unsigned long long *best_nonce,
    uint32_t *completed_blocks,
    uint32_t *transcript_nonce) {
    __shared__ Prefix prefix;
    if (threadIdx.x < 8) {
        prefix.words[threadIdx.x] = prefix_digest[threadIdx.x];
    }
    __syncthreads();

    const unsigned long long worker =
        static_cast<unsigned long long>(blockIdx.x) * blockDim.x +
        threadIdx.x;
    const unsigned long long stride =
        static_cast<unsigned long long>(gridDim.x) * blockDim.x;
    unsigned long long index = worker;
    while (index < search_end) {
        const unsigned long long candidate = index_to_nonce(index);
        const unsigned long long current_best = atomicAdd(best_nonce, 0ull);
        if (candidate >= current_best) break;
        if (trailing_zeros(candidate_hash_word(prefix, candidate)) >= pow_bits) {
            atomicMin(best_nonce, candidate);
        }
        if (stride >= search_end - index) break;
        index += stride;
    }

    __syncthreads();
    if (threadIdx.x == 0) {
        __threadfence();
        const uint32_t completed = atomicAdd(completed_blocks, 1u) + 1u;
        if (completed == gridDim.x) {
            const unsigned long long nonce = atomicAdd(best_nonce, 0ull);
            transcript_nonce[0] = static_cast<uint32_t>(nonce);
            transcript_nonce[1] = static_cast<uint32_t>(nonce >> 32);
            __threadfence();
        }
    }
}

inline bool valid_workspace(
    const uint32_t *transcript_state,
    uint32_t *prefix_digest,
    unsigned long long *best_nonce,
    uint32_t *completed_blocks,
    uint32_t *transcript_nonce) {
    if (transcript_state == nullptr || prefix_digest == nullptr ||
        best_nonce == nullptr || completed_blocks == nullptr ||
        transcript_nonce == nullptr ||
        reinterpret_cast<uintptr_t>(best_nonce) % alignof(uint64_t) != 0) {
        return false;
    }
    const void *pointers[5] = {
        transcript_state,
        prefix_digest,
        best_nonce,
        completed_blocks,
        transcript_nonce,
    };
    const size_t sizes[5] = {
        16 * sizeof(uint32_t),
        8 * sizeof(uint32_t),
        sizeof(uint64_t),
        sizeof(uint32_t),
        2 * sizeof(uint32_t),
    };
    return all_disjoint(pointers, sizes);
}

}  // namespace stwo::cuda::pow

extern "C" int stwo_blake2s_pow_persistent_on(
    const uint32_t *transcript_state,
    uint32_t pow_bits,
    unsigned long long search_end,
    uint32_t *prefix_digest,
    unsigned long long *best_nonce,
    uint32_t *completed_blocks,
    uint32_t *transcript_nonce,
    void *stream) {
    if (pow_bits > 32 || search_end == 0 ||
        search_end > stwo::cuda::pow::kIndexLimit || stream == nullptr ||
        !stwo::cuda::pow::valid_workspace(
            transcript_state, prefix_digest, best_nonce, completed_blocks,
            transcript_nonce)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    const cudaStream_t proof_stream = reinterpret_cast<cudaStream_t>(stream);
    stwo::cuda::pow::initialize_kernel<<<1, 1, 0, proof_stream>>>(
        best_nonce, completed_blocks, transcript_nonce);
    cudaError_t status = cudaPeekAtLastError();
    if (status != cudaSuccess) return static_cast<int>(status);

    stwo::cuda::pow::prefix_kernel<<<1, 1, 0, proof_stream>>>(
        transcript_state, pow_bits, prefix_digest);
    status = cudaPeekAtLastError();
    if (status != cudaSuccess) return static_cast<int>(status);

    stwo::cuda::pow::search_kernel<<<
        stwo::cuda::pow::kBlocks,
        stwo::cuda::pow::kThreads,
        0,
        proof_stream>>>(
            prefix_digest, pow_bits, search_end, best_nonce, completed_blocks,
            transcript_nonce);
    return static_cast<int>(cudaPeekAtLastError());
}
