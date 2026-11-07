// M9 proof-params (stream m9-proof-params): PoW grind cost per bit on one GPU.
//
// Times the production grind (stwo_blake2s_pow_persistent_on, search.cu as built: one atomic read
// of the shared best nonce per candidate) against an engineered variant that reads the best nonce
// once per 64 candidates, at pow_bits 16..30 over several transcript seeds. Both must return the
// same minimal nonce (the protocol's exact minimum-nonce rule). Standalone:
//   nvcc -O3 -std=c++17 -arch=sm_120 -I src/backends/cuda/native/pow \
//        src/backends/cuda/native/pow/bench/m9_pow_bench.cu -o /tmp/m9_pow_bench
//   ./m9_pow_bench [max_bits=28] [seeds=4]
// Output: one JSON line per (variant, bits): mean ms per grind, candidates/s, nonce parity.
#include "../search.cu"

#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

namespace m9 {
using namespace stwo::cuda::pow;
constexpr uint32_t kCheckEvery = 64;

__global__ __launch_bounds__(kThreads, kMinimumBlocksPerMultiprocessor)
void search_batched(const uint32_t *prefix_digest, uint32_t pow_bits, unsigned long long search_end,
                    unsigned long long *best_nonce) {
    __shared__ Prefix prefix;
    if (threadIdx.x < 8) prefix.words[threadIdx.x] = prefix_digest[threadIdx.x];
    __syncthreads();
    const unsigned long long worker = static_cast<unsigned long long>(blockIdx.x) * blockDim.x + threadIdx.x;
    const unsigned long long stride = static_cast<unsigned long long>(gridDim.x) * blockDim.x;
    unsigned long long index = worker;
    unsigned long long current_best = ~0ull;
    uint32_t since = kCheckEvery;
    while (index < search_end) {
        if (since == kCheckEvery) {  // a stale bound only costs extra hashes; it never changes the minimum
            current_best = *reinterpret_cast<volatile unsigned long long *>(best_nonce);
            since = 0;
        }
        ++since;
        const unsigned long long candidate = index_to_nonce(index);
        if (candidate >= current_best) break;  // index_to_nonce is monotone in index
        const uint32_t word = candidate_hash_word(prefix, candidate);
        if (trailing_zeros(word) >= pow_bits) {
            atomicMin(best_nonce, candidate);
            current_best = candidate;
        }
        if (stride >= search_end - index) break;
        index += stride;
    }
}

__global__ void reset(unsigned long long *best) { *best = ~0ull; }
}  // namespace m9

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); exit(1); } } while (0)

int main(int argc, char **argv) {
    const uint32_t max_bits = argc > 1 ? atoi(argv[1]) : 28;
    const uint32_t seeds = argc > 2 ? atoi(argv[2]) : 4;
    cudaDeviceProp prop; CK(cudaGetDeviceProperties(&prop, 0));
    printf("{\"device\":\"%s\",\"sms\":%d}\n", prop.name, prop.multiProcessorCount);
    uint32_t *state, *prefix, *completed, *tnonce; unsigned long long *best;
    CK(cudaMalloc(&state, 16 * 4)); CK(cudaMalloc(&prefix, 8 * 4)); CK(cudaMalloc(&completed, 4));
    CK(cudaMalloc(&tnonce, 8)); CK(cudaMalloc(&best, 8));
    cudaStream_t s; CK(cudaStreamCreate(&s));
    cudaEvent_t e0, e1; CK(cudaEventCreate(&e0)); CK(cudaEventCreate(&e1));
    const unsigned long long end = stwo::cuda::pow::kIndexLimit;
    for (uint32_t bits = 16; bits <= max_bits; bits += 2) {
        double ms_ref = 0, ms_new = 0; int mismatches = 0; double expect_cands = 0;
        for (uint32_t seed = 0; seed < seeds; ++seed) {
            uint32_t host_state[16] = {0};
            for (int i = 0; i < 8; ++i) host_state[i] = 0x9e3779b9u * (seed * 8 + i + 1) ^ (bits << 24);
            CK(cudaMemcpy(state, host_state, sizeof(host_state), cudaMemcpyHostToDevice));
            // as built (includes init + prefix kernels, exactly what the prover launches)
            CK(cudaEventRecord(e0, s));
            CK(static_cast<cudaError_t>(stwo_blake2s_pow_persistent_on(state, bits, end, prefix, best, completed, tnonce, s)));
            CK(cudaEventRecord(e1, s)); CK(cudaEventSynchronize(e1));
            float t; CK(cudaEventElapsedTime(&t, e0, e1)); ms_ref += t;
            unsigned long long ref; CK(cudaMemcpy(&ref, best, 8, cudaMemcpyDeviceToHost));
            // engineered (prefix digest already computed by the as-built call above for this state)
            CK(cudaEventRecord(e0, s));
            m9::reset<<<1, 1, 0, s>>>(best);
            m9::search_batched<<<stwo::cuda::pow::kBlocks, stwo::cuda::pow::kThreads, 0, s>>>(prefix, bits, end, best);
            CK(cudaEventRecord(e1, s)); CK(cudaEventSynchronize(e1)); CK(cudaGetLastError());
            CK(cudaEventElapsedTime(&t, e0, e1)); ms_new += t;
            unsigned long long got; CK(cudaMemcpy(&got, best, 8, cudaMemcpyDeviceToHost));
            if (got != ref) ++mismatches;
            // candidates actually needed = index of the winning nonce + 1 (index lattice: hi << 20 | lo)
            expect_cands += static_cast<double>(((ref >> 32) << 20) | (ref & 0xfffffull)) + 1.0;
        }
        const double cands = expect_cands / seeds + 262144.0;  // + one grid of overshoot
        printf("{\"variant\":\"as_built\",\"pow_bits\":%u,\"ms_per_grind\":%.4f,\"gcands_per_s\":%.3f}\n", bits, ms_ref / seeds, cands / (ms_ref / seeds) * 1e-6);
        printf("{\"variant\":\"check_every_64\",\"pow_bits\":%u,\"ms_per_grind\":%.4f,\"gcands_per_s\":%.3f,\"nonce_mismatches\":%d,\"seeds\":%u}\n", bits, ms_new / seeds, cands / (ms_new / seeds) * 1e-6, mismatches, seeds);
        fflush(stdout);
    }
    cudaFree(state); cudaFree(prefix); cudaFree(completed); cudaFree(tnonce); cudaFree(best);
    return 0;
}
