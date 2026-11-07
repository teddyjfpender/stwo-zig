// M9 review: single-thread transcript-mix microbenchmark (default-off
// STWO_RV64_M9_POSEIDON2_LEAVES integration cost). The production device
// channel (native/rv64/channel.cu channel_mix) runs <<<1,1>>> and hashes
// digest || words with Blake2s (transcript::hash_digest_and_words). Moving the
// channel to Poseidon2 (design doc §8 step 5) makes that serial chain a
// single-thread P2 sponge over the same words. This measures both, chained so
// each call depends on the previous digest, with CUDA events.
// Build (pod), N=src/backends/cuda/native:
//   nvcc -O3 -std=c++17 -arch=sm_120 -I $N -I $N/commitment \
//     tests/cuda/rv64/m9_poseidon2/m9_p2_serial_mix.cu -o m9mix
// Run: m9mix ITERS COUNT...   (prints one MIX json line per COUNT)
#include "transcript/state.cuh"
#include "rv64/poseidon2_m31_register.cuh"

#include <cuda_runtime.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

#define CU(x) do { auto e_ = (x); if (e_ != cudaSuccess) throw std::runtime_error(std::string(#x) + ": " + cudaGetErrorString(cudaError_t(e_))); } while (0)

namespace t = stwo::cuda::transcript;
namespace R = stwo::cuda::p2m31_register;

__global__ void fill(uint32_t* w, uint32_t n) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) w[i] = (i * 2654435761u) & 0x3fffffffu;  // canonical
}

// Blake2s: exactly channel_mix's digest update, `iters` dependent calls.
__global__ void blake_mix(uint32_t* digest, const uint32_t* words, uint32_t count, uint32_t iters) {
    uint32_t d[8];
    for (uint32_t i = 0; i < 8; ++i) d[i] = digest[i];
    for (uint32_t it = 0; it < iters; ++it) {
        const auto h = t::hash_digest_and_words(d, words, count);
        for (uint32_t i = 0; i < 8; ++i) d[i] = h.words[i];
    }
    for (uint32_t i = 0; i < 8; ++i) digest[i] = d[i];
}

// Poseidon2 W24 sponge (M7 framing: rate 12, cap22 version, cap23 domain
// mix_felts = 4, additive absorb, 1-marker, 9-limb digest) over digest || words.
__device__ __forceinline__ void absorb(uint32_t* s, uint32_t& at, uint32_t v) {
#pragma unroll
    for (uint32_t i = 0; i < 12; ++i) if (i == at) s[i] = R::add(s[i], v);
    if (++at == 12) { R::permute(s); at = 0; }
}
__global__ void p2_mix(uint32_t* digest, const uint32_t* words, uint32_t count, uint32_t iters) {
    uint32_t d[9];
    for (uint32_t i = 0; i < 9; ++i) d[i] = digest[i] & 0x3fffffffu;
    for (uint32_t it = 0; it < iters; ++it) {
        uint32_t s[24] = {};
        s[22] = 1; s[23] = 4;
        uint32_t at = 0;
        for (uint32_t i = 0; i < 9; ++i) absorb(s, at, d[i]);
        for (uint32_t i = 0; i < count; ++i) absorb(s, at, words[i]);
#pragma unroll
        for (uint32_t i = 0; i < 12; ++i) if (i == at) s[i] = R::add(s[i], 1u);
        R::permute(s);
        for (uint32_t i = 0; i < 9; ++i) d[i] = s[i];
    }
    for (uint32_t i = 0; i < 9; ++i) digest[i] = d[i];
}

int main(int argc, char** argv) {
    try {
        if (argc < 3) { std::fprintf(stderr, "usage: m9mix ITERS COUNT...\n"); return 2; }
        const uint32_t iters = uint32_t(std::atoi(argv[1]));
        uint32_t max_count = 0;
        for (int i = 2; i < argc; ++i) max_count = std::max<uint32_t>(max_count, uint32_t(std::atoi(argv[i])));
        uint32_t *words = nullptr, *digest = nullptr;
        CU(cudaMalloc(&words, std::max<uint32_t>(max_count, 1) * 4));
        CU(cudaMalloc(&digest, 64));
        CU(cudaMemset(digest, 0, 64));
        fill<<<(max_count + 255) / 256, 256>>>(words, max_count);
        CU(cudaDeviceSynchronize());
        cudaEvent_t a, b; CU(cudaEventCreate(&a)); CU(cudaEventCreate(&b));
        auto time = [&](auto launch) {
            std::vector<float> v;
            for (int r = 0; r < 6; ++r) {  // first is warm-up
                CU(cudaEventRecord(a)); launch(); CU(cudaEventRecord(b)); CU(cudaEventSynchronize(b));
                float ms; CU(cudaEventElapsedTime(&ms, a, b)); if (r) v.push_back(ms);
            }
            std::sort(v.begin(), v.end());
            return v[v.size() / 2];
        };
        cudaDeviceProp prop; CU(cudaGetDeviceProperties(&prop, 0));
        for (int i = 2; i < argc; ++i) {
            const uint32_t count = uint32_t(std::atoi(argv[i]));
            const float bms = time([&] { blake_mix<<<1, 1>>>(digest, words, count, iters); });
            const float pms = time([&] { p2_mix<<<1, 1>>>(digest, words, count, iters); });
            CU(cudaGetLastError());
            const uint64_t bcomp = (8ull + count - 1) / 16 + 1, pperm = (9ull + count) / 12 + 1;
            std::printf("MIX {\"device\":\"%s\",\"count\":%u,\"iters\":%u,\"blake_us_per_mix\":%.3f,\"p2_us_per_mix\":%.3f,\"ratio\":%.2f,"
                        "\"blake_compressions\":%llu,\"p2_perms\":%llu,\"blake_us_per_comp\":%.3f,\"p2_us_per_perm\":%.3f}\n",
                        prop.name, count, iters, 1e3 * bms / iters, 1e3 * pms / iters, pms / bms,
                        (unsigned long long)bcomp, (unsigned long long)pperm, 1e3 * bms / iters / bcomp, 1e3 * pms / iters / pperm);
        }
        CU(cudaEventDestroy(a)); CU(cudaEventDestroy(b));
        CU(cudaFree(words)); CU(cudaFree(digest));
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL %s\n", e.what());
        return 1;
    }
}
