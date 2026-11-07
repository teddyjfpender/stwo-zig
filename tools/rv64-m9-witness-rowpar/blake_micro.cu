// Microbenchmark (CUDA events): latency of ONE chained Blake2s compression
// sequence in a single thread vs a 4-lane quad, with/without the 328 output
// stores the recursion MAIN needs. Not a parity test (see bench.cu).
//   nvcc -O3 -std=c++17 -arch=sm_120 blake_micro.cu -o blake_micro
#include <cstdio>
#include <cstdint>
#include <cuda_runtime.h>
__device__ __forceinline__ uint32_t ror(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
__device__ __forceinline__ void g(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t f0, uint32_t f1) {
    a = a + b + f0; d = ror(d ^ a, 16); c += d; b = ror(b ^ c, 12);
    a = a + b + f1; d = ror(d ^ a, 8); c += d; b = ror(b ^ c, 7);
}
template <int R, int I> struct Sig;
#define S(R, ...) template <int I> struct Sig<R, I> { static constexpr int v[16] = {__VA_ARGS__}; static constexpr int value = v[I]; };
S(0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15) S(1, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
S(2, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4) S(3, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8)
S(4, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13) S(5, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9)
S(6, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11) S(7, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10)
S(8, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5) S(9, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0)
#undef S
__device__ __forceinline__ void put(uint4* out, uint32_t i, uint32_t w) { out[i] = make_uint4(w & 65535u, w >> 16, 0u, 0u); }
template <bool Store, int R>
__device__ __forceinline__ void round1(uint4* out, uint32_t o, uint32_t (&v)[16], const uint32_t (&m)[16]) {
#define G1(A, B, C, D, I) g(v[A], v[B], v[C], v[D], m[Sig<R, 2 * I>::value], m[Sig<R, 2 * I + 1>::value]); \
    if (Store) { put(out, o + 4 * I, v[A]); put(out, o + 4 * I + 1, v[B]); put(out, o + 4 * I + 2, v[C]); put(out, o + 4 * I + 3, v[D]); }
    G1(0, 4, 8, 12, 0) G1(1, 5, 9, 13, 1) G1(2, 6, 10, 14, 2) G1(3, 7, 11, 15, 3)
    G1(0, 5, 10, 15, 4) G1(1, 6, 11, 12, 5) G1(2, 7, 8, 13, 6) G1(3, 4, 9, 14, 7)
#undef G1
}
template <bool Store>
__global__ void single(uint4* out, uint32_t k, uint32_t seed) {
    uint32_t v[16], m[16], h[8];
    for (int i = 0; i < 8; ++i) h[i] = seed * (i + 1);
    for (int i = 0; i < 16; ++i) m[i] = seed ^ (i * 0x9e3779b9u);
    for (uint32_t c = 0; c < k; ++c) {
        for (int i = 0; i < 8; ++i) { v[i] = h[i]; v[8 + i] = 0x6a09e667u + i; }
        const uint32_t o = c * 328;
        round1<Store, 0>(out, o, v, m); round1<Store, 1>(out, o + 32, v, m); round1<Store, 2>(out, o + 64, v, m);
        round1<Store, 3>(out, o + 96, v, m); round1<Store, 4>(out, o + 128, v, m); round1<Store, 5>(out, o + 160, v, m);
        round1<Store, 6>(out, o + 192, v, m); round1<Store, 7>(out, o + 224, v, m); round1<Store, 8>(out, o + 256, v, m);
        round1<Store, 9>(out, o + 288, v, m);
        for (int i = 0; i < 8; ++i) { h[i] ^= v[i] ^ v[i + 8]; put(out, o + 320 + i, h[i]); m[i] = h[i]; }
    }
}
// Quad: lane j owns column j (a=v[j], b=v[4+j], c=v[8+j], d=v[12+j]);
// diagonals rotate b/c/d across the quad with shuffles.
template <int R, int I> __device__ __forceinline__ uint32_t msel(const uint32_t (&m)[16], int j) {
    const uint32_t x0 = m[Sig<R, 2 * (I + 0)>::value], x1 = m[Sig<R, 2 * (I + 1)>::value], x2 = m[Sig<R, 2 * (I + 2)>::value], x3 = m[Sig<R, 2 * (I + 3)>::value];
    return j == 0 ? x0 : j == 1 ? x1 : j == 2 ? x2 : x3;
}
template <int R, int I> __device__ __forceinline__ uint32_t msel1(const uint32_t (&m)[16], int j) {
    const uint32_t x0 = m[Sig<R, 2 * (I + 0) + 1>::value], x1 = m[Sig<R, 2 * (I + 1) + 1>::value], x2 = m[Sig<R, 2 * (I + 2) + 1>::value], x3 = m[Sig<R, 2 * (I + 3) + 1>::value];
    return j == 0 ? x0 : j == 1 ? x1 : j == 2 ? x2 : x3;
}
template <bool Store, int R>
__device__ __forceinline__ void round4(uint4* out, uint32_t o, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, const uint32_t (&m)[16], int j, unsigned mask, int qb) {
    g(a, b, c, d, msel<R, 0>(m, j), msel1<R, 0>(m, j));
    if (Store) { put(out, o + 4 * j, a); put(out, o + 4 * j + 1, b); put(out, o + 4 * j + 2, c); put(out, o + 4 * j + 3, d); }
    b = __shfl_sync(mask, b, qb + ((j + 1) & 3)); c = __shfl_sync(mask, c, qb + ((j + 2) & 3)); d = __shfl_sync(mask, d, qb + ((j + 3) & 3));
    g(a, b, c, d, msel<R, 4>(m, j), msel1<R, 4>(m, j));
    if (Store) { put(out, o + 16 + 4 * j, a); put(out, o + 16 + 4 * j + 1, b); put(out, o + 16 + 4 * j + 2, c); put(out, o + 16 + 4 * j + 3, d); }
    b = __shfl_sync(mask, b, qb + ((j + 3) & 3)); c = __shfl_sync(mask, c, qb + ((j + 2) & 3)); d = __shfl_sync(mask, d, qb + ((j + 1) & 3));
}
template <bool Store>
__global__ void quad(uint4* out, uint32_t k, uint32_t seed) {
    const int j = threadIdx.x & 3, qb = threadIdx.x & ~3;
    const unsigned mask = 0xfu << qb;
    uint32_t m[16], h0 = seed * (j + 1), h1 = seed * (j + 5);
    for (int i = 0; i < 16; ++i) m[i] = seed ^ (i * 0x9e3779b9u);
    for (uint32_t cc = 0; cc < k; ++cc) {
        uint32_t a = h0, b = h1, c = 0x6a09e667u + j, d = 0x6a09e667u + 4 + j;
        const uint32_t o = cc * 328;
        round4<Store, 0>(out, o, a, b, c, d, m, j, mask, qb); round4<Store, 1>(out, o + 32, a, b, c, d, m, j, mask, qb);
        round4<Store, 2>(out, o + 64, a, b, c, d, m, j, mask, qb); round4<Store, 3>(out, o + 96, a, b, c, d, m, j, mask, qb);
        round4<Store, 4>(out, o + 128, a, b, c, d, m, j, mask, qb); round4<Store, 5>(out, o + 160, a, b, c, d, m, j, mask, qb);
        round4<Store, 6>(out, o + 192, a, b, c, d, m, j, mask, qb); round4<Store, 7>(out, o + 224, a, b, c, d, m, j, mask, qb);
        round4<Store, 8>(out, o + 256, a, b, c, d, m, j, mask, qb); round4<Store, 9>(out, o + 288, a, b, c, d, m, j, mask, qb);
        h0 ^= a ^ c; h1 ^= b ^ d;
        put(out, o + 320 + j, h0); put(out, o + 324 + j, h1);
        // all-gather h into the message (Merkle-style chaining)
        for (int i = 0; i < 4; ++i) { m[i] = __shfl_sync(mask, h0, qb + i); m[4 + i] = __shfl_sync(mask, h1, qb + i); }
    }
}

// Group mode: G lanes compute the SAME compression (SIMT-redundant: same
// instructions, broadcast loads) and split the stores, so one warp store
// instruction writes G consecutive 16-byte outputs (coalesced).
template <int Gl>
__device__ __forceinline__ void putg(uint4* out, uint32_t i, uint32_t w, int lane) { if ((i & (Gl - 1)) == uint32_t(lane)) put(out, i, w); }
template <int Gl, int R>
__device__ __forceinline__ void roundg(uint4* out, uint32_t o, uint32_t (&v)[16], const uint32_t (&m)[16], int lane) {
#define GG(A, B, C, D, I) g(v[A], v[B], v[C], v[D], m[Sig<R, 2 * I>::value], m[Sig<R, 2 * I + 1>::value]); \
    putg<Gl>(out, o + 4 * I, v[A], lane); putg<Gl>(out, o + 4 * I + 1, v[B], lane); putg<Gl>(out, o + 4 * I + 2, v[C], lane); putg<Gl>(out, o + 4 * I + 3, v[D], lane);
    GG(0, 4, 8, 12, 0) GG(1, 5, 9, 13, 1) GG(2, 6, 10, 14, 2) GG(3, 7, 11, 15, 3)
    GG(0, 5, 10, 15, 4) GG(1, 6, 11, 12, 5) GG(2, 7, 8, 13, 6) GG(3, 4, 9, 14, 7)
#undef GG
}
template <int Gl>
__global__ void group(uint4* out, uint32_t k, uint32_t seed) {
    const int lane = threadIdx.x & (Gl - 1);
    uint32_t v[16], m[16], h[8];
    for (int i = 0; i < 8; ++i) h[i] = seed * (i + 1);
    for (int i = 0; i < 16; ++i) m[i] = seed ^ (i * 0x9e3779b9u);
    for (uint32_t c = 0; c < k; ++c) {
        for (int i = 0; i < 8; ++i) { v[i] = h[i]; v[8 + i] = 0x6a09e667u + i; }
        const uint32_t o = c * 328;
        roundg<Gl, 0>(out, o, v, m, lane); roundg<Gl, 1>(out, o + 32, v, m, lane); roundg<Gl, 2>(out, o + 64, v, m, lane);
        roundg<Gl, 3>(out, o + 96, v, m, lane); roundg<Gl, 4>(out, o + 128, v, m, lane); roundg<Gl, 5>(out, o + 160, v, m, lane);
        roundg<Gl, 6>(out, o + 192, v, m, lane); roundg<Gl, 7>(out, o + 224, v, m, lane); roundg<Gl, 8>(out, o + 256, v, m, lane);
        roundg<Gl, 9>(out, o + 288, v, m, lane);
        for (int i = 0; i < 8; ++i) { h[i] ^= v[i] ^ v[i + 8]; putg<Gl>(out, o + 320 + i, h[i], lane); m[i] = h[i]; }
    }
}

// Select form: one store instruction per G (Gl = 4: lane j stores output j)
// or per half round (Gl = 16: lane 4i+j stores G i's output j).
__device__ __forceinline__ uint32_t pick4(uint32_t a, uint32_t b, uint32_t c, uint32_t d, int j) { return j == 0 ? a : j == 1 ? b : j == 2 ? c : d; }
template <int Gl, int R>
__device__ __forceinline__ void rounds(uint4* out, uint32_t o, uint32_t (&v)[16], const uint32_t (&m)[16], int lane) {
    const int j = lane & 3, gi = lane >> 2;
#define GH(A0,B0,C0,D0, A1,B1,C1,D1, A2,B2,C2,D2, A3,B3,C3,D3, I, OFF) \
    g(v[A0], v[B0], v[C0], v[D0], m[Sig<R, 2 * (I + 0)>::value], m[Sig<R, 2 * (I + 0) + 1>::value]); \
    g(v[A1], v[B1], v[C1], v[D1], m[Sig<R, 2 * (I + 1)>::value], m[Sig<R, 2 * (I + 1) + 1>::value]); \
    g(v[A2], v[B2], v[C2], v[D2], m[Sig<R, 2 * (I + 2)>::value], m[Sig<R, 2 * (I + 2) + 1>::value]); \
    g(v[A3], v[B3], v[C3], v[D3], m[Sig<R, 2 * (I + 3)>::value], m[Sig<R, 2 * (I + 3) + 1>::value]); \
    if (Gl == 16) { \
        const uint32_t w0 = pick4(v[A0], v[B0], v[C0], v[D0], j), w1 = pick4(v[A1], v[B1], v[C1], v[D1], j), \
                       w2 = pick4(v[A2], v[B2], v[C2], v[D2], j), w3 = pick4(v[A3], v[B3], v[C3], v[D3], j); \
        put(out, o + OFF + lane, gi == 0 ? w0 : gi == 1 ? w1 : gi == 2 ? w2 : w3); \
    } else { \
        put(out, o + OFF + j, pick4(v[A0], v[B0], v[C0], v[D0], j)); put(out, o + OFF + 4 + j, pick4(v[A1], v[B1], v[C1], v[D1], j)); \
        put(out, o + OFF + 8 + j, pick4(v[A2], v[B2], v[C2], v[D2], j)); put(out, o + OFF + 12 + j, pick4(v[A3], v[B3], v[C3], v[D3], j)); \
    }
    GH(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 0, 0)
    GH(0, 5, 10, 15, 1, 6, 11, 12, 2, 7, 8, 13, 3, 4, 9, 14, 4, 16)
#undef GH
}
template <int Gl>
__global__ void groups(uint4* out, uint32_t k, uint32_t seed) {
    const int lane = threadIdx.x & (Gl - 1);
    uint32_t v[16], m[16], h[8];
    for (int i = 0; i < 8; ++i) h[i] = seed * (i + 1);
    for (int i = 0; i < 16; ++i) m[i] = seed ^ (i * 0x9e3779b9u);
    for (uint32_t c = 0; c < k; ++c) {
        for (int i = 0; i < 8; ++i) { v[i] = h[i]; v[8 + i] = 0x6a09e667u + i; }
        const uint32_t o = c * 328;
        rounds<Gl, 0>(out, o, v, m, lane); rounds<Gl, 1>(out, o + 32, v, m, lane); rounds<Gl, 2>(out, o + 64, v, m, lane);
        rounds<Gl, 3>(out, o + 96, v, m, lane); rounds<Gl, 4>(out, o + 128, v, m, lane); rounds<Gl, 5>(out, o + 160, v, m, lane);
        rounds<Gl, 6>(out, o + 192, v, m, lane); rounds<Gl, 7>(out, o + 224, v, m, lane); rounds<Gl, 8>(out, o + 256, v, m, lane);
        rounds<Gl, 9>(out, o + 288, v, m, lane);
        for (int i = 0; i < 8; ++i) { h[i] ^= v[i] ^ v[i + 8]; m[i] = h[i]; }
        if (lane < 8) put(out, o + 320 + lane, lane == 0 ? h[0] : lane == 1 ? h[1] : lane == 2 ? h[2] : lane == 3 ? h[3] : lane == 4 ? h[4] : lane == 5 ? h[5] : lane == 6 ? h[6] : h[7]);
    }
}
int main() {
    const uint32_t K = 2000;
    uint4* out; cudaMalloc(&out, size_t(K) * 328 * 16 + 4096);
    cudaEvent_t e0, e1; cudaEventCreate(&e0); cudaEventCreate(&e1);
    auto t = [&](auto launch, const char* name) {
        launch(); cudaDeviceSynchronize();
        float best = 1e9;
        for (int r = 0; r < 5; ++r) { cudaEventRecord(e0); launch(); cudaEventRecord(e1); cudaEventSynchronize(e1); float ms; cudaEventElapsedTime(&ms, e0, e1); best = ms < best ? ms : best; }
        std::printf("{\"variant\":\"%s\",\"compressions\":%u,\"us_per_compression\":%.3f}\n", name, K, best * 1000.0 / K);
    };
    t([&] { single<true><<<1, 1>>>(out, K, 7); }, "single_thread_store");
    t([&] { single<false><<<1, 1>>>(out, K, 7); }, "single_thread_nostore");
    t([&] { single<true><<<1, 32>>>(out, K, 7); }, "single_thread_store_x32lanes_same_addr");
    t([&] { quad<true><<<1, 4>>>(out, K, 7); }, "quad_store");
    t([&] { quad<false><<<1, 4>>>(out, K, 7); }, "quad_nostore");
    t([&] { groups<4><<<1, 4>>>(out, K, 7); }, "group4_select_store");
    t([&] { groups<16><<<1, 16>>>(out, K, 7); }, "group16_select_store");
    t([&] { groups<16><<<1, 512>>>(out, K, 7); }, "group16_select_store_x32groups");
    t([&] { group<4><<<1, 4>>>(out, K, 7); }, "group4_split_store");
    t([&] { group<8><<<1, 8>>>(out, K, 7); }, "group8_split_store");
    t([&] { group<16><<<1, 16>>>(out, K, 7); }, "group16_split_store");
    t([&] { group<32><<<1, 32>>>(out, K, 7); }, "group32_split_store");
    t([&] { group<8><<<1, 256>>>(out, K, 7); }, "group8_x32groups_same_target");
    std::printf("{\"error\":\"%s\"}\n", cudaGetErrorString(cudaGetLastError()));
    cudaFree(out);
}
