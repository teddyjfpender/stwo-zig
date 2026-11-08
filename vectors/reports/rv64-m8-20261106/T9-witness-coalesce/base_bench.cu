// T9 parity test + CUDA-event microbenchmark for stwo_circuit_base_witness_on:
// reference generate<Kind> (flag off) vs the T9 variant (flag on, if built).
//   nvcc -O3 -std=c++17 -arch=sm_120 base_bench.cu -I<repo>/src/backends/cuda/native/circuit -o base_bench
//   ./base_bench selftest | bench <component> <log_rows> <log_values> <pattern:0 random,1 local,2 skew> [reps]
#define T9_HAS_VARIANT 1
#include "base_witness.cu"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>
#define CK(x) do { auto _e = (x); if (_e != cudaSuccess) { std::fprintf(stderr, "CUDA %s at %s:%d: %s\n", cudaGetErrorString(cudaError_t(_e)), __FILE__, __LINE__, #x); std::exit(2); } } while (0)
static cudaStream_t g_stream;
static const unsigned kPP[] = {1, 7, 4, 1, 10}, kOut[] = {4, 12, 20, 4, 52};
static size_t count_len(unsigned c) { return c < 2 ? 1u << 16 : c < 18 ? 1u << 20 : c == 18 ? 1u << 8 : c == 19 ? 1u << 14 : c == 20 ? 1u << 18 : 1u << 16; }
struct Case { unsigned comp, log_rows, log_values, pattern, first_perm; std::vector<uint32_t> values; std::vector<std::vector<uint32_t>> pp; };
static uint32_t rotr(uint32_t x, unsigned k) { return (x >> k) | (x << (32 - k)); }
// Values: a pool of 2^log_values words read through pp, plus (comp 2/4) per-row
// derived words so every row satisfies the component's checks (error stays 0
// and every lookup is counted): comp 2 is w3 = w0^w1^w2; comp 4 is Blake G:
// xr16 = rotr16((a+b+m)^d), xr12 = rotr12(b^(c+xr16)), w9 = rotr8(w6^xr16), w7 = rotr7(xr12^w8).
static Case make(unsigned comp, unsigned log_rows, unsigned log_values, unsigned pattern, uint64_t seed) {
    std::mt19937_64 rng(seed);
    Case c{comp, log_rows, log_values, pattern, 0, {}, {}};
    const uint32_t rows = 1u << log_rows, pool = 1u << log_values;
    const uint32_t derived = comp == 2 ? 1 : comp == 4 ? 2 : 0;
    const uint32_t nv = pool + derived * rows;
    c.values.resize(size_t(nv) * 4);
    auto set = [&](uint32_t v, uint32_t w) {
        c.values[4 * v] = comp == 3 ? w : (w & 0xffff); c.values[4 * v + 1] = comp == 3 ? 0 : w >> 16;
        c.values[4 * v + 2] = uint32_t(rng()) & 0xffff; c.values[4 * v + 3] = uint32_t(rng()) & 0xffff;
    };
    auto word = [&](uint32_t v) { return c.values[4 * v] | (c.values[4 * v + 1] << 16); };
    for (uint32_t v = 0; v < pool; ++v) {
        uint32_t w = uint32_t(rng());
        if (pattern == 2 && (rng() & 3)) w &= 0xff;  // skew: mostly small words (hot low bins)
        if (comp == 3) w &= 0x7fffffffu;
        set(v, w);
    }
    c.pp.assign(kPP[comp], std::vector<uint32_t>(rows));
    for (unsigned i = 0; i < kPP[comp]; ++i)
        for (uint32_t r = 0; r < rows; ++r)
            c.pp[i][r] = pattern == 1 ? uint32_t((uint64_t(r) * kPP[comp] + i + (rng() % 64)) % pool) : uint32_t(rng() % pool);
    for (uint32_t r = 0; r < rows; ++r) {
        const uint32_t d0 = pool + derived * r;
        if (comp == 2) {
            set(d0, word(c.pp[0][r]) ^ word(c.pp[1][r]) ^ word(c.pp[2][r]));
            c.pp[3][r] = d0;
        } else if (comp == 4) {
            const uint32_t a = word(c.pp[0][r]), b = word(c.pp[1][r]), cc = word(c.pp[2][r]), d = word(c.pp[3][r]), m = word(c.pp[4][r]);
            const uint32_t xr16 = rotr((a + b + m) ^ d, 16), xr12 = rotr(b ^ (cc + xr16), 12);
            set(d0, rotr(word(c.pp[6][r]) ^ xr16, 8)); c.pp[9][r] = d0;
            set(d0 + 1, rotr(xr12 ^ word(c.pp[8][r]), 7)); c.pp[7][r] = d0 + 1;
        }
    }
    if (comp == 1) c.first_perm = rows / 2;
    return c;
}
struct Out { std::vector<std::vector<uint32_t>> out, counts; uint32_t error; float ms; };
static std::vector<float> g_times;
static Out run(const Case& c, int mode, int reps) {
    const uint32_t rows = 1u << c.log_rows;
    uint32_t *values, *error; CK(cudaMalloc(&values, c.values.size() * 4)); CK(cudaMalloc(&error, 4));
    CK(cudaMemcpy(values, c.values.data(), c.values.size() * 4, cudaMemcpyHostToDevice));
    std::vector<uint32_t*> pp(kPP[c.comp]), out(kOut[c.comp]), counts(22);
    for (unsigned i = 0; i < pp.size(); ++i) { CK(cudaMalloc(&pp[i], rows * 4)); CK(cudaMemcpy(pp[i], c.pp[i].data(), rows * 4, cudaMemcpyHostToDevice)); }
    for (auto& o : out) CK(cudaMalloc(&o, rows * 4));
    for (unsigned i = 0; i < 22; ++i) CK(cudaMalloc(&counts[i], count_len(i) * 4));
#ifdef T9_HAS_VARIANT
    stwo::cuda::circuit_base::base_coalesce = mode;
#else
    if (mode) { std::fprintf(stderr, "no variant built\n"); std::exit(6); }
#endif
    cudaEvent_t e0, e1; CK(cudaEventCreate(&e0)); CK(cudaEventCreate(&e1));
    for (int r = 0; r <= reps; ++r) {
        for (unsigned i = 0; i < 22; ++i) CK(cudaMemsetAsync(counts[i], 0, count_len(i) * 4, g_stream));
        for (auto& o : out) CK(cudaMemsetAsync(o, 0, rows * 4, g_stream));
        CK(cudaMemsetAsync(error, 0, 4, g_stream));
        CK(cudaEventRecord(e0, g_stream));
        const int rc = stwo_circuit_base_witness_on(c.comp, values, uint32_t(c.values.size() / 4), rows, c.first_perm,
            (const uint32_t* const*)pp.data(), pp.size(), out.data(), out.size(), counts.data(), 22, error, g_stream);
        if (rc) { std::fprintf(stderr, "rc=%d\n", rc); std::exit(3); }
        CK(cudaEventRecord(e1, g_stream)); CK(cudaEventSynchronize(e1));
        float ms; CK(cudaEventElapsedTime(&ms, e0, e1));
        if (r) g_times.push_back(ms);
    }
    Out o; o.out.resize(out.size()); o.counts.resize(22);
    for (unsigned i = 0; i < out.size(); ++i) { o.out[i].resize(rows); CK(cudaMemcpy(o.out[i].data(), out[i], rows * 4, cudaMemcpyDeviceToHost)); }
    for (unsigned i = 0; i < 22; ++i) { o.counts[i].resize(count_len(i)); CK(cudaMemcpy(o.counts[i].data(), counts[i], count_len(i) * 4, cudaMemcpyDeviceToHost)); }
    CK(cudaMemcpy(&o.error, error, 4, cudaMemcpyDeviceToHost));
    for (auto p : pp) cudaFree(p); for (auto p : out) cudaFree(p); for (auto p : counts) cudaFree(p); cudaFree(values); cudaFree(error);
    return o;
}
static bool parity(const Case& c) {
    const Out a = run(c, 0, 0), b = run(c, 1, 0);
    const bool ok = a.out == b.out && a.counts == b.counts && a.error == b.error && a.error == 0;
    std::printf("parity comp=%u log_rows=%u log_values=%u pattern=%u: %s out=%d counts=%d error=%u/%u\n", c.comp, c.log_rows, c.log_values, c.pattern,
        ok ? "OK" : "FAIL", a.out == b.out, a.counts == b.counts, a.error, b.error);
    return ok;
}
int main(int argc, char** argv) {
    CK(cudaStreamCreateWithFlags(&g_stream, cudaStreamNonBlocking));
    const std::string cmd = argc > 1 ? argv[1] : "selftest";
    if (cmd == "selftest") {
        bool ok = true;
        for (unsigned comp = 0; comp < 5; ++comp)
            for (unsigned log : {4u, 8u, 13u, 18u})
                for (unsigned pattern : {0u, 1u, 2u}) ok &= parity(make(comp, log, log + 1, pattern, 31 * comp + log + 7 * pattern));
        std::printf("SELFTEST %s\n", ok ? "PASS" : "FAIL");
        return ok ? 0 : 1;
    }
    if (cmd == "bench") {
        const unsigned comp = std::atoi(argv[2]), lr = std::atoi(argv[3]), lv = std::atoi(argv[4]), pat = std::atoi(argv[5]);
        const int reps = argc > 6 ? std::atoi(argv[6]) : 7;
        const Case c = make(comp, lr, lv, pat, 42);
        int modes = 1;
#ifdef T9_HAS_VARIANT
        if (!parity(c)) return 1;
        modes = 2;
#endif
        std::vector<float> t[2];
        for (int r = 0; r < reps; ++r) for (int m = 0; m < modes; ++m) { g_times.clear(); run(c, m, 1); t[m].push_back(g_times[0]); }
        for (int m = 0; m < modes; ++m) {
            auto v = t[m]; std::sort(v.begin(), v.end());
            std::printf("bench comp=%u log_rows=%u log_values=%u pattern=%u %s median %.3f ms min %.3f max %.3f (n=%zu) %.2f ns/row\n", comp, lr, lv, pat,
                m ? "t9       " : "reference", v[v.size() / 2], v.front(), v.back(), v.size(), v[v.size() / 2] * 1e6 / double(1u << lr));
        }
        return 0;
    }
    return 5;
}
