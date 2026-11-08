// T9 parity test + CUDA-event microbenchmark for stwo_rv64_keccak_witness_on:
// reference (keccak_witness, flag off) vs coalesced (staged + bitrev, flag on).
// Bit-exact MAIN, chi, xor5 and status on the same inputs.
//   nvcc -O3 -std=c++17 -arch=sm_120 -I<repo>/src/backends/cuda/native/rv64 keccak_bench.cu -o keccak_bench
//   ./keccak_bench selftest                    edge shapes, both policies
//   ./keccak_bench bench <policy> <log> <calls> [reps]
//   ./keccak_bench dump <file> [reps]          recorded launch (u32 header: policy log calls first_id; then inputs)
#include "keccak_witness.cu"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>
static cudaStream_t g_stream;
extern "C" int stwo_exec_context_lane_stream(void*, uint32_t, void** out) { *out = g_stream; return 0; }
extern "C" int stwo_exec_context_validate_allocation(void*, const void*, size_t) { return 0; }
#define CK(x) do { auto _e = (x); if (_e != cudaSuccess) { std::fprintf(stderr, "CUDA %s at %s:%d: %s\n", cudaGetErrorString(cudaError_t(_e)), __FILE__, __LINE__, #x); std::exit(2); } } while (0)
using namespace stwo::cuda::rv64;
struct Shape { uint32_t policy, log, calls, first_id; std::vector<uint32_t> inputs; };
struct Dev { uint32_t *inputs = nullptr, *main = nullptr, *chi = nullptr, *xor5 = nullptr, *status = nullptr; StwoRv64KeccakWitness p{}; };
static Dev upload(const Shape& s) {
    Dev d;
    const uint64_t main_words = uint64_t(1923) << s.log;
    CK(cudaMalloc(&d.inputs, s.inputs.size() * 4));
    CK(cudaMalloc(&d.main, main_words * 4));
    CK(cudaMalloc(&d.chi, (size_t(1) << 21) * 4));
    CK(cudaMalloc(&d.xor5, (size_t(1) << 16) * 4));
    CK(cudaMalloc(&d.status, 4));
    CK(cudaMemcpy(d.inputs, s.inputs.data(), s.inputs.size() * 4, cudaMemcpyHostToDevice));
    d.p = {d.inputs, d.main, d.chi, d.xor5, d.status, uint64_t(s.calls) * 50, main_words, s.calls, s.first_id, s.log, s.policy};
    return d;
}
static void release(Dev& d) { for (void* x : {(void*)d.inputs, (void*)d.main, (void*)d.chi, (void*)d.xor5, (void*)d.status}) cudaFree(x); }
struct Out { std::vector<uint32_t> main, chi, xor5; uint32_t status; };
static Out run(Dev& d, int mode) {
    keccak_coalesce = mode;
    // Poison MAIN so the coalesced path's "no memset" claim is tested.
    CK(cudaMemsetAsync(d.main, 0xab, d.p.main_words * 4, g_stream));
    const int rc = stwo_rv64_keccak_witness_on(nullptr, 0, &d.p);
    if (rc) { std::fprintf(stderr, "entry rc=%d\n", rc); std::exit(3); }
    CK(cudaStreamSynchronize(g_stream));
    Out o;
    o.main.resize(d.p.main_words);
    o.chi.resize(size_t(1) << (d.p.policy ? 13 : 21));
    o.xor5.resize(size_t(1) << (d.p.policy ? 10 : 16));
    CK(cudaMemcpy(o.main.data(), d.main, o.main.size() * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(o.chi.data(), d.chi, o.chi.size() * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(o.xor5.data(), d.xor5, o.xor5.size() * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(&o.status, d.status, 4, cudaMemcpyDeviceToHost));
    return o;
}
static Shape random_shape(uint32_t policy, uint32_t log, uint32_t calls, uint64_t seed) {
    Shape s{policy, log, calls, 7, {}};
    std::mt19937_64 rng(seed);
    s.inputs.resize(size_t(calls) * 50);
    for (auto& w : s.inputs) w = uint32_t(rng());
    // A few structured states (all-zero, all-ones) exercise the extremes.
    if (calls > 2) std::fill(s.inputs.begin(), s.inputs.begin() + 50, 0u);
    if (calls > 3) std::fill(s.inputs.begin() + 50, s.inputs.begin() + 100, 0xffffffffu);
    return s;
}
static uint64_t digest(const std::vector<uint32_t>& v) { uint64_t h = 1469598103934665603ull; for (uint32_t x : v) { h ^= x; h *= 1099511628211ull; } return h; }
static bool parity(const Shape& s) {
    Dev d = upload(s);
    const Out a = run(d, 0), b = run(d, 1);
    release(d);
    size_t bad = 0, first = SIZE_MAX;
    for (size_t i = 0; i < a.main.size(); ++i) if (a.main[i] != b.main[i]) { if (!bad) first = i; ++bad; }
    const bool ok = !bad && a.chi == b.chi && a.xor5 == b.xor5 && a.status == b.status && a.status == 0;
    std::printf("parity policy=%u log=%u calls=%u: %s main_mismatch=%zu (first %zd) chi=%d xor5=%d status=%u/%u digest=%016llx\n",
        s.policy, s.log, s.calls, ok ? "OK" : "FAIL", bad, bad ? ssize_t(first) : -1, a.chi == b.chi, a.xor5 == b.xor5, a.status, b.status,
        (unsigned long long)(digest(a.main) ^ digest(a.chi) * 3 ^ digest(a.xor5) * 5));
    return ok;
}
static uint32_t max_calls(uint32_t policy, uint32_t log) { return 2 * uint32_t((uint64_t(1) << log) / (policy ? 29 : 27)); }
static void bench(const Shape& s, int reps) {
    Dev d = upload(s);
    cudaEvent_t e0, e1; CK(cudaEventCreate(&e0)); CK(cudaEventCreate(&e1));
    std::vector<float> t[2];
    for (int r = -1; r < reps; ++r)
        for (int mode = 0; mode < 2; ++mode) {  // interleaved A/B
            keccak_coalesce = mode;
            CK(cudaEventRecord(e0, g_stream));
            if (stwo_rv64_keccak_witness_on(nullptr, 0, &d.p)) std::exit(3);
            CK(cudaEventRecord(e1, g_stream));
            CK(cudaEventSynchronize(e1));
            float ms; CK(cudaEventElapsedTime(&ms, e0, e1));
            if (r >= 0) t[mode].push_back(ms);  // r=-1 is warm-up
        }
    {  // Pass split of the coalesced path (CUDA events per kernel).
        const auto& p = d.p;
        const uint32_t pairs = (p.calls + 1) / 2, active = pairs * (p.policy ? 29 : 27), ee = (active + 1) / 2, ob = (1u << p.log) - active / 2;
        // Same launch configuration as stwo_rv64_keccak_witness_on (count grid cap 2 x SMs, small bitrev below log 10).
        int sms = 0, device = 0; CK(cudaGetDevice(&device)); CK(cudaDeviceGetAttribute(&sms, cudaDevAttrMultiProcessorCount, device));
        const uint32_t cgrid_cap = uint32_t(2 * sms);
        cudaEvent_t m, mc; CK(cudaEventCreate(&m)); CK(cudaEventCreate(&mc));
        std::vector<float> ta, tb, tc;
        for (int r = 0; r < reps; ++r) {
            CK(cudaEventRecord(e0, g_stream));
            const uint32_t grid = (pairs + keccak_stage_warps - 1) / keccak_stage_warps;
            if (p.policy) {
                keccak_witness_counts<<<std::min((pairs + keccak_count_warps - 1) / keccak_count_warps, cgrid_cap), 32 * keccak_count_warps, 0, g_stream>>>(p);
                CK(cudaEventRecord(mc, g_stream));
                keccak_witness_staged<false><<<grid, 32 * keccak_stage_warps, 0, g_stream>>>(p);
            } else {
                CK(cudaEventRecord(mc, g_stream));
                keccak_witness_staged<true><<<grid, 32 * keccak_stage_warps, 0, g_stream>>>(p);
            }
            CK(cudaEventRecord(m, g_stream));
            if (p.log >= 10) keccak_bitrev<<<dim3(1u << (p.log - 10), 1923), 256, 0, g_stream>>>(p.main, p.log, ee, ob);
            else keccak_bitrev_small<<<1923, 256, 0, g_stream>>>(p.main, p.log, ee, ob);
            CK(cudaEventRecord(e1, g_stream)); CK(cudaEventSynchronize(e1));
            float a, b, c; CK(cudaEventElapsedTime(&c, e0, mc)); CK(cudaEventElapsedTime(&a, mc, m)); CK(cudaEventElapsedTime(&b, m, e1)); ta.push_back(a); tb.push_back(b); tc.push_back(c);
        }
        std::sort(ta.begin(), ta.end()); std::sort(tb.begin(), tb.end()); std::sort(tc.begin(), tc.end());
        std::printf("split policy=%u log=%u: counts(policy 1) median %.3f ms, staged median %.3f ms (min %.3f max %.3f), bitrev median %.3f ms (min %.3f max %.3f)\n", p.policy, p.log,
            tc[tc.size() / 2], ta[ta.size() / 2], ta.front(), ta.back(), tb[tb.size() / 2], tb.front(), tb.back());
    }
    const char* names[2] = {"reference keccak_witness", "coalesced staged+bitrev"};
    for (int mode = 0; mode < 2; ++mode) {
        auto v = t[mode]; std::sort(v.begin(), v.end());
        const double bytes = double(1923ull << s.log) * 4;
        std::printf("bench policy=%u log=%u calls=%u %-26s median %.3f ms min %.3f max %.3f (n=%d) MAIN %.2f GB -> %.0f GB/s\n", s.policy, s.log, s.calls, names[mode],
            v[v.size() / 2], v.front(), v.back(), int(v.size()), bytes / 1e9, bytes / (v[v.size() / 2] * 1e-3) / 1e9);
    }
    release(d);
}
int main(int argc, char** argv) {
    CK(cudaStreamCreateWithFlags(&g_stream, cudaStreamNonBlocking));
    const std::string cmd = argc > 1 ? argv[1] : "selftest";
    if (cmd == "selftest") {
        bool ok = true;
        for (uint32_t policy : {0u, 1u})
            for (uint32_t log : {5u, 6u, 9u, 10u, 11u, 12u, 15u}) {
                const uint32_t mc = max_calls(policy, log);
                uint32_t done[8]; uint32_t ndone = 0;  // small logs: mc - 1 / mc repeat earlier counts
                for (uint32_t calls : {1u, 2u, 3u, 7u, 8u, 9u, mc - 1, mc}) {
                    if (calls < 1 || calls > mc || std::find(done, done + ndone, calls) != done + ndone) continue;
                    done[ndone++] = calls;
                    ok &= parity(random_shape(policy, log, calls, 1000 * log + calls + 77 * policy));
                }
            }
        ok &= parity(random_shape(0, 17, max_calls(0, 17) - 1, 5));
        ok &= parity(random_shape(1, 17, max_calls(1, 17), 6));
        std::printf("SELFTEST %s\n", ok ? "PASS" : "FAIL");
        return ok ? 0 : 1;
    }
    if (cmd == "bench") {
        const uint32_t policy = std::atoi(argv[2]), log = std::atoi(argv[3]);
        uint32_t calls = std::strtoul(argv[4], nullptr, 10);
        if (!calls) calls = max_calls(policy, log);
        const Shape s = random_shape(policy, log, calls, 42);
        if (!parity(s)) return 1;
        bench(s, argc > 5 ? std::atoi(argv[5]) : 7);
        return 0;
    }
    if (cmd == "dump") {
        FILE* f = std::fopen(argv[2], "rb"); if (!f) return 4;
        uint32_t h[4]; if (std::fread(h, 4, 4, f) != 4) return 4;
        Shape s{h[0], h[1], h[2], h[3], std::vector<uint32_t>(size_t(h[2]) * 50)};
        if (std::fread(s.inputs.data(), 4, s.inputs.size(), f) != s.inputs.size()) return 4;
        std::fclose(f);
        if (!parity(s)) return 1;
        bench(s, argc > 3 ? std::atoi(argv[3]) : 7);
        return 0;
    }
    return 5;
}
