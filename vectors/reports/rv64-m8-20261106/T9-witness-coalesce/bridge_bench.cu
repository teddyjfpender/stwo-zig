// T9 parity test + CUDA-event microbenchmark for stwo_rv64_bridge_witness_on:
// reference bridge::witness (flag off) vs witness_private (flag on).
// Bit-exact MAIN, range16, range8 and status on synthetic valid inputs.
//   nvcc -O3 -std=c++17 -arch=sm_120 -I<repo>/src/backends/cuda/native/rv64 bridge_bench.cu -o bridge_bench
//   ./bridge_bench selftest | bench <kind> <log> <coordinates> [reps]
#include "bridge_witness.cu"
#include <algorithm>
#include <cstdio>
#include <random>
#include <string>
#include <vector>
static cudaStream_t g_stream;
extern "C" int stwo_exec_context_lane_stream(void*, uint32_t, void** out) { *out = g_stream; return 0; }
extern "C" int stwo_exec_context_validate_allocation(void*, const void*, size_t) { return 0; }
#define CK(x) do { auto _e = (x); if (_e != cudaSuccess) { std::fprintf(stderr, "CUDA %s at %s:%d: %s\n", cudaGetErrorString(cudaError_t(_e)), __FILE__, __LINE__, #x); std::exit(2); } } while (0)
using namespace stwo::cuda::rv64;
struct Shape { uint32_t kind, log, coordinates, calls, write_mask; std::vector<uint32_t> inputs; };
// Valid predecessor: equal value copies, rights, epoch/tick strictly before.
// skew: guest RAM words are mostly small (zero high bytes), the realistic hot-bin case.
static bool g_skew = false;
static uint64_t value(std::mt19937_64& rng) { if (!g_skew) return rng(); const uint64_t r = rng() % 8; return r < 4 ? 0 : r < 7 ? rng() % 256 : rng(); }
static void item(std::mt19937_64& rng, uint32_t* it, uint32_t epoch, uint32_t tick, bool write, bool keccak) {
    const uint64_t v = value(rng), v2 = write ? value(rng) : v;
    it[0] = uint32_t(v); it[1] = uint32_t(v >> 32); it[2] = uint32_t(v2); it[3] = uint32_t(v2 >> 32); it[4] = it[0]; it[5] = it[1];
    const bool same = rng() & 1;
    const uint32_t pe = same ? epoch : uint32_t(rng() % epoch);
    const uint32_t pt = same ? uint32_t(rng() % tick) : uint32_t(rng() % (1u << 24));
    const uint32_t rights = keccak ? 3 : (write ? 3 : 1 + 2 * (rng() & 1));
    it[6] = pe | (rights << 16); it[7] = pt;
}
static Shape make(uint32_t kind, uint32_t log, uint32_t coordinates, uint32_t calls, uint64_t seed, bool corrupt = false) {
    std::mt19937_64 rng(seed);
    const bool k = kind == 0;
    Shape s{kind, log, k ? 25u : coordinates, calls, 0, {}};
    if (!k) s.write_mask = uint32_t(rng()) & ((1u << coordinates) - 1);
    const uint32_t words = k ? 25 : 4 * coordinates, stride = 4 + 8 * words;
    s.inputs.resize(size_t(calls) * stride);
    for (uint32_t c = 0; c < calls; ++c) {
        uint32_t* in = s.inputs.data() + size_t(c) * stride;
        // Real pointers cluster: a few heaps, so range16 limbs repeat.
        const uint64_t pointer = (0x10000000ull + (rng() % 4096) * 256) & ~31ull;
        in[0] = uint32_t(pointer); in[1] = uint32_t(pointer >> 32);
        in[2] = 1 + uint32_t(rng() % 60000); in[3] = 1 + uint32_t(rng() % ((1u << 24) - 1));
        for (uint32_t w = 0; w < words; ++w) item(rng, in + 4 + 8 * w, in[2], in[3], k || ((s.write_mask >> (w / 4)) & 1), k);
    }
    if (corrupt && calls) s.inputs[4 + 6] |= 1u << 18;  // invalid packed rights on row 0
    return s;
}
struct Out { std::vector<uint32_t> main, r16, r8; uint32_t status; };
static Out run(const Shape& s, int mode, float* ms_out = nullptr, int reps = 0, std::vector<float>* times = nullptr) {
    const bool k = s.kind == 0; const uint64_t n = 1ull << s.log, width = k ? 66 : 134;
    uint32_t *in = nullptr, *main, *r16, *r8, *st;
    if (!s.inputs.empty()) { CK(cudaMalloc(&in, s.inputs.size() * 4)); CK(cudaMemcpy(in, s.inputs.data(), s.inputs.size() * 4, cudaMemcpyHostToDevice)); }
    CK(cudaMalloc(&main, n * width * 4)); CK(cudaMalloc(&r16, 65536 * 4)); CK(cudaMalloc(&r8, 256 * 4)); CK(cudaMalloc(&st, 4));
    StwoRv64BridgeWitness p{in, main, r16, r8, st, s.inputs.size(), n * width, s.calls, 3, s.log, s.kind, s.coordinates, s.write_mask};
    bridge::bridge_coalesce = mode;
    cudaEvent_t e0, e1; CK(cudaEventCreate(&e0)); CK(cudaEventCreate(&e1));
    for (int r = 0; r <= reps; ++r) {
        CK(cudaMemsetAsync(main, 0, n * width * 4, g_stream)); CK(cudaMemsetAsync(r16, 0, 65536 * 4, g_stream));
        CK(cudaMemsetAsync(r8, 0, 1024, g_stream)); CK(cudaMemsetAsync(st, 0, 4, g_stream));
        CK(cudaEventRecord(e0, g_stream));
        const int rc = stwo_rv64_bridge_witness_on(nullptr, 0, &p);
        if (rc) { std::fprintf(stderr, "entry rc=%d\n", rc); std::exit(3); }
        CK(cudaEventRecord(e1, g_stream)); CK(cudaEventSynchronize(e1));
        float ms; CK(cudaEventElapsedTime(&ms, e0, e1));
        if (r && times) times->push_back(ms);
    }
    Out o; o.main.resize(n * width); o.r16.resize(65536); o.r8.resize(256);
    CK(cudaMemcpy(o.main.data(), main, n * width * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(o.r16.data(), r16, 65536 * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(o.r8.data(), r8, 1024, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(&o.status, st, 4, cudaMemcpyDeviceToHost));
    for (void* x : {(void*)in, (void*)main, (void*)r16, (void*)r8, (void*)st}) if (x) cudaFree(x);
    (void)ms_out;
    return o;
}
static bool parity(const Shape& s, bool expect_status = false) {
    const Out a = run(s, 0), b = run(s, 1);
    const bool same = a.main == b.main && a.r16 == b.r16 && a.r8 == b.r8 && a.status == b.status;
    const bool ok = same && (a.status != 0) == expect_status;
    std::printf("parity kind=%u log=%u coords=%u calls=%u: %s main=%d r16=%d r8=%d status=%u/%u\n", s.kind, s.log, s.coordinates, s.calls,
        ok ? "OK" : "FAIL", a.main == b.main, a.r16 == b.r16, a.r8 == b.r8, a.status, b.status);
    return ok;
}
int main(int argc, char** argv) {
    CK(cudaStreamCreateWithFlags(&g_stream, cudaStreamNonBlocking));
    const std::string cmd = argc > 1 ? argv[1] : "selftest";
    if (cmd == "selftest") {
        bool ok = true;
        for (uint32_t log : {5u, 8u, 12u, 16u}) {
            const uint32_t n = 1u << log;
            for (uint32_t calls : {0u, 1u, (n - 1) / 25}) ok &= parity(make(0, log, 25, calls, 11 * log + calls));
            for (uint32_t coords : {1u, 4u, 6u})
                for (uint32_t calls : {0u, 1u, (n - 1) / coords}) ok &= parity(make(1, log, coords, calls, 13 * log + calls + coords));
        }
        g_skew = true;
        ok &= parity(make(0, 16, 25, 2621, 7)); ok &= parity(make(1, 16, 4, 16383, 8)); ok &= parity(make(1, 16, 6, 10922, 9));
        g_skew = false;
        ok &= parity(make(0, 12, 25, 100, 99, true), true);
        ok &= parity(make(1, 12, 4, 500, 98, true), true);
        std::printf("SELFTEST %s\n", ok ? "PASS" : "FAIL");
        return ok ? 0 : 1;
    }
    if (cmd == "bench") {
        const uint32_t kind = std::atoi(argv[2]), log = std::atoi(argv[3]), coords = kind ? std::atoi(argv[4]) : 25;
        const int reps = argc > 5 ? std::atoi(argv[5]) : 7;
        g_skew = argc > 6 && std::atoi(argv[6]);
        const Shape s = make(kind, log, coords, ((1u << log) - 1) / coords, 42);
        if (!parity(s)) return 1;
        // Interleave A/B: alternate single-rep batches.
        std::vector<float> t[2];
        for (int r = 0; r < reps; ++r) for (int mode = 0; mode < 2; ++mode) run(s, mode, nullptr, 1, &t[mode]);
        const char* names[2] = {"reference witness", "witness_private"};
        for (int mode = 0; mode < 2; ++mode) {
            auto v = t[mode]; std::sort(v.begin(), v.end());
            std::printf("bench kind=%u log=%u coords=%u skew=%d %-18s median %.3f ms min %.3f max %.3f (n=%zu) %.1f ns/row\n", kind, log, coords, int(g_skew), names[mode],
                v[v.size() / 2], v.front(), v.back(), v.size(), v[v.size() / 2] * 1e6 / double(1u << log));
        }
        return 0;
    }
    return 5;
}
