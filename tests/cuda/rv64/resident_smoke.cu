// Real-driver parity/benchmark harness. It never substitutes a CPU prover.
// Host reference/readbacks are validation only and outside the timed hot loop.
#include "rv64/om31.cuh"
#include "rv64/gkr.h"
#include "runtime/context_options.h"
#include <cuda_runtime.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
using namespace stwo::cuda::rv64;
extern "C" int stwo_exec_context_create_options(const StwoCudaContextOptions*, void**);
extern "C" int stwo_exec_context_destroy(void*);
extern "C" int stwo_exec_context_sync(void*);
extern "C" int stwo_exec_context_alloc_u32(void*, size_t, uint32_t**);
extern "C" int stwo_exec_context_free_u32(void*, uint32_t*);
extern "C" int stwo_exec_context_memcpy_h2d_async(void*, void*, const void*, size_t);
extern "C" int stwo_exec_context_memcpy_d2h_async(void*, void*, const void*, size_t);
extern "C" int stwo_exec_context_dependency_record(void*, uint32_t, uint32_t,
                                                   StwoCudaDependency*);
extern "C" int stwo_exec_context_dependency_wait(void*, uint32_t, const StwoCudaDependency*);
extern "C" int stwo_exec_context_dependency_release(void*, const StwoCudaDependency*);
extern "C" int stwo_exec_context_lane_stream(void*, uint32_t, void**);
static void check(int status, const char* operation) {
    if (status)
        throw std::runtime_error(std::string(operation) + ": " +
                                 cudaGetErrorString(cudaError_t(status)));
}
#define CHECK(expr) check((expr), #expr)
struct Owner {
    void* ctx = nullptr;
    std::vector<uint32_t*> allocations;
    std::vector<cudaEvent_t> events;
    uint64_t allocated_bytes = 0;
    explicit Owner(int device) {
        StwoCudaContextOptions options{1, uint32_t(device), 2, 8};
        const int status = stwo_exec_context_create_options(&options, &ctx);
        if (status) {
            if (ctx) {
                const int cleanup = stwo_exec_context_destroy(ctx);
                (void)cleanup;
                ctx = nullptr;
            }
            check(status, "context create");
        }
    }
    StwoRv64Plane plane(uint32_t count, uint32_t coordinates) {
        uint32_t* p = nullptr;
        CHECK(stwo_exec_context_alloc_u32(ctx, size_t(count) * coordinates, &p));
        allocations.push_back(p);
        allocated_bytes += uint64_t(count) * coordinates * 4;
        return {p, count, coordinates, 0};
    }
    cudaEvent_t event() {
        cudaEvent_t e;
        CHECK(cudaEventCreate(&e));
        events.push_back(e);
        return e;
    }
    void upload(StwoRv64Plane p, const std::vector<uint32_t>& v) {
        CHECK(stwo_exec_context_memcpy_h2d_async(ctx, p.words, v.data(), v.size() * 4));
    }
    std::vector<uint32_t> read(StwoRv64Plane p) {
        std::vector<uint32_t> out(size_t(p.stride) * p.coordinates);
        CHECK(stwo_exec_context_memcpy_d2h_async(ctx, out.data(), p.words, out.size() * 4));
        CHECK(stwo_exec_context_sync(ctx));
        return out;
    }
    void close() {
        CHECK(stwo_exec_context_sync(ctx));
        for (auto p : allocations) CHECK(stwo_exec_context_free_u32(ctx, p));
        allocations.clear();
        for (auto e : events) CHECK(cudaEventDestroy(e));
        events.clear();
        CHECK(stwo_exec_context_destroy(ctx));
        ctx = nullptr;
    }
    ~Owner() {
        if (!ctx) return;
        // An earlier failure already makes the run fail. Join before teardown;
        // never publish data from this destructor's best-effort cleanup.
        if (stwo_exec_context_sync(ctx)) return;
        for (auto p : allocations)
            if (stwo_exec_context_free_u32(ctx, p)) return;
        for (auto e : events)
            if (cudaEventDestroy(e)) return;
        (void)stwo_exec_context_destroy(ctx);
    }
};
static OM31 value(uint32_t seed) {
    uint32_t w[8];
    for (auto& x : w) {
        seed = seed * 1664525u + 1013904223u;
        x = seed % 2147483647u;
    }
    return from_words(w);
}
static void require_equal(const std::vector<uint32_t>& a, const std::vector<uint32_t>& b,
                          const char* name) {
    if (a != b) throw std::runtime_error(std::string("numerical mismatch: ") + name);
}
struct Result {
    int device;
    uint32_t count;
    uint64_t bytes;
    float median_ms;
    std::string name;
};
static Result exercise(int device, uint32_t count, uint32_t iterations) {
    Owner o(device);
    const uint32_t half = count / 2, quarter = count / 4, groups = (quarter + 127) / 128;
    auto tuples = o.plane(count, 3), weights = o.plane(count, 1), active = o.plane(count, 1),
         challenges = o.plane(4, 8);
    auto n = o.plane(count, 1), d = o.plane(count, 8), verdict = o.plane(1, 1);
    auto n1 = o.plane(half, 8), d1 = o.plane(half, 8), n2 = o.plane(quarter, 8),
         d2 = o.plane(quarter, 8);
    auto nf = o.plane(half, 8), df = o.plane(half, 8), y = o.plane(28, 8),
         eq = o.plane(quarter, 8);
    auto lambda = o.plane(1, 8), assignment = o.plane(1, 8), a = o.plane(2 * groups, 8),
         b = o.plane(2 * groups, 8), out = o.plane(2, 8);
    uint32_t variables = 0;
    for (uint32_t m = half; m > 1; m >>= 1) ++variables;
    std::vector<uint32_t> ht(size_t(count) * 3), hw(count), ha(count, 1), hn(count), hc(32),
        hy(28 * 8), hl(8), hx(8), zero_status(1, 0);
    for (uint32_t i = 0; i < count; ++i) {
        hw[i] = i % 13;
        ha[i] = (i % 17 == 16) ? 0 : 1;
        hn[i] = ha[i] ? hw[i] : 0;
        for (uint32_t j = 0; j < 3; ++j) ht[j * count + i] = (i * 37u + j * 11u) % 2147483647u;
    }
    // Challenges and y are AoS, unlike the large secure planes.
    for (uint32_t j = 0; j < 4; ++j)
        for (uint32_t c = 0; c < 8; ++c) hc[8 * j + c] = coordinate(value(50 + j), c);
    for (uint32_t j = 0; j < 28; ++j)
        for (uint32_t c = 0; c < 8; ++c) hy[8 * j + c] = coordinate(value(90 + j), c);
    for (uint32_t c = 0; c < 8; ++c) {
        hl[c] = coordinate(value(7), c);
        hx[c] = coordinate(value(8), c);
    }
    // Pageable host owners stay live through the ingress dependency join.
    o.upload(tuples, ht);
    o.upload(weights, hw);
    o.upload(active, ha);
    o.upload(challenges, hc);
    o.upload(verdict, zero_status);
    o.upload(y, hy);
    o.upload(lambda, hl);
    o.upload(assignment, hx);
    StwoCudaDependency ingress{};
    CHECK(stwo_exec_context_dependency_record(o.ctx, 0, 0, &ingress));
    CHECK(stwo_exec_context_dependency_wait(o.ctx, 1, &ingress));
    void* raw = nullptr;
    CHECK(stwo_exec_context_lane_stream(o.ctx, 1, &raw));
    const auto stream = reinterpret_cast<cudaStream_t>(raw);
    auto wave = [&]() {
        CHECK(stwo_rv64_gkr_project_on(o.ctx, 1, tuples, weights, active, count, 3,
                                       challenges.words, n, d, verdict.words));
        CHECK(stwo_rv64_gkr_layer_on(o.ctx, 1, n, d, count, 1, n1, d1));
        CHECK(stwo_rv64_gkr_layer_on(o.ctx, 1, n, d, count, 2, n2, d2));
        CHECK(stwo_rv64_gkr_eq_on(o.ctx, 1, y.words, variables, eq));
        CHECK(stwo_rv64_gkr_sum_on(o.ctx, 1, n, d, count, eq, lambda.words, a, b, out));
        CHECK(stwo_rv64_gkr_fold_on(o.ctx, 1, n, d, count, assignment.words, nf, df));
    };
    for (int i = 0; i < 3; ++i) wave();
    const auto begin = o.event(), end = o.event();
    std::vector<float> timings;
    for (uint32_t i = 0; i < iterations; ++i) {
        CHECK(cudaEventRecord(begin, stream));
        wave();
        CHECK(cudaEventRecord(end, stream));
        CHECK(cudaEventSynchronize(end));
        float ms = 0;
        CHECK(cudaEventElapsedTime(&ms, begin, end));
        timings.push_back(ms);
    }
    CHECK(stwo_exec_context_sync(o.ctx));
    CHECK(stwo_exec_context_dependency_release(o.ctx, &ingress));
    if (o.read(verdict)[0]) throw std::runtime_error("projection device verdict failed");
    std::vector<uint32_t> expected_d(size_t(count) * 8), expected_eq(size_t(quarter) * 8);
    for (uint32_t i = 0; i < count; ++i) {
        OM31 v = from_words(hc.data());
        for (uint32_t j = 0; j < 3; ++j)
            v = sub(v, scale(from_words(hc.data() + 8 * (j + 1)), ht[j * count + i]));
        if (!ha[i]) v = one();
        if (is_zero(v)) throw std::runtime_error("unexpected deterministic pole");
        store(expected_d.data(), count, i, v);
    }
    require_equal(o.read(n), hn, "project N");
    require_equal(o.read(d), expected_d, "project D");
    for (uint32_t i = 0; i < quarter; ++i) {
        OM31 e = sub(one(), from_words(hy.data()));
        for (uint32_t j = 1; j < variables; ++j) {
            const OM31 t = from_words(hy.data() + 8 * j);
            e = mul(e, (i & (1u << (variables - 1 - j))) ? t : sub(one(), t));
        }
        store(expected_eq.data(), quarter, i, e);
    }
    require_equal(o.read(eq), expected_eq, "EqEvals");
    auto ref_fraction = [&](uint32_t i) {
        return Fraction{base(hn[i]), load(expected_d.data(), count, i)};
    };
    std::vector<uint32_t> en1(size_t(half) * 8), ed1(en1.size()), en2(size_t(quarter) * 8),
        ed2(en2.size());
    std::vector<uint32_t> efn(size_t(half) * 8), efd(efn.size());
    for (uint32_t i = 0; i < half; ++i) {
        auto f = combine(ref_fraction(2 * i), ref_fraction(2 * i + 1));
        store(en1.data(), half, i, f.n);
        store(ed1.data(), half, i, f.d);
        const auto u = ref_fraction(i), v = ref_fraction(i + half);
        const auto x = from_words(hx.data());
        store(efn.data(), half, i, fold(u.n, v.n, x));
        store(efd.data(), half, i, fold(u.d, v.d, x));
    }
    for (uint32_t i = 0; i < quarter; ++i) {
        const auto f =
            combine({load(en1.data(), half, 2 * i), load(ed1.data(), half, 2 * i)},
                    {load(en1.data(), half, 2 * i + 1), load(ed1.data(), half, 2 * i + 1)});
        store(en2.data(), quarter, i, f.n);
        store(ed2.data(), quarter, i, f.d);
    }
    require_equal(o.read(n1), en1, "layer1 N");
    require_equal(o.read(d1), ed1, "layer1 D");
    require_equal(o.read(n2), en2, "fused2 N");
    require_equal(o.read(d2), ed2, "fused2 D");
    require_equal(o.read(nf), efn, "fold N");
    require_equal(o.read(df), efd, "fold D");
    Pair sum{zero(), zero()};
    for (uint32_t i = 0; i < quarter; ++i) {
        const uint32_t j = 2 * i, k = 2 * (quarter + i);
        const auto t =
            sum_term(ref_fraction(j), ref_fraction(j + 1), ref_fraction(k), ref_fraction(k + 1),
                     load(expected_eq.data(), quarter, i), from_words(hl.data()));
        sum.at0 = add(sum.at0, t.at0);
        sum.at2 = add(sum.at2, t.at2);
    }
    std::vector<uint32_t> es(16);
    store(es.data(), 2, 0, sum.at0);
    store(es.data(), 2, 1, sum.at2);
    require_equal(o.read(out), es, "sumcheck at0/2");
    // Exercise the secure-numerator route as well, reusing resident layer1.
    if (half >= 4) {
        CHECK(stwo_rv64_gkr_sum_on(o.ctx, 1, n1, d1, half, eq, lambda.words, a, b, out));
        CHECK(stwo_exec_context_sync(o.ctx));
        Pair s{zero(), zero()};
        const uint32_t terms = half / 4;
        const auto f = [&](uint32_t i) {
            return Fraction{load(en1.data(), half, i), load(ed1.data(), half, i)};
        };
        for (uint32_t i = 0; i < terms; ++i) {
            const auto t =
                sum_term(f(2 * i), f(2 * i + 1), f(2 * (terms + i)), f(2 * (terms + i) + 1),
                         load(expected_eq.data(), quarter, i), from_words(hl.data()));
            s.at0 = add(s.at0, t.at0);
            s.at2 = add(s.at2, t.at2);
        }
        store(es.data(), 2, 0, s.at0);
        store(es.data(), 2, 1, s.at2);
        require_equal(o.read(out), es, "secure sum");
        CHECK(stwo_rv64_gkr_layer_on(o.ctx, 1, n1, d1, half, 1, n2, d2));
        CHECK(stwo_rv64_gkr_fold_on(o.ctx, 1, n1, d1, half, assignment.words, n2, d2));
        CHECK(stwo_exec_context_sync(o.ctx));
        for (uint32_t i = 0; i < quarter; ++i) {
            store(en2.data(), quarter, i,
                  fold(load(en1.data(), half, i), load(en1.data(), half, i + quarter),
                       from_words(hx.data())));
            store(ed2.data(), quarter, i,
                  fold(load(ed1.data(), half, i), load(ed1.data(), half, i + quarter),
                       from_words(hx.data())));
        }
        require_equal(o.read(n2), en2, "secure fold N");
        require_equal(o.read(d2), ed2, "secure fold D");
    }
    // Invalid custody/geometry must reject before any launch.
    if (!stwo_rv64_gkr_fold_on(o.ctx, 1, n, d, count, assignment.words, n1, d))
        throw std::runtime_error("overlap accepted");
    if (!stwo_rv64_gkr_layer_on(o.ctx, 2, n, d, count, 1, n1, d1))
        throw std::runtime_error("bad lane accepted");
    if (!stwo_rv64_gkr_layer_on(o.ctx, 1, n, d, count - 1, 1, n1, d1))
        throw std::runtime_error("bad shape accepted");
    // Noncanonical tuple and challenge pole each set the sticky verdict.
    auto bad = ht;
    bad[0] = 0x7fffffffu;
    o.upload(tuples, bad);
    CHECK(stwo_exec_context_sync(o.ctx));
    CHECK(stwo_rv64_gkr_project_on(o.ctx, 1, tuples, weights, active, count, 3,
                                   challenges.words, n, d, verdict.words));
    CHECK(stwo_exec_context_sync(o.ctx));
    if (!(o.read(verdict)[0] & 1)) throw std::runtime_error("bad coordinate missed");
    o.upload(tuples, ht);
    std::vector<uint32_t> poles(32, 0);
    o.upload(challenges, poles);
    CHECK(stwo_exec_context_sync(o.ctx));
    CHECK(stwo_rv64_gkr_project_on(o.ctx, 1, tuples, weights, active, count, 3,
                                   challenges.words, n, d, verdict.words));
    CHECK(stwo_exec_context_sync(o.ctx));
    if (o.read(verdict)[0] != 3) throw std::runtime_error("pole verdict not sticky");
    cudaDeviceProp properties{};
    CHECK(cudaGetDeviceProperties(&properties, device));
    std::sort(timings.begin(), timings.end());
    Result result{device, count, o.allocated_bytes, timings[timings.size() / 2],
                  properties.name};
    o.close();
    return result;
}
int main(int argc, char** argv) {
    try {
        const int devices = argc > 1 ? std::stoi(argv[1]) : 1,
                  log = argc > 2 ? std::stoi(argv[2]) : 10;
        if ((devices != 1 && devices != 2 && devices != 4) || log < 2 || log > 22)
            throw std::runtime_error("usage: resident-smoke [1|2|4] [log_count 2..22]");
        int available = 0;
        const auto status = cudaGetDeviceCount(&available);
        if (status == cudaErrorNoDevice || status == cudaErrorInsufficientDriver) {
            std::fprintf(stderr, "SKIP: NVIDIA device/driver unavailable\n");
            return 77;
        }
        CHECK(status);
        if (available < devices) throw std::runtime_error("requested GPU count unavailable");
        std::vector<std::thread> workers;
        std::vector<Result> results(devices);
        std::vector<std::exception_ptr> errors(devices);
        for (int i = 0; i < devices; ++i)
            workers.emplace_back([&, i] {
                try {
                    results[i] = exercise(i, 1u << log, 11);
                } catch (...) {
                    errors[i] = std::current_exception();
                }
            });
        for (auto& w : workers) w.join();
        for (auto& e : errors)
            if (e) std::rethrow_exception(e);
        for (auto& r : results)
            std::printf(
                "{\"schema\":\"rv64-cuda-resident-smoke-v1\",\"device\":%d,\"name\":\"%s\","
                "\"count\":%u,\"allocated_bytes\":%llu,\"wave_median_ms\":%.6f,\"warmup\":3,"
                "\"repeats\":11,\"hot_h2d_bytes\":0,\"hot_d2h_bytes\":0,\"numerical_verified\":"
                "true,\"full_block_verified\":false}\n",
                r.device, r.name.c_str(), r.count, (unsigned long long)r.bytes, r.median_ms);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
