// T2 parity test + CUDA-event microbenchmark: chain_run (reference) vs
// chain_flow<Per> (M8 T2 dataflow executor), bit-exact outputs.
//   nvcc -O3 -std=c++17 -arch=sm_120 -I<repo>/src/backends/cuda/native/rv64 chain_flow_bench.cu -o chain_flow_bench
//   ./chain_flow_bench selftest            random DAGs + edge cases, all Per, plus graph API path
//   ./chain_flow_bench dump <file> [reps]  replay of a real node (STWO_RV64_M8_ASSIGNMENT_DUMP)
#include "circuit_fill_chain.cu"
#include <algorithm>
#include <chrono>
#include <random>
#include <string>
static cudaStream_t g_stream;
extern "C" int stwo_exec_context_lane_stream(void*, uint32_t, void** out) { *out = g_stream; return 0; }
extern "C" int stwo_exec_context_validate_allocation(void*, const void*, size_t) { return 0; }
extern "C" int stwo_exec_context_identity(void*, uint64_t* id) { *id = 1; return 0; }
using namespace stwo::cuda::circuit_fill;
#define CK(x) do { auto _e = (x); if (_e != cudaSuccess) { std::fprintf(stderr, "CUDA %s at %s:%d: %s\n", cudaGetErrorString(cudaError_t(_e)), __FILE__, __LINE__, #x); std::exit(2); } } while (0)
struct Plan {
    uint32_t values = 0;
    std::vector<StwoCircuitAssignmentTask> tasks;
    std::vector<uint32_t> ends, indices, init;  // init: values*4 words
    std::vector<StwoAssignmentGraphStep> steps;
};
struct Dev {
    uint32_t *values = nullptr, *values0 = nullptr, *records = nullptr, *indices = nullptr, *ends = nullptr, *status = nullptr;
    StwoCircuitAssignmentJob job{};
};
static Dev upload(const Plan& p) {
    Dev d;
    CK(cudaMalloc(&d.values, size_t(p.values) * 16));
    CK(cudaMalloc(&d.values0, size_t(p.values) * 16));
    CK(cudaMalloc(&d.records, std::max<size_t>(p.tasks.size(), 1) * 32));
    CK(cudaMalloc(&d.ends, std::max<size_t>(p.ends.size(), 1) * 4));
    CK(cudaMalloc(&d.status, 4));
    if (!p.indices.empty()) { CK(cudaMalloc(&d.indices, p.indices.size() * 4)); CK(cudaMemcpy(d.indices, p.indices.data(), p.indices.size() * 4, cudaMemcpyHostToDevice)); }
    CK(cudaMemcpy(d.values0, p.init.data(), size_t(p.values) * 16, cudaMemcpyHostToDevice));
    CK(cudaMemcpy(d.records, p.tasks.data(), p.tasks.size() * 32, cudaMemcpyHostToDevice));
    CK(cudaMemcpy(d.ends, p.ends.data(), p.ends.size() * 4, cudaMemcpyHostToDevice));
    d.job = {d.values, d.records, d.indices, d.status, p.values, uint32_t(p.tasks.size()), uint32_t(p.indices.size()), 0, 0, 0};
    return d;
}
static void release(Dev& d) {
    for (void* x : {(void*)d.values, (void*)d.values0, (void*)d.records, (void*)d.indices, (void*)d.ends, (void*)d.status}) if (x) cudaFree(x);
}
// Executor variants: -1 reference chain_run; otherwise chain_flow<kWide[v]>.
// -DT2_REFERENCE_ONLY builds against the pre-T2 circuit_fill_chain.cu (no
// chain_flow): the "before" kernel for the A/B.
#ifdef T2_REFERENCE_ONLY
#define VARIANTS(X)
#else
#define VARIANTS(X) X(0xffffffffu) X(16) X(32) X(64) X(128)
#endif
struct Variant { uint32_t wide; void (*launch)(StwoCircuitAssignmentJob, const uint32_t*, uint32_t, uint32_t); };
#define DEF(V) Variant{V, [](StwoCircuitAssignmentJob j, const uint32_t* e, uint32_t f, uint32_t l) { chain_flow<V><<<1, kChainThreads, 0, g_stream>>>(j, e, f, l); }},
static const Variant kVariants[] = {VARIANTS(DEF) Variant{0, nullptr}};
#undef DEF
static std::string vname(int v) {
    if (v < 0) return "chain_run";
    return "chain_flow<wide=" + (kVariants[v].wide == 0xffffffffu ? std::string("never") : std::to_string(kVariants[v].wide)) + ">";
}
static void launch_chain(int v, StwoCircuitAssignmentJob j, const uint32_t* ends, uint32_t fl, uint32_t lv) {
    if (v < 0) chain_run<<<1, kChainThreads, 0, g_stream>>>(j, ends, fl, lv);
    else kVariants[v].launch(j, ends, fl, lv);
    CK(cudaPeekAtLastError());
}
static std::vector<int> all_variants() { std::vector<int> v{-1}; for (int i = 0; i + 1 < int(sizeof kVariants / sizeof kVariants[0]); ++i) v.push_back(i); return v; }
struct Timing { double total_ms, chain_ms; };
static Timing run(const Plan& p, Dev& d, int per, bool time_chain) {
    CK(cudaMemcpyAsync(d.values, d.values0, size_t(p.values) * 16, cudaMemcpyDeviceToDevice, g_stream));
    CK(cudaMemsetAsync(d.status, 0, 4, g_stream));
    std::vector<cudaEvent_t> ev;
    auto mark = [&] { cudaEvent_t e; CK(cudaEventCreate(&e)); CK(cudaEventRecord(e, g_stream)); ev.push_back(e); };
    mark();
    std::vector<std::pair<size_t, size_t>> chain_pairs;
    for (const auto& s : p.steps) {
        auto j = d.job; j.first = s.first; j.count = s.count;
        if (s.kind == 1) {
            if (time_chain) mark();
            launch_chain(per, j, d.ends, s.first_level, s.levels);
            if (time_chain) { mark(); chain_pairs.push_back({ev.size() - 2, ev.size() - 1}); }
        } else {
            wide_level<<<(j.count + 127) / 128, 128, 0, g_stream>>>(j);
            CK(cudaPeekAtLastError());
        }
    }
    mark();
    CK(cudaStreamSynchronize(g_stream));
    float ms = 0; Timing t{0, 0};
    CK(cudaEventElapsedTime(&ms, ev.front(), ev.back())); t.total_ms = ms;
    for (auto [a, b] : chain_pairs) { CK(cudaEventElapsedTime(&ms, ev[a], ev[b])); t.chain_ms += ms; }
    for (auto e : ev) cudaEventDestroy(e);
    return t;
}
static std::vector<uint32_t> fetch_values(const Plan& p, const Dev& d, uint32_t& status) {
    std::vector<uint32_t> out(size_t(p.values) * 4);
    CK(cudaMemcpy(out.data(), d.values, out.size() * 4, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(&status, d.status, 4, cudaMemcpyDeviceToHost));
    return out;
}
static uint64_t fnv(const std::vector<uint32_t>& v) { uint64_t h = 1469598103934665603ull; for (auto w : v) { h ^= w; h *= 1099511628211ull; } return h; }
// Steps the way assignment_runs.zig initChain groups levels (max width 2048).
static void chain_steps(Plan& p) {
    p.steps.clear();
    uint32_t first = 0, i = 0, n = uint32_t(p.ends.size());
    while (i < n) {
        const uint32_t level = i;
        if (p.ends[i] - first > kChainMaxWidth) { p.steps.push_back({first, p.ends[i] - first, level, 1, 0}); first = p.ends[i]; ++i; continue; }
        uint32_t end = first;
        while (i < n && p.ends[i] - end <= kChainMaxWidth) end = p.ends[i++];
        if (end != first) p.steps.push_back({first, end - first, level, i - level, 1});
        first = end;
    }
}
// Random leveled DAG. Every variable has one producer in a strictly earlier
// level (or is a seed); args biased to the last few levels to build chains.
static Plan random_plan(uint64_t seed, uint32_t levels, int shape) {
    std::mt19937_64 r(seed);
    Plan p;
    const uint32_t seeds = 4096;
    std::vector<std::vector<uint32_t>> by_level;  // variables defined per level (level 0 = seeds)
    std::vector<uint32_t> nonzero;                 // seeds: safe inverse inputs
    by_level.emplace_back();
    for (uint32_t v = 0; v < seeds; ++v) { by_level[0].push_back(v); nonzero.push_back(v); }
    uint32_t next = seeds;
    std::vector<std::vector<StwoCircuitAssignmentTask>> lv(levels);
    for (uint32_t l = 0; l < levels; ++l) {
        uint32_t w;
        const uint32_t u = uint32_t(r() % 1000);
        if (shape == 0) w = u < 700 ? 1 + r() % 4 : u < 900 ? 1 + r() % 32 : u < 985 ? 33 + r() % 200 : u < 995 ? 600 + r() % 600 : 1025 + r() % 1100;
        else if (shape == 1) w = 1;               // one long chain
        else w = 64 + r() % 64;                   // mid-width Blake-like
        if (u == 999 && shape == 0) w = 3000;     // > chain max width: an ordinary step
        by_level.emplace_back();
        auto pick = [&]() -> uint32_t {
            const uint32_t back = 1 + uint32_t(std::min<uint64_t>(r() % 6 == 0 ? r() % (l + 1) : r() % 3, l));
            const auto& src = by_level[l + 1 - back];
            if (src.empty()) return uint32_t(r() % seeds);
            return src[r() % src.size()];
        };
        for (uint32_t i = 0; i < w; ++i) {
            StwoCircuitAssignmentTask t{};
            static const uint32_t kinds[] = {0, 1, 2, 3, 4, 5, 6, 6, 6, 6, 8, 9, 10, 11, 12, 13, 14, 15, 0, 2};
            t.kind = shape == 2 ? (r() % 4 ? 6u : 4u) : kinds[r() % 20];
            const unsigned ar = arity_of(t.kind);
            for (unsigned a = 0; a < ar; ++a) t.args[a] = pick();
            if (t.kind == 8) t.args[0] = nonzero[r() % nonzero.size()];
            if (t.kind == 9) t.args[1] = nonzero[r() % nonzero.size()];
            if (t.kind == 12 || t.kind == 13) t.args[1] = uint32_t(r() % 4);
            if (t.kind == 6) next = (next + 3) & ~3u;  // quads stay inside one permuted block
            t.out = next;
            const uint32_t outs = t.kind == 6 ? 4 : 1;
            for (uint32_t s = 0; s < outs; ++s) by_level[l + 1].push_back(next + s);
            next += outs;
            lv[l].push_back(t);
        }
    }
    // Scatter variable numbering (keeps the map honest): random bijection.
    p.values = ((next + 3) & ~3u) + 64;
    std::vector<uint32_t> perm(p.values);
    for (uint32_t i = 0; i < p.values; ++i) perm[i] = i;
    // keep kind-6 quads contiguous: permute in blocks of 4 above the seeds
    std::vector<uint32_t> blocks;
    for (uint32_t b = seeds / 4; b < p.values / 4; ++b) blocks.push_back(b);
    auto shuffled = blocks; std::shuffle(shuffled.begin(), shuffled.end(), r);
    for (size_t i = 0; i < blocks.size(); ++i) for (uint32_t s = 0; s < 4; ++s) perm[blocks[i] * 4 + s] = shuffled[i] * 4 + s;
    for (auto& level : lv) {
        std::shuffle(level.begin(), level.end(), r);
        for (auto& t : level) {
            t.out = perm[t.out];
            const unsigned ar = arity_of(t.kind);
            for (unsigned a = 0; a < ar; ++a) if (!((t.kind == 12 || t.kind == 13) && a == 1)) t.args[a] = perm[t.args[a]];
            p.tasks.push_back(t);
        }
        p.ends.push_back(uint32_t(p.tasks.size()));
    }
    p.init.resize(size_t(p.values) * 4);
    for (auto& w : p.init) w = uint32_t(r() % 2147483647u);
    for (uint32_t v = 0; v < seeds; ++v) if (!(p.init[v * 4] | p.init[v * 4 + 1] | p.init[v * 4 + 2] | p.init[v * 4 + 3])) p.init[v * 4] = 1;
    chain_steps(p);
    return p;
}
static int compare(const char* name, Plan& p) {
    Dev d = upload(p);
    uint32_t s_ref = 0;
    run(p, d, -1, false);
    const auto ref = fetch_values(p, d, s_ref);
    int bad = 0;
    {
        uint32_t s2 = 0;
        run(p, d, -1, false);
        const bool det = fetch_values(p, d, s2) == ref && s2 == s_ref;
        if (!det) { std::printf("PARITY %s reference chain_run NONDETERMINISTIC\n", name); ++bad; }
    }
    for (int per : all_variants()) {
        if (per < 0) continue;
        uint32_t s = 0;
        run(p, d, per, false);
        const auto got = fetch_values(p, d, s);
        // Values are compared on failing plans too: a failed task stores
        // nothing in both executors, so every value must still agree.
        const bool same = s == s_ref && got == ref;
        std::printf("PARITY %s %s tasks=%zu levels=%zu status_ref=%u status=%u values_equal=%d fnv=%016llx %s\n", name, vname(per).c_str(), p.tasks.size(), p.ends.size(), s_ref, s, int(got == ref), (unsigned long long)fnv(got), same ? "OK" : "MISMATCH");
        bad += !same;
    }
    release(d);
    return bad;
}
// Graph API path (whatever STWO_RV64_M8_ASSIGNMENT_FLOW says) vs reference.
static int compare_graph(Plan& p) {
    Dev d = upload(p);
    uint32_t s_ref = 0;
    run(p, d, -1, false);
    const auto ref = fetch_values(p, d, s_ref);
    CK(cudaMemcpy(d.values, d.values0, size_t(p.values) * 16, cudaMemcpyDeviceToDevice));
    CK(cudaMemset(d.status, 0, 4));
    auto j = d.job; j.first = 0; j.count = j.record_count;
    void* g = nullptr; int ctx = 0;
    int rc = stwo_assignment_graph_create_v1(&ctx, 1, &j, p.steps.data(), uint32_t(p.steps.size()), d.ends, uint32_t(p.ends.size()), &g);
    if (!rc) rc = stwo_assignment_graph_launch_v1(&ctx, 1, g, &j, d.ends, uint32_t(p.ends.size()));
    CK(cudaStreamSynchronize(g_stream));
    uint32_t s = 0;
    const auto got = fetch_values(p, d, s);
    // second launch (SetParams rebinding path)
    CK(cudaMemcpy(d.values, d.values0, size_t(p.values) * 16, cudaMemcpyDeviceToDevice));
    if (!rc) rc = stwo_assignment_graph_launch_v1(&ctx, 1, g, &j, d.ends, uint32_t(p.ends.size()));
    CK(cudaStreamSynchronize(g_stream));
    uint32_t s2 = 0;
    const auto got2 = fetch_values(p, d, s2);
    if (g) stwo_assignment_graph_destroy_v1(&ctx, g);
    const char* mode = std::getenv("STWO_RV64_M8_ASSIGNMENT_FLOW");
    const bool ok = !rc && s == s_ref && got == ref && got2 == ref;
    std::printf("PARITY graph_api flow_env=%s rc=%d status=%u values_equal=%d relaunch_equal=%d %s\n", mode ? mode : "unset", rc, s, int(got == ref), int(got2 == ref), ok ? "OK" : "MISMATCH");
    release(d);
    return !ok;
}
static int selftest() {
    int bad = 0;
    for (uint64_t sd = 1; sd <= 6; ++sd) { auto p = random_plan(sd, 3000, 0); bad += compare(("random-mixed-" + std::to_string(sd)).c_str(), p); }
    { auto p = random_plan(11, 5000, 1); bad += compare("chain-width1", p); }
    { auto p = random_plan(12, 600, 2); bad += compare("blake-mid", p); }
    // Edge: duplicate producer (malformed; later level wins in chain_run).
    {
        auto p = random_plan(21, 40, 1);
        auto t = p.tasks[5]; t.kind = 0; t.args[0] = 1; t.args[1] = 2; t.out = p.tasks[2].out;  // overwrite level-2 var at level 5
        if (p.tasks[2].kind == 6) t.out = p.tasks[2].out + 1;
        p.tasks[5] = t;
        bad += compare("edge-duplicate-producer", p);
    }
    // Edge: write-after-read (level 1 reads seed 7, level 6 overwrites seed 7).
    {
        auto p = random_plan(22, 40, 1);
        p.tasks[1].kind = 0; p.tasks[1].args[0] = 7; p.tasks[1].args[1] = 8;
        p.tasks[6].kind = 2; p.tasks[6].out = 7;
        bad += compare("edge-write-after-read", p);
    }
    // Edge: permutation (kind 7) inside a chunk.
    {
        auto p = random_plan(23, 200, 0);
        const uint32_t base = uint32_t(p.indices.size());
        for (uint32_t i = 0; i < 5; ++i) p.indices.push_back(100 + i);          // inputs
        for (uint32_t i = 0; i < 5; ++i) p.indices.push_back(p.values - 64 + i);  // outputs (unused vars)
        StwoCircuitAssignmentTask t{7u, p.values - 64, {base, 5, 0, 0, 0, 0}};
        p.tasks[p.ends[10]] = t;  // first task of level 11
        bad += compare("edge-permutation", p);
    }
    // Edge: failing tasks (bad kind, out of range arg, Blake out+4 overflow).
    {
        auto p = random_plan(24, 100, 0);
        p.tasks[p.ends[3]].kind = 16;
        bad += compare("edge-bad-kind", p);
        auto q = random_plan(25, 100, 0);
        q.tasks[q.ends[4]].kind = 0; q.tasks[q.ends[4]].args[0] = q.values + 5;
        bad += compare("edge-arg-range", q);
        auto r = random_plan(26, 100, 0);
        r.tasks[r.ends[5]].kind = 6; r.tasks[r.ends[5]].out = r.values - 2;
        bad += compare("edge-blake-out-range", r);
    }
    // Edge: in-chunk consumers of failing producers read the pre-chunk value
    // (refused arg range, Blake G refused with 4 registered outputs, zero
    // inverse, octet index > 3), in a width-1 chain so producer and consumer
    // share a dataflow chunk.
    {
        const auto consume = [](Plan& p, uint32_t level, uint32_t var) {
            auto& c = p.tasks[p.ends[level]];
            c.kind = 0; c.args[0] = var; c.args[1] = 9;
        };
        auto a = random_plan(41, 60, 1);
        a.tasks[a.ends[9]].kind = 0; a.tasks[a.ends[9]].args[0] = a.values + 1;
        consume(a, 10, a.tasks[a.ends[9]].out);
        bad += compare("edge-failed-producer-arg-range", a);
        // An existing Blake G task keeps its own four outputs (no duplicate
        // producer, so the chunk stays on the dataflow path).
        auto b = random_plan(42, 200, 1);
        uint32_t gl = 5;
        while (b.tasks[b.ends[gl]].kind != 6) ++gl;
        b.tasks[b.ends[gl]].args[3] = b.values + 7;
        consume(b, gl + 1, b.tasks[b.ends[gl]].out + 2);
        bad += compare("edge-failed-producer-blake", b);
        auto c = random_plan(43, 60, 1);
        c.tasks[c.ends[9]].kind = 8; c.tasks[c.ends[9]].args[0] = 4000;  // a seed (never produced), zeroed
        for (uint32_t w = 0; w < 4; ++w) c.init[size_t(4000) * 4 + w] = 0;
        consume(c, 10, c.tasks[c.ends[9]].out);
        bad += compare("edge-failed-producer-zero-inverse", c);
        auto d = random_plan(44, 60, 1);
        d.tasks[d.ends[9]].kind = 12; d.tasks[d.ends[9]].args[1] = 4;
        consume(d, 10, d.tasks[d.ends[9]].out);
        bad += compare("edge-failed-producer-octet", d);
    }
    // Edge: empty levels inside chunks and at window starts, and the smallest
    // plans (one level, one task).
    {
        auto p = random_plan(51, 2100, 0);
        std::vector<uint32_t> ends;
        for (size_t i = 0; i < p.ends.size(); ++i) { ends.push_back(p.ends[i]); if (i % 7 == 0 || i == 1023) ends.push_back(p.ends[i]); }
        ends.insert(ends.begin(), 0u);
        p.ends = ends;
        chain_steps(p);
        bad += compare("edge-empty-levels", p);
        auto one = random_plan(52, 1, 1);
        bad += compare("edge-one-level", one);
    }
    { auto p = random_plan(31, 2500, 0); bad += compare_graph(p); }
    std::printf("SELFTEST %s failures=%d\n", bad ? "FAIL" : "PASS", bad);
    return bad ? 1 : 0;
}
static Plan load_dump(const char* path) {
    FILE* f = std::fopen(path, "rb");
    if (!f) { std::perror(path); std::exit(2); }
    uint32_t h[8];
    if (std::fread(h, 4, 8, f) != 8 || h[0] != 0x54324e44u) { std::fprintf(stderr, "bad dump\n"); std::exit(2); }
    Plan p;
    const auto read = [&](void* dst, size_t size, size_t count) {
        if (count && std::fread(dst, size, count, f) != count) { std::fprintf(stderr, "short dump\n"); std::exit(2); }
    };
    p.values = h[2];
    p.steps.resize(h[6]); read(p.steps.data(), sizeof(StwoAssignmentGraphStep), h[6]);
    p.ends.resize(h[5]); read(p.ends.data(), 4, h[5]);
    p.tasks.resize(h[3]); read(p.tasks.data(), 32, h[3]);
    p.indices.resize(h[4]); read(p.indices.data(), 4, h[4]);
    p.init.resize(size_t(h[2]) * 4); read(p.init.data(), 4, p.init.size());
    std::fclose(f);
    return p;
}
static void census(const Plan& p) {
    uint64_t chain_levels = 0, chain_tasks = 0, kinds[17] = {}, wide_tasks = 0;
    uint64_t widths[6] = {};
    for (const auto& s : p.steps) {
        if (s.kind != 1) { wide_tasks += s.count; continue; }
        uint32_t b = s.first;
        for (uint32_t l = s.first_level; l < s.first_level + s.levels; ++l) {
            const uint32_t e = p.ends[l], w = e - b;
            ++chain_levels; chain_tasks += w;
            widths[w <= 32 ? 0 : w <= 128 ? 1 : w <= 256 ? 2 : w <= 512 ? 3 : w <= 1024 ? 4 : 5]++;
            for (uint32_t i = b; i < e; ++i) kinds[std::min<uint32_t>(p.tasks[i].kind, 16)]++;
            b = e;
        }
    }
    std::printf("CENSUS values=%u tasks=%zu levels=%zu steps=%zu chain_levels=%llu chain_tasks=%llu wide_tasks=%llu widths(<=32,<=128,<=256,<=512,<=1024,<=2048)=%llu,%llu,%llu,%llu,%llu,%llu kinds=",
        p.values, p.tasks.size(), p.ends.size(), p.steps.size(), (unsigned long long)chain_levels, (unsigned long long)chain_tasks, (unsigned long long)wide_tasks,
        (unsigned long long)widths[0], (unsigned long long)widths[1], (unsigned long long)widths[2], (unsigned long long)widths[3], (unsigned long long)widths[4], (unsigned long long)widths[5]);
    for (int k = 0; k <= 16; ++k) if (kinds[k]) std::printf("%d:%llu,", k, (unsigned long long)kinds[k]);
    std::printf("\n");
}
static int bench_plan(Plan& p, int reps, const std::vector<int>& pers);
static int bench(const char* path, int reps, const std::vector<int>& pers) {
    auto p = load_dump(path);
    return bench_plan(p, reps, pers);
}
static int bench_plan(Plan& p, int reps, const std::vector<int>& pers) {
    census(p);
    Dev d = upload(p);
    uint32_t s_ref = 0;
    run(p, d, -1, false);  // warm
    const auto ref = fetch_values(p, d, s_ref);
    std::printf("REF status=%u fnv=%016llx\n", s_ref, (unsigned long long)fnv(ref));
    int bad = 0;
    for (int per : pers) {
        std::vector<double> tot, ch;
        run(p, d, per, true);  // warm
        for (int i = 0; i < reps; ++i) { auto t = run(p, d, per, true); tot.push_back(t.total_ms); ch.push_back(t.chain_ms); }
        uint32_t s = 0;
        const auto got = fetch_values(p, d, s);
#ifdef STWO_T2_PROF
        if (per >= 0) {
            unsigned long long z[8] = {};
            CK(cudaMemcpyToSymbol(g_t2_prof, z, sizeof z));
            run(p, d, per, false);
            CK(cudaMemcpyFromSymbol(z, g_t2_prof, sizeof z));
            std::printf("PROF %s chunks=%llu cycles/chunk: build_load=%.0f insert=%.0f lookup=%.0f exec=%.0f\n", vname(per).c_str(), z[7], double(z[0]) / z[7], double(z[1]) / z[7], double(z[2]) / z[7], double(z[3]) / z[7]);
        }
#endif
        std::sort(tot.begin(), tot.end()); std::sort(ch.begin(), ch.end());
        const bool same = s == s_ref && got == ref;
        bad += !same;
        std::printf("BENCH exec=%s reps=%d node_ms_median=%.3f node_ms_min=%.3f node_ms_max=%.3f chain_ms_median=%.3f chain_ms_min=%.3f chain_ms_max=%.3f status=%u values_equal=%d fnv=%016llx\n",
            vname(per).c_str(), reps, tot[tot.size() / 2], tot.front(), tot.back(), ch[ch.size() / 2], ch.front(), ch.back(), s, int(got == ref), (unsigned long long)fnv(got));
    }
    release(d);
    return bad ? 1 : 0;
}
int main(int argc, char** argv) {
    CK(cudaStreamCreateWithFlags(&g_stream, cudaStreamNonBlocking));
    if (argc >= 2 && std::string(argv[1]) == "selftest") return selftest();
    if (argc >= 3 && std::string(argv[1]) == "dump") {
        const int reps = argc >= 4 ? std::atoi(argv[3]) : 7;
        return bench(argv[2], reps, all_variants());
    }
    if (argc >= 4 && std::string(argv[1]) == "synth") {
        auto p = random_plan(77, uint32_t(std::atoi(argv[3])), std::atoi(argv[2]));
        return bench_plan(p, 7, all_variants());
    }
    std::fprintf(stderr, "usage: %s selftest | dump <file> [reps]\n", argv[0]);
    return 2;
}
