// M9 witness-rowpar parity + CUDA-event microbenchmark on RECORDED real nodes.
//   nvcc -O3 -std=c++17 -arch=sm_120 -I<repo>/src/backends/cuda/native/rv64 bench.cu -o rowpar_bench
//   ./rowpar_bench <node.m9rp> <plan.m9rw>... [--reps N]
// Baseline: the production DAG executor exactly as outer_assignment launches
// it (assignment_runs.initChain, max width kChainMaxWidth: chain_run for runs
// of narrow levels, wide_level for wider levels). Candidate: m9 rowpar plans.
// Both arms start from the same seeded values; MAIN values must equal the
// recorded CPU reference (witness_plan.evaluate) byte for byte, status 0.
#include "circuit_fill_chain.cu"
#include "m9_witness_rowpar.cuh"
#include <string>
#include <vector>
#include <algorithm>
static cudaStream_t g_stream;
extern "C" int stwo_exec_context_lane_stream(void*, uint32_t, void** out) { *out = g_stream; return 0; }
extern "C" int stwo_exec_context_validate_allocation(void*, const void*, size_t) { return 0; }
extern "C" int stwo_exec_context_identity(void*, uint64_t* id) { *id = 1; return 0; }
#define CK(x) do { auto _e = (x); if (_e != cudaSuccess) { std::fprintf(stderr, "CUDA %s at %s:%d: %s\n", cudaGetErrorString(cudaError_t(_e)), __FILE__, __LINE__, #x); std::exit(2); } } while (0)
static std::vector<uint32_t> slurp(const char* path) {
    FILE* f = std::fopen(path, "rb");
    if (!f) { std::fprintf(stderr, "open %s\n", path); std::exit(2); }
    std::fseek(f, 0, SEEK_END); long n = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    std::vector<uint32_t> w(size_t(n) / 4);
    if (std::fread(w.data(), 4, w.size(), f) != w.size()) { std::fprintf(stderr, "short %s\n", path); std::exit(2); }
    std::fclose(f);
    return w;
}
struct Node { uint32_t vars, tasks, nidx, nlev, nseed; std::vector<uint32_t> raw; const uint32_t *ends, *records, *indices, *seeds, *ref; };
static Node load_node(const char* path) {
    Node n; n.raw = slurp(path);
    const uint32_t* h = n.raw.data();
    if (h[0] != 0x5052394du || h[1] != 1) { std::fprintf(stderr, "bad node\n"); std::exit(2); }
    n.vars = h[2]; n.tasks = h[3]; n.nidx = h[4]; n.nlev = h[5]; n.nseed = h[6];
    size_t o = 8;
    n.ends = h + o; o += n.nlev; n.records = h + o; o += size_t(n.tasks) * 8; n.indices = h + o; o += n.nidx;
    n.seeds = h + o; o += size_t(n.nseed) * 5; n.ref = h + o; o += size_t(n.vars) * 4;
    if (o != n.raw.size()) { std::fprintf(stderr, "node length\n"); std::exit(2); }
    return n;
}
struct RPlan { std::string name; uint32_t nlev, nstr, nunit, nblake; std::vector<uint32_t> raw; const uint32_t *lev, *str, *units, *blake; };
static RPlan load_plan(const char* path) {
    RPlan p; p.name = path; p.raw = slurp(path);
    const uint32_t* h = p.raw.data();
    if (h[0] != 0x5752394du || h[1] != 1) { std::fprintf(stderr, "bad plan\n"); std::exit(2); }
    p.nlev = h[2]; p.nstr = h[3]; p.nunit = h[4]; p.nblake = h[5];
    size_t o = 8;
    p.lev = h + o; o += p.nlev; p.str = h + o; o += p.nstr; p.units = h + o; o += p.nunit; p.blake = h + o; o += size_t(p.nblake) * 48;
    if (o != p.raw.size()) { std::fprintf(stderr, "plan length\n"); std::exit(2); }
    return p;
}
template <class T> static T* up(const T* src, size_t n) { T* d = nullptr; CK(cudaMalloc(&d, std::max<size_t>(n, 1) * sizeof(T))); if (n) CK(cudaMemcpy(d, src, n * sizeof(T), cudaMemcpyHostToDevice)); return d; }
struct Step { int kind; uint32_t first, count, level, levels; };  // kind 0 wide, 1 chain/run
int main(int argc, char** argv) {
    if (argc < 3) { std::fprintf(stderr, "usage: %s <node.m9rp> <plan.m9rw>... [--reps N] [--wide W]\n", argv[0]); return 2; }
    int reps = 5; uint32_t rp_wide = 2048; int threads = 512; const char* step_log = nullptr;
    std::vector<const char*> plans;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--reps") reps = std::atoi(argv[++i]); else if (a == "--wide") rp_wide = uint32_t(std::atoi(argv[++i])); else if (a == "--threads") threads = std::atoi(argv[++i]); else if (a == "--step-log") step_log = argv[++i]; else plans.push_back(argv[i]);
    }
    CK(cudaStreamCreateWithFlags(&g_stream, cudaStreamNonBlocking));
    Node n = load_node(argv[1]);
    std::vector<uint32_t> init(size_t(n.vars) * 4, 0);
    for (uint32_t s = 0; s < n.nseed; ++s) { const uint32_t* e = n.seeds + 5 * s; std::copy(e + 1, e + 5, init.begin() + size_t(e[0]) * 4); }
    uint32_t *values, *values0, *status;
    CK(cudaMalloc(&values, size_t(n.vars) * 16)); CK(cudaMalloc(&values0, size_t(n.vars) * 16)); CK(cudaMalloc(&status, 4));
    CK(cudaMemcpy(values0, init.data(), size_t(n.vars) * 16, cudaMemcpyHostToDevice));
    uint32_t* records = up(n.records, size_t(n.tasks) * 8);
    uint32_t* indices = n.nidx ? up(n.indices, n.nidx) : nullptr;
    uint32_t* ends = up(n.ends, n.nlev);
    StwoCircuitAssignmentJob job{values, records, indices, status, n.vars, n.tasks, n.nidx, 0, n.tasks, 0};
    // Production chain plan (assignment_runs.initChain).
    const uint32_t W = stwo::cuda::circuit_fill::kChainMaxWidth;
    std::vector<Step> dag;
    { uint32_t i = 0, first = 0;
      while (i < n.nlev) {
        const uint32_t level = i;
        if (n.ends[i] - first > W) { dag.push_back({0, first, n.ends[i] - first, i, 1}); first = n.ends[i]; ++i; continue; }
        uint32_t end = first;
        while (i < n.nlev && n.ends[i] - end <= W) { end = n.ends[i]; ++i; }
        if (end != first) dag.push_back({1, first, end - first, level, i - level});
        first = end;
      } }
    cudaEvent_t e0, e1; CK(cudaEventCreate(&e0)); CK(cudaEventCreate(&e1));
    std::vector<uint32_t> host(size_t(n.vars) * 4);
    auto reset = [&] { CK(cudaMemcpyAsync(values, values0, size_t(n.vars) * 16, cudaMemcpyDeviceToDevice, g_stream)); CK(cudaMemsetAsync(status, 0, 4, g_stream)); };
    auto check = [&](const char* what) -> bool {
        CK(cudaStreamSynchronize(g_stream));
        uint32_t st = 0; CK(cudaMemcpy(&st, status, 4, cudaMemcpyDeviceToHost));
        CK(cudaMemcpy(host.data(), values, host.size() * 4, cudaMemcpyDeviceToHost));
        size_t bad = 0, first = SIZE_MAX;
        for (size_t v = 0; v < n.vars; ++v) if (std::memcmp(&host[v * 4], n.ref + v * 4, 16)) { ++bad; if (first == SIZE_MAX) first = v; }
        std::printf("{\"arm\":\"%s\",\"status\":%u,\"mismatched_vars\":%zu,\"first_mismatch\":%lld}\n", what, st, bad, first == SIZE_MAX ? -1ll : (long long)first);
        return st == 0 && bad == 0;
    };
    auto time_it = [&](auto&& body) {
        std::vector<float> ms;
        for (int r = 0; r < reps; ++r) { reset(); CK(cudaEventRecord(e0, g_stream)); body(); CK(cudaEventRecord(e1, g_stream)); CK(cudaEventSynchronize(e1)); float t; CK(cudaEventElapsedTime(&t, e0, e1)); ms.push_back(t); }
        std::sort(ms.begin(), ms.end());
        return ms;
    };
    auto run_dag = [&] {
        for (const auto& s : dag) {
            if (s.kind == 0) { auto j = job; j.first = s.first; j.count = s.count; stwo::cuda::circuit_fill::wide_level<<<(s.count + 127) / 128, 128, 0, g_stream>>>(j); }
            else { auto j = job; j.first = s.first; j.count = s.count; stwo::cuda::circuit_fill::chain_run<<<1, stwo::cuda::circuit_fill::kChainThreads, 0, g_stream>>>(j, ends, s.level, s.levels); }
        }
        CK(cudaPeekAtLastError());
    };
    reset(); run_dag(); bool ok = check("dag_chain_run");
    auto ms = time_it(run_dag);
    std::printf("{\"arm\":\"dag_chain_run\",\"launches\":%zu,\"levels\":%u,\"ms_min\":%.3f,\"ms_med\":%.3f,\"ms_max\":%.3f,\"exact\":%s}\n", dag.size(), n.nlev, ms.front(), ms[ms.size() / 2], ms.back(), ok ? "true" : "false");
    for (const char* path : plans) {
        RPlan p = load_plan(path);
        namespace R = stwo::cuda::m9_rowpar;
        // Strand-ordered record stream (plan.zig can emit it directly).
        std::vector<StwoCircuitAssignmentTask> srec(p.nunit);
        for (uint32_t u = 0; u < p.nunit; ++u) {
            const uint32_t x = p.units[u];
            if (x >> 31) srec[u] = {R::kKindBlake, x & 0x7fffffffu, {0, 0, 0, 0, 0, 0}};
            else std::memcpy(&srec[u], n.records + size_t(x) * 8, 32);
        }
        R::Job J{job, up(p.lev, p.nlev), up(p.str, p.nstr), up(p.units, p.nunit), reinterpret_cast<const R::BlakeUnit*>(up(p.blake, size_t(p.nblake) * 48)), up(srec.data(), srec.size())};
        std::vector<Step> steps;
        { uint32_t i = 0, begin = 0;
          while (i < p.nlev) {
            if (p.lev[i] - begin > rp_wide) { steps.push_back({0, 0, p.lev[i] - begin, i, 1}); begin = p.lev[i]; ++i; continue; }
            const uint32_t level = i;
            while (i < p.nlev && p.lev[i] - begin <= rp_wide) { begin = p.lev[i]; ++i; }
            steps.push_back({1, 0, 0, level, i - level});
          } }
        auto run = [&] {
            for (const auto& s : steps) {
                if (s.kind == 0) R::rowpar_wide<<<(s.count + 127) / 128, 128, 0, g_stream>>>(J, s.level);
                else if (threads == 128) R::rowpar_run_t<128><<<1, 128, 0, g_stream>>>(J, s.level, s.levels);
                else if (threads == 256) R::rowpar_run_t<256><<<1, 256, 0, g_stream>>>(J, s.level, s.levels);
                else if (threads == 512) R::rowpar_run_t<512><<<1, 512, 0, g_stream>>>(J, s.level, s.levels);
                else R::rowpar_run<<<1, R::kThreads, 0, g_stream>>>(J, s.level, s.levels);
            }
            if (p.nblake) R::rowpar_blake_fill<<<(p.nblake + 127) / 128, 128, 0, g_stream>>>(J, p.nblake);
            CK(cudaPeekAtLastError());
        };
        if (step_log) {
            // Per-launch CUDA events (diagnostic; one run): duration and shape.
            FILE* lf = std::fopen((std::string(step_log) + ".tsv").c_str(), "w");
            std::vector<cudaEvent_t> ev(steps.size() + 2);
            for (auto& e : ev) CK(cudaEventCreate(&e));
            reset();
            CK(cudaEventRecord(ev[0], g_stream));
            for (size_t k = 0; k < steps.size(); ++k) {
                const auto& s = steps[k];
                if (s.kind == 0) R::rowpar_wide<<<(s.count + 127) / 128, 128, 0, g_stream>>>(J, s.level);
                else if (threads == 256) R::rowpar_run_t<256><<<1, 256, 0, g_stream>>>(J, s.level, s.levels);
                else if (threads == 128) R::rowpar_run_t<128><<<1, 128, 0, g_stream>>>(J, s.level, s.levels);
                else R::rowpar_run_t<512><<<1, 512, 0, g_stream>>>(J, s.level, s.levels);
                CK(cudaEventRecord(ev[k + 1], g_stream));
            }
            if (p.nblake) R::rowpar_blake_fill<<<(p.nblake + 127) / 128, 128, 0, g_stream>>>(J, p.nblake);
            CK(cudaEventRecord(ev.back(), g_stream));
            CK(cudaStreamSynchronize(g_stream));
            std::fprintf(lf, "step\tkind\tlevel\tlevels\tstrands\tunits\tblake\tmax_width\tms\n");
            for (size_t k = 0; k < steps.size(); ++k) {
                const auto& s = steps[k];
                const uint32_t sb = s.level ? p.lev[s.level - 1] : 0, se = p.lev[s.level + s.levels - 1];
                const uint32_t ub = sb ? p.str[sb - 1] : 0, ue = se ? p.str[se - 1] : 0;
                uint32_t blake = 0, maxw = 0;
                for (uint32_t u = ub; u < ue; ++u) blake += (p.units[u] >> 31);
                for (uint32_t l = s.level; l < s.level + s.levels; ++l) maxw = std::max(maxw, p.lev[l] - (l ? p.lev[l - 1] : 0));
                float t; CK(cudaEventElapsedTime(&t, ev[k], ev[k + 1]));
                std::fprintf(lf, "%zu\t%d\t%u\t%u\t%u\t%u\t%u\t%u\t%.4f\n", k, s.kind, s.level, s.levels, se - sb, ue - ub, blake, maxw, t);
            }
            { float t; CK(cudaEventElapsedTime(&t, ev[steps.size()], ev.back())); std::fprintf(lf, "fill\t2\t0\t0\t0\t0\t%u\t0\t%.4f\n", p.nblake, t); }
            std::fclose(lf);
            for (auto& e : ev) cudaEventDestroy(e);
        }
        reset(); run(); const bool exact = check(path);
        // Byte identity against the DAG arm as well (same buffer contents).
        auto t = time_it(run);
        std::printf("{\"arm\":\"%s\",\"threads\":%d,\"launches\":%zu,\"levels\":%u,\"strands\":%u,\"blake_units\":%u,\"ms_min\":%.3f,\"ms_med\":%.3f,\"ms_max\":%.3f,\"speedup_med\":%.2f,\"exact\":%s}\n", path, threads, steps.size(), p.nlev, p.nstr, p.nblake, t.front(), t[t.size() / 2], t.back(), ms[ms.size() / 2] / t[t.size() / 2], exact ? "true" : "false");
        cudaFree((void*)J.level_ends); cudaFree((void*)J.strand_ends); cudaFree((void*)J.units); cudaFree((void*)J.blake); cudaFree((void*)J.srec);
    }
    for (void* x : {(void*)values, (void*)values0, (void*)status, (void*)records, (void*)indices, (void*)ends}) if (x) cudaFree(x);
    return 0;
}
