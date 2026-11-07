// M9 Poseidon2 mixed-leaf gate (default-off STWO_RV64_M9_POSEIDON2_LEAVES).
//   parity VECTORS.txt          GPU == Zig reference (both permutation variants)
//   bench REPS log:w[,log:w...]  CUDA-event medians: Blake2s mixed_leaf_kernel
//                                (stwo_blake2s_mixed_leaf_on, production prefixed
//                                framing) vs P2 v1/v2 at the SAME segments, plus
//                                the full retained Merkle tree over those leaves.
// Build (pod), N=src/backends/cuda/native, D=tests/cuda/rv64/m9_poseidon2:
//   nvcc -O3 -std=c++17 -arch=sm_120 -I $N -I $N/commitment $D/m9_poseidon2_leaves.cu
//     $D/poseidon2_mixed_leaf.cu $N/commitment/progressive.cu $N/commitment/merkle.cu -o m9p2
#include <cuda_runtime.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>
#include "mixed_layout.h"

using stwo::cuda::blake2s::MixedSegment;
struct Hash { uint32_t words[8]; };
extern "C" int stwo_p2m31_mixed_seeded_on(uint32_t, uint32_t, const MixedSegment*, uint32_t, uint32_t,
    const uint32_t*, uint64_t, uint32_t*, uint64_t, uint32_t*, uint64_t, uint32_t*, uint32_t, void*);
extern "C" int stwo_p2m31_parent_layer_on(const uint32_t*, uint32_t, uint32_t*, uint32_t, void*);
extern "C" int stwo_blake2s_mixed_leaf_on(uint32_t, uint32_t, const MixedSegment*, void*, void*);
extern "C" int stwo_blake2s_layer_on(const void*, uint32_t, void*, void*);
// Production default seeded entry (pcs_pipeline.cuh): 96-byte eager states.
extern "C" int stwo_blake2s_mixed_seeded_eager_on(uint32_t, uint32_t, const MixedSegment*, uint32_t, uint32_t,
    const void*, void*, void*, void*);

#define CU(x) do { auto e_ = (x); if (e_ != cudaSuccess) throw std::runtime_error(std::string(#x) + ": " + cudaGetErrorString(cudaError_t(e_))); } while (0)

__device__ __host__ inline uint32_t column_word(uint64_t seed, uint64_t column, uint64_t row) {
    uint64_t z = (seed << 40) ^ (column << 24) ^ row;
    z += 0x9e3779b97f4a7c15ull;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    z ^= z >> 31;
    const uint32_t v = uint32_t(z >> 33);
    return v == 0x7fffffffu ? 0 : v;
}
__global__ void fill(uint32_t* out, uint64_t seed, uint32_t base, uint32_t width, uint32_t log) {
    const uint64_t rows = 1ull << log;
    const uint64_t i = uint64_t(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= rows * width) return;
    out[i] = column_word(seed, base + i / rows, i % rows);
}

struct Device {
    std::vector<void*> owned;
    ~Device() { for (auto p : owned) cudaFree(p); }
    template <class T> T* alloc(size_t n) { void* p = nullptr; CU(cudaMalloc(&p, std::max<size_t>(n, 1) * sizeof(T))); owned.push_back(p); return static_cast<T*>(p); }
};

struct Seg { uint32_t log, width, base; };
struct Case {
    std::string name; char kind; uint64_t seed; uint32_t log, split;
    std::vector<Seg> segs;
    std::vector<std::pair<uint32_t, std::vector<uint32_t>>> rows, prefix;
};

static std::vector<Case> parse(const char* path) {
    FILE* f = std::fopen(path, "r");
    if (!f) throw std::runtime_error("open vectors");
    std::vector<Case> out;
    char tag[16];
    while (std::fscanf(f, "%15s", tag) == 1) {
        if (!std::strcmp(tag, "CASE")) {
            Case c; char name[128], kind; unsigned long long seed; unsigned log, nseg, split, nrows, npre;
            if (std::fscanf(f, "%127s %c %llu %u %u %u %u %u", name, &kind, &seed, &log, &nseg, &split, &nrows, &npre) != 8) throw std::runtime_error("CASE");
            c.name = name; c.kind = kind; c.seed = seed; c.log = log; c.split = split;
            out.push_back(c);
        } else if (!std::strcmp(tag, "SEG")) {
            Seg s; if (std::fscanf(f, "%u %u %u", &s.log, &s.width, &s.base) != 3) throw std::runtime_error("SEG");
            out.back().segs.push_back(s);
        } else if (!std::strcmp(tag, "R") || !std::strcmp(tag, "P")) {
            const bool r = tag[0] == 'R'; unsigned row; std::vector<uint32_t> v(r ? 9 : 24);
            if (std::fscanf(f, "%u", &row) != 1) throw std::runtime_error("row");
            for (auto& x : v) if (std::fscanf(f, "%u", &x) != 1) throw std::runtime_error("word");
            (r ? out.back().rows : out.back().prefix).push_back({row, v});
        } else if (std::strcmp(tag, "END")) throw std::runtime_error("tag");
    }
    std::fclose(f);
    return out;
}

// Materialise segments with aliasing on (log, base, width).
static std::vector<MixedSegment> materialise(Device& d, const std::vector<Seg>& segs, uint64_t seed, cudaStream_t st) {
    std::map<std::tuple<uint32_t, uint32_t, uint32_t>, uint32_t*> slabs;
    std::vector<MixedSegment> out;
    for (auto s : segs) {
        if (!s.width) continue;
        auto key = std::make_tuple(s.log, s.base, s.width);
        auto it = slabs.find(key);
        uint32_t* p;
        const uint64_t rows = 1ull << s.log, n = rows * s.width;
        if (it == slabs.end()) {
            p = d.alloc<uint32_t>(n);
            fill<<<unsigned((n + 255) / 256), 256, 0, st>>>(p, seed, s.base, s.width, s.log);
            CU(cudaPeekAtLastError());
            slabs[key] = p;
        } else p = it->second;
        out.push_back(MixedSegment{p, size_t(rows), size_t(n), uint32_t(rows), 0});
    }
    return out;
}

static int parity(const char* path) {
    auto cases = parse(path);
    cudaStream_t st; CU(cudaStreamCreateWithFlags(&st, cudaStreamNonBlocking));
    unsigned pass = 0, fail = 0; uint64_t rows_checked = 0, prefix_checked = 0;
    for (auto& c : cases) {
        for (uint32_t variant = 1; variant <= 2; ++variant) {
            Device d;
            auto segs = materialise(d, c.segs, c.seed, st);
            const uint32_t size = 1u << c.log;
            auto* status = d.alloc<uint32_t>(1); CU(cudaMemsetAsync(status, 0, 4, st));
            auto* digests = d.alloc<uint32_t>(size_t(size) * 9);
            std::vector<uint32_t> host_prefix;
            uint32_t seed_size = 0;
            if (c.kind == 'C') {
                // Split in descriptor space: count real (non-empty) segments before split.
                uint32_t before = 0, absorbed = 0;
                for (uint32_t i = 0; i < c.split; ++i) if (c.segs[i].width) { ++before; absorbed += c.segs[i].width; }
                seed_size = 1u << c.segs[c.split - 1].log;
                auto* bank = d.alloc<uint32_t>(size_t(seed_size) * 24);
                CU(cudaError_t(stwo_p2m31_mixed_seeded_on(seed_size, before, segs.data(), 0, 0, nullptr, 0, bank, uint64_t(seed_size) * 24, nullptr, 0, status, variant, st)));
                CU(cudaError_t(stwo_p2m31_mixed_seeded_on(size, uint32_t(segs.size()) - before, segs.data() + before, absorbed, seed_size, bank, uint64_t(seed_size) * 24, nullptr, 0, digests, uint64_t(size) * 9, status, variant, st)));
                host_prefix.resize(size_t(seed_size) * 24);
                CU(cudaMemcpyAsync(host_prefix.data(), bank, host_prefix.size() * 4, cudaMemcpyDeviceToHost, st));
            } else {
                CU(cudaError_t(stwo_p2m31_mixed_seeded_on(size, uint32_t(segs.size()), segs.data(), 0, 0, nullptr, 0, nullptr, 0, digests, uint64_t(size) * 9, status, variant, st)));
            }
            std::vector<uint32_t> host(size_t(size) * 9); uint32_t flag = 0;
            CU(cudaMemcpyAsync(host.data(), digests, host.size() * 4, cudaMemcpyDeviceToHost, st));
            CU(cudaMemcpyAsync(&flag, status, 4, cudaMemcpyDeviceToHost, st));
            CU(cudaStreamSynchronize(st));
            bool ok = flag == 0;
            for (auto& [row, want] : c.rows) { ok &= !std::memcmp(&host[size_t(row) * 9], want.data(), 36); ++rows_checked; }
            for (auto& [row, want] : c.prefix) {
                for (uint32_t k = 0; k < 24; ++k) ok &= host_prefix[size_t(k) * seed_size + row] == want[k];
                ++prefix_checked;
            }
            (ok ? pass : fail)++;
            if (!ok) std::printf("FAIL %s variant=%u status=%u\n", c.name.c_str(), variant, flag);
        }
    }
    // Refusal checks on the host contract.
    Device d; uint32_t* st32 = d.alloc<uint32_t>(1); uint32_t* out = d.alloc<uint32_t>(9 * 4);
    MixedSegment bad{out, 4, 4, 3, 0};  // non power-of-two source
    const bool refuses = stwo_p2m31_mixed_seeded_on(4, 1, &bad, 0, 0, nullptr, 0, nullptr, 0, out, 36, st32, 2, st) != 0;
    // Non-canonical input sets the status bit.
    uint32_t* col = d.alloc<uint32_t>(2); uint32_t vals[2] = {1, 0x7fffffffu};
    CU(cudaMemcpy(col, vals, 8, cudaMemcpyHostToDevice)); CU(cudaMemset(st32, 0, 4));
    MixedSegment nc{col, 2, 2, 2, 0}; uint32_t* o2 = d.alloc<uint32_t>(18);
    CU(cudaError_t(stwo_p2m31_mixed_seeded_on(2, 1, &nc, 0, 0, nullptr, 0, nullptr, 0, o2, 18, st32, 2, st)));
    uint32_t flag = 0; CU(cudaMemcpyAsync(&flag, st32, 4, cudaMemcpyDeviceToHost, st)); CU(cudaStreamSynchronize(st));
    cudaDeviceProp prop; CU(cudaGetDeviceProperties(&prop, 0));
    std::printf("PARITY {\"device\":\"%s\",\"cases\":%zu,\"runs_pass\":%u,\"runs_fail\":%u,\"digest_rows_checked\":%llu,\"prefix_rows_checked\":%llu,\"refuses_bad_geometry\":%s,\"noncanonical_status\":%u}\n",
                prop.name, cases.size(), pass, fail, (unsigned long long)rows_checked, (unsigned long long)prefix_checked, refuses ? "true" : "false", flag);
    CU(cudaStreamDestroy(st));
    return fail == 0 && refuses && flag == 1 ? 0 : 1;
}

struct Events {
    cudaEvent_t a, b;
    Events() { CU(cudaEventCreate(&a)); CU(cudaEventCreate(&b)); }
    ~Events() { cudaEventDestroy(a); cudaEventDestroy(b); }
    template <class F> float time(cudaStream_t s, F f) { CU(cudaEventRecord(a, s)); f(); CU(cudaEventRecord(b, s)); CU(cudaEventSynchronize(b)); float ms; CU(cudaEventElapsedTime(&ms, a, b)); return ms; }
};
static float median(std::vector<float> v) { std::sort(v.begin(), v.end()); return v[v.size() / 2]; }

static int bench(uint32_t reps, const char* spec) {
    std::vector<Seg> segs; uint32_t base = 0;
    for (const char* p = spec; *p;) {
        unsigned log, width; int n = 0;
        if (std::sscanf(p, "%u:%u%n", &log, &width, &n) != 2) throw std::runtime_error("spec");
        segs.push_back({log, width, base}); base += width; p += n; if (*p == ',') ++p;
    }
    std::sort(segs.begin(), segs.end(), [](Seg x, Seg y) { return x.log < y.log; });
    const uint32_t log = segs.back().log, size = 1u << log;
    uint64_t cells = 0, words = 0;
    for (auto s : segs) { cells += (uint64_t(1) << s.log) * s.width; words += s.width; }
    size_t free_b = 0, total_b = 0; CU(cudaMemGetInfo(&free_b, &total_b));
    uint64_t need = cells * 4 + uint64_t(size) * (32 + 36) * 2 + (64ull << 20);
    bool trees = true;
    if (need > free_b) { trees = false; need = cells * 4 + uint64_t(size) * (32 + 36) + (64ull << 20); }
    if (need > free_b) { std::printf("SKIP {\"spec\":\"%s\",\"need_bytes\":%llu,\"free_bytes\":%zu}\n", spec, (unsigned long long)need, free_b); return 0; }
    cudaStream_t st; CU(cudaStreamCreateWithFlags(&st, cudaStreamNonBlocking));
    Device d;
    auto ms = materialise(d, segs, 0x5eed, st);
    auto* status = d.alloc<uint32_t>(1); CU(cudaMemsetAsync(status, 0, 4, st));
    auto* btree = d.alloc<Hash>(size_t(trees ? 2 : 1) * size);
    auto* ptree = d.alloc<uint32_t>(size_t(trees ? 2 : 1) * size * 9);
    CU(cudaStreamSynchronize(st));
    auto blake_leaf = [&] { CU(cudaError_t(stwo_blake2s_mixed_leaf_on(size, uint32_t(ms.size()), ms.data(), btree, st))); };
    auto blake_tree = [&] { Hash* prev = btree; Hash* out = btree + size; for (uint32_t n = size; n > 1; n /= 2) { CU(cudaError_t(stwo_blake2s_layer_on(prev, n / 2, out, st))); prev = out; out += n / 2; } };
    auto p2_leaf = [&](uint32_t v) { CU(cudaError_t(stwo_p2m31_mixed_seeded_on(size, uint32_t(ms.size()), ms.data(), 0, 0, nullptr, 0, nullptr, 0, ptree, uint64_t(size) * 9, status, v, st))); };
    auto p2_tree = [&](uint32_t v) { uint32_t* prev = ptree; uint32_t* out = ptree + size_t(size) * 9; for (uint32_t n = size; n > 1; n /= 2) { CU(cudaError_t(stwo_p2m31_parent_layer_on(prev, n / 2, out, v, st))); prev = out; out += size_t(n / 2) * 9; } };
    Events ev;
    std::vector<float> bl, bt, p1l, p1t, p2l, p2t;
    for (uint32_t r = 0; r < reps + 1; ++r) {  // first round is warm-up
        float t;
        t = ev.time(st, blake_leaf); if (r) bl.push_back(t);
        t = trees ? ev.time(st, blake_tree) : 0.f; if (r) bt.push_back(t);
        t = ev.time(st, [&] { p2_leaf(1); }); if (r) p1l.push_back(t);
        t = trees ? ev.time(st, [&] { p2_tree(1); }) : 0.f; if (r) p1t.push_back(t);
        t = ev.time(st, [&] { p2_leaf(2); }); if (r) p2l.push_back(t);
        t = trees ? ev.time(st, [&] { p2_tree(2); }) : 0.f; if (r) p2t.push_back(t);
    }
    uint32_t flag = 0; uint32_t root[9]; Hash broot;
    CU(cudaMemcpy(&flag, status, 4, cudaMemcpyDeviceToHost));
    CU(cudaMemcpy(root, ptree + (trees ? (size_t(2) * size - 2) * 9 : 0), 36, cudaMemcpyDeviceToHost));
    CU(cudaMemcpy(&broot, btree + (trees ? size_t(2) * size - 2 : 0), 32, cudaMemcpyDeviceToHost));
    // Permutation count: per row floor(words/12)+1 leaf perms, 2 per parent.
    const uint64_t leaf_perms = uint64_t(size) * (words / 12 + 1), node_perms = 2ull * (size - 1);
    uint64_t blake_comp = 0;  // prefix block is a precomputed IV: ceil(4*words/64)
    blake_comp = uint64_t(size) * std::max<uint64_t>(1, (words * 4 + 63) / 64);
    cudaDeviceProp prop; CU(cudaGetDeviceProperties(&prop, 0));
    std::printf("BENCH {\"device\":\"%s\",\"spec\":\"%s\",\"log_size\":%u,\"segments\":%zu,\"leaf_words\":%llu,\"input_cells\":%llu,\"reps\":%u,"
                "\"blake_leaf_ms\":%.6f,\"blake_tree_ms\":%.6f,\"p2v1_leaf_ms\":%.6f,\"p2v1_tree_ms\":%.6f,\"p2v2_leaf_ms\":%.6f,\"p2v2_tree_ms\":%.6f,"
                "\"trees\":%s,\"p2_leaf_perms\":%llu,\"p2_node_perms\":%llu,\"blake_leaf_compressions_model\":%llu,\"status\":%u,\"p2_root0\":%u,\"blake_root0\":%u}\n",
                prop.name, spec, log, ms.size(), (unsigned long long)words, (unsigned long long)cells, reps,
                median(bl), median(bt), median(p1l), median(p1t), median(p2l), median(p2t),
                trees ? "true" : "false", (unsigned long long)leaf_perms, (unsigned long long)node_perms, (unsigned long long)blake_comp, flag, root[0], broot.words[0]);
    CU(cudaStreamDestroy(st));
    return flag ? 1 : 0;
}


// Prefix-bank chain, one call per distinct source height (the production
// pcs_pipeline.cuh pattern): Blake eager seeded vs P2 seeded, then the
// retained interior layers. Prints per-tree medians.
static int chain(uint32_t reps, const char* arg) {
    std::string name(arg), spec;
    const char* eq = std::strchr(arg, '=');
    if (eq) { name.assign(arg, eq - arg); spec = eq + 1; } else spec = arg;
    std::vector<Seg> segs; uint32_t base = 0;
    for (const char* p = spec.c_str(); *p;) {
        unsigned log, width; int n = 0;
        if (std::sscanf(p, "%u:%u%n", &log, &width, &n) != 2) throw std::runtime_error("spec");
        if (width) segs.push_back({log, width, base}); base += width; p += n; if (*p == ',') ++p;
    }
    std::stable_sort(segs.begin(), segs.end(), [](Seg x, Seg y) { return x.log < y.log; });
    // Heights below 2 rows are lifted from a 2-row seed (Blake/P2 contract).
    for (auto& s : segs) if (s.log < 1) s.log = 1;
    const uint32_t log = segs.back().log, size = 1u << log;
    uint64_t cells = 0;
    for (auto s : segs) cells += (uint64_t(1) << s.log) * s.width;
    size_t free_b = 0, total_b = 0; CU(cudaMemGetInfo(&free_b, &total_b));
    const uint64_t need = cells * 4 + uint64_t(size) * (96 + 96 + 64 + 72) + (64ull << 20);
    if (need > free_b) { std::printf("SKIP {\"tree\":\"%s\",\"need_bytes\":%llu,\"free_bytes\":%zu}\n", name.c_str(), (unsigned long long)need, free_b); return 0; }
    cudaStream_t st; CU(cudaStreamCreateWithFlags(&st, cudaStreamNonBlocking));
    Device d;
    auto ms = materialise(d, segs, 0x5eed, st);
    // Group descriptors by height.
    std::vector<std::pair<uint32_t, uint32_t>> groups;  // (first index, count)
    std::vector<uint32_t> group_words;
    for (uint32_t i = 0; i < ms.size(); ++i) {
        if (groups.empty() || ms[groups.back().first].source_size != ms[i].source_size) { groups.push_back({i, 0}); group_words.push_back(0); }
        groups.back().second++; group_words.back() += segs[i].width;
    }
    auto* status = d.alloc<uint32_t>(1); CU(cudaMemsetAsync(status, 0, 4, st));
    char* bbank[2] = {d.alloc<char>(size_t(size) * 96), d.alloc<char>(size_t(size) * 96)};
    uint32_t* pbank[2] = {d.alloc<uint32_t>(size_t(size) * 24), d.alloc<uint32_t>(size_t(size) * 24)};
    auto* btree = d.alloc<Hash>(size_t(2) * size);
    auto* ptree = d.alloc<uint32_t>(size_t(2) * size * 9);
    CU(cudaStreamSynchronize(st));
    uint64_t p2_perms = 0, blake_comp = 0;
    {
        uint64_t absorbed = 0, prev_rows = 0;
        for (uint32_t g = 0; g < groups.size(); ++g) {
            const uint64_t rows = ms[groups[g].first].source_size, w = group_words[g];
            const uint64_t after = absorbed + w;
            const bool last = g + 1 == groups.size();
            p2_perms += rows * (after / 12 - absorbed / 12) + (last ? rows : 0);
            // Blake eager: blocks completed strictly before the final block.
            const uint64_t full_after = last ? (after ? (after - 1) / 16 + 1 : 1) : after / 16;
            blake_comp += rows * (full_after - absorbed / 16);
            absorbed = after; prev_rows = rows;
        }
        (void)prev_rows;
        p2_perms += 2ull * (size - 1); blake_comp += size - 1;
    }
    auto blake_chain = [&] {
        uint32_t absorbed = 0, seed_size = 0; int in = -1;
        for (uint32_t g = 0; g < groups.size(); ++g) {
            const bool last = g + 1 == groups.size();
            const uint32_t rows = ms[groups[g].first].source_size; const int out = in == 0 ? 1 : 0;
            CU(cudaError_t(stwo_blake2s_mixed_seeded_eager_on(rows, groups[g].second, ms.data() + groups[g].first, absorbed, seed_size,
                in < 0 ? nullptr : bbank[in], last ? nullptr : bbank[out], last ? (void*)btree : nullptr, st)));
            absorbed += group_words[g]; seed_size = rows; in = out;
        }
        Hash* prev = btree; Hash* o = btree + size;
        for (uint32_t n = size; n > 1; n /= 2) { CU(cudaError_t(stwo_blake2s_layer_on(prev, n / 2, o, st))); prev = o; o += n / 2; }
    };
    auto p2_chain = [&] {
        uint32_t absorbed = 0, seed_size = 0; int in = -1;
        for (uint32_t g = 0; g < groups.size(); ++g) {
            const bool last = g + 1 == groups.size();
            const uint32_t rows = ms[groups[g].first].source_size; const int out = in == 0 ? 1 : 0;
            CU(cudaError_t(stwo_p2m31_mixed_seeded_on(rows, groups[g].second, ms.data() + groups[g].first, absorbed, seed_size,
                in < 0 ? nullptr : pbank[in], in < 0 ? 0 : uint64_t(size) * 24, last ? nullptr : pbank[out], last ? 0 : uint64_t(size) * 24,
                last ? ptree : nullptr, last ? uint64_t(size) * 9 : 0, status, 1, st)));
            absorbed += group_words[g]; seed_size = rows; in = out;
        }
        uint32_t* prev = ptree; uint32_t* o = ptree + size_t(size) * 9;
        for (uint32_t n = size; n > 1; n /= 2) { CU(cudaError_t(stwo_p2m31_parent_layer_on(prev, n / 2, o, 1, st))); prev = o; o += size_t(n / 2) * 9; }
    };
    // Cross-check: chained P2 leaves equal the single flat call on 4096 rows.
    {
        auto* flat = d.alloc<uint32_t>(size_t(size) * 9);
        p2_chain();
        CU(cudaError_t(stwo_p2m31_mixed_seeded_on(size, uint32_t(ms.size()), ms.data(), 0, 0, nullptr, 0, nullptr, 0, flat, uint64_t(size) * 9, status, 1, st)));
        const size_t n = std::min<size_t>(size, 4096) * 9;
        std::vector<uint32_t> a(n), b(n);
        CU(cudaMemcpyAsync(a.data(), ptree + (size_t(size) - n / 9) * 9, n * 4, cudaMemcpyDeviceToHost, st));
        CU(cudaMemcpyAsync(b.data(), flat + (size_t(size) - n / 9) * 9, n * 4, cudaMemcpyDeviceToHost, st));
        CU(cudaStreamSynchronize(st));
        if (a != b) throw std::runtime_error("chained != flat P2 leaves");
    }
    Events ev; std::vector<float> bt, pt;
    for (uint32_t r = 0; r < reps + 1; ++r) {
        float t = ev.time(st, blake_chain); if (r) bt.push_back(t);
        t = ev.time(st, p2_chain); if (r) pt.push_back(t);
    }
    uint32_t flag = 0; CU(cudaMemcpy(&flag, status, 4, cudaMemcpyDeviceToHost));
    std::printf("CHAIN {\"tree\":\"%s\",\"log_size\":%u,\"groups\":%zu,\"input_cells\":%llu,\"reps\":%u,\"blake_ms\":%.6f,\"p2_ms\":%.6f,"
                "\"p2_perms_model\":%llu,\"blake_compressions_model\":%llu,\"status\":%u}\n",
                name.c_str(), log, groups.size(), (unsigned long long)cells, reps, median(bt), median(pt),
                (unsigned long long)p2_perms, (unsigned long long)blake_comp, flag);
    CU(cudaStreamDestroy(st));
    return flag ? 1 : 0;
}

int main(int argc, char** argv) {
    try {
        CU(cudaSetDevice(argc > 3 && !std::strcmp(argv[1], "bench") ? 0 : 0));
        if (argc >= 3 && !std::strcmp(argv[1], "parity")) return parity(argv[2]);
        if (argc >= 4 && !std::strcmp(argv[1], "bench")) {
            int rc = 0;
            for (int i = 3; i < argc; ++i) rc |= bench(uint32_t(std::atoi(argv[2])), argv[i]);
            return rc;
        }
        if (argc >= 4 && !std::strcmp(argv[1], "chain")) {
            int rc = 0;
            for (int i = 3; i < argc; ++i) rc |= chain(uint32_t(std::atoi(argv[2])), argv[i]);
            return rc;
        }
        std::fprintf(stderr, "usage: parity VECTORS | bench REPS spec... | chain REPS name=spec...\n");
        return 2;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL %s\n", e.what());
        return 1;
    }
}
