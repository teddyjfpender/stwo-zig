// T6 Merkle leaf + tree (M8 round 2): parity and CUDA-event measurements of the
// production extern "C" entry points. Not product code.
//   parity : stwo_blake2s_merkle_layers_on{,_plain} with STWO_RV64_M8_MERKLE_FUSED
//            0 and 1 (switched in-process through
//            stwo_blake2s_m8_merkle_fused_override) vs the callers' own
//            stwo_blake2s_layer_on loop; whole buffer incl. guard words.
//   bench  : (tree) callers' loop vs fused layers, A/B interleaved;
//            (leaf, eager_step) roofline of the unchanged mixed leaf kernel;
//            (chain) one 64-column eager chain split into w-column calls, i.e.
//            the effect of the stream chunk budget (2^27 words = 8 columns at
//            2^24 rows = w 8 here at 2^22 rows with the same per-row traffic).
//   C=src/backends/cuda/native/commitment R=vectors/reports/rv64-m8-20261106/opt-T6-merkle-leaf-tree
//   nvcc -O3 -std=c++17 -lineinfo -arch=sm_120 -I src/backends/cuda/native \
//     $R/merkle_fused_bench.cu $C/progressive.cu $C/merkle.cu -o merkle_bench
//   ./merkle_bench parity | ./merkle_bench bench REPS
#include "commitment/blake2s_core.cuh"
#include "commitment/mixed_layout.h"

#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace b = stwo::cuda::blake2s;

extern "C" {
void stwo_blake2s_m8_merkle_fused_override(int mode);
int stwo_blake2s_mixed_leaf_on(uint32_t, uint32_t, const b::MixedSegment *, b::Hash *, void *);
int stwo_blake2s_mixed_seeded_eager_on(uint32_t, uint32_t, const b::MixedSegment *, uint32_t, uint32_t,
                                       const b::ProgressiveState *, b::ProgressiveState *, b::Hash *, void *);
int stwo_blake2s_mixed_seeded_eager_compact_on(uint32_t, uint32_t, const b::MixedSegment *, uint32_t,
                                               uint32_t, const uint32_t *, uint64_t, uint32_t *, uint64_t,
                                               uint32_t *, uint64_t, void *);
int stwo_blake2s_layer_on(const b::Hash *, uint32_t, b::Hash *, void *);
int stwo_blake2s_layer_plain_on(const b::Hash *, uint32_t, b::Hash *, void *);
int stwo_blake2s_merkle_layers_on(b::Hash *, uint32_t, uint64_t, void *);
int stwo_blake2s_merkle_layers_plain_on(b::Hash *, uint32_t, uint64_t, void *);
}

#define CK(x)                                                                         \
    do {                                                                              \
        cudaError_t e_ = (cudaError_t)(x);                                            \
        if (e_ != cudaSuccess) {                                                      \
            fprintf(stderr, "%s:%d %s -> %s\n", __FILE__, __LINE__, #x,               \
                    cudaGetErrorString(e_));                                          \
            exit(2);                                                                  \
        }                                                                             \
    } while (0)

static cudaStream_t g_stream;
static std::mt19937_64 g_rng(0x7e6);

struct Dev {
    void *p = nullptr;
    size_t bytes = 0;
    explicit Dev(size_t n) : bytes(n) {
        CK(cudaMalloc(&p, n ? n : 4));
        CK(cudaMemset(p, 0, n ? n : 4));
        CK(cudaDeviceSynchronize());
    }
    ~Dev() { cudaFree(p); }
    Dev(const Dev &) = delete;
    template <class T> T *as() const { return reinterpret_cast<T *>(p); }
    std::vector<uint8_t> host() const {
        std::vector<uint8_t> h(bytes);
        CK(cudaStreamSynchronize(g_stream));
        CK(cudaMemcpy(h.data(), p, bytes, cudaMemcpyDeviceToHost));
        return h;
    }
};

static void fill_random(Dev &d, size_t bytes = 0) {
    std::vector<uint32_t> h((bytes ? bytes : d.bytes) / 4);
    for (auto &x : h) x = uint32_t(g_rng()) & 0x7fffffffu;
    CK(cudaMemcpy(d.p, h.data(), h.size() * 4, cudaMemcpyHostToDevice));
    CK(cudaDeviceSynchronize());
}

// ---------------------------------------------------------------- parity
static int g_cases = 0, g_fail = 0;

static int callers_loop(bool plain, b::Hash *t, uint32_t leaves) {
    uint64_t off = 0;
    for (uint32_t n = leaves; n > 1; off += n, n >>= 1) {
        const int rc = plain ? stwo_blake2s_layer_plain_on(t + off, n / 2, t + off + n, g_stream)
                             : stwo_blake2s_layer_on(t + off, n / 2, t + off + n, g_stream);
        if (rc) return rc;
    }
    return 0;
}

static void parity_tree(uint32_t max_log) {
    for (uint32_t log = 1; log <= max_log; ++log)
        for (int plain = 0; plain < 2; ++plain) {
            const uint32_t leaves = 1u << log;
            const uint64_t nodes = 2ull * leaves - 1;
            Dev seed(size_t(leaves) * 32);
            fill_random(seed);
            std::vector<uint8_t> r[3];
            for (int arm = 0; arm < 3; ++arm) {
                Dev tree(size_t(nodes) * 32 + 64);  // 2 guard hashes past the root stay zero
                CK(cudaMemcpy(tree.p, seed.p, seed.bytes, cudaMemcpyDeviceToDevice));
                CK(cudaDeviceSynchronize());
                b::Hash *t = tree.as<b::Hash>();
                int rc;
                if (arm == 0) {
                    rc = callers_loop(plain, t, leaves);
                } else {
                    stwo_blake2s_m8_merkle_fused_override(arm - 1);
                    rc = plain ? stwo_blake2s_merkle_layers_plain_on(t, leaves, nodes, g_stream)
                               : stwo_blake2s_merkle_layers_on(t, leaves, nodes, g_stream);
                }
                if (rc) { fprintf(stderr, "tree arm %d rc=%d\n", arm, rc); exit(3); }
                r[arm] = tree.host();
            }
            const bool ok = r[0] == r[1] && r[0] == r[2];
            ++g_cases;
            g_fail += !ok;
            printf("{\"case\":\"tree\",\"protocol\":\"%s\",\"leaves_log\":%u,\"mode0_eq_loop\":%s,"
                   "\"mode1_eq_loop\":%s,\"bit_identical\":%s}\n",
                   plain ? "plain" : "prefixed", log, r[0] == r[1] ? "true" : "false",
                   r[0] == r[2] ? "true" : "false", ok ? "true" : "false");
        }
}

static void parity_contract() {
    // Rejections (both modes): non-power-of-two, < 2 leaves, short capacity,
    // null tree/stream; invalid flag value fails closed.
    Dev tree(64 * 32);
    b::Hash *t = tree.as<b::Hash>();
    struct { const char *name; b::Hash *tree; uint32_t leaves; uint64_t cap; void *stream; } bad[] = {
        {"leaves_3", t, 3, 64, g_stream},        {"leaves_1", t, 1, 64, g_stream},
        {"short_capacity", t, 32, 62, g_stream}, {"null_tree", nullptr, 32, 63, g_stream},
        {"null_stream", t, 32, 63, nullptr},
    };
    for (int mode = 0; mode < 2; ++mode) {
        stwo_blake2s_m8_merkle_fused_override(mode);
        for (auto &c : bad) {
            const int rc = stwo_blake2s_merkle_layers_on(c.tree, c.leaves, c.cap, c.stream);
            const bool ok = rc == int(cudaErrorInvalidValue);
            ++g_cases;
            g_fail += !ok;
            printf("{\"case\":\"contract\",\"mode\":%d,\"input\":\"%s\",\"rc\":%d,\"ok\":%s}\n", mode, c.name, rc,
                   ok ? "true" : "false");
        }
    }
    stwo_blake2s_m8_merkle_fused_override(-1);  // what an invalid env value maps to
    const int rc = stwo_blake2s_merkle_layers_on(t, 32, 63, g_stream);
    const bool ok = rc == int(cudaErrorInvalidValue);
    ++g_cases;
    g_fail += !ok;
    printf("{\"case\":\"contract\",\"mode\":-1,\"input\":\"invalid_flag\",\"rc\":%d,\"ok\":%s}\n", rc,
           ok ? "true" : "false");
    stwo_blake2s_m8_merkle_fused_override(-2);
}

// ---------------------------------------------------------------- bench
struct Stat { double median, lo, hi; };
static Stat stats(std::vector<float> v) {
    std::sort(v.begin(), v.end());
    return {v[v.size() / 2], v.front(), v.back()};
}

// Times fn() per arm with CUDA events on g_stream; arms interleaved per rep.
template <class F>
static std::vector<Stat> timed(int reps, int arms, F &&fn) {
    cudaEvent_t a, z;
    CK(cudaEventCreate(&a));
    CK(cudaEventCreate(&z));
    std::vector<std::vector<float>> t(arms);
    for (int arm = 0; arm < arms; ++arm) fn(arm);  // warm-up
    CK(cudaStreamSynchronize(g_stream));
    for (int rep = 0; rep < reps; ++rep)
        for (int arm = 0; arm < arms; ++arm) {
            CK(cudaEventRecord(a, g_stream));
            fn(arm);
            CK(cudaEventRecord(z, g_stream));
            CK(cudaEventSynchronize(z));
            float ms;
            CK(cudaEventElapsedTime(&ms, a, z));
            t[arm].push_back(ms);
        }
    CK(cudaGetLastError());
    cudaEventDestroy(a);
    cudaEventDestroy(z);
    std::vector<Stat> out;
    for (auto &v : t) out.push_back(stats(v));
    return out;
}

static void bench_tree(int reps) {
    for (uint32_t tlog : {10u, 12u, 14u, 16u, 18u, 20u, 21u, 22u, 23u, 24u}) {
        const uint32_t leaves = 1u << tlog;
        const uint64_t nodes = 2ull * leaves - 1;
        Dev tree(size_t(nodes) * 32);
        fill_random(tree, size_t(leaves) * 32);
        auto s = timed(reps, 2, [&](int arm) {
            stwo_blake2s_m8_merkle_fused_override(arm);
            if (stwo_blake2s_merkle_layers_on(tree.as<b::Hash>(), leaves, nodes, g_stream)) exit(3);
        });
        // Bytes of the callers' loop: every layer reads 2 and writes 1 hash per output.
        const double bytes = double(leaves - 1) * 96;
        printf("{\"bench\":\"tree_layers\",\"leaves_log\":%u,\"reps\":%d,\"loop_ms\":[%.4f,%.4f,%.4f],"
               "\"fused_ms\":[%.4f,%.4f,%.4f],\"ratio\":%.3f,\"loop_TBps\":%.3f,\"loop_launches\":%u}\n",
               tlog, reps, s[0].median, s[0].lo, s[0].hi, s[1].median, s[1].lo, s[1].hi,
               s[1].median / s[0].median, bytes / s[0].median / 1e9, tlog);
        fflush(stdout);
    }
    stwo_blake2s_m8_merkle_fused_override(-2);
}

static void bench_leaf(int reps) {
    const uint32_t log = 22, rows = 1u << log;
    for (uint32_t w : {1u, 4u, 8u, 16u, 32u, 64u, 128u}) {
        const uint32_t r = w >= 64 ? rows / 4 : rows;
        Dev data(size_t(r) * w * 4), out(size_t(r) * 32);
        fill_random(data);
        const b::MixedSegment s{data.as<uint32_t>(), r, size_t(r) * w, r, 0};
        auto t = timed(reps, 1, [&](int) { stwo_blake2s_mixed_leaf_on(r, 1, &s, out.as<b::Hash>(), g_stream); });
        const double comps = double(r) * ((w + 15) / 16);
        printf("{\"bench\":\"leaf_roofline\",\"rows_log\":%u,\"width\":%u,\"reps\":%d,\"ms\":[%.4f,%.4f,%.4f],"
               "\"all_bytes_TBps\":%.3f,\"Gcompress_per_s\":%.2f}\n",
               r == rows ? log : log - 2, w, reps, t[0].median, t[0].lo, t[0].hi,
               double(r) * (w * 4 + 32) / t[0].median / 1e9, comps / t[0].median / 1e6);
        fflush(stdout);
    }
    // Eager chain steps at the tallest height: seed pending pin in, prefix out.
    struct Step { uint32_t w, absorbed; bool fin; };
    for (Step st : {Step{8, 296, false}, Step{8, 304, false}, Step{8, 304, true}, Step{16, 288, false},
                    Step{16, 288, true}, Step{32, 288, false}}) {
        Dev data(size_t(rows) * st.w * 4), seed(size_t(rows) * 4 * 23), out(size_t(rows) * 4 * (st.fin ? 8 : 24));
        fill_random(data);
        fill_random(seed);
        const b::MixedSegment s{data.as<uint32_t>(), rows, size_t(rows) * st.w, rows, 0};
        const uint32_t pin = st.absorbed & 15u, pout = st.fin ? 0 : (st.absorbed + st.w) & 15u;
        auto t = timed(reps, 1, [&](int) {
            stwo_blake2s_mixed_seeded_eager_on(rows, 1, &s, st.absorbed, rows, seed.as<b::ProgressiveState>(),
                                               st.fin ? nullptr : out.as<b::ProgressiveState>(),
                                               st.fin ? out.as<b::Hash>() : nullptr, g_stream);
        });
        const double bytes = double(rows) * 4 * (st.w + 8 + pin + 8 + pout);
        printf("{\"bench\":\"eager_step_roofline\",\"rows_log\":%u,\"width\":%u,\"pending_in\":%u,\"pending_out\":%u,"
               "\"final\":%s,\"reps\":%d,\"ms\":[%.4f,%.4f,%.4f],\"all_bytes_TBps\":%.3f}\n",
               log, st.w, pin, pout, st.fin ? "true" : "false", reps, t[0].median, t[0].lo, t[0].hi,
               bytes / t[0].median / 1e9);
        fflush(stdout);
    }
}

// One 64-column eager chain at 2^21 rows (absorbed starts at 0, final call
// writes leaves), split into calls of w columns; default (non-compact) and
// compact eager entries. Same leaves for every w (checked).
static void bench_chain(int reps) {
    const uint32_t rows = 1u << 21, total = 64;  // 2^21: fits beside the 30 GB orphan
    Dev data(size_t(rows) * total * 4), bank0(size_t(rows) * 96), bank1(size_t(rows) * 96);
    fill_random(data);
    std::vector<uint8_t> reference;
    for (int compact = 0; compact < 2; ++compact)
        for (uint32_t w : {4u, 8u, 16u, 32u, 64u}) {
            auto run = [&](int) {
                Dev *banks[2] = {&bank0, &bank1};
                for (uint32_t first = 0, call = 0; first < total; first += w, ++call) {
                    const bool fin = first + w >= total;
                    const b::MixedSegment s{data.as<uint32_t>() + size_t(first) * rows, rows, size_t(rows) * w, rows, 0};
                    const void *seed = call ? banks[(call - 1) & 1]->p : nullptr;
                    void *out = banks[call & 1]->p;
                    int rc;
                    if (compact) {
                        const uint64_t seed_cap = call ? uint64_t(rows) * (8 + (first & 15u)) : 0;
                        const uint64_t out_cap = fin ? uint64_t(rows) * 8 : uint64_t(rows) * (8 + ((first + w) & 15u));
                        rc = stwo_blake2s_mixed_seeded_eager_compact_on(
                            rows, 1, &s, first, call ? rows : 0, (const uint32_t *)seed, seed_cap,
                            fin ? nullptr : (uint32_t *)out, fin ? 0 : out_cap, fin ? (uint32_t *)out : nullptr,
                            fin ? out_cap : 0, g_stream);
                    } else {
                        rc = stwo_blake2s_mixed_seeded_eager_on(
                            rows, 1, &s, first, call ? rows : 0, (const b::ProgressiveState *)seed,
                            fin ? nullptr : (b::ProgressiveState *)out, fin ? (b::Hash *)out : nullptr, g_stream);
                    }
                    if (rc) { fprintf(stderr, "chain rc=%d\n", rc); exit(3); }
                }
            };
            auto t = timed(reps, 1, run);
            const uint32_t calls = total / w;
            Dev *last = ((calls - 1) & 1) ? &bank1 : &bank0;
            std::vector<uint8_t> leaves(size_t(rows) * 32);
            CK(cudaStreamSynchronize(g_stream));
            CK(cudaMemcpy(leaves.data(), last->p, leaves.size(), cudaMemcpyDeviceToHost));
            if (reference.empty()) reference = leaves;
            printf("{\"bench\":\"chain_chunk\",\"rows_log\":21,\"columns\":%u,\"call_width\":%u,\"calls\":%u,"
                   "\"compact\":%s,\"reps\":%d,\"ms\":[%.4f,%.4f,%.4f],\"ms_per_column\":%.4f,\"leaves_equal\":%s}\n",
                   total, w, calls, compact ? "true" : "false", reps, t[0].median, t[0].lo, t[0].hi,
                   t[0].median / total, leaves == reference ? "true" : "false");
            fflush(stdout);
        }
}

int main(int argc, char **argv) {
    // Blocking stream: ordered after the legacy-stream setup copies/memsets.
    CK(cudaStreamCreate(&g_stream));
    const std::string what = argc > 1 ? argv[1] : "parity";
    if (what == "parity") {
        parity_contract();
        parity_tree(argc > 2 ? uint32_t(atoi(argv[2])) : 22);
        printf("{\"summary\":\"parity\",\"cases\":%d,\"failures\":%d}\n", g_cases, g_fail);
        return g_fail ? 1 : 0;
    }
    const int reps = argc > 2 ? atoi(argv[2]) : 9;
    const std::string only = argc > 3 ? argv[3] : "all";
    if (only == "all" || only == "tree") bench_tree(reps);
    if (only == "all" || only == "leaf") bench_leaf(reps);
    if (only == "all" || only == "chain") bench_chain(reps);
    return 0;
}
