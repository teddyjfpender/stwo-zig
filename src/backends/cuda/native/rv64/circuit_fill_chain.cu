// M6 hint-tape: dependency-chain runs of the original circuit assignment DAG.
//
// One CTA executes an UNBOUNDED sequence of consecutive dependency levels of
// width <= kChainMaxWidth (strided over kChainThreads threads), with one
// __syncthreads per level, reading the absolute level ends from a device array
// staged through shared memory. Task records (immutable, generation-only
// descriptors of the authenticated topology) are prefetched one level ahead so
// the record load leaves the per-level dependency latency. Wider levels keep
// the ordinary grid launch (stwo_circuit_assignment_level_on).
//
// Generation only: the task evaluation `at` is the exact semantics of
// circuit_assignment.cu (same kinds, same arithmetic, same status failures);
// identical tasks/seeds give identical values, hence identical MAIN and proofs.
#include "circuit_assignment.h"
#include "custody.cuh"
#include "../oods/field.cuh"
#include "assignment_graph.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>
namespace stwo::cuda::circuit_fill {
namespace q = stwo::cuda::oods;
constexpr uint32_t kChainThreads = 512, kChainMaxWidth = 2048, kEndsChunk = 1024;
// One 16-byte access per QM31 value (the assignment lease is 16-byte aligned:
// arena allocations are at least 256-byte aligned). Scattered narrow levels are
// bound by memory transactions per warp instruction; the scalar form issued
// four per value.
__device__ __forceinline__ q::QM31 load(const uint32_t* p, uint32_t i) {
    const uint4 v = reinterpret_cast<const uint4*>(p)[i];
    return {{v.x, v.y}, {v.z, v.w}};
}
__device__ __forceinline__ void store(uint32_t* p, uint32_t i, q::QM31 v) {
    reinterpret_cast<uint4*>(p)[i] = make_uint4(v.a.a, v.a.b, v.b.a, v.b.b);
}
__device__ __forceinline__ bool zero(q::QM31 x) { return !(x.a.a | x.a.b | x.b.a | x.b.b); }
__device__ __forceinline__ uint32_t word(q::QM31 v) { return v.a.a | (v.a.b << 16); }
__device__ __forceinline__ q::QM31 packed(uint32_t v) { return {{v & 65535, v >> 16}, {0, 0}}; }
__device__ __forceinline__ uint32_t ror(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
__device__ void fail(uint32_t* p) { atomicOr(p, 1u); }
__host__ __device__ __forceinline__ unsigned arity_of(uint32_t kind) {
    return kind == 15 ? 0 : kind <= 3 ? 2 : kind == 4 ? 3 : kind == 6 ? 6 : kind == 9 ? 2 : 1;
}
// The arithmetic of one non-permutation task from its gathered inputs, with
// the exact status failures of circuit_assignment.cu `at`. The caller has
// already refused kind > 15, out >= value_count, kind 7 and any input index
// >= value_count. Stores the outputs to `values` and returns them in `r`
// (kind 6: the four packed words a,b,c,d; otherwise the QM31 limbs) so the
// dataflow executor can forward them through shared memory. Returns false
// (status already failed, nothing stored) on a failing task.
__device__ __forceinline__ bool eval(const StwoCircuitAssignmentJob& j, const StwoCircuitAssignmentTask& t, const q::QM31* x, uint4& r) {
    q::QM31 v{};
    switch (t.kind) {
        case 0: v = q::add(x[0], x[1]); break;
        case 1: v = q::sub(x[0], x[1]); break;
        case 2: v = q::mul(x[0], x[1]); break;
        case 3: v = {{q::mul(x[0].a.a, x[1].a.a), q::mul(x[0].a.b, x[1].a.b)}, {q::mul(x[0].b.a, x[1].b.a), q::mul(x[0].b.b, x[1].b.b)}}; break;
        case 4: v = packed(word(x[0]) ^ word(x[1]) ^ word(x[2])); break;
        case 5: v = packed(x[0].a.a); break;
        case 6: {
            if (uint64_t(t.out) + 4 > j.value_count) { fail(j.status); return false; }
            uint32_t a = word(x[0]), b = word(x[1]), c = word(x[2]), d = word(x[3]);
            a = a + b + word(x[4]); d = ror(d ^ a, 16); c += d; b = ror(b ^ c, 12);
            a = a + b + word(x[5]); d = ror(d ^ a, 8); c += d; b = ror(b ^ c, 7);
            store(j.values, t.out, packed(a)); store(j.values, t.out + 1, packed(b));
            store(j.values, t.out + 2, packed(c)); store(j.values, t.out + 3, packed(d));
            r = make_uint4(a, b, c, d);
            return true;
        }
        case 8: if (zero(x[0])) { fail(j.status); return false; } v = q::inverse(x[0]); break;
        case 9: if (zero(x[1])) { fail(j.status); return false; } v = q::mul(x[0], q::inverse(x[1])); break;
        case 10: { const auto a = x[0]; v = {{a.a.a ? q::inverse(a.a.a) : 0, a.a.b ? q::inverse(a.a.b) : 0}, {a.b.a ? q::inverse(a.b.a) : 0, a.b.b ? q::inverse(a.b.b) : 0}}; break; }
        case 11: { const auto a = x[0]; v = {{a.a.a & 1, a.a.b & 1}, {a.b.a & 1, a.b.b & 1}}; break; }
        case 12: case 13: { if (t.args[1] > 3) { fail(j.status); return false; } const auto octet = (word(x[0]) >> (t.args[1] * 8)) & 255u; v = {{t.kind == 12 ? octet : 255u - octet, 0}, {0, 0}}; break; }
        case 14: v = {{zero(x[0]) ? 0u : 1u, 0}, {0, 0}}; break;
        case 15: v = q::zero(); break;
        default: fail(j.status); return false;
    }
    store(j.values, t.out, v);
    r = make_uint4(v.a.a, v.a.b, v.b.a, v.b.b);
    return true;
}
// Byte-for-byte the evaluation of circuit_assignment.cu `at`.
__device__ void at(const StwoCircuitAssignmentJob& j, const StwoCircuitAssignmentTask& t) {
    if (t.kind > 15 || t.out >= j.value_count) { fail(j.status); return; }
    unsigned arity = t.kind == 15 ? 0 : t.kind <= 3 ? 2 : t.kind == 4 ? 3 : t.kind == 6 ? 6 : t.kind == 9 ? 2 : 1;
    if (t.kind == 7) {
        const uint32_t base = t.args[0], count = t.args[1];
        if (uint64_t(base) + uint64_t(count) * 2 > j.index_count) { fail(j.status); return; }
        for (uint32_t i = 0; i < count; ++i) {
            const auto vi = j.indices[base + i];
            if (vi >= j.value_count) { fail(j.status); return; }
            const auto x = load(j.values, vi);
            uint32_t rank = 0;
            for (uint32_t k = 0; k < count; ++k) {
                const auto vk = j.indices[base + k];
                if (vk >= j.value_count) { fail(j.status); return; }
                const auto y = load(j.values, vk);
                rank += (y.b.a < x.b.a || (y.b.a == x.b.a && k < i));
            }
            const auto out = j.indices[base + count + rank];
            if (out >= j.value_count) { fail(j.status); return; }
            store(j.values, out, x);
        }
        return;
    }
    q::QM31 x[6];
    for (unsigned i = 0; i < arity; ++i) {
        if (t.args[i] >= j.value_count) { fail(j.status); return; }
        x[i] = load(j.values, t.args[i]);
    }
    q::QM31 v{};
    switch (t.kind) {
        case 0: v = q::add(x[0], x[1]); break;
        case 1: v = q::sub(x[0], x[1]); break;
        case 2: v = q::mul(x[0], x[1]); break;
        case 3: v = {{q::mul(x[0].a.a, x[1].a.a), q::mul(x[0].a.b, x[1].a.b)}, {q::mul(x[0].b.a, x[1].b.a), q::mul(x[0].b.b, x[1].b.b)}}; break;
        case 4: v = packed(word(x[0]) ^ word(x[1]) ^ word(x[2])); break;
        case 5: v = packed(x[0].a.a); break;
        case 6: {
            if (uint64_t(t.out) + 4 > j.value_count) { fail(j.status); return; }
            uint32_t a = word(x[0]), b = word(x[1]), c = word(x[2]), d = word(x[3]);
            a = a + b + word(x[4]); d = ror(d ^ a, 16); c += d; b = ror(b ^ c, 12);
            a = a + b + word(x[5]); d = ror(d ^ a, 8); c += d; b = ror(b ^ c, 7);
            store(j.values, t.out, packed(a)); store(j.values, t.out + 1, packed(b));
            store(j.values, t.out + 2, packed(c)); store(j.values, t.out + 3, packed(d));
            return;
        }
        case 8: if (zero(x[0])) { fail(j.status); return; } v = q::inverse(x[0]); break;
        case 9: if (zero(x[1])) { fail(j.status); return; } v = q::mul(x[0], q::inverse(x[1])); break;
        case 10: { const auto a = x[0]; v = {{a.a.a ? q::inverse(a.a.a) : 0, a.a.b ? q::inverse(a.a.b) : 0}, {a.b.a ? q::inverse(a.b.a) : 0, a.b.b ? q::inverse(a.b.b) : 0}}; break; }
        case 11: { const auto a = x[0]; v = {{a.a.a & 1, a.a.b & 1}, {a.b.a & 1, a.b.b & 1}}; break; }
        case 12: case 13: { if (t.args[1] > 3) { fail(j.status); return; } const auto octet = (word(x[0]) >> (t.args[1] * 8)) & 255u; v = {{t.kind == 12 ? octet : 255u - octet, 0}, {0, 0}}; break; }
        case 14: v = {{zero(x[0]) ? 0u : 1u, 0}, {0, 0}}; break;
        case 15: v = q::zero(); break;
        default: fail(j.status); return;
    }
    store(j.values, t.out, v);
}
// Out-of-line `at` for chain_flow's per-level paths: one body of the task
// arithmetic there instead of three inlined copies (chain_run keeps its own
// inlined `at`). [M synthetic mid-width Blake: run_levels with at_ni 2.45 ms
// vs chain_run 2.69 ms.]
__device__ __noinline__ void at_ni(const StwoCircuitAssignmentJob& j, const StwoCircuitAssignmentTask t) { at(j, t); }
__device__ __forceinline__ StwoCircuitAssignmentTask fetch(const StwoCircuitAssignmentTask* tasks, uint32_t i) {
    // Records are immutable for the whole node: read-only path.
    const uint4* p = reinterpret_cast<const uint4*>(tasks + i);
    const uint4 lo = __ldg(p), hi = __ldg(p + 1);
    return {lo.x, lo.y, {lo.z, lo.w, hi.x, hi.y, hi.z, hi.w}};
}
// L2 prefetch hint for the value inputs of a future task. A hint never changes
// memory contents or ordering: a line that a level writes later is updated in
// L2 by that write; only the DRAM latency of OLD inputs (Blake message words,
// seeds, constants) leaves the dependency chain.
__device__ __forceinline__ void prefetch_inputs(const StwoCircuitAssignmentJob& j, const StwoCircuitAssignmentTask& t) {
    if (t.kind > 15 || t.kind == 7 || t.kind == 15) return;
    const unsigned arity = t.kind <= 3 ? 2 : t.kind == 4 ? 3 : t.kind == 6 ? 6 : t.kind == 9 ? 2 : 1;
#pragma unroll
    for (unsigned i = 0; i < 6; ++i)
        if (i < arity && t.args[i] < j.value_count)
            asm volatile("prefetch.global.L2 [%0];" ::"l"(j.values + uint64_t(t.args[i]) * 4));
}
__global__ void __launch_bounds__(kChainThreads) chain_run(StwoCircuitAssignmentJob j, const uint32_t* __restrict__ ends, uint32_t first_level, uint32_t levels) {
    __shared__ uint32_t s_ends[kEndsChunk];
    __shared__ uint32_t s_bad;
    const auto* tasks = static_cast<const StwoCircuitAssignmentTask*>(j.records);
    const uint32_t tid = threadIdx.x;
    if (tid == 0) s_bad = 0;
    uint32_t begin = j.first;
    for (uint32_t chunk = 0; chunk < levels; chunk += kEndsChunk) {
        const uint32_t n = min(kEndsChunk, levels - chunk);
        __syncthreads();  // previous chunk fully consumed
        for (uint32_t i = tid; i < n; i += kChainThreads) s_ends[i] = ends[first_level + chunk + i];
        __syncthreads();
        // A malformed end is a uniform decision (every thread reads the same
        // shared flag), so every thread leaves together; the status word
        // records the refusal.
        if (tid == 0) {
            uint32_t b = begin;
            for (uint32_t i = 0; i < n; ++i) {
                const uint32_t e = s_ends[i];
                if (e < b || e - b > kChainMaxWidth || e > j.record_count) { s_bad = 1; break; }
                b = e;
            }
            if (s_bad) fail(j.status);
        }
        __syncthreads();
        if (s_bad) return;
        // Record pipeline: records of levels l+1 and l+2 are in registers and
        // the record of l+3 is requested during level l; the value inputs of
        // level l+2 (record already arrived) are prefetched into L2 two levels
        // before they are read. Nothing issued here waits on a load.
        const auto record = [&](uint32_t level) -> StwoCircuitAssignmentTask {
            const StwoCircuitAssignmentTask none{15u, 0u, {0, 0, 0, 0, 0, 0}};
            if (level >= n) return none;
            const uint32_t first = level == 0 ? begin : s_ends[level - 1];
            return first + tid < s_ends[level] ? fetch(tasks, first + tid) : none;
        };
        StwoCircuitAssignmentTask current = record(0), next1 = record(1), next2 = record(2);
        prefetch_inputs(j, next1);
        for (uint32_t l = 0; l < n; ++l) {
            const uint32_t end = s_ends[l];
            const StwoCircuitAssignmentTask next3 = record(l + 3);
            prefetch_inputs(j, next2);
            if (begin + tid < end) at(j, current);
            for (uint32_t i = begin + tid + kChainThreads; i < end; i += kChainThreads) at(j, fetch(tasks, i));
            // Global writes of this level are visible to the whole CTA after
            // the barrier, before any later dependency level reads them.
            __syncthreads();
            current = next1;
            next1 = next2;
            next2 = next3;
            begin = end;
        }
    }
    if (tid == 0 && begin != j.first + j.count) fail(j.status);
}
// chain_run's per-level loop (same record pipeline, same barriers) over the
// window levels [from, to); `begin` is the first task of level `from` and is
// advanced past level to-1.
__device__ __forceinline__ void run_levels(const StwoCircuitAssignmentJob& j, const StwoCircuitAssignmentTask* tasks, const uint32_t* s_ends, uint32_t& begin, uint32_t from, uint32_t to) {
    const uint32_t tid = threadIdx.x, begin0 = begin;
    const auto record = [&](uint32_t level) -> StwoCircuitAssignmentTask {
        const StwoCircuitAssignmentTask none{15u, 0u, {0, 0, 0, 0, 0, 0}};
        if (level >= to) return none;
        const uint32_t first = level == from ? begin0 : s_ends[level - 1];
        return first + tid < s_ends[level] ? fetch(tasks, first + tid) : none;
    };
    StwoCircuitAssignmentTask current = record(from), next1 = record(from + 1), next2 = record(from + 2);
    prefetch_inputs(j, next1);
    for (uint32_t l = from; l < to; ++l) {
        const uint32_t end = s_ends[l];
        const StwoCircuitAssignmentTask next3 = record(l + 3);
        prefetch_inputs(j, next2);
        if (begin + tid < end) at_ni(j, current);
        for (uint32_t i = begin + tid + kChainThreads; i < end; i += kChainThreads) at_ni(j, fetch(tasks, i));
        __syncthreads();
        current = next1;
        next1 = next2;
        next2 = next3;
        begin = end;
    }
}
// ---------------------------------------------------------------------------
// M8 T2 dataflow chunk executor (STWO_RV64_M8_ASSIGNMENT_FLOW=1; same ABI,
// same records, same level ends as chain_run).
//
// chain_run pays one 512-thread barrier plus a dependent global round trip per
// dependency level (~430 ns [D], 120k levels per node, 75% of them <= 32
// wide). chain_flow splits each window of levels into runs by width class.
// Runs of levels >= kFlowWideWidth wide execute exactly like chain_run
// (run_levels). Runs of narrower levels are cut into chunks of <= 512 tasks
// (one per thread); per chunk the CTA builds a shared-memory map from every
// output variable to its producing task (open addressing on the variable
// index). Each task then waits only for its own in-chunk producers through
// shared-memory ready flags and reads their outputs from shared memory;
// inputs produced before the chunk come from global memory. 4 barriers per
// chunk instead of one per level. [M synthetic, CUDA events, 7 reps: width-1
// chain 15.48 -> 2.77 ms; 64-128-wide Blake 2.69 -> 2.68 ms.]
//
// Exactness: every task runs `eval`, the arithmetic of `at`, on the same
// input values (an in-chunk producer's shared copy equals what it stored).
// The plan builder makes every variable single-producer, and producers lie in
// strictly earlier levels. A chunk that holds a permutation task (kind 7),
// two producers of one variable, or a consumer whose producer is not in a
// strictly earlier level (which also covers write-after-read) instead runs
// with chain_run's exact per-level barrier semantics. Status failures equal
// `at`'s: a failing task stores nothing and releases its consumers with
// kFlowFailed, so they read the variable from global memory (its pre-chunk
// value, exactly what chain_run reads) instead of a stale shared slot.
// Deadlock freedom: task k (chunk order) depends only on tasks < k; a warp
// polls until each of its lanes' producers is ready, executing every ready
// lane per round, so the lowest unfinished task can always run.
#ifdef STWO_T2_PROF  // microbenchmark-only phase clocks (never in an image)
__device__ unsigned long long g_t2_prof[8];
#define T2_MARK(i) do { if (tid == 0) { const long long now = clock64(); atomicAdd(&g_t2_prof[i], (unsigned long long)(now - t2_last)); t2_last = now; } } while (0)
#else
#define T2_MARK(i) do {} while (0)
#endif
// One task per thread per chunk; the map holds <= 4 keys per task (Blake G)
// at load factor <= 1/2. All state is static shared memory (39 KB).
constexpr uint32_t kFlowCap = kChainThreads, kFlowTableBits = 12, kFlowTable = 1u << kFlowTableBits;
static_assert(kFlowTable >= 8 * kFlowCap, "flow map load factor <= 1/2");
static_assert(((kFlowCap - 1) << 3 | 7) < 0xffffu, "producer code fits u16");
constexpr uint32_t kFlowEmpty = 0xffffffffu;
constexpr uint16_t kFlowGlobal = 0xffffu;
// s_ready states: 0 pending, kFlowDone (outputs in s_vals), kFlowFailed
// (stored nothing; consumers read global memory).
constexpr uint32_t kFlowDone = 1, kFlowFailed = 2;
__device__ __forceinline__ uint32_t flow_hash(uint32_t key) { return (key * 2654435761u) >> (32 - kFlowTableBits); }
__device__ __forceinline__ q::QM31 flow_decode(uint4 v, uint32_t code) {
    if (!(code & 4)) return {{v.x, v.y}, {v.z, v.w}};
    const uint32_t s = code & 3;
    return packed(s == 0 ? v.x : s == 1 ? v.y : s == 2 ? v.z : v.w);
}
// Levels at least WideWidth wide (runs of them) execute exactly as chain_run
// does (run_levels): a chunk of them would span few levels, so a map build
// would not pay. Runs of narrower levels form dataflow chunks.
// The phase code is deliberately small and loops are not unrolled: every
// chunk re-enters each phase after the (large) task arithmetic, so phase code
// size is instruction-cache refetch time [M bench: unrolled Per=2 phases cost
// 1.5-2x the cycles of Per=1 at equal work].
template <uint32_t WideWidth>
__global__ void __launch_bounds__(kChainThreads) chain_flow(StwoCircuitAssignmentJob j, const uint32_t* __restrict__ ends, uint32_t first_level, uint32_t levels) {
    __shared__ uint4 s_vals[kFlowCap];
    __shared__ uint32_t s_keys[kFlowTable];
    __shared__ uint16_t s_prod[kFlowTable];
    __shared__ volatile uint32_t s_ready[kFlowCap];
    __shared__ uint32_t s_ends[kEndsChunk];
    __shared__ uint32_t s_bad, s_fallback, s_seg[2];
    const auto* tasks = static_cast<const StwoCircuitAssignmentTask*>(j.records);
    const uint32_t tid = threadIdx.x;
    if (tid == 0) { s_bad = 0; s_seg[0] = s_seg[1] = kFlowEmpty; }
    uint32_t begin = j.first, parity = 0;
    for (uint32_t chunk = 0; chunk < levels; chunk += kEndsChunk) {
        const uint32_t n = min(kEndsChunk, levels - chunk);
        __syncthreads();
        for (uint32_t i = tid; i < n; i += kChainThreads) s_ends[i] = ends[first_level + chunk + i];
        __syncthreads();
        if (tid == 0) {
            uint32_t b = begin;
            for (uint32_t i = 0; i < n; ++i) {
                const uint32_t e = s_ends[i];
                if (e < b || e - b > kChainMaxWidth || e > j.record_count) { s_bad = 1; break; }
                b = e;
            }
            if (s_bad) fail(j.status);
        }
        __syncthreads();
        if (s_bad) return;
        const uint32_t window_begin = begin;
        uint32_t l = 0;
        while (l < n) {
            uint32_t seg = n;  // end of the run of levels of level l's class
            {
                const auto wide = [&](uint32_t i) { return s_ends[i] - (i == 0 ? window_begin : s_ends[i - 1]) >= WideWidth; };
                const bool cls = wide(l);
                // Parity-alternating slot: the other slot was last read
                // before this segment's barriers, so resetting it is race-free.
                if (tid == 0) s_seg[parity ^ 1] = kFlowEmpty;
                for (uint32_t base = l + 1; base < n; base += kChainThreads) {
                    const uint32_t i = base + tid;
                    const bool change = i < n && wide(i) != cls;
                    if (change) atomicMin(&s_seg[parity], i);
                    // Uniform decision; nobody writes the slot after a hit.
                    if (__syncthreads_or(change)) { seg = s_seg[parity]; break; }
                }
                parity ^= 1;
                if (cls) {
                    run_levels(j, tasks, s_ends, begin, l, seg);
                    l = seg;
                    continue;
                }
            }
            if (s_ends[l] - begin > kFlowCap) {
                // A narrow-class level wider than a chunk (WideWidth > cap).
                const uint32_t end = s_ends[l];
                for (uint32_t i = begin + tid; i < end; i += kChainThreads) at_ni(j, fetch(tasks, i));
                __syncthreads();
                begin = end;
                ++l;
                continue;
            }
            // Chunk = levels [l, l2): the longest prefix with <= cap tasks.
            uint32_t lo = l + 1, hi = seg;
            while (lo < hi) {
                const uint32_t mid = (lo + hi) >> 1;
                if (s_ends[mid] - begin > kFlowCap) hi = mid; else lo = mid + 1;
            }
            const uint32_t l2 = lo, ce = s_ends[l2 - 1];
#ifdef STWO_T2_PROF
            long long t2_last = clock64();
            if (tid == 0) atomicAdd(&g_t2_prof[7], 1ull);
#endif
            // Next chunk's records toward L2 (hint only; records are immutable).
            if (uint64_t(ce) + uint64_t(tid) * 4 < j.record_count)
                asm volatile("prefetch.global.L2 [%0];" ::"l"(tasks + ce + tid * 4));
            const uint32_t k = tid, abs = begin + tid;
            const bool valid = abs < ce;
            const StwoCircuitAssignmentTask t = valid ? fetch(tasks, abs) : StwoCircuitAssignmentTask{15u, 0u, {0, 0, 0, 0, 0, 0}};
            for (uint32_t i = tid; i < kFlowTable; i += kChainThreads) s_keys[i] = kFlowEmpty;
            s_ready[k] = 0;
            if (tid == 0) s_fallback = 0;
            __syncthreads();  // map cleared
            T2_MARK(0);
            const unsigned arity = t.kind <= 15 && t.kind != 7 ? arity_of(t.kind) : 0;
            uint32_t lb = begin;
            if (valid) {
                if (t.kind == 7) s_fallback = 1;
                const uint32_t keys = t.kind > 15 || t.kind == 7 || t.out >= j.value_count ? 0 : t.kind == 6 ? (uint64_t(t.out) + 4 <= j.value_count ? 4 : 0) : 1;
#pragma unroll 1
                for (uint32_t s = 0; s < keys; ++s) {
                    const uint32_t key = t.out + s;
                    uint32_t h = flow_hash(key);
                    for (;;) {
                        const uint32_t old = atomicCAS(&s_keys[h], kFlowEmpty, key);
                        if (old == kFlowEmpty) { s_prod[h] = uint16_t(k << 3 | (t.kind == 6 ? 4u : 0u) | s); break; }
                        if (old == key) { s_fallback = 1; break; }
                        h = (h + 1) & (kFlowTable - 1);
                    }
                }
                // Level begin of this task: the last level end <= its index.
                uint32_t a = l, b = l2;  // first m in [l, l2) with s_ends[m] > abs
                while (a < b) {
                    const uint32_t mid = (a + b) >> 1;
                    if (s_ends[mid] > abs) b = mid; else a = mid + 1;
                }
                lb = a == l ? begin : s_ends[a - 1];
            }
            __syncthreads();  // map complete
            T2_MARK(1);
            uint16_t dep[6];
#pragma unroll
            for (unsigned a = 0; a < 6; ++a) {
                const uint32_t key = t.args[a];
                uint16_t code = kFlowGlobal;
                if (a < arity && key < j.value_count) {
                    uint32_t h = flow_hash(key);
                    for (uint32_t probe = s_keys[h]; probe != kFlowEmpty; probe = s_keys[h]) {
                        if (probe == key) {
                            code = s_prod[h];
                            if (begin + (code >> 3) >= lb) s_fallback = 1;
                            break;
                        }
                        h = (h + 1) & (kFlowTable - 1);
                    }
                }
                dep[a] = code;
            }
            __syncthreads();  // dependencies resolved, fallback decided
            T2_MARK(2);
            if (s_fallback) {
                uint32_t b = begin;
                run_levels(j, tasks, s_ends, b, l, l2);
            } else {
                bool pending = valid;
                q::QM31 x[6];
                if (pending) {
                    // `at`'s refusals before any arithmetic.
                    bool refused = t.kind > 15 || t.out >= j.value_count;
#pragma unroll
                    for (unsigned a = 0; a < 6; ++a) refused = refused || (a < arity && t.args[a] >= j.value_count);
                    if (refused) {
                        fail(j.status);
                        __threadfence_block();
                        s_ready[k] = kFlowFailed;
                        pending = false;
                    } else {
                        // Inputs produced before this chunk are final.
#pragma unroll
                        for (unsigned a = 0; a < 6; ++a)
                            if (a < arity && dep[a] == kFlowGlobal) x[a] = load(j.values, t.args[a]);
                    }
                }
                while (__any_sync(0xffffffffu, pending)) {
                    if (!pending) continue;
                    bool ready = true;
#pragma unroll
                    for (unsigned a = 0; a < 6; ++a) {
                        if (a < arity && dep[a] != kFlowGlobal) ready = ready && s_ready[dep[a] >> 3];
                    }
                    if (!ready) continue;
                    __threadfence_block();
#pragma unroll
                    for (unsigned a = 0; a < 6; ++a) {
                        if (a < arity && dep[a] != kFlowGlobal)
                            x[a] = s_ready[dep[a] >> 3] == kFlowFailed ? load(j.values, t.args[a]) : flow_decode(s_vals[dep[a] >> 3], dep[a]);
                    }
                    uint4 r;
                    const bool ok = eval(j, t, x, r);
                    if (ok) s_vals[k] = r;
                    __threadfence_block();
                    s_ready[k] = ok ? kFlowDone : kFlowFailed;
                    pending = false;
                }
            }
            __syncthreads();  // chunk complete: global writes visible to the CTA
            T2_MARK(3);
            begin = ce;
            l = l2;
        }
    }
    if (tid == 0 && begin != j.first + j.count) fail(j.status);
}
// [E -> M pending real-node A/B] wide-level routing threshold. Synthetic only
// so far [M, CUDA events, 7 reps]: i.i.d. mixed widths wide=32 34.3 ms vs
// wide=never 29.9 ms (chain_run 39.56 ms); it must be re-chosen on the real
// node replay (chain_flow_bench dump) before FLOW can become a default.
constexpr uint32_t kFlowWideWidth = 32;
inline auto flow_kernel() { return chain_flow<kFlowWideWidth>; }
// 0: chain_run (default), 1: chain_flow. Read once per process.
inline int flow_mode() {
  return 0;
}
}  // namespace stwo::cuda::circuit_fill

// Optional generation-only grouping (capability: symbol present). `ends` is a
// device array of absolute task ends for the whole plan; this run covers
// levels [first_level, first_level + levels) and tasks [j->first, j->first + j->count).
extern "C" int stwo_circuit_assignment_chain_run_on(void* ctx, uint32_t lane, const StwoCircuitAssignmentJob* j, const uint32_t* ends, uint32_t first_level, uint32_t levels) {
    using namespace stwo::cuda::rv64;
    using namespace stwo::cuda::circuit_fill;
    if (!j || j->reserved || !j->value_count || j->value_count >= (1u << 31) || !j->count || uint64_t(j->first) + j->count > j->record_count || !ends || !levels) return int(cudaErrorInvalidValue);
    if (reinterpret_cast<uintptr_t>(j->values) % 16 || reinterpret_cast<uintptr_t>(j->records) % 16) return int(cudaErrorMisalignedAddress);
    Custody c(ctx, lane);
    if (!c.range(j->values, uint64_t(j->value_count) * 4, true) ||
        !c.range(static_cast<const uint32_t*>(j->records), uint64_t(j->record_count) * 8, false) ||
        !c.range(j->status, 1, true) || (j->index_count && !c.range(j->indices, j->index_count, false)) ||
        !c.range(ends + first_level, levels, false))
        return c.status;
    const int mode = flow_mode();
    if (mode < 0) return int(cudaErrorInvalidValue);
    if (mode == 1) {
        flow_kernel()<<<1, kChainThreads, 0, c.stream>>>(*j, ends, first_level, levels);
    } else {
        chain_run<<<1, kChainThreads, 0, c.stream>>>(*j, ends, first_level, levels);
    }
    return int(cudaPeekAtLastError());
}
extern "C" uint32_t stwo_circuit_assignment_chain_max_width() { return stwo::cuda::circuit_fill::kChainMaxWidth; }
namespace stwo::cuda::circuit_fill {
__global__ void wide_level(StwoCircuitAssignmentJob j) {
    const auto i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < j.count) at(j, fetch(static_cast<const StwoCircuitAssignmentTask*>(j.records), j.first + i));
}
}  // namespace stwo::cuda::circuit_fill
// One dependency level as a grid (the vectorised twin of
// stwo_circuit_assignment_level_on), used for levels wider than a chain CTA.
extern "C" int stwo_circuit_assignment_wide_level_on(void* ctx, uint32_t lane, const StwoCircuitAssignmentJob* j) {
    using namespace stwo::cuda::rv64;
    if (!j || j->reserved || !j->value_count || j->value_count >= (1u << 31) || !j->count || uint64_t(j->first) + j->count > j->record_count) return int(cudaErrorInvalidValue);
    if (reinterpret_cast<uintptr_t>(j->values) % 16 || reinterpret_cast<uintptr_t>(j->records) % 16) return int(cudaErrorMisalignedAddress);
    Custody c(ctx, lane);
    if (!c.range(j->values, uint64_t(j->value_count) * 4, true) ||
        !c.range(static_cast<const uint32_t*>(j->records), uint64_t(j->record_count) * 8, false) ||
        !c.range(j->status, 1, true) || (j->index_count && !c.range(j->indices, j->index_count, false)))
        return c.status;
    stwo::cuda::circuit_fill::wide_level<<<(j->count + 127) / 128, 128, 0, c.stream>>>(*j);
    return int(cudaPeekAtLastError());
}

// A graph owns only host CUDA graph metadata. Every replay supplies and
// validates fresh live allocations, and replaces ALL pointer-bearing kernel
// arguments before enqueue. Freed witness addresses can never be replayed.
extern "C" int stwo_exec_context_identity(void*, uint64_t*);
namespace stwo::cuda::assignment_graph {
struct Node { cudaGraphNode_t handle{}; StwoAssignmentGraphStep step{}; };
struct Graph {
  void* context{}; uint64_t identity{}; uint32_t lane{}, values{}, records{}, indices{}, ends{};
  int flow{};  // circuit_fill::flow_mode() at creation; fixed for the graph's life
  cudaGraph_t graph{}; cudaGraphExec_t exec{}; std::vector<Node> nodes;
  ~Graph() {
    if (exec) (void)cudaGraphExecDestroy(exec);
    if (graph) (void)cudaGraphDestroy(graph);
  }
};
bool validJob(const StwoCircuitAssignmentJob* j) {
  return j && !j->reserved && j->value_count && j->value_count < (1u << 31) &&
      j->record_count && j->first == 0 && j->count == j->record_count &&
      !(reinterpret_cast<uintptr_t>(j->values) % 16) &&
      !(reinterpret_cast<uintptr_t>(j->records) % 16);
}
int validate(rv64::Custody& c, const StwoCircuitAssignmentJob* j,
             const uint32_t* ends, uint32_t end_count) {
  if (!validJob(j) || !ends || !end_count) return int(cudaErrorInvalidValue);
  if (!c.range(j->values, uint64_t(j->value_count) * 4, true) ||
      !c.range(static_cast<const uint32_t*>(j->records), uint64_t(j->record_count) * 8, false) ||
      !c.range(j->status, 1, true) ||
      (j->index_count && !c.range(j->indices, j->index_count, false)) ||
      !c.range(ends, end_count, false)) return c.status;
  return 0;
}
int setNode(Graph& g, Node& node, const StwoCircuitAssignmentJob& base,
            const uint32_t* ends, bool creating, cudaGraphNode_t previous) {
  auto job = base; job.first = node.step.first; job.count = node.step.count;
  uint32_t first = node.step.first_level, levels = node.step.levels;
  void* args[] = {&job, &ends, &first, &levels};
  cudaKernelNodeParams p{};
  p.func = node.step.kind != 1 ? reinterpret_cast<void*>(circuit_fill::wide_level)
      : g.flow ? reinterpret_cast<void*>(circuit_fill::flow_kernel())
               : reinterpret_cast<void*>(circuit_fill::chain_run);
  p.gridDim = node.step.kind == 1 ? dim3(1) : dim3((job.count + 127) / 128);
  p.blockDim = node.step.kind == 1 ? dim3(circuit_fill::kChainThreads) : dim3(128);
  p.kernelParams = args;
  // CUDA copies the complete argument values during Add/SetParams. The
  // dependency chain and launch geometry are unchanged across all replays.
  if (creating) return int(cudaGraphAddKernelNode(&node.handle, g.graph,
      previous ? &previous : nullptr, previous ? 1 : 0, &p));
  return int(cudaGraphExecKernelNodeSetParams(g.exec, node.handle, &p));
}
// Diagnostic only (STWO_RV64_M8_ASSIGNMENT_DUMP=<dir>, default unset): writes
// the first node whose plan has >= STWO_RV64_M8_ASSIGNMENT_DUMP_MIN_LEVELS
// (default 100000) levels, as the kernel sees it right before launch (seeded
// values, records, indices, level ends, steps), for the chain microbenchmark
// and parity test. Synchronises the lane stream; never changes any value.
int dump(const Graph& g, const StwoCircuitAssignmentJob& j, const uint32_t* ends, cudaStream_t stream) {
  static std::atomic<int> taken{0};
  const char* dir = std::getenv("STWO_RV64_M8_ASSIGNMENT_DUMP");
  if (!dir || !*dir) return 0;
  const char* min_text = std::getenv("STWO_RV64_M8_ASSIGNMENT_DUMP_MIN_LEVELS");
  const unsigned long min_levels = min_text ? std::strtoul(min_text, nullptr, 10) : 100000ul;
  if (g.ends < min_levels || taken.exchange(1)) return 0;
  if (const auto rc = cudaStreamSynchronize(stream)) return int(rc);
  std::vector<uint32_t> host;
  char path[4096];
  std::snprintf(path, sizeof path, "%s/assignment-node.bin", dir);
  FILE* f = std::fopen(path, "wb");
  if (!f) return 0;
  const uint32_t header[8] = {0x54324e44u, 1u, j.value_count, j.record_count, j.index_count, g.ends, uint32_t(g.nodes.size()), 0u};
  std::fwrite(header, 4, 8, f);
  for (const auto& node : g.nodes) std::fwrite(&node.step, sizeof node.step, 1, f);
  const auto put = [&](const void* device, uint64_t words) {
    host.resize(size_t(words));
    if (cudaMemcpy(host.data(), device, size_t(words) * 4, cudaMemcpyDeviceToHost) == cudaSuccess)
      std::fwrite(host.data(), 4, size_t(words), f);
  };
  put(ends, g.ends);
  put(j.records, uint64_t(j.record_count) * 8);
  if (j.index_count) put(j.indices, j.index_count);
  put(j.values, uint64_t(j.value_count) * 4);
  std::fclose(f);
  std::fprintf(stderr, "GPU_M8_ASSIGNMENT_DUMP path=%s values=%u records=%u levels=%u steps=%zu\n", path, j.value_count, j.record_count, g.ends, g.nodes.size());
  return 0;
}
} // namespace stwo::cuda::assignment_graph
extern "C" int stwo_assignment_graph_create_v1(void* ctx, uint32_t lane,
    const StwoCircuitAssignmentJob* j, const StwoAssignmentGraphStep* steps,
    uint32_t count, const uint32_t* ends, uint32_t end_count, void** result) {
  using namespace stwo::cuda;
  if (!result) return int(cudaErrorInvalidValue);
  *result = nullptr;
  if (!steps || !count || count > 65536) return int(cudaErrorInvalidValue);
  rv64::Custody custody(ctx, lane);
  if (const int rc = assignment_graph::validate(custody, j, ends, end_count)) return rc;
  uint64_t identity = 0;
  if (const int rc = stwo_exec_context_identity(ctx, &identity)) return rc;
  if (!identity) return int(cudaErrorInvalidResourceHandle);
  uint32_t task = 0, last_level = 0;
  for (uint32_t i = 0; i < count; ++i) {
    const auto& s = steps[i];
    if (s.kind > 1 || !s.count || s.first != task || s.count > j->record_count - task ||
        !s.levels || s.first_level < last_level || s.first_level > end_count ||
        s.levels > end_count - s.first_level || (s.kind == 0 && s.levels != 1))
      return int(cudaErrorInvalidValue);
    task += s.count; last_level = s.first_level + s.levels;
  }
  if (task != j->record_count) return int(cudaErrorInvalidValue);
  try {
    auto g = std::make_unique<assignment_graph::Graph>();
    g->context = ctx; g->identity = identity; g->lane = lane;
    g->values = j->value_count; g->records = j->record_count; g->indices = j->index_count; g->ends = end_count;
    g->flow = circuit_fill::flow_mode();
    if (g->flow < 0) return int(cudaErrorInvalidValue);
    if (const auto rc = cudaGraphCreate(&g->graph, 0)) return int(rc);
    g->nodes.resize(count);
    cudaGraphNode_t previous = nullptr;
    for (uint32_t i = 0; i < count; ++i) {
      g->nodes[i].step = steps[i];
      if (const int rc = assignment_graph::setNode(*g, g->nodes[i], *j, ends, true, previous)) return rc;
      previous = g->nodes[i].handle;
    }
    if (const auto rc = cudaGraphInstantiate(&g->exec, g->graph, nullptr, nullptr, 0)) return int(rc);
    *result = g.release();
    return 0;
  } catch (const std::bad_alloc&) { return int(cudaErrorMemoryAllocation); }
}
extern "C" int stwo_assignment_graph_launch_v1(void* ctx, uint32_t lane, void* handle,
    const StwoCircuitAssignmentJob* j, const uint32_t* ends, uint32_t end_count) {
  using namespace stwo::cuda;
  if (!handle) return int(cudaErrorInvalidValue);
  auto& g = *static_cast<assignment_graph::Graph*>(handle);
  uint64_t identity = 0;
  if (const int rc = stwo_exec_context_identity(ctx, &identity)) return rc;
  if (g.context != ctx || g.identity != identity || g.lane != lane)
    return int(cudaErrorInvalidResourceHandle);
  rv64::Custody custody(ctx, lane);
  if (const int rc = assignment_graph::validate(custody, j, ends, end_count)) return rc;
  if (j->value_count != g.values || j->record_count != g.records ||
      j->index_count != g.indices || end_count != g.ends) return int(cudaErrorInvalidValue);
  for (auto& node : g.nodes)
    if (const int rc = assignment_graph::setNode(g, node, *j, ends, false, nullptr)) return rc;
  if (const int rc = assignment_graph::dump(g, *j, ends, custody.stream)) return rc;
  return int(cudaGraphLaunch(g.exec, custody.stream));
}
extern "C" int stwo_assignment_graph_destroy_v1(void* ctx, void* handle) {
  using namespace stwo::cuda;
  if (!handle) return int(cudaErrorInvalidValue);
  auto* g = static_cast<assignment_graph::Graph*>(handle);
  uint64_t identity = 0;
  if (const int rc = stwo_exec_context_identity(ctx, &identity)) return rc;
  if (g->context != ctx || g->identity != identity) return int(cudaErrorInvalidResourceHandle);
  delete g;
  return 0;
}
