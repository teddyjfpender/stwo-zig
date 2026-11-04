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
namespace stwo::cuda::circuit_fill {
namespace q = stwo::cuda::oods;
constexpr uint32_t kChainThreads = 512, kChainMaxWidth = 2048, kEndsChunk = 1024;
__device__ __forceinline__ q::QM31 load(const uint32_t* p, uint32_t i) {
    p += uint64_t(i) * 4;
    return {{p[0], p[1]}, {p[2], p[3]}};
}
__device__ __forceinline__ void store(uint32_t* p, uint32_t i, q::QM31 v) {
    p += uint64_t(i) * 4;
    p[0] = v.a.a;
    p[1] = v.a.b;
    p[2] = v.b.a;
    p[3] = v.b.b;
}
__device__ __forceinline__ bool zero(q::QM31 x) { return !(x.a.a | x.a.b | x.b.a | x.b.b); }
__device__ __forceinline__ uint32_t word(q::QM31 v) { return v.a.a | (v.a.b << 16); }
__device__ __forceinline__ q::QM31 packed(uint32_t v) { return {{v & 65535, v >> 16}, {0, 0}}; }
__device__ __forceinline__ uint32_t ror(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
__device__ void fail(uint32_t* p) { atomicOr(p, 1u); }
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
__device__ __forceinline__ StwoCircuitAssignmentTask fetch(const StwoCircuitAssignmentTask* tasks, uint32_t i) {
    // Records are immutable for the whole node: read-only path.
    const uint4* p = reinterpret_cast<const uint4*>(tasks + i);
    const uint4 lo = __ldg(p), hi = __ldg(p + 1);
    return {lo.x, lo.y, {lo.z, lo.w, hi.x, hi.y, hi.z, hi.w}};
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
        StwoCircuitAssignmentTask current{};
        if (begin + tid < s_ends[0]) current = fetch(tasks, begin + tid);
        for (uint32_t l = 0; l < n; ++l) {
            const uint32_t end = s_ends[l];
            // Prefetch the next level's first strided record before this
            // level's dependent loads: the record load leaves the chain latency.
            StwoCircuitAssignmentTask following{};
            if (l + 1 < n && end + tid < s_ends[l + 1]) following = fetch(tasks, end + tid);
            if (begin + tid < end) at(j, current);
            for (uint32_t i = begin + tid + kChainThreads; i < end; i += kChainThreads) at(j, fetch(tasks, i));
            // Global writes of this level are visible to the whole CTA after
            // the barrier, before any later dependency level reads them.
            __syncthreads();
            current = following;
            begin = end;
        }
    }
    if (tid == 0 && begin != j.first + j.count) fail(j.status);
}
}  // namespace stwo::cuda::circuit_fill

// Optional generation-only grouping (capability: symbol present). `ends` is a
// device array of absolute task ends for the whole plan; this run covers
// levels [first_level, first_level + levels) and tasks [j->first, j->first + j->count).
extern "C" int stwo_circuit_assignment_chain_run_on(void* ctx, uint32_t lane, const StwoCircuitAssignmentJob* j, const uint32_t* ends, uint32_t first_level, uint32_t levels) {
    using namespace stwo::cuda::rv64;
    using namespace stwo::cuda::circuit_fill;
    if (!j || j->reserved || !j->value_count || j->value_count >= (1u << 31) || !j->count || uint64_t(j->first) + j->count > j->record_count || !ends || !levels) return int(cudaErrorInvalidValue);
    Custody c(ctx, lane);
    if (!c.range(j->values, uint64_t(j->value_count) * 4, true) ||
        !c.range(static_cast<const uint32_t*>(j->records), uint64_t(j->record_count) * 8, false) ||
        !c.range(j->status, 1, true) || (j->index_count && !c.range(j->indices, j->index_count, false)) ||
        !c.range(ends + first_level, levels, false))
        return c.status;
    chain_run<<<1, kChainThreads, 0, c.stream>>>(*j, ends, first_level, levels);
    return int(cudaPeekAtLastError());
}
extern "C" uint32_t stwo_circuit_assignment_chain_max_width() { return stwo::cuda::circuit_fill::kChainMaxWidth; }
