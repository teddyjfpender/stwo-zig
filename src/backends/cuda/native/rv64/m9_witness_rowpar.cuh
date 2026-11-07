// M9 prep, STWO_RV64_M9_WITNESS_ROWPAR (default off; not linked into the
// native library yet): row-parallel executor of the recursion MAIN assignment.
//
// Include AFTER circuit_fill_chain.cu (it reuses that file's exact task
// arithmetic `eval`/`at`, `fetch`, `load`/`store`, `word`/`packed`, `ror`).
// The plan (src/integrations/riscv_cuda/rv64/m9_witness_rowpar/plan.zig) is a
// CSR of levels -> strands -> units over the SAME device records:
//   unit = plain record index | (1<<31 | fused Blake2s compression index).
// A thread runs a whole strand serially: plain records with the running value
// forwarded in a register, compressions with the 16-word state in registers
// (80 G + 8 finalisation xors -> one unit, all 328 outputs stored). One
// __syncthreads per strand level instead of one per DAG level.
//
// Exactness: plain records run `eval` (the arithmetic of `at`) on the same
// inputs; a forwarded value is the value the producer stored (forwarding only
// after a successful single-output eval; kinds 6/7/8/9 failures never
// forward). Compressions compute blake2sG on word() of the same inputs and
// store packed() words: the bytes the G and triple-xor records store.
#pragma once
#include <cstdint>
namespace stwo::cuda::m9_rowpar {
namespace cf = stwo::cuda::circuit_fill;
namespace q = stwo::cuda::oods;
constexpr uint32_t kThreads = 512;
constexpr uint32_t kBlakeFlag = 1u << 31;
struct BlakeUnit { uint32_t base, init[16], msg[16], xout[8], flags, pad[6]; };
constexpr uint32_t kBlakeInline = 1;  // a G output is read outside the compression
static_assert(sizeof(BlakeUnit) == 192);
struct Job {
    StwoCircuitAssignmentJob j;
    const uint32_t* level_ends;   // absolute strand ends per level
    const uint32_t* strand_ends;  // absolute unit ends per strand
    const uint32_t* units;
    const BlakeUnit* blake;
    // Strand-ordered record stream (one 32-byte record per unit, plain records
    // copied verbatim, a compression as {kKindBlake, index}): the next
    // record's address needs no load, so the record pipeline has no
    // dependent metadata latency.
    const StwoCircuitAssignmentTask* srec;
};
constexpr uint32_t kKindBlake = 0x100u;
__device__ __forceinline__ void g(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t f0, uint32_t f1) {
    a = a + b + f0; d = cf::ror(d ^ a, 16); c += d; b = cf::ror(b ^ c, 12);
    a = a + b + f1; d = cf::ror(d ^ a, 8); c += d; b = cf::ror(b ^ c, 7);
}
__device__ __forceinline__ void put(uint32_t* values, uint32_t i, uint32_t w) {
    reinterpret_cast<uint4*>(values)[i] = make_uint4(w & 65535u, w >> 16, 0u, 0u);
}
// Diagnostic only (-DM9_DIAG_NO_G_STORES: values NOT exact): drops the 320 G
// output stores of a compression to separate store cost from G arithmetic.
template <bool StoreG>
__device__ __forceinline__ void put_g(uint32_t* values, uint32_t i, uint32_t w) {
    if (StoreG) put(values, i, w);
}
// Per-thread forwarding state across the units of one strand.
struct Fwd {
    uint32_t out = 0xffffffffu;  // last plain single-output variable
    uint4 val{};
    uint32_t hvar[8];            // last compression's finalisation outputs
    uint32_t h[8];
    bool hvalid = false;
};
__device__ __forceinline__ uint32_t word_of(const uint32_t* values, uint32_t var, const Fwd& f) {
    if (f.hvalid) {
#pragma unroll
        for (int i = 0; i < 8; ++i) if (f.hvar[i] == var) return f.h[i];
    }
    if (var == f.out) return f.val.x | (f.val.y << 16);
    return cf::word(cf::load(values, var));
}
// Compile-time sigma: after unrolling every message index is a constant, so
// the 16 message words and the 16-word state stay in registers (a
// __constant__ table would force a local-memory array).
template <int R, int I> struct Sig;
#define M9_SIG(R, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15) \
    template <int I> struct Sig<R, I> { static constexpr int v[16] = {a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15}; static constexpr int value = v[I]; };
M9_SIG(0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
M9_SIG(1, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
M9_SIG(2, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4)
M9_SIG(3, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8)
M9_SIG(4, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13)
M9_SIG(5, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9)
M9_SIG(6, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11)
M9_SIG(7, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10)
M9_SIG(8, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5)
M9_SIG(9, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0)
#undef M9_SIG
template <int R, bool StoreG>
__device__ __forceinline__ void round_(uint32_t* values, uint32_t o, uint32_t (&v)[16], const uint32_t (&m)[16]) {
#define M9_G(A, B, C, D, I)                                                                  \
    g(v[A], v[B], v[C], v[D], m[Sig<R, 2 * I>::value], m[Sig<R, 2 * I + 1>::value]);        \
    put_g<StoreG>(values, o + 4 * I, v[A]); put_g<StoreG>(values, o + 4 * I + 1, v[B]); put_g<StoreG>(values, o + 4 * I + 2, v[C]); put_g<StoreG>(values, o + 4 * I + 3, v[D]);
    M9_G(0, 4, 8, 12, 0) M9_G(1, 5, 9, 13, 1) M9_G(2, 6, 10, 14, 2) M9_G(3, 7, 11, 15, 3)
    M9_G(0, 5, 10, 15, 4) M9_G(1, 6, 11, 12, 5) M9_G(2, 7, 8, 13, 6) M9_G(3, 4, 9, 14, 7)
#undef M9_G
}
template <bool StoreG>
__device__ __forceinline__ void rounds(uint32_t* values, uint32_t base, uint32_t (&v)[16], const uint32_t (&m)[16]) {
    round_<0, StoreG>(values, base, v, m); round_<1, StoreG>(values, base + 32, v, m); round_<2, StoreG>(values, base + 64, v, m);
    round_<3, StoreG>(values, base + 96, v, m); round_<4, StoreG>(values, base + 128, v, m); round_<5, StoreG>(values, base + 160, v, m);
    round_<6, StoreG>(values, base + 192, v, m); round_<7, StoreG>(values, base + 224, v, m); round_<8, StoreG>(values, base + 256, v, m);
    round_<9, StoreG>(values, base + 288, v, m);
}
__device__ __forceinline__ void run_blake(const Job& J, const BlakeUnit* __restrict__ u, Fwd& f) {
    uint32_t* values = J.j.values;
    const uint4* r4 = reinterpret_cast<const uint4*>(u);
    // All 32 input variables, then all 32 independent value loads, then the
    // forwarding overrides: one memory latency per compression, not 32.
    uint32_t var[33];
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        const uint4 w = __ldg(r4 + i);
        var[4 * i] = w.x; var[4 * i + 1] = w.y; var[4 * i + 2] = w.z; var[4 * i + 3] = w.w;
    }
    var[32] = __ldg(reinterpret_cast<const uint32_t*>(u) + 32);
    // var[0] = base, var[1..16] = init, var[17..32] = msg
    uint32_t v[16], m[16];
    // Forwarded words (the previous compression's h, the previous plain
    // output) issue no load; the rest are 32 independent predicated loads.
    uint32_t hit = 0;
    const uint32_t fw = f.val.x | (f.val.y << 16);
#pragma unroll
    for (int i = 0; i < 32; ++i) {
        uint32_t w = 0;
        bool h = false;
        if (var[1 + i] == f.out) { w = fw; h = true; }
        if (f.hvalid) {
#pragma unroll
            for (int k = 0; k < 8; ++k) if (var[1 + i] == f.hvar[k]) { w = f.h[k]; h = true; }
        }
        if (h) hit |= 1u << i;
        if (i < 16) v[i] = w; else m[i - 16] = w;
    }
#pragma unroll
    for (int i = 0; i < 32; ++i) {
        if (hit >> i & 1) continue;
        const uint32_t w = cf::word(cf::load(values, var[1 + i]));
        if (i < 16) v[i] = w; else m[i - 16] = w;
    }
    uint32_t init[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) init[i] = v[i];
    const uint32_t base = var[0];
    // Critical pass: a compression whose G outputs nobody else reads stores
    // only h here; its 320 G outputs come from rowpar_blake_fill.
    if (__ldg(reinterpret_cast<const uint32_t*>(u) + 41) & kBlakeInline) rounds<true>(values, base, v, m);
    else rounds<false>(values, base, v, m);
    const uint32_t* xr = reinterpret_cast<const uint32_t*>(u) + 33;
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        const uint32_t h = init[i] ^ v[i] ^ v[i + 8];
        const uint32_t xv = __ldg(xr + i);
        put(values, xv, h);
        f.hvar[i] = xv;
        f.h[i] = h;
    }
    f.hvalid = true;
}
__device__ __forceinline__ void run_plain(const Job& J, uint32_t rec, Fwd& f) {
    const auto& j = J.j;
    const auto t = cf::fetch(static_cast<const StwoCircuitAssignmentTask*>(j.records), rec);
    if (t.kind == 7) {  // permutation: the exact `at` path, never forwarded
        cf::at(j, t);
        f.out = 0xffffffffu;
        f.hvalid = false;
        return;
    }
    const unsigned n = cf::arity_of(t.kind);
    q::QM31 x[6];
    // Independent loads first (one latency), then the register overrides.
    // A forwarded input issues no load; the others are independent predicated
    // loads (one memory latency per record).
#pragma unroll
    for (unsigned i = 0; i < 6; ++i) {
        if (i >= n) break;
        const uint32_t a = t.args[i];
        bool hit = false;
        if (a == f.out) { x[i] = q::QM31{{f.val.x, f.val.y}, {f.val.z, f.val.w}}; hit = true; }
        if (f.hvalid) {
#pragma unroll
            for (int k = 0; k < 8; ++k) if (f.hvar[k] == a) { x[i] = {{f.h[k] & 65535u, f.h[k] >> 16}, {0, 0}}; hit = true; }
        }
        if (!hit) x[i] = cf::load(j.values, a);
    }
    uint4 r;
    const bool ok = cf::eval(j, t, x, r);
    if (ok && t.kind != 6) { f.out = t.out; f.val = r; } else f.out = 0xffffffffu;
}
__device__ __forceinline__ void run_strand(const Job& J, uint32_t s) {
    const uint32_t ub = s ? J.strand_ends[s - 1] : 0, ue = J.strand_ends[s];
    Fwd f;
    for (uint32_t u = ub; u < ue; ++u) {
        const uint32_t unit = J.units[u];
        if (unit & kBlakeFlag) run_blake(J, J.blake + (unit & ~kBlakeFlag), f);
        else run_plain(J, unit, f);
    }
}
// v2 executor state for one strand head: unit range and the first unit's
// record, loaded one/two levels ahead (metadata is immutable for the node).
struct Head { uint32_t ub, ue, unit; StwoCircuitAssignmentTask rec; };
__device__ __forceinline__ StwoCircuitAssignmentTask none_task() { return {15u, 0u, {0, 0, 0, 0, 0, 0}}; }
__device__ __forceinline__ void run_plain_rec(const Job& J, const StwoCircuitAssignmentTask& t, Fwd& f) {
    const auto& j = J.j;
    if (t.kind == 7) { cf::at(j, t); f.out = 0xffffffffu; f.hvalid = false; return; }
    const unsigned n = cf::arity_of(t.kind);
    q::QM31 x[6];
#pragma unroll
    for (unsigned i = 0; i < 6; ++i) {
        if (i >= n) break;
        const uint32_t a = t.args[i];
        bool hit = false;
        if (a == f.out) { x[i] = q::QM31{{f.val.x, f.val.y}, {f.val.z, f.val.w}}; hit = true; }
        if (f.hvalid) {
#pragma unroll
            for (int k = 0; k < 8; ++k) if (f.hvar[k] == a) { x[i] = {{f.h[k] & 65535u, f.h[k] >> 16}, {0, 0}}; hit = true; }
        }
        if (!hit) x[i] = cf::load(j.values, a);
    }
    uint4 r;
    const bool ok = cf::eval(j, t, x, r);
    if (ok && t.kind != 6) { f.out = t.out; f.val = r; } else f.out = 0xffffffffu;
}
// Outputs of the unit just executed, for the input pipeline: an input of the
// next record that the current unit produces is resolved after it runs
// (forwarded register, or a load in program order); every other input is
// final (seed, earlier strand level, or an earlier member of this strand
// already stored by this thread) and is loaded BEFORE the current unit runs.
struct Produced { uint32_t lo, hi; const uint32_t* xout; };
__device__ __forceinline__ bool produced_by(const Produced& p, uint32_t a) {
    if (a >= p.lo && a < p.hi) return true;
    if (p.xout) {
#pragma unroll
        for (int k = 0; k < 8; ++k) if (__ldg(p.xout + k) == a) return true;
    }
    return false;
}
__device__ __forceinline__ void run_head(const Job& J, const Head& h) {
    const auto& j = J.j;
    Fwd f;
    // Two records in flight ahead of the one executing.
    StwoCircuitAssignmentTask rec = h.rec;
    StwoCircuitAssignmentTask nrec = h.ub + 1 < h.ue ? cf::fetch(J.srec, h.ub + 1) : none_task();
    q::QM31 x[6];
    uint32_t late = 0x3f;  // the head's inputs: loaded at its start
    for (uint32_t u = h.ub; u < h.ue; ++u) {
        const StwoCircuitAssignmentTask nnrec = u + 2 < h.ue ? cf::fetch(J.srec, u + 2) : none_task();
        const bool has_next = u + 1 < h.ue;
        const bool next_plain = has_next && nrec.kind != kKindBlake && nrec.kind != 7;
        Produced p{0, 0, nullptr};
        uint32_t nlate = 0x3f;
        q::QM31 nx[6];
        if (rec.kind == kKindBlake) {
            const BlakeUnit* b = J.blake + rec.out;
            p.xout = b->xout;
            if (__ldg(&b->flags) & kBlakeInline) { p.lo = __ldg(&b->base); p.hi = p.lo + 320; }
            if (next_plain) {
                nlate = 0;
                const unsigned n = cf::arity_of(nrec.kind);
#pragma unroll
                for (unsigned i = 0; i < 6; ++i) if (i < n) {
                    if (produced_by(p, nrec.args[i])) nlate |= 1u << i; else nx[i] = cf::load(j.values, nrec.args[i]);
                }
            }
            run_blake(J, b, f);
        } else if (rec.kind == 7) {
            cf::at(j, rec); f.out = 0xffffffffu; f.hvalid = false;
        } else {
            const unsigned n = cf::arity_of(rec.kind);
            // Resolve this record's late inputs (forwarded or loaded now).
#pragma unroll
            for (unsigned i = 0; i < 6; ++i) {
                if (i >= n || !(late >> i & 1)) continue;
                const uint32_t a = rec.args[i];
                bool hit = false;
                if (a == f.out) { x[i] = q::QM31{{f.val.x, f.val.y}, {f.val.z, f.val.w}}; hit = true; }
                if (f.hvalid) {
#pragma unroll
                    for (int k = 0; k < 8; ++k) if (f.hvar[k] == a) { x[i] = {{f.h[k] & 65535u, f.h[k] >> 16}, {0, 0}}; hit = true; }
                }
                if (!hit) x[i] = cf::load(j.values, a);
            }
            p.lo = rec.out; p.hi = rec.out + (rec.kind == 6 ? 4 : 1);
            // The next plain record's final inputs, issued before this
            // record's arithmetic.
            if (next_plain) {
                nlate = 0;
                const unsigned nn = cf::arity_of(nrec.kind);
#pragma unroll
                for (unsigned i = 0; i < 6; ++i) if (i < nn) {
                    if (produced_by(p, nrec.args[i])) nlate |= 1u << i; else nx[i] = cf::load(j.values, nrec.args[i]);
                }
            }
            uint4 r;
            const bool ok = cf::eval(j, rec, x, r);
            if (ok && rec.kind != 6) { f.out = rec.out; f.val = r; } else f.out = 0xffffffffu;
        }
#pragma unroll
        for (int i = 0; i < 6; ++i) x[i] = nx[i];
        late = nlate;
        rec = nrec;
        nrec = nnrec;
    }
}
// Deferred pass: the 320 G outputs of every compression whose G outputs are
// read only inside it (flags bit 0 clear). All its inputs are final by now.
__global__ void rowpar_blake_fill(Job J, uint32_t count) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) return;
    const BlakeUnit* u = J.blake + i;
    if (__ldg(&u->flags) & kBlakeInline) return;
    uint32_t* values = J.j.values;
    uint32_t v[16], m[16];
#pragma unroll
    for (int k = 0; k < 16; ++k) v[k] = cf::word(cf::load(values, __ldg(u->init + k)));
#pragma unroll
    for (int k = 0; k < 16; ++k) m[k] = cf::word(cf::load(values, __ldg(u->msg + k)));
    rounds<true>(values, __ldg(&u->base), v, m);
}
// One CTA over strand levels [first_level, first_level + levels): level ends
// staged in shared memory, each thread's next-level head (strand range, first
// unit, first record) loaded during the current level, its record inputs
// prefetched into L2 (a hint; never changes values). One barrier per level.
template <uint32_t Threads>
__global__ void __launch_bounds__(Threads) rowpar_run_t(Job J, uint32_t first_level, uint32_t levels) {
    constexpr uint32_t kChunk = 1024;
    __shared__ uint32_t s_ends[kChunk];
    const uint32_t tid = threadIdx.x;
    uint32_t begin = first_level ? J.level_ends[first_level - 1] : 0;
    for (uint32_t chunk = 0; chunk < levels; chunk += kChunk) {
        const uint32_t n = min(kChunk, levels - chunk);
        __syncthreads();
        for (uint32_t i = tid; i < n; i += Threads) s_ends[i] = J.level_ends[first_level + chunk + i];
        __syncthreads();
        const auto head = [&](uint32_t level, uint32_t first) -> Head {
            Head h{0, 0, 0, none_task()};
            if (level >= n) return h;
            const uint32_t s = first + tid;
            if (s >= s_ends[level]) return h;
            h.ub = s ? __ldg(J.strand_ends + s - 1) : 0;
            h.ue = __ldg(J.strand_ends + s);
            h.rec = cf::fetch(J.srec, h.ub);
            return h;
        };
        Head cur = head(0, begin);
        for (uint32_t l = 0; l < n; ++l) {
            const uint32_t end = s_ends[l];
            const Head nxt = head(l + 1, end);
            if (nxt.ue != nxt.ub && nxt.rec.kind != kKindBlake) cf::prefetch_inputs(J.j, nxt.rec);
            if (cur.ue != cur.ub) run_head(J, cur);
            for (uint32_t s = begin + tid + Threads; s < end; s += Threads) run_strand(J, s);
            __syncthreads();
            cur = nxt;
            begin = end;
        }
    }
}
__global__ void __launch_bounds__(kThreads) rowpar_run(Job J, uint32_t first_level, uint32_t levels) {
    uint32_t begin = first_level ? J.level_ends[first_level - 1] : 0;
    for (uint32_t l = first_level; l < first_level + levels; ++l) {
        const uint32_t end = J.level_ends[l];
        for (uint32_t s = begin + threadIdx.x; s < end; s += kThreads) run_strand(J, s);
        __syncthreads();
        begin = end;
    }
}
// One wide strand level as a grid.
__global__ void rowpar_wide(Job J, uint32_t level) {
    const uint32_t begin = level ? J.level_ends[level - 1] : 0, end = J.level_ends[level];
    const uint32_t s = begin + blockIdx.x * blockDim.x + threadIdx.x;
    if (s < end) run_strand(J, s);
}
}  // namespace stwo::cuda::m9_rowpar
