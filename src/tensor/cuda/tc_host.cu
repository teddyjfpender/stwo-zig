// Host layer of the tensor CUDA backend: the C ABI of tc_api.h over the
// kernels of tc_kernels.cuh. Built by nvcc for a device, or as C++ with the
// CPU emulation (tc_emu.cpp), from this one file.
//
// Residency and transfer rules (design/tensor-frontend/cuda.md):
//  - one context = one non-blocking stream + a stream-ordered memory pool
//    (cudaMallocAsync with a high release threshold: freed blocks are reused
//    without driver calls, the arena behaviour of FlashProve's CardArena);
//  - every launch, copy and free is enqueued on that stream; the host waits
//    only where it needs a value (a round's 3 QM31, an MLE value, final
//    outputs). All of it is counted in tc_stats (the emulation counts the
//    same bytes, so transfer budgets are testable without a GPU);
//  - pinned ranges (tc_pin) stay on the device for the context's life.
#include "tc_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <atomic>
#include <vector>

static thread_local uint64_t *tc_launch_counter = nullptr;
static inline void tc_note_launch() {
    if (tc_launch_counter) ++*tc_launch_counter;
}

#include "tc_kernels.cuh"

#if defined(__CUDACC__)
#include <cuda_runtime.h>
typedef cudaStream_t tc_stream_t;
#else
typedef void *tc_stream_t;
#endif

using tc::qm;

static_assert(sizeof(tc_terms) == sizeof(tc::ScTerms), "tc_terms layout");

struct Pinned {
    const void *host;
    uint64_t bytes;
    void *dev;
};

struct tc_ctx {
    int device = 0;
    tc_stream_t stream = nullptr;
    tc_stats stats = {};
    char err[512] = {0};
    char name[256] = {0};
    bool failed = false;
    // One thread at a time (cuda.md 2.4): entry points take this flag and a
    // concurrent call is refused (error, context stays usable).
    std::atomic<bool> busy{false};
    // host-visible mailbox (TC_MAILBOX_BYTES) for reduction results, and its device alias
    uint32_t *mailbox = nullptr;
    uint32_t *mailbox_dev = nullptr;
    uint32_t *counter = nullptr;   // device ticket counter (kept at 0 between launches)
    uint32_t *partials = nullptr;  // device: 1024 blocks x 3 QM31
    std::vector<Pinned> pinned;
    uint64_t commit_chunk_rows = 0;
    uint64_t commit_budget_bytes = 256ull << 20;
};

struct tc_sc {
    uint32_t *f[tc::SC_MAX_FACTORS] = {nullptr, nullptr, nullptr, nullptr};
    uint32_t nf = 0;
    tc::ScTerms t = {};
    uint64_t len = 0, active = 0, prev_half = 0, prev_active = 0;
};

static const uint32_t SC_MAX_GROUPS = 1024;
// host-mapped mailbox: 64 B per GKR job (TC_GKR_MAX_JOBS), 48 B per sumcheck round
static const uint32_t TC_MAILBOX_BYTES = 64u * TC_GKR_MAX_JOBS;

// A shape outside the kernels' bounds: refused before any device work; the
// context stays usable and the caller runs the CPU path.
static int decline(tc_ctx *c, const char *what) {
    if (c) {
        snprintf(c->err, sizeof(c->err), "declined: %s", what);
        c->stats.declined++;
    }
    return TC_DECLINED;
}

static int fail(tc_ctx *c, const char *what) {
    if (c) {
        snprintf(c->err, sizeof(c->err), "%s", what);
        c->failed = true;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Runtime primitives (device or emulation).

#if defined(__CUDACC__)
#define TC_CU(c, call)                                                         \
    do {                                                                       \
        cudaError_t e_ = (call);                                               \
        if (e_ != cudaSuccess) {                                               \
            snprintf((c)->err, sizeof((c)->err), "%s: %s", #call, cudaGetErrorString(e_)); \
            (c)->failed = true;                                                \
            return 1;                                                          \
        }                                                                      \
    } while (0)
#define TC_CHECK_LAUNCH(c) TC_CU(c, cudaGetLastError())
#else
#define TC_CU(c, call) ((void)0)
#define TC_CHECK_LAUNCH(c) ((void)0)
#endif

static void *dev_alloc(tc_ctx *c, uint64_t bytes) {
    c->stats.device_allocs++;
    if (bytes == 0) bytes = 16;
#if defined(__CUDACC__)
    void *p = nullptr;
    if (cudaMallocAsync(&p, bytes, c->stream) != cudaSuccess) {
        fail(c, "cudaMallocAsync failed");
        return nullptr;
    }
    return p;
#else
    void *p = malloc(bytes);
    if (!p) fail(c, "malloc failed");
    return p;
#endif
}

static void dev_free(tc_ctx *c, void *p) {
    if (!p) return;
#if defined(__CUDACC__)
    cudaFreeAsync(p, c->stream);
#else
    (void)c;
    free(p);
#endif
}

static int h2d(tc_ctx *c, void *dst, const void *src, uint64_t bytes) {
    c->stats.h2d_bytes += bytes;
#if defined(__CUDACC__)
    TC_CU(c, cudaMemcpyAsync(dst, src, bytes, cudaMemcpyHostToDevice, c->stream));
#else
    memcpy(dst, src, bytes);
#endif
    return 0;
}

static int d2h(tc_ctx *c, void *dst, const void *src, uint64_t bytes) {
    c->stats.d2h_bytes += bytes;
#if defined(__CUDACC__)
    TC_CU(c, cudaMemcpyAsync(dst, src, bytes, cudaMemcpyDeviceToHost, c->stream));
#else
    memcpy(dst, src, bytes);
#endif
    return 0;
}

static int dsync(tc_ctx *c) {
    c->stats.syncs++;
#if defined(__CUDACC__)
    TC_CU(c, cudaStreamSynchronize(c->stream));
#endif
    return 0;
}

// Mailbox reads count as device-to-host bytes (they cross PCIe).
static void mailbox_read(tc_ctx *c, uint32_t *out, uint32_t words) {
    memcpy(out, c->mailbox, 4ull * words);
    c->stats.d2h_bytes += 4ull * words;
}

static uint32_t grid_for(uint64_t n, uint32_t per_thread) {
    uint64_t g = (n + (uint64_t)TC_TB * per_thread - 1) / ((uint64_t)TC_TB * per_thread);
    if (g < 1) g = 1;
    if (g > 65535) g = 65535;
    return (uint32_t)g;
}

// Device copy of a host range: pinned (no transfer) or a fresh upload that the
// caller frees (*owned = true).
static const void *upload(tc_ctx *c, const void *host, uint64_t bytes, bool *owned) {
    for (const Pinned &p : c->pinned) {
        if (p.host == host && p.bytes >= bytes) {
            c->stats.resident_hits++;
            *owned = false;
            return p.dev;
        }
    }
    void *d = dev_alloc(c, bytes);
    if (!d) return nullptr;
    if (h2d(c, d, host, bytes)) return nullptr;
    *owned = true;
    return d;
}

static qm qm_from(const uint32_t *l) { return qm{l[0], l[1], l[2], l[3]}; }

// ---------------------------------------------------------------------------
// Context.

extern "C" int tc_backend_kind(void) {
#if defined(__CUDACC__)
    return 1;
#else
    return 2;
#endif
}

extern "C" tc_ctx *tc_create(int device) {
    tc_ctx *c = new tc_ctx();
    c->device = device;
    tc_launch_counter = &c->stats.launches;
#if defined(__CUDACC__)
    cudaDeviceProp prop;
    if (cudaSetDevice(device) != cudaSuccess || cudaGetDeviceProperties(&prop, device) != cudaSuccess) {
        delete c;
        return nullptr;
    }
    snprintf(c->name, sizeof(c->name), "%s (sm_%d%d, %.1f GB)", prop.name, prop.major, prop.minor, prop.totalGlobalMem / 1e9);
    if (cudaStreamCreateWithFlags(&c->stream, cudaStreamNonBlocking) != cudaSuccess) {
        delete c;
        return nullptr;
    }
    // keep freed pool memory for reuse (no driver round trips between proofs)
    cudaMemPool_t pool;
    if (cudaDeviceGetDefaultMemPool(&pool, device) == cudaSuccess) {
        uint64_t threshold = UINT64_MAX;
        cudaMemPoolSetAttribute(pool, cudaMemPoolAttrReleaseThreshold, &threshold);
    }
    if (cudaHostAlloc((void **)&c->mailbox, TC_MAILBOX_BYTES, cudaHostAllocMapped) != cudaSuccess ||
        cudaHostGetDevicePointer((void **)&c->mailbox_dev, c->mailbox, 0) != cudaSuccess) {
        delete c;
        return nullptr;
    }
    if (cudaMalloc((void **)&c->counter, 4) != cudaSuccess || cudaMemset(c->counter, 0, 4) != cudaSuccess ||
        cudaMalloc((void **)&c->partials, SC_MAX_GROUPS * 3 * 16) != cudaSuccess) {
        delete c;
        return nullptr;
    }
#else
    snprintf(c->name, sizeof(c->name), "CPU emulation of the tensor CUDA kernels");
    c->mailbox = (uint32_t *)calloc(TC_MAILBOX_BYTES, 1);
    c->mailbox_dev = c->mailbox;
    c->counter = (uint32_t *)calloc(1, 4);
    c->partials = (uint32_t *)calloc(SC_MAX_GROUPS * 3, 16);
#endif
    return c;
}

extern "C" void tc_destroy(tc_ctx *c) {
    if (!c) return;
    tc_unpin_all(c);
#if defined(__CUDACC__)
    cudaStreamSynchronize(c->stream);
    cudaFree(c->counter);
    cudaFree(c->partials);
    cudaFreeHost(c->mailbox);
    cudaStreamDestroy(c->stream);
#else
    free(c->mailbox);
    free(c->counter);
    free(c->partials);
#endif
    if (tc_launch_counter == &c->stats.launches) tc_launch_counter = nullptr;
    delete c;
}

extern "C" const char *tc_last_error(tc_ctx *c) { return c ? c->err : "no context"; }
extern "C" const char *tc_device_name(tc_ctx *c) { return c ? c->name : ""; }
extern "C" void tc_get_stats(tc_ctx *c, tc_stats *out) { *out = c->stats; }
extern "C" void tc_set_commit_chunk_rows(tc_ctx *c, uint64_t rows) { c->commit_chunk_rows = rows; }

// Entry guard: refuses failed contexts and concurrent use from a second
// thread, and binds the launch counter of the calling thread to this context.
struct TcBusy {
    tc_ctx *c;
    bool ok;
    explicit TcBusy(tc_ctx *ctx) : c(ctx), ok(!ctx->busy.exchange(true, std::memory_order_acquire)) {}
    ~TcBusy() {
        if (ok) c->busy.store(false, std::memory_order_release);
    }
};
static int busy_error(tc_ctx *c) {
    snprintf(c->err, sizeof(c->err), "tc_ctx used from two threads at once (one context per prover thread)");
    return 1;
}
#define TC_ENTER(c)                               \
    if (!(c) || (c)->failed) return 1;            \
    TcBusy tc_busy_(c);                           \
    if (!tc_busy_.ok) return busy_error(c);       \
    tc_launch_counter = &(c)->stats.launches
#define TC_ENTER_PTR(c)                           \
    if (!(c) || (c)->failed) return nullptr;      \
    TcBusy tc_busy_(c);                           \
    if (!tc_busy_.ok) {                           \
        busy_error(c);                            \
        return nullptr;                           \
    }                                             \
    tc_launch_counter = &(c)->stats.launches

extern "C" int tc_ok(tc_ctx *c) { return c && !c->failed; }

extern "C" int tc_pin(tc_ctx *c, const void *host, uint64_t bytes) {
    TC_ENTER(c);
    for (const Pinned &p : c->pinned)
        if (p.host == host && p.bytes >= bytes) return 0;
    void *d = dev_alloc(c, bytes);
    if (!d || h2d(c, d, host, bytes)) return 1;
    c->pinned.push_back(Pinned{host, bytes, d});
    return dsync(c);
}

extern "C" void tc_unpin_all(tc_ctx *c) {
    if (!c) return;
    for (const Pinned &p : c->pinned) dev_free(c, p.dev);
    c->pinned.clear();
}

extern "C" void tc_free_visible(tc_ctx *c, void *p) {
    (void)c;
#if defined(__CUDACC__)
    cudaFree(p);
#else
    free(p);
#endif
}

// ---------------------------------------------------------------------------
// Field / eq references.

TC_GLOBAL tc_qm_mul_k(const uint32_t *x, const uint32_t *y, uint64_t n, uint32_t *out) {
    TC_THREADS
        const uint64_t stride = (uint64_t)TC_NBLOCKS * TC_BLOCK_DIM;
        for (uint64_t i = (uint64_t)TC_BLOCK_ID * TC_BLOCK_DIM + tid; i < n; i += stride) tc::qm_store(out, i, tc::qm_mul(tc::qm_load(x, i), tc::qm_load(y, i)));
    TC_END_THREADS
}

extern "C" int tc_qm_mul_batch(tc_ctx *c, const uint32_t *x, const uint32_t *y, uint64_t n, uint32_t *out) {
    TC_ENTER(c);
    uint32_t *dx = (uint32_t *)dev_alloc(c, n * 16), *dy = (uint32_t *)dev_alloc(c, n * 16), *dout = (uint32_t *)dev_alloc(c, n * 16);
    if (!dx || !dy || !dout) return 1;
    h2d(c, dx, x, n * 16);
    h2d(c, dy, y, n * 16);
    TC_LAUNCH(tc_qm_mul_k, grid_for(n, 1), TC_TB, c->stream, dx, dy, n, dout);
    TC_CHECK_LAUNCH(c);
    d2h(c, out, dout, n * 16);
    int rc = dsync(c);
    dev_free(c, dx);
    dev_free(c, dy);
    dev_free(c, dout);
    return rc;
}

// gamma * eq(point, .) into the device QM31 vector dst[off ..][0 .. 2^n << free_bits)
// (accumulating if asked). point is a host array.
static int eq_build(tc_ctx *c, const uint32_t *point, uint32_t n, qm gamma, uint32_t free_bits, uint64_t off, bool accumulate, uint32_t *dst) {
    const uint32_t n_lo = n / 2, n_hi = n - n_lo;
    uint32_t *dpt = (uint32_t *)dev_alloc(c, 16ull * (n ? n : 1));
    uint32_t *hi = (uint32_t *)dev_alloc(c, 16ull << n_hi);
    uint32_t *lo = (uint32_t *)dev_alloc(c, 16ull << n_lo);
    if (!dpt || !hi || !lo) return 1;
    if (n) h2d(c, dpt, point, 16ull * n);
    TC_LAUNCH(tc::tc_eq_halves, 2, TC_TB, c->stream, dpt, n_hi, n_lo, gamma, hi, lo);
    TC_CHECK_LAUNCH(c);
    const uint64_t count = (1ull << n) << free_bits;
    TC_LAUNCH(tc::tc_eq_expand, grid_for(count, 4), TC_TB, c->stream, hi, lo, n_lo, free_bits, count, off, accumulate ? 1u : 0u, dst);
    TC_CHECK_LAUNCH(c);
    dev_free(c, dpt);
    dev_free(c, hi);
    dev_free(c, lo);
    return 0;
}

extern "C" int tc_eq_table(tc_ctx *c, const uint32_t *point, uint32_t n, const uint32_t gamma[4], uint32_t *out) {
    TC_ENTER(c);
    uint32_t *d = (uint32_t *)dev_alloc(c, 16ull << n);
    if (!d || eq_build(c, point, n, qm_from(gamma), 0, 0, false, d)) return 1;
    d2h(c, out, d, 16ull << n);
    int rc = dsync(c);
    dev_free(c, d);
    return rc;
}

// ---------------------------------------------------------------------------
// Weight passes, matmul, MLE.

extern "C" int tc_combine_rows(tc_ctx *c, const void *m, int is_i8, uint64_t R, uint64_t C, const uint32_t *coeffs, uint32_t G, uint32_t *out) {
    TC_ENTER(c);
    if (G == 0 || G > 4 || R == 0) return decline(c, "combine: bad shape");
    c->stats.weight_passes++;
    const uint64_t esz = is_i8 ? 1 : 4;
    bool owned = false;
    const void *dm = upload(c, m, R * C * esz, &owned);
    uint32_t *dc = (uint32_t *)dev_alloc(c, 16ull * G * R);
    if (!dm || !dc) return 1;
    h2d(c, dc, coeffs, 16ull * G * R);
    // enough row chunks to fill the device when there are few columns
    uint64_t chunk_rows = (R * C) >> 21;
    if (chunk_rows < 256) chunk_rows = 256;
    if (chunk_rows > (1ull << 24)) chunk_rows = 1ull << 24;  // int64 exactness of the i8 sums
    const uint64_t n_chunks = (R + chunk_rows - 1) / chunk_rows;
    const uint32_t col_tiles = (uint32_t)((C + TC_TB - 1) / TC_TB);
    uint32_t *part = (uint32_t *)dev_alloc(c, 16ull * n_chunks * G * C);
    uint32_t *dout = (uint32_t *)dev_alloc(c, 16ull * G * C);
    if (!part || !dout) return 1;
    TC_LAUNCH(tc::tc_combine_rows, (uint32_t)(col_tiles * n_chunks), TC_TB, c->stream, dm, (uint32_t)is_i8, R, C, G, dc, chunk_rows, col_tiles, part);
    TC_CHECK_LAUNCH(c);
    TC_LAUNCH(tc::tc_sum_chunks, grid_for(G * C, 4), TC_TB, c->stream, part, G * C, n_chunks, dout);
    TC_CHECK_LAUNCH(c);
    d2h(c, out, dout, 16ull * G * C);
    int rc = dsync(c);
    if (owned) dev_free(c, (void *)dm);
    dev_free(c, dc);
    dev_free(c, part);
    dev_free(c, dout);
    return rc;
}

extern "C" int tc_row_dots_i8(tc_ctx *c, const int8_t *m, uint64_t R, uint64_t C, const uint32_t *vec, uint32_t *out) {
    TC_ENTER(c);
    // the int64 limb sums are exact while C * 2^7 * (2^31 - 1) < 2^63, i.e. C <= 2^24
    if (R == 0 || R > 0x7fffffffull || C > (1ull << 24)) return decline(c, "row dots: bad shape");
    c->stats.weight_passes++;
    bool owned = false;
    const void *dm = upload(c, m, R * C, &owned);
    uint32_t *dv = (uint32_t *)dev_alloc(c, 16ull * C), *dout = (uint32_t *)dev_alloc(c, 16ull * R);
    if (!dm || !dv || !dout) return 1;
    h2d(c, dv, vec, 16ull * C);
    TC_LAUNCH(tc::tc_row_dots_i8, (uint32_t)R, TC_TB, c->stream, (const int8_t *)dm, C, dv, dout);
    TC_CHECK_LAUNCH(c);
    d2h(c, out, dout, 16ull * R);
    int rc = dsync(c);
    if (owned) dev_free(c, (void *)dm);
    dev_free(c, dv);
    dev_free(c, dout);
    return rc;
}

extern "C" int tc_matmul_i32_i8(tc_ctx *c, const int32_t *x, const int8_t *w, uint32_t T, uint32_t K, uint32_t N, int64_t *out) {
    TC_ENTER(c);
    if (K >= (1u << 24)) return decline(c, "matmul: K too large for exact int64 sums");
    c->stats.matmuls++;
    bool owned = false;
    const void *dw = upload(c, w, (uint64_t)K * N, &owned);
    int32_t *dx = (int32_t *)dev_alloc(c, 4ull * T * K);
    int64_t *dout = (int64_t *)dev_alloc(c, 8ull * T * N);
    if (!dw || !dx || !dout) return 1;
    h2d(c, dx, x, 4ull * T * K);
    const uint32_t tiles_n = (N + tc::MM_B - 1) / tc::MM_B, tiles_t = (T + tc::MM_B - 1) / tc::MM_B;
    TC_LAUNCH(tc::tc_matmul_i32_i8, tiles_n * tiles_t, TC_TB, c->stream, dx, (const int8_t *)dw, T, K, N, tiles_n, dout);
    TC_CHECK_LAUNCH(c);
    d2h(c, out, dout, 8ull * T * N);
    int rc = dsync(c);
    if (owned) dev_free(c, (void *)dw);
    dev_free(c, dx);
    dev_free(c, dout);
    return rc;
}

extern "C" int tc_matmul_i8_dp4a(tc_ctx *c, const int8_t *x, const int8_t *w, uint32_t T, uint32_t K, uint32_t N, int64_t *out) {
    TC_ENTER(c);
    if (K >= (1u << 17) || T == 0 || N == 0) return decline(c, "dp4a matmul: K too large for exact int32 sums");
    c->stats.matmuls++;
    c->stats.matmuls_dp4a++;
    bool owned = false;
    const void *dw = upload(c, w, (uint64_t)K * N, &owned);
    int8_t *dx = (int8_t *)dev_alloc(c, (uint64_t)T * K);
    int64_t *dout = (int64_t *)dev_alloc(c, 8ull * T * N);
    if (!dw || !dx || !dout) return 1;
    if (h2d(c, dx, x, (uint64_t)T * K)) return 1;
    const uint32_t tiles_n = (N + tc::MM_B - 1) / tc::MM_B, tiles_t = (T + tc::MM_B - 1) / tc::MM_B;
    TC_LAUNCH(tc::tc_matmul_i8_dp4a, tiles_n * tiles_t, TC_TB, c->stream, dx, (const int8_t *)dw, T, K, N, tiles_n, dout);
    TC_CHECK_LAUNCH(c);
    d2h(c, out, dout, 8ull * T * N);
    int rc = dsync(c);
    if (owned) dev_free(c, (void *)dw);
    dev_free(c, dx);
    dev_free(c, dout);
    return rc;
}

extern "C" int tc_mle_i32(tc_ctx *c, const int32_t *v, uint32_t log_n, const uint32_t *point, uint32_t out[4]) {
    TC_ENTER(c);
    c->stats.mles++;
    const uint64_t n = 1ull << log_n;
    const uint32_t lo_bits = log_n / 2, hi_bits = log_n - lo_bits;
    uint32_t *pre = (uint32_t *)dev_alloc(c, 16ull << hi_bits), *suf = (uint32_t *)dev_alloc(c, 16ull << lo_bits);
    int32_t *dv = (int32_t *)dev_alloc(c, 4 * n);
    if (!pre || !suf || !dv) return 1;
    if (eq_build(c, point, hi_bits, tc::qm_one(), 0, 0, false, pre)) return 1;
    if (eq_build(c, point + 4 * hi_bits, lo_bits, tc::qm_one(), 0, 0, false, suf)) return 1;
    h2d(c, dv, v, 4 * n);
    uint32_t groups = (uint32_t)((n >> lo_bits) < SC_MAX_GROUPS ? (n >> lo_bits) : SC_MAX_GROUPS);
    if (groups < 1) groups = 1;
    TC_LAUNCH(tc::tc_mle_i32, groups, TC_TB, c->stream, dv, n, lo_bits, pre, suf, c->partials, c->counter, c->mailbox_dev);
    TC_CHECK_LAUNCH(c);
    if (dsync(c)) return 1;
    mailbox_read(c, out, 4);
    dev_free(c, pre);
    dev_free(c, suf);
    dev_free(c, dv);
    return 0;
}

// ---------------------------------------------------------------------------
// Sumcheck sessions.

static tc_sc *sc_new(tc_ctx *c, uint32_t nf, uint64_t len, uint64_t active, const tc_terms *terms) {
    if (nf == 0 || nf > tc::SC_MAX_FACTORS || len < 2) {
        decline(c, "sumcheck: bad shape");
        return nullptr;
    }
    tc_sc *s = new tc_sc();
    s->nf = nf;
    memcpy(&s->t, terms, sizeof(s->t));
    s->len = len;
    s->active = active < len ? active : len;
    for (uint32_t j = 0; j < nf; ++j) {
        s->f[j] = (uint32_t *)dev_alloc(c, 16ull * len);
        if (!s->f[j]) {
            tc_sc_abort(c, s);
            return nullptr;
        }
    }
    c->stats.sc_sessions++;
    return s;
}

extern "C" tc_sc *tc_sc_begin(tc_ctx *c, const uint32_t *const *factors, uint32_t nf, uint64_t len, uint64_t active, const tc_terms *terms) {
    TC_ENTER_PTR(c);
    tc_sc *s = sc_new(c, nf, len, active, terms);
    if (!s) return nullptr;
    for (uint32_t j = 0; j < nf; ++j) h2d(c, s->f[j], factors[j], 16ull * len);
    return s;
}

// Factors built on the device: integer vectors upload as int32 (4 B/entry
// instead of 16), eq factors are never materialised on the host.
extern "C" tc_sc *tc_sc_begin_specs(tc_ctx *c, const tc_spec *specs, uint32_t nf, uint64_t len, uint64_t active, const tc_terms *terms) {
    TC_ENTER_PTR(c);
    tc_sc *s = sc_new(c, nf, len, active, terms);
    if (!s) return nullptr;
    for (uint32_t j = 0; j < nf; ++j) {
        const tc_spec &sp = specs[j];
        int rc = 0;
        if (sp.kind == TC_SPEC_INT) {
            const uint64_t n = sp.n_ints < len ? sp.n_ints : len;
            int32_t *dv = (int32_t *)dev_alloc(c, 4 * (n ? n : 1));
            if (!dv) rc = 1;
            else {
                if (n) h2d(c, dv, sp.ints, 4 * n);
                TC_LAUNCH(tc::tc_int_to_qm, grid_for(len, 4), TC_TB, c->stream, dv, n, len, s->f[j]);
                dev_free(c, dv);
            }
        } else if (sp.kind == TC_SPEC_EQ) {
            TC_LAUNCH(tc::tc_zero_u32, grid_for(4 * len, 4), TC_TB, c->stream, s->f[j], 4 * len);
            for (uint32_t k = 0; k < sp.n_claims && !rc; ++k) {
                const tc_claim &cl = sp.claims[k];
                if (cl.offset + (1ull << cl.point_len) > len) rc = decline(c, "eq claim out of range");
                else rc = eq_build(c, cl.point, cl.point_len, qm_from(cl.gamma), 0, cl.offset, true, s->f[j]);
            }
        } else if (sp.kind == TC_SPEC_EQ_PREFIX) {
            const tc_claim &cl = sp.claims[0];
            if (((1ull << cl.point_len) << sp.free_bits) != len) rc = decline(c, "eq prefix shape");
            else rc = eq_build(c, cl.point, cl.point_len, tc::qm_one(), sp.free_bits, 0, false, s->f[j]);
        } else {
            rc = decline(c, "unknown factor spec");
        }
        if (rc) {
            tc_sc_abort(c, s);
            return nullptr;
        }
    }
    return s;
}

extern "C" uint64_t tc_sc_len(tc_sc *s) { return s->len; }

extern "C" int tc_sc_round(tc_ctx *c, tc_sc *s, const uint32_t *r_prev, uint32_t out[12]) {
    TC_ENTER(c);
    tc::ScRound p = {};
    if (r_prev) {
        p.prev_half = s->prev_half;
        p.prev_active = s->prev_active;
        p.r = qm_from(r_prev);
    }
    const uint64_t half = s->len / 2;
    const uint64_t work = half < s->active ? half : s->active;
    p.half_len = half;
    p.active = s->active;
    p.work = work;
    uint64_t g = (work + TC_TB * 4 - 1) / (TC_TB * 4);
    if (g < 1) g = 1;
    if (g > SC_MAX_GROUPS) g = SC_MAX_GROUPS;
    tc::Factors fs = {{s->f[0], s->f[1], s->f[2], s->f[3]}};
    TC_LAUNCH(tc::tc_sc_round, (uint32_t)g, TC_TB, c->stream, fs, s->t, p, c->partials, c->counter, c->mailbox_dev);
    TC_CHECK_LAUNCH(c);
    if (dsync(c)) return 1;
    mailbox_read(c, out, 12);
    c->stats.sc_rounds++;
    s->prev_half = half;
    s->prev_active = s->active;
    s->len = half;
    s->active = work;
    return 0;
}

extern "C" int tc_sc_finish(tc_ctx *c, tc_sc *s, const uint32_t r_last[4], uint32_t *const *out) {
    TC_ENTER(c);
    tc::ScRound p = {};
    p.half_len = s->prev_half;
    p.active = s->prev_active;
    p.work = s->active;
    p.r = qm_from(r_last);
    tc::Factors fs = {{s->f[0], s->f[1], s->f[2], s->f[3]}};
    TC_LAUNCH(tc::tc_sc_fold, grid_for(s->active, 4), TC_TB, c->stream, fs, s->t, p);
    TC_CHECK_LAUNCH(c);
    for (uint32_t j = 0; j < s->nf; ++j) d2h(c, out[j], s->f[j], 16ull * s->len);
    int rc = dsync(c);
    tc_sc_abort(c, s);
    return rc;
}

extern "C" void tc_sc_abort(tc_ctx *c, tc_sc *s) {
    if (!s) return;
    for (uint32_t j = 0; j < tc::SC_MAX_FACTORS; ++j) dev_free(c, s->f[j]);
    delete s;
}

// ---------------------------------------------------------------------------
// Commitment.

extern "C" int tc_commit(tc_ctx *c, const void *m, int is_i8, uint64_t R, uint32_t log_c, uint32_t log_b, const uint32_t *twiddles, uint32_t tw_len, uint32_t **enc_out, uint8_t *nodes_out) {
    TC_ENTER(c);
    const uint32_t log_e = log_c + log_b;
    if (R == 0 || log_e < 3 || log_e > 30 || tw_len != (1u << (log_e - 1))) return decline(c, "commit: bad shape");
    const uint64_t C = 1ull << log_c, E = 1ull << log_e;
    c->stats.commits++;
    const uint64_t esz = is_i8 ? 1 : 4;
    bool owned = false;
    const void *dm = upload(c, m, R * C * esz, &owned);
    uint32_t *dtw = (uint32_t *)dev_alloc(c, 4ull * tw_len);
    uint32_t *nodes = (uint32_t *)dev_alloc(c, 64ull * E);
    uint32_t *states = (uint32_t *)dev_alloc(c, 32ull * E);
    if (!dm || !dtw || !nodes || !states) return 1;
    h2d(c, dtw, twiddles, 4ull * tw_len);
    uint32_t *enc = nullptr;
#if defined(__CUDACC__)
    TC_CU(c, cudaMallocManaged((void **)&enc, 4ull * R * E, cudaMemAttachGlobal));
#else
    enc = (uint32_t *)malloc(4ull * R * E);
    if (!enc) return fail(c, "malloc enc");
#endif
    uint64_t ch = c->commit_chunk_rows;
    if (ch == 0) ch = c->commit_budget_bytes / (4 * E);
    ch &= ~15ull;
    if (ch < 16) ch = 16;
    if (ch > R) ch = R;
    uint32_t *scratch = (uint32_t *)dev_alloc(c, 4ull * ch * E);
    if (!scratch) return 1;
    const uint32_t tile_log = log_e < tc::RS_TILE_LOG ? log_e : tc::RS_TILE_LOG;
    for (uint64_t row0 = 0; row0 < R; row0 += ch) {
        const uint64_t rows = ch < R - row0 ? ch : R - row0;
        TC_LAUNCH(tc::tc_rs_expand, grid_for(rows * E, 4), TC_TB, c->stream, dm, (uint32_t)is_i8, log_c, log_e, rows, row0, scratch);
        TC_CHECK_LAUNCH(c);
        for (uint32_t i = log_c; i-- > tile_log;) {
            TC_LAUNCH(tc::tc_rs_layer, grid_for(rows * E / 2, 4), TC_TB, c->stream, scratch, rows, log_e, i, dtw, tw_len);
            TC_CHECK_LAUNCH(c);
        }
        if (log_c > 0) {
            const uint32_t top = (log_c < tile_log ? log_c : tile_log) - 1;
            const uint64_t blocks = rows << (log_e - tile_log);
            const uint32_t threads = (1u << (tile_log - 1)) < TC_TB ? (1u << (tile_log - 1)) : TC_TB;
            if (blocks > 0x7fffffffull) return fail(c, "commit: too many tail blocks");
            TC_LAUNCH(tc::tc_rs_tail, (uint32_t)blocks, threads, c->stream, scratch, log_e, tile_log, top, dtw, tw_len);
            TC_CHECK_LAUNCH(c);
        }
        const bool last = row0 + rows == R;
        TC_LAUNCH(tc::tc_rs_leaves, (uint32_t)((E + TC_TB - 1) / TC_TB), TC_TB, c->stream, scratch, log_e, rows, row0, R, last ? 1u : 0u, states, enc, nodes);
        TC_CHECK_LAUNCH(c);
    }
    uint64_t level = E / 2;
    for (; level > 2048; level /= 2) {
        TC_LAUNCH(tc::tc_merkle_level, grid_for(level, 1), TC_TB, c->stream, nodes, level);
        TC_CHECK_LAUNCH(c);
    }
    TC_LAUNCH(tc::tc_merkle_top, 1, TC_TB, c->stream, nodes, level);
    TC_CHECK_LAUNCH(c);
#if defined(__CUDACC__)
    // The CPU reads the codeword (openings) while later kernels of this or
    // another context may run: attach it to the host after the encode, so
    // devices without concurrentManagedAccess never fault on those reads,
    // and the stream sync below orders the attach before any CPU access.
    TC_CU(c, cudaStreamAttachMemAsync(c->stream, enc, 0, cudaMemAttachHost));
#endif
    // nodes[0] is unused; the CPU Merkle (pcs.Merkle) keeps 2E entries
    d2h(c, nodes_out + 32, nodes + 8, 32ull * (2 * E - 1));
    memset(nodes_out, 0, 32);
    int rc = dsync(c);
    if (owned) dev_free(c, (void *)dm);
    dev_free(c, dtw);
    dev_free(c, nodes);
    dev_free(c, states);
    dev_free(c, scratch);
    if (rc) {
        tc_free_visible(c, enc);
        return rc;
    }
    *enc_out = enc;
    return 0;
}

// ---------------------------------------------------------------------------
// GKR layer.

extern "C" int tc_gkr_layer(tc_ctx *c, const uint64_t *in_off, const uint64_t *out_off, uint32_t n_inst, const uint32_t *num, const uint32_t *den, uint64_t n_in, uint32_t *num_out, uint32_t *den_out) {
    TC_ENTER(c);
    c->stats.gkr_layers++;
    const uint64_t n_out = out_off[n_inst];
    uint64_t *di = (uint64_t *)dev_alloc(c, 8ull * n_inst), *dout_off = (uint64_t *)dev_alloc(c, 8ull * (n_inst + 1));
    uint32_t *dn = (uint32_t *)dev_alloc(c, 16 * n_in), *dd = (uint32_t *)dev_alloc(c, 16 * n_in);
    uint32_t *on = (uint32_t *)dev_alloc(c, 16 * n_out), *od = (uint32_t *)dev_alloc(c, 16 * n_out);
    if (!di || !dout_off || !dn || !dd || !on || !od) return 1;
    h2d(c, di, in_off, 8ull * n_inst);
    h2d(c, dout_off, out_off, 8ull * (n_inst + 1));
    h2d(c, dn, num, 16 * n_in);
    h2d(c, dd, den, 16 * n_in);
    TC_LAUNCH(tc::tc_gkr_layer, grid_for(n_out, 4), TC_TB, c->stream, di, dout_off, n_inst, dn, dd, on, od);
    TC_CHECK_LAUNCH(c);
    d2h(c, num_out, on, 16 * n_out);
    d2h(c, den_out, od, 16 * n_out);
    int rc = dsync(c);
    dev_free(c, di);
    dev_free(c, dout_off);
    dev_free(c, dn);
    dev_free(c, dd);
    dev_free(c, on);
    dev_free(c, od);
    return rc;
}

// ---------------------------------------------------------------------------
// Batched LogUp-GKR sessions (accel.gkr_prove; cuda/gkr.zig drives them with
// gkr_prover_fast's control flow and transcript).
//
// Arena layout: depth j (0 = the inputs) holds layer n_i - j of every
// instance with n_i >= j, in instance order, so building depth j + 1 from
// depth j is ONE tc_gkr_layer launch for all instances. Every layer stays
// on the device until tc_gkr_end; rounds fold layers in place.

struct tc_gkr {
    uint32_t n_inst = 0;
    std::vector<uint32_t> n_vars;
    std::vector<std::vector<uint64_t>> off;  // off[i][k]: layer k (2^k entries) of instance i
    uint32_t *num = nullptr, *den = nullptr;
    uint32_t *pre = nullptr, *suf = nullptr, *point = nullptr;
    uint32_t eq_lo = 0;
    bool eq_ready = false;
    qm lambda = {};
    uint32_t *partials = nullptr;
    uint64_t partials_blocks = 0;
    tc::GkrJob *djobs = nullptr;
    uint32_t *dblock = nullptr;
};

static void gkr_free(tc_ctx *c, tc_gkr *g) {
    if (!g) return;
    dev_free(c, g->num);
    dev_free(c, g->den);
    dev_free(c, g->pre);
    dev_free(c, g->suf);
    dev_free(c, g->point);
    dev_free(c, g->partials);
    dev_free(c, g->djobs);
    dev_free(c, g->dblock);
    delete g;
}

static const uint32_t GKR_BLOCKS_PER_JOB = 256;

// One tc_gkr_round launch + sync; results stay in the mailbox.
static int gkr_launch(tc_ctx *c, tc_gkr *g, const std::vector<tc::GkrJob> &jobs, qm r) {
    const uint32_t n = (uint32_t)jobs.size();
    std::vector<uint32_t> bs(n + 1, 0);
    for (uint32_t j = 0; j < n; ++j) {
        const uint64_t units = (jobs[j].flags & tc::GKR_SUM) ? jobs[j].len / 4 : jobs[j].len;
        uint64_t b = (units + TC_TB * 4 - 1) / (TC_TB * 4);
        if (b < 1) b = 1;
        if (b > GKR_BLOCKS_PER_JOB) b = GKR_BLOCKS_PER_JOB;
        bs[j + 1] = bs[j] + (uint32_t)b;
    }
    const uint32_t blocks = bs[n];
    if (blocks > g->partials_blocks) {
        dev_free(c, g->partials);
        g->partials = (uint32_t *)dev_alloc(c, 32ull * blocks);
        if (!g->partials) return 1;
        g->partials_blocks = blocks;
    }
    if (h2d(c, g->djobs, jobs.data(), sizeof(tc::GkrJob) * n) || h2d(c, g->dblock, bs.data(), 4ull * (n + 1))) return 1;
    const uint32_t *pre = g->eq_ready ? g->pre : g->num, *suf = g->eq_ready ? g->suf : g->num;
    TC_LAUNCH(tc::tc_gkr_round, blocks, TC_TB, c->stream, g->djobs, n, g->dblock, g->num, g->den, pre, suf, g->eq_lo, g->lambda, r, g->partials, c->counter, c->mailbox_dev);
    TC_CHECK_LAUNCH(c);
    c->stats.gkr_rounds++;
    return dsync(c);
}

extern "C" tc_gkr *tc_gkr_begin(tc_ctx *c, const tc_gkr_input *in, uint32_t n, uint32_t *top_out) {
    TC_ENTER_PTR(c);
    if (n == 0 || n > TC_GKR_MAX_JOBS) {
        decline(c, "gkr: instance count");
        return nullptr;
    }
    uint32_t max_n = 0;
    for (uint32_t i = 0; i < n; ++i) {
        if (in[i].log_n < 1 || in[i].log_n > 30 || in[i].kind > TC_GKR_SECURE || !in[i].den || (in[i].kind != TC_GKR_ONES && !in[i].num)) {
            decline(c, "gkr: input shape");
            return nullptr;
        }
        if (in[i].log_n > max_n) max_n = in[i].log_n;
    }
    tc_gkr *g = new tc_gkr();
    g->n_inst = n;
    g->n_vars.resize(n);
    g->off.resize(n);
    std::vector<uint64_t> base(max_n + 2, 0);
    for (uint32_t i = 0; i < n; ++i) {
        g->n_vars[i] = in[i].log_n;
        g->off[i].assign(in[i].log_n + 1, 0);
    }
    for (uint32_t j = 0; j <= max_n; ++j) {
        uint64_t pos = base[j];
        for (uint32_t i = 0; i < n; ++i)
            if (g->n_vars[i] >= j) {
                g->off[i][g->n_vars[i] - j] = pos;
                pos += 1ull << (g->n_vars[i] - j);
            }
        base[j + 1] = pos;
    }
    const uint64_t total = base[max_n + 1];
    g->num = (uint32_t *)dev_alloc(c, 16 * total);
    g->den = (uint32_t *)dev_alloc(c, 16 * total);
    g->djobs = (tc::GkrJob *)dev_alloc(c, sizeof(tc::GkrJob) * TC_GKR_MAX_JOBS);
    g->dblock = (uint32_t *)dev_alloc(c, 4ull * (TC_GKR_MAX_JOBS + 1));
    if (!g->num || !g->den || !g->djobs || !g->dblock) {
        gkr_free(c, g);
        return nullptr;
    }
    c->stats.gkr_sessions++;
    // inputs: den and secure num straight into the arena, base num staged as u32
    std::vector<tc::GkrTop> tops;
    std::vector<uint64_t> prefix(1, 0);
    uint64_t staged = 0;
    for (uint32_t i = 0; i < n; ++i)
        if (in[i].kind == TC_GKR_BASE) staged += 1ull << in[i].log_n;
    uint32_t *staging = staged ? (uint32_t *)dev_alloc(c, 4 * staged) : nullptr;
    if (staged && !staging) {
        gkr_free(c, g);
        return nullptr;
    }
    uint64_t soff = 0;
    int rc = 0;
    for (uint32_t i = 0; i < n && !rc; ++i) {
        const uint64_t len = 1ull << in[i].log_n, o = g->off[i][in[i].log_n];
        rc |= h2d(c, g->den + 4 * o, in[i].den, 16 * len);
        if (in[i].kind == TC_GKR_SECURE) {
            rc |= h2d(c, g->num + 4 * o, in[i].num, 16 * len);
        } else {
            tops.push_back(tc::GkrTop{o, soff, in[i].kind, 0});
            prefix.push_back(prefix.back() + len);
            if (in[i].kind == TC_GKR_BASE) {
                rc |= h2d(c, staging + soff, in[i].num, 4 * len);
                soff += len;
            }
        }
    }
    tc::GkrTop *dtops = nullptr;
    uint64_t *dprefix = nullptr;
    if (!rc && !tops.empty()) {
        dtops = (tc::GkrTop *)dev_alloc(c, sizeof(tc::GkrTop) * tops.size());
        dprefix = (uint64_t *)dev_alloc(c, 8 * prefix.size());
        if (!dtops || !dprefix) rc = 1;
        else {
            rc |= h2d(c, dtops, tops.data(), sizeof(tc::GkrTop) * tops.size());
            rc |= h2d(c, dprefix, prefix.data(), 8 * prefix.size());
            TC_LAUNCH(tc::tc_gkr_top, grid_for(prefix.back(), 4), TC_TB, c->stream, dtops, dprefix, (uint32_t)tops.size(), staging, g->num);
        }
    }
    // all depths: one table upload, one launch per depth
    std::vector<uint64_t> tab;
    std::vector<uint64_t> tab_at(max_n, 0), tab_m(max_n, 0);
    for (uint32_t j = 0; j < max_n; ++j) {
        tab_at[j] = tab.size();
        std::vector<uint64_t> outs(1, 0);
        for (uint32_t i = 0; i < n; ++i)
            if (g->n_vars[i] >= j + 1) {
                tab.push_back(g->off[i][g->n_vars[i] - j] - base[j]);
                outs.push_back(g->off[i][g->n_vars[i] - j - 1] - base[j + 1] + (1ull << (g->n_vars[i] - j - 1)));
            }
        tab_m[j] = outs.size() - 1;
        tab.insert(tab.end(), outs.begin(), outs.end());
    }
    uint64_t *dtab = rc ? nullptr : (uint64_t *)dev_alloc(c, 8 * (tab.size() ? tab.size() : 1));
    if (!rc && !dtab) rc = 1;
    if (!rc && !tab.empty()) rc |= h2d(c, dtab, tab.data(), 8 * tab.size());
    for (uint32_t j = 0; j < max_n && !rc; ++j) {
        const uint64_t m = tab_m[j];
        const uint64_t *din = dtab + tab_at[j], *dout = dtab + tab_at[j] + m;
        const uint64_t n_out = base[j + 2] - base[j + 1];
        TC_LAUNCH(tc::tc_gkr_layer, grid_for(n_out, 4), TC_TB, c->stream, din, dout, (uint32_t)m, g->num + 4 * base[j], g->den + 4 * base[j], g->num + 4 * base[j + 1], g->den + 4 * base[j + 1]);
        c->stats.gkr_layers++;
    }
    // output claims: the roots (layer 0) of all instances, one gather launch
    if (!rc) {
        std::vector<tc::GkrJob> jobs(n);
        for (uint32_t i = 0; i < n; ++i) jobs[i] = tc::GkrJob{g->off[i][0], 1, tc::GKR_MASK, 0};
        rc = gkr_launch(c, g, jobs, tc::qm_zero());
    }
    if (!rc)
        for (uint32_t i = 0; i < n; ++i) {
            memcpy(top_out + 8 * i, c->mailbox + 16 * i, 16);
            memcpy(top_out + 8 * i + 4, c->mailbox + 16 * i + 8, 16);
            c->stats.d2h_bytes += 32;
        }
    dev_free(c, staging);
    dev_free(c, dtops);
    dev_free(c, dprefix);
    dev_free(c, dtab);
    if (rc) {
        gkr_free(c, g);
        return nullptr;
    }
    return g;
}

extern "C" int tc_gkr_eq(tc_ctx *c, tc_gkr *g, const uint32_t *y, uint32_t y_len, const uint32_t lambda[4]) {
    TC_ENTER(c);
    if (y_len > 62) return decline(c, "gkr: ood point too long");
    const uint32_t rl = y_len ? y_len - 1 : 0;
    const uint32_t n_lo = rl / 2, n_hi = rl - n_lo;
    dev_free(c, g->pre);
    dev_free(c, g->suf);
    dev_free(c, g->point);
    g->pre = (uint32_t *)dev_alloc(c, 16ull << n_hi);
    g->suf = (uint32_t *)dev_alloc(c, 16ull << n_lo);
    g->point = (uint32_t *)dev_alloc(c, 16ull * (rl ? rl : 1));
    if (!g->pre || !g->suf || !g->point) return 1;
    if (rl && h2d(c, g->point, y + 4, 16ull * rl)) return 1;
    const qm gamma = y_len ? tc::qm_sub(tc::qm_one(), qm_from(y)) : tc::qm_one();
    TC_LAUNCH(tc::tc_eq_halves, 2, TC_TB, c->stream, g->point, n_hi, n_lo, gamma, g->pre, g->suf);
    TC_CHECK_LAUNCH(c);
    g->eq_lo = n_lo;
    g->lambda = qm_from(lambda);
    g->eq_ready = true;
    return 0;
}

extern "C" int tc_gkr_round(tc_ctx *c, tc_gkr *g, const tc_gkr_job *jobs, uint32_t n_jobs, const uint32_t *r, uint32_t *out) {
    TC_ENTER(c);
    if (n_jobs == 0 || n_jobs > TC_GKR_MAX_JOBS) return decline(c, "gkr: job count");
    std::vector<tc::GkrJob> dj(n_jobs);
    for (uint32_t j = 0; j < n_jobs; ++j) {
        const tc_gkr_job &jb = jobs[j];
        const bool fold = jb.flags & TC_GKR_FOLD, sum = jb.flags & TC_GKR_SUM, mask = jb.flags & TC_GKR_MASK;
        if (jb.inst >= g->n_inst || jb.layer > g->n_vars[jb.inst] || jb.cur_log > jb.layer || (fold && (!r || jb.cur_log < 1)) || (sum && mask) || (!sum && !mask))
            return decline(c, "gkr: bad job");
        const uint32_t new_log = fold ? jb.cur_log - 1 : jb.cur_log;
        if (sum && (!g->eq_ready || new_log < 2)) return decline(c, "gkr: bad sum job");
        dj[j] = tc::GkrJob{g->off[jb.inst][jb.layer], 1ull << new_log, jb.flags, 0};
    }
    if (gkr_launch(c, g, dj, r ? qm_from(r) : tc::qm_zero())) return 1;
    for (uint32_t j = 0; j < n_jobs; ++j) {
        const uint32_t words = (dj[j].flags & tc::GKR_SUM) ? 8 : 16;
        memcpy(out + 16 * j, c->mailbox + 16 * j, 4ull * words);
        c->stats.d2h_bytes += 4ull * words;
    }
    return 0;
}

extern "C" void tc_gkr_end(tc_ctx *c, tc_gkr *g) { gkr_free(c, g); }
