// rv64_cuda_counters: LD_PRELOAD CUDA driver-API counter shim (stream measure, M4.0).
//
// Counts and times the host CUDA driver calls that the 10x plan gates on
// (syncs, kernel launches, pool mallocs, library loads, pageable copies, ...)
// per request, per thread and in 10 ms bins, with no CUPTI dependency.
//
// How it hooks: libstwo-rv64-native.so links cudart statically. Static cudart
// dlopen()s libcuda.so.1 and resolves every driver entry point through
// cuGetProcAddress(_v2), which it obtains with dlsym(). This library
// interposes dlsym (LD_PRELOAD), returns a wrapper for cuGetProcAddress, and
// that wrapper swaps the returned pointer of each counted symbol for a timing
// wrapper. Everything else passes through untouched, so proof bytes cannot
// change (the shim never alters arguments or results).
//
// Pageable detection: for host<->device copies the host pointer is checked
// with cuPointerGetAttribute(CU_POINTER_ATTRIBUTE_MEMORY_TYPE); a failure means
// unregistered (pageable) host memory, which makes cuMemcpy*Async blocking.
//
// Env: RV64_CUDA_COUNTERS_OUT=<dir>  -> <dir>/cuda-counters-<pid>.json at exit.
//      RV64_CUDA_COUNTERS_BIN_MS=10  -> bin width (default 10 ms).
// Build: gcc -O2 -shared -fPIC -I/usr/local/cuda/include -o librv64_cuda_counters.so rv64_cuda_counters.c -ldl -lpthread
#define _GNU_SOURCE
#include <cuda.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// ----------------------------------------------------------------------------- counters
enum Klass { K_SYNC, K_LAUNCH, K_POOL_MALLOC, K_PAGEABLE_COPY, K_COPY, K_LIBLOAD, K_ALLOC, K_OTHER, K_COUNT };
static const char *KLASS_NAME[K_COUNT] = {"sync", "launch", "pool_malloc", "pageable_copy", "copy", "library_load", "alloc", "other"};

enum Sym {
  S_StreamSynchronize, S_CtxSynchronize, S_EventSynchronize, S_StreamWaitEvent, S_StreamQuery, S_EventQuery, S_EventRecord,
  S_LaunchKernel, S_LaunchKernelEx, S_LaunchHostFunc, S_GraphLaunch,
  S_MemAllocFromPoolAsync, S_MemAllocAsync, S_MemFreeAsync, S_MemPoolTrimTo, S_MemAlloc, S_MemFree,
  S_MemHostAlloc, S_MemAllocHost, S_MemHostRegister, S_MemFreeHost,
  S_LibraryLoadData, S_LibraryUnload, S_ModuleLoadData, S_ModuleLoadFatBinary, S_ModuleUnload,
  S_MemcpyHtoDAsync, S_MemcpyDtoHAsync, S_MemcpyAsync, S_MemcpyDtoDAsync, S_MemcpyHtoD, S_MemcpyDtoH, S_Memcpy,
  S_MemsetD8Async, S_MemsetD32Async,
  S_COUNT
};
static const char *SYM_NAME[S_COUNT] = {
  "cuStreamSynchronize", "cuCtxSynchronize", "cuEventSynchronize", "cuStreamWaitEvent", "cuStreamQuery", "cuEventQuery", "cuEventRecord",
  "cuLaunchKernel", "cuLaunchKernelEx", "cuLaunchHostFunc", "cuGraphLaunch",
  "cuMemAllocFromPoolAsync", "cuMemAllocAsync", "cuMemFreeAsync", "cuMemPoolTrimTo", "cuMemAlloc", "cuMemFree",
  "cuMemHostAlloc", "cuMemAllocHost", "cuMemHostRegister", "cuMemFreeHost",
  "cuLibraryLoadData", "cuLibraryUnload", "cuModuleLoadData", "cuModuleLoadFatBinary", "cuModuleUnload",
  "cuMemcpyHtoDAsync", "cuMemcpyDtoHAsync", "cuMemcpyAsync", "cuMemcpyDtoDAsync", "cuMemcpyHtoD", "cuMemcpyDtoH", "cuMemcpy",
  "cuMemsetD8Async", "cuMemsetD32Async",
};
static const enum Klass SYM_KLASS[S_COUNT] = {
  K_SYNC, K_SYNC, K_SYNC, K_OTHER, K_OTHER, K_OTHER, K_OTHER,
  K_LAUNCH, K_LAUNCH, K_LAUNCH, K_LAUNCH,
  K_POOL_MALLOC, K_POOL_MALLOC, K_ALLOC, K_ALLOC, K_ALLOC, K_ALLOC,
  K_ALLOC, K_ALLOC, K_ALLOC, K_ALLOC,
  K_LIBLOAD, K_OTHER, K_LIBLOAD, K_LIBLOAD, K_OTHER,
  K_COPY, K_COPY, K_COPY, K_COPY, K_COPY, K_COPY, K_COPY,
  K_OTHER, K_OTHER,
};

static _Atomic uint64_t g_count[S_COUNT], g_ns[S_COUNT], g_bytes[S_COUNT];
static _Atomic uint64_t g_pageable_count, g_pageable_bytes, g_pageable_ns, g_pinned_copy_count, g_pinned_copy_bytes;
static void *g_real[S_COUNT];

// Pinned host allocations (address, size, kind) so an smaps census can attribute pinned pages.
#define MAX_PINNED 65536
typedef struct { uint64_t ptr, size; int kind; uint64_t t_ns; } PinnedRec;
static PinnedRec g_pinned[MAX_PINNED];
static _Atomic int g_npinned;
static void pinned_log(const void *p, size_t n, int kind) {
  int i = atomic_fetch_add(&g_npinned, 1);
  if (i < MAX_PINNED) g_pinned[i] = (PinnedRec){(uint64_t)(uintptr_t)p, (uint64_t)n, kind, 0};
}

#define MAX_THREADS 512
#define MAX_BINS 120000  // 1200 s at 10 ms
typedef struct {
  pid_t tid;
  uint64_t first_ns, last_ns;
  uint64_t count[K_COUNT], ns[K_COUNT];
  uint32_t *bins[K_COUNT];  // lazily allocated, MAX_BINS each
} ThreadRec;
static ThreadRec *g_threads[MAX_THREADS];
static _Atomic int g_nthreads;
static __thread int t_index = -1;
static uint64_t g_origin_mono, g_origin_real, g_bin_ns = 10000000ull;

static inline uint64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static ThreadRec *thread_rec(void) {
  if (t_index >= 0) return g_threads[t_index];
  int i = atomic_fetch_add(&g_nthreads, 1);
  if (i >= MAX_THREADS) { t_index = MAX_THREADS; return NULL; }
  ThreadRec *r = calloc(1, sizeof(ThreadRec));
  if (!r) return NULL;
  r->tid = (pid_t)gettid();
  g_threads[i] = r;
  t_index = i;
  return r;
}

static inline void record(enum Sym s, uint64_t t0, uint64_t t1, uint64_t bytes) {
  uint64_t d = t1 - t0;
  atomic_fetch_add_explicit(&g_count[s], 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&g_ns[s], d, memory_order_relaxed);
  if (bytes) atomic_fetch_add_explicit(&g_bytes[s], bytes, memory_order_relaxed);
  ThreadRec *r = (t_index == MAX_THREADS) ? NULL : thread_rec();
  if (!r) return;
  enum Klass k = SYM_KLASS[s];
  if (!r->first_ns) r->first_ns = t0;
  r->last_ns = t1;
  r->count[k]++;
  r->ns[k] += d;
  uint64_t bin = (t0 - g_origin_mono) / g_bin_ns;
  if (bin < MAX_BINS) {
    if (!r->bins[k]) r->bins[k] = calloc(MAX_BINS, sizeof(uint32_t));
    if (r->bins[k]) r->bins[k][bin]++;
  }
}

static inline void record_pageable(uint64_t t0, uint64_t t1, uint64_t bytes) {
  atomic_fetch_add_explicit(&g_pageable_count, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&g_pageable_bytes, bytes, memory_order_relaxed);
  atomic_fetch_add_explicit(&g_pageable_ns, t1 - t0, memory_order_relaxed);
  ThreadRec *r = (t_index == MAX_THREADS) ? NULL : thread_rec();
  if (!r) return;
  r->count[K_PAGEABLE_COPY]++;
  r->ns[K_PAGEABLE_COPY] += t1 - t0;
  uint64_t bin = (t0 - g_origin_mono) / g_bin_ns;
  if (bin < MAX_BINS) {
    if (!r->bins[K_PAGEABLE_COPY]) r->bins[K_PAGEABLE_COPY] = calloc(MAX_BINS, sizeof(uint32_t));
    if (r->bins[K_PAGEABLE_COPY]) r->bins[K_PAGEABLE_COPY][bin]++;
  }
}

// ----------------------------------------------------------------------------- pageable check
typedef CUresult (*PFN_getattr)(void *, CUpointer_attribute, CUdeviceptr);
static PFN_getattr g_getattr;
// 1 = pageable host memory, 0 = device/pinned/managed or not a host pointer.
static int is_pageable_host(const void *p) {
  if (!g_getattr || !p) return 0;
  unsigned int type = 0;
  CUresult rc = g_getattr(&type, CU_POINTER_ATTRIBUTE_MEMORY_TYPE, (CUdeviceptr)(uintptr_t)p);
  return rc != CUDA_SUCCESS;  // unregistered host allocation
}

// ----------------------------------------------------------------------------- wrappers
#define REAL(s, T) ((T)g_real[s])
#define TIMED(s, bytes, call) do { uint64_t _t0 = mono_ns(); CUresult _rc = (call); record((s), _t0, mono_ns(), (bytes)); return _rc; } while (0)

static CUresult w_StreamSynchronize(CUstream h) { TIMED(S_StreamSynchronize, 0, REAL(S_StreamSynchronize, CUresult (*)(CUstream))(h)); }
static CUresult w_CtxSynchronize(void) { TIMED(S_CtxSynchronize, 0, REAL(S_CtxSynchronize, CUresult (*)(void))()); }
static CUresult w_EventSynchronize(CUevent e) { TIMED(S_EventSynchronize, 0, REAL(S_EventSynchronize, CUresult (*)(CUevent))(e)); }
static CUresult w_StreamWaitEvent(CUstream s, CUevent e, unsigned f) { TIMED(S_StreamWaitEvent, 0, REAL(S_StreamWaitEvent, CUresult (*)(CUstream, CUevent, unsigned))(s, e, f)); }
static CUresult w_StreamQuery(CUstream s) { TIMED(S_StreamQuery, 0, REAL(S_StreamQuery, CUresult (*)(CUstream))(s)); }
static CUresult w_EventQuery(CUevent e) { TIMED(S_EventQuery, 0, REAL(S_EventQuery, CUresult (*)(CUevent))(e)); }
static CUresult w_EventRecord(CUevent e, CUstream s) { TIMED(S_EventRecord, 0, REAL(S_EventRecord, CUresult (*)(CUevent, CUstream))(e, s)); }
static CUresult w_LaunchKernel(CUfunction f, unsigned gx, unsigned gy, unsigned gz, unsigned bx, unsigned by, unsigned bz, unsigned sh, CUstream s, void **p, void **x) {
  TIMED(S_LaunchKernel, 0, REAL(S_LaunchKernel, CUresult (*)(CUfunction, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, CUstream, void **, void **))(f, gx, gy, gz, bx, by, bz, sh, s, p, x));
}
static CUresult w_LaunchKernelEx(const CUlaunchConfig *c, CUfunction f, void **p, void **x) { TIMED(S_LaunchKernelEx, 0, REAL(S_LaunchKernelEx, CUresult (*)(const CUlaunchConfig *, CUfunction, void **, void **))(c, f, p, x)); }
static CUresult w_LaunchHostFunc(CUstream s, CUhostFn fn, void *u) { TIMED(S_LaunchHostFunc, 0, REAL(S_LaunchHostFunc, CUresult (*)(CUstream, CUhostFn, void *))(s, fn, u)); }
static CUresult w_GraphLaunch(CUgraphExec g, CUstream s) { TIMED(S_GraphLaunch, 0, REAL(S_GraphLaunch, CUresult (*)(CUgraphExec, CUstream))(g, s)); }
static CUresult w_MemAllocFromPoolAsync(CUdeviceptr *d, size_t n, CUmemoryPool p, CUstream s) { TIMED(S_MemAllocFromPoolAsync, n, REAL(S_MemAllocFromPoolAsync, CUresult (*)(CUdeviceptr *, size_t, CUmemoryPool, CUstream))(d, n, p, s)); }
static CUresult w_MemAllocAsync(CUdeviceptr *d, size_t n, CUstream s) { TIMED(S_MemAllocAsync, n, REAL(S_MemAllocAsync, CUresult (*)(CUdeviceptr *, size_t, CUstream))(d, n, s)); }
static CUresult w_MemFreeAsync(CUdeviceptr d, CUstream s) { TIMED(S_MemFreeAsync, 0, REAL(S_MemFreeAsync, CUresult (*)(CUdeviceptr, CUstream))(d, s)); }
static CUresult w_MemPoolTrimTo(CUmemoryPool p, size_t n) { TIMED(S_MemPoolTrimTo, 0, REAL(S_MemPoolTrimTo, CUresult (*)(CUmemoryPool, size_t))(p, n)); }
static CUresult w_MemAlloc(CUdeviceptr *d, size_t n) { TIMED(S_MemAlloc, n, REAL(S_MemAlloc, CUresult (*)(CUdeviceptr *, size_t))(d, n)); }
static CUresult w_MemFree(CUdeviceptr d) { TIMED(S_MemFree, 0, REAL(S_MemFree, CUresult (*)(CUdeviceptr))(d)); }
static CUresult w_MemHostAlloc(void **p, size_t n, unsigned f) {
  uint64_t t0 = mono_ns(); CUresult rc = REAL(S_MemHostAlloc, CUresult (*)(void **, size_t, unsigned))(p, n, f); record(S_MemHostAlloc, t0, mono_ns(), n);
  if (rc == CUDA_SUCCESS && p) pinned_log(*p, n, 0);
  return rc;
}
static CUresult w_MemAllocHost(void **p, size_t n) {
  uint64_t t0 = mono_ns(); CUresult rc = REAL(S_MemAllocHost, CUresult (*)(void **, size_t))(p, n); record(S_MemAllocHost, t0, mono_ns(), n);
  if (rc == CUDA_SUCCESS && p) pinned_log(*p, n, 1);
  return rc;
}
static CUresult w_MemHostRegister(void *p, size_t n, unsigned f) {
  uint64_t t0 = mono_ns(); CUresult rc = REAL(S_MemHostRegister, CUresult (*)(void *, size_t, unsigned))(p, n, f); record(S_MemHostRegister, t0, mono_ns(), n);
  if (rc == CUDA_SUCCESS) pinned_log(p, n, 2);
  return rc;
}
static CUresult w_MemFreeHost(void *p) {
  uint64_t t0 = mono_ns(); CUresult rc = REAL(S_MemFreeHost, CUresult (*)(void *))(p); record(S_MemFreeHost, t0, mono_ns(), 0);
  if (rc == CUDA_SUCCESS) pinned_log(p, 0, 3);  // size 0 = free marker
  return rc;
}
static CUresult w_LibraryLoadData(CUlibrary *l, const void *c, CUjit_option *jo, void **jv, unsigned nj, CUlibraryOption *lo, void **lv, unsigned nl) {
  TIMED(S_LibraryLoadData, 0, REAL(S_LibraryLoadData, CUresult (*)(CUlibrary *, const void *, CUjit_option *, void **, unsigned, CUlibraryOption *, void **, unsigned))(l, c, jo, jv, nj, lo, lv, nl));
}
static CUresult w_LibraryUnload(CUlibrary l) { TIMED(S_LibraryUnload, 0, REAL(S_LibraryUnload, CUresult (*)(CUlibrary))(l)); }
static CUresult w_ModuleLoadData(CUmodule *m, const void *c) { TIMED(S_ModuleLoadData, 0, REAL(S_ModuleLoadData, CUresult (*)(CUmodule *, const void *))(m, c)); }
static CUresult w_ModuleLoadFatBinary(CUmodule *m, const void *c) { TIMED(S_ModuleLoadFatBinary, 0, REAL(S_ModuleLoadFatBinary, CUresult (*)(CUmodule *, const void *))(m, c)); }
static CUresult w_ModuleUnload(CUmodule m) { TIMED(S_ModuleUnload, 0, REAL(S_ModuleUnload, CUresult (*)(CUmodule))(m)); }

static CUresult copy_common(enum Sym s, size_t n, const void *host_a, const void *host_b, CUresult (*thunk)(void *), void *ctx) {
  int pageable = is_pageable_host(host_a) || is_pageable_host(host_b);
  uint64_t t0 = mono_ns();
  CUresult rc = thunk(ctx);
  uint64_t t1 = mono_ns();
  record(s, t0, t1, n);
  if (pageable) record_pageable(t0, t1, n);
  else { atomic_fetch_add_explicit(&g_pinned_copy_count, 1, memory_order_relaxed); atomic_fetch_add_explicit(&g_pinned_copy_bytes, n, memory_order_relaxed); }
  return rc;
}
typedef struct { CUdeviceptr d; const void *h; void *hd; CUdeviceptr s; size_t n; CUstream st; } CopyArgs;
static CUresult t_HtoDAsync(void *c) { CopyArgs *a = c; return REAL(S_MemcpyHtoDAsync, CUresult (*)(CUdeviceptr, const void *, size_t, CUstream))(a->d, a->h, a->n, a->st); }
static CUresult t_DtoHAsync(void *c) { CopyArgs *a = c; return REAL(S_MemcpyDtoHAsync, CUresult (*)(void *, CUdeviceptr, size_t, CUstream))(a->hd, a->s, a->n, a->st); }
static CUresult t_Async(void *c) { CopyArgs *a = c; return REAL(S_MemcpyAsync, CUresult (*)(CUdeviceptr, CUdeviceptr, size_t, CUstream))(a->d, a->s, a->n, a->st); }
static CUresult t_HtoD(void *c) { CopyArgs *a = c; return REAL(S_MemcpyHtoD, CUresult (*)(CUdeviceptr, const void *, size_t))(a->d, a->h, a->n); }
static CUresult t_DtoH(void *c) { CopyArgs *a = c; return REAL(S_MemcpyDtoH, CUresult (*)(void *, CUdeviceptr, size_t))(a->hd, a->s, a->n); }
static CUresult t_Sync(void *c) { CopyArgs *a = c; return REAL(S_Memcpy, CUresult (*)(CUdeviceptr, CUdeviceptr, size_t))(a->d, a->s, a->n); }
static CUresult w_MemcpyHtoDAsync(CUdeviceptr d, const void *h, size_t n, CUstream s) { CopyArgs a = {.d = d, .h = h, .n = n, .st = s}; return copy_common(S_MemcpyHtoDAsync, n, h, NULL, t_HtoDAsync, &a); }
static CUresult w_MemcpyDtoHAsync(void *h, CUdeviceptr src, size_t n, CUstream s) { CopyArgs a = {.hd = h, .s = src, .n = n, .st = s}; return copy_common(S_MemcpyDtoHAsync, n, h, NULL, t_DtoHAsync, &a); }
static CUresult w_MemcpyAsync(CUdeviceptr d, CUdeviceptr src, size_t n, CUstream s) { CopyArgs a = {.d = d, .s = src, .n = n, .st = s}; return copy_common(S_MemcpyAsync, n, (const void *)(uintptr_t)d, (const void *)(uintptr_t)src, t_Async, &a); }
static CUresult w_MemcpyHtoD(CUdeviceptr d, const void *h, size_t n) { CopyArgs a = {.d = d, .h = h, .n = n}; return copy_common(S_MemcpyHtoD, n, h, NULL, t_HtoD, &a); }
static CUresult w_MemcpyDtoH(void *h, CUdeviceptr src, size_t n) { CopyArgs a = {.hd = h, .s = src, .n = n}; return copy_common(S_MemcpyDtoH, n, h, NULL, t_DtoH, &a); }
static CUresult w_Memcpy(CUdeviceptr d, CUdeviceptr src, size_t n) { CopyArgs a = {.d = d, .s = src, .n = n}; return copy_common(S_Memcpy, n, (const void *)(uintptr_t)d, (const void *)(uintptr_t)src, t_Sync, &a); }
static CUresult w_MemcpyDtoDAsync(CUdeviceptr d, CUdeviceptr s, size_t n, CUstream st) { TIMED(S_MemcpyDtoDAsync, n, REAL(S_MemcpyDtoDAsync, CUresult (*)(CUdeviceptr, CUdeviceptr, size_t, CUstream))(d, s, n, st)); }
static CUresult w_MemsetD8Async(CUdeviceptr d, unsigned char v, size_t n, CUstream s) { TIMED(S_MemsetD8Async, n, REAL(S_MemsetD8Async, CUresult (*)(CUdeviceptr, unsigned char, size_t, CUstream))(d, v, n, s)); }
static CUresult w_MemsetD32Async(CUdeviceptr d, unsigned v, size_t n, CUstream s) { TIMED(S_MemsetD32Async, n * 4, REAL(S_MemsetD32Async, CUresult (*)(CUdeviceptr, unsigned, size_t, CUstream))(d, v, n, s)); }

static void *WRAP[S_COUNT] = {
  w_StreamSynchronize, w_CtxSynchronize, w_EventSynchronize, w_StreamWaitEvent, w_StreamQuery, w_EventQuery, w_EventRecord,
  w_LaunchKernel, w_LaunchKernelEx, w_LaunchHostFunc, w_GraphLaunch,
  w_MemAllocFromPoolAsync, w_MemAllocAsync, w_MemFreeAsync, w_MemPoolTrimTo, w_MemAlloc, w_MemFree,
  w_MemHostAlloc, w_MemAllocHost, w_MemHostRegister, w_MemFreeHost,
  w_LibraryLoadData, w_LibraryUnload, w_ModuleLoadData, w_ModuleLoadFatBinary, w_ModuleUnload,
  w_MemcpyHtoDAsync, w_MemcpyDtoHAsync, w_MemcpyAsync, w_MemcpyDtoDAsync, w_MemcpyHtoD, w_MemcpyDtoH, w_Memcpy,
  w_MemsetD8Async, w_MemsetD32Async,
};

// ----------------------------------------------------------------------------- hook
typedef CUresult (*PFN_gpa2)(const char *, void **, int, cuuint64_t, CUdriverProcAddressQueryResult *);
typedef CUresult (*PFN_gpa1)(const char *, void **, int, cuuint64_t);
static PFN_gpa2 g_gpa2;
static PFN_gpa1 g_gpa1;
static _Atomic uint64_t g_gpa_calls, g_wrapped_symbols;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static CUresult hook_gpa2(const char *, void **, int, cuuint64_t, CUdriverProcAddressQueryResult *);
static CUresult hook_gpa1(const char *, void **, int, cuuint64_t);

static void substitute(const char *symbol, void **pfn) {
  atomic_fetch_add(&g_gpa_calls, 1);
  if (!pfn || !*pfn || !symbol) return;
  if (!strcmp(symbol, "cuGetProcAddress")) {
    // cudart may re-resolve the resolver itself; keep it hooked.
    pthread_mutex_lock(&g_mu);
    if (!g_gpa2) g_gpa2 = (PFN_gpa2)*pfn;
    pthread_mutex_unlock(&g_mu);
    *pfn = (void *)hook_gpa2;
    return;
  }
  if (!strcmp(symbol, "cuPointerGetAttribute") && !g_getattr) g_getattr = (PFN_getattr)*pfn;
  for (int s = 0; s < S_COUNT; s++) {
    if (!strcmp(symbol, SYM_NAME[s])) {
      pthread_mutex_lock(&g_mu);
      // Per-thread-default-stream variants share names and signatures; the
      // first resolution wins (the driver returns the variant cudart asked for,
      // and cudart is consistent for the whole process).
      if (!g_real[s]) { g_real[s] = *pfn; atomic_fetch_add(&g_wrapped_symbols, 1); }
      int same = g_real[s] == *pfn;
      pthread_mutex_unlock(&g_mu);
      if (same) *pfn = WRAP[s];
      return;
    }
  }
}

static void ensure_getattr(void) {
  if (g_getattr || !g_gpa2) return;
  void *p = NULL;
  CUdriverProcAddressQueryResult st;
  if (g_gpa2("cuPointerGetAttribute", &p, 12000, CU_GET_PROC_ADDRESS_DEFAULT, &st) == CUDA_SUCCESS) g_getattr = (PFN_getattr)p;
}

static CUresult hook_gpa2(const char *symbol, void **pfn, int ver, cuuint64_t flags, CUdriverProcAddressQueryResult *st) {
  CUresult rc = g_gpa2(symbol, pfn, ver, flags, st);
  if (rc == CUDA_SUCCESS) { substitute(symbol, pfn); ensure_getattr(); }
  return rc;
}
static CUresult hook_gpa1(const char *symbol, void **pfn, int ver, cuuint64_t flags) {
  CUresult rc = g_gpa1(symbol, pfn, ver, flags);
  if (rc == CUDA_SUCCESS) substitute(symbol, pfn);
  return rc;
}

typedef void *(*PFN_dlsym)(void *, const char *);
static PFN_dlsym real_dlsym(void) {
  static PFN_dlsym real;
  if (!real) real = (PFN_dlsym)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
  if (!real) real = (PFN_dlsym)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.34");
  return real;
}

void *dlsym(void *handle, const char *symbol) {
  void *p = real_dlsym()(handle, symbol);
  if (!p || strncmp(symbol, "cu", 2)) return p;
  if (!strcmp(symbol, "cuGetProcAddress_v2")) { g_gpa2 = (PFN_gpa2)p; return (void *)hook_gpa2; }
  if (!strcmp(symbol, "cuGetProcAddress")) { g_gpa1 = (PFN_gpa1)p; return (void *)hook_gpa1; }
  // Direct dlsym of a counted symbol (dynamic cudart or direct driver users).
  void *q = p;
  substitute(symbol, &q);
  return q;
}


// ----------------------------------------------------------------------------- mmap tracer
// RV64_MMAP_TRACE=1: interpose mmap/munmap/mremap (Zig's page_allocator calls libc mmap
// directly), forward through raw syscalls, and log every anonymous mapping >= 1 MiB with a
// call-site id (hash of a backtrace), plus every munmap/mremap. An offline pass computes live
// bytes per call site at any instant (e.g. the RSS peak). Smaller maps are only summed.
#define TRACE_MIN (1ull << 20)
#define MAX_EVENTS (1 << 21)
#define MAX_SITES 8192
#define SITE_DEPTH 14
typedef struct { uint64_t t_ns, addr, len, aux; uint32_t site; uint8_t op; } MapEvent;  // op 0 map 1 unmap 2 remap(aux=new addr)
static MapEvent *g_events;
static _Atomic int g_nevents;
static _Atomic uint64_t g_small_maps, g_small_bytes;
typedef struct { uint64_t hash; int depth; void *frames[SITE_DEPTH]; uint64_t count, bytes; } Site;
static Site g_sites[MAX_SITES];
static _Atomic int g_nsites;
static pthread_mutex_t g_site_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_trace;
static __thread int t_in_trace;

static void push_event(uint8_t op, uint64_t addr, uint64_t len, uint64_t aux, uint32_t site) {
  if (!g_events) return;
  int i = atomic_fetch_add(&g_nevents, 1);
  if (i < MAX_EVENTS) g_events[i] = (MapEvent){mono_ns(), addr, len, aux, site, op};
}

static uint32_t site_of(uint64_t len) {
  void *frames[SITE_DEPTH + 2];
  int n = backtrace(frames, SITE_DEPTH + 2);
  uint64_t h = 1469598103934665603ull;
  int skip = 2, depth = n - skip < SITE_DEPTH ? n - skip : SITE_DEPTH;
  if (depth < 0) depth = 0;
  for (int i = 0; i < depth; i++) { h ^= (uint64_t)(uintptr_t)frames[i + skip]; h *= 1099511628211ull; }
  pthread_mutex_lock(&g_site_mu);
  int ns = g_nsites, found = -1;
  for (int i = 0; i < ns; i++) if (g_sites[i].hash == h) { found = i; break; }
  if (found < 0 && ns < MAX_SITES) {
    found = ns;
    g_sites[ns].hash = h;
    g_sites[ns].depth = depth;
    memcpy(g_sites[ns].frames, frames + skip, depth * sizeof(void *));
    g_nsites = ns + 1;
  }
  if (found >= 0) { g_sites[found].count++; g_sites[found].bytes += len; }
  pthread_mutex_unlock(&g_site_mu);
  return found < 0 ? 0xffffffffu : (uint32_t)found;
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
  void *p = (void *)syscall(SYS_mmap, addr, len, prot, flags, fd, off);
  if (g_trace && p != MAP_FAILED && (flags & MAP_ANONYMOUS) && !t_in_trace) {
    if (len >= TRACE_MIN) {
      t_in_trace = 1;
      push_event(0, (uint64_t)(uintptr_t)p, len, 0, site_of(len));
      t_in_trace = 0;
    } else { atomic_fetch_add_explicit(&g_small_maps, 1, memory_order_relaxed); atomic_fetch_add_explicit(&g_small_bytes, len, memory_order_relaxed); }
  }
  return p;
}
void *mmap64(void *addr, size_t len, int prot, int flags, int fd, off_t off) { return mmap(addr, len, prot, flags, fd, off); }
int munmap(void *addr, size_t len) {
  long rc = syscall(SYS_munmap, addr, len);
  if (g_trace && rc == 0 && len >= 4096 && !t_in_trace) push_event(1, (uint64_t)(uintptr_t)addr, len, 0, 0);
  return (int)rc;
}
void *mremap(void *old, size_t old_len, size_t new_len, int flags, ...) {
  void *new_addr = NULL;
  if (flags & MREMAP_FIXED) { va_list ap; va_start(ap, flags); new_addr = va_arg(ap, void *); va_end(ap); }
  void *p = (void *)syscall(SYS_mremap, old, old_len, new_len, flags, new_addr);
  if (g_trace && p != MAP_FAILED && !t_in_trace && (old_len >= TRACE_MIN || new_len >= TRACE_MIN)) {
    push_event(2, (uint64_t)(uintptr_t)old, old_len, (uint64_t)(uintptr_t)p, 0);
    push_event(3, (uint64_t)(uintptr_t)p, new_len, 0, 0);  // op 3: remapped region now live at p with new_len
  }
  return p;
}

static void dump_mmap_trace(void) {
  const char *dir = getenv("RV64_CUDA_COUNTERS_OUT");
  if (!g_trace || !dir || !*dir) return;
  g_trace = 0;
  char path[4096];
  snprintf(path, sizeof path, "%s/mmap-trace-%d.bin", dir, (int)getpid());
  FILE *f = fopen(path, "wb");
  if (f) {
    int n = g_nevents < MAX_EVENTS ? g_nevents : MAX_EVENTS;
    fwrite(g_events, sizeof(MapEvent), n, f);
    fclose(f);
  }
  snprintf(path, sizeof path, "%s/mmap-sites-%d.json", dir, (int)getpid());
  f = fopen(path, "w");
  if (!f) return;
  fprintf(f, "{\"schema\":\"rv64-mmap-trace/v1\",\"event_bytes\":%zu,\"events\":%d,\"dropped\":%d,\"small_maps\":%llu,\"small_bytes\":%llu,\"origin_monotonic_ns\":%llu,\"sites\":[",
          sizeof(MapEvent), g_nevents, g_nevents > MAX_EVENTS ? g_nevents - MAX_EVENTS : 0, (unsigned long long)g_small_maps, (unsigned long long)g_small_bytes,
          (unsigned long long)g_origin_mono);
  for (int i = 0; i < g_nsites; i++) {
    fprintf(f, "%s{\"id\":%d,\"count\":%llu,\"bytes\":%llu,\"frames\":[", i ? "," : "", i, (unsigned long long)g_sites[i].count, (unsigned long long)g_sites[i].bytes);
    for (int k = 0; k < g_sites[i].depth; k++) fprintf(f, "%s\"%p\"", k ? "," : "", g_sites[i].frames[k]);
    fprintf(f, "]}");
  }
  fprintf(f, "],\"maps\":\"");
  // /proc/self/maps for offline symbolization (load bases)
  FILE *m = fopen("/proc/self/maps", "r");
  if (m) {
    char line[4096];
    while (fgets(line, sizeof line, m)) {
      if (!strstr(line, " r-xp ") && !strstr(line, " r--p ")) continue;
      for (char *c = line; *c; c++) { if (*c == '\n') fputs("\\n", f); else if (*c == '"' || *c == '\\') { fputc('\\', f); fputc(*c, f); } else fputc(*c, f); }
    }
    fclose(m);
  }
  fprintf(f, "\"}\n");
  fclose(f);
}

// ----------------------------------------------------------------------------- dump
static void dump_bins(FILE *f, const uint32_t *bins) {
  fputc('[', f);
  int first = 1;
  for (int b = 0; b < MAX_BINS; b++) if (bins[b]) { fprintf(f, "%s[%d,%u]", first ? "" : ",", b, bins[b]); first = 0; }
  fputc(']', f);
}

static void dump(void) {
  const char *dir = getenv("RV64_CUDA_COUNTERS_OUT");
  if (!dir || !*dir) return;
  char path[4096];
  snprintf(path, sizeof path, "%s/cuda-counters-%d.json", dir, (int)getpid());
  FILE *f = fopen(path, "w");
  if (!f) return;
  uint64_t end = mono_ns();
  fprintf(f, "{\"schema\":\"rv64-cuda-counters/v1\",\"pid\":%d,\"origin_monotonic_ns\":%llu,\"origin_realtime_ns\":%llu,\"end_monotonic_ns\":%llu,\"bin_ns\":%llu,",
          (int)getpid(), (unsigned long long)g_origin_mono, (unsigned long long)g_origin_real, (unsigned long long)end, (unsigned long long)g_bin_ns);
  fprintf(f, "\"hook\":{\"get_proc_address_calls\":%llu,\"wrapped_symbols\":%llu,\"pointer_attribute_available\":%s},",
          (unsigned long long)g_gpa_calls, (unsigned long long)g_wrapped_symbols, g_getattr ? "true" : "false");
  fprintf(f, "\"symbols\":{");
  int first = 1;
  for (int s = 0; s < S_COUNT; s++) {
    if (!g_count[s]) continue;
    fprintf(f, "%s\"%s\":{\"class\":\"%s\",\"count\":%llu,\"ns\":%llu,\"bytes\":%llu}", first ? "" : ",", SYM_NAME[s], KLASS_NAME[SYM_KLASS[s]],
            (unsigned long long)g_count[s], (unsigned long long)g_ns[s], (unsigned long long)g_bytes[s]);
    first = 0;
  }
  fprintf(f, "},\"copies\":{\"pageable_count\":%llu,\"pageable_bytes\":%llu,\"pageable_ns\":%llu,\"pinned_or_device_count\":%llu,\"pinned_or_device_bytes\":%llu},",
          (unsigned long long)g_pageable_count, (unsigned long long)g_pageable_bytes, (unsigned long long)g_pageable_ns,
          (unsigned long long)g_pinned_copy_count, (unsigned long long)g_pinned_copy_bytes);
  int np = g_npinned < MAX_PINNED ? g_npinned : MAX_PINNED;
  fprintf(f, "\"pinned_host\":{\"records\":%d,\"kinds\":[\"cuMemHostAlloc\",\"cuMemAllocHost\",\"cuMemHostRegister\",\"cuMemFreeHost\"],\"list\":[", g_npinned);
  for (int i = 0; i < np; i++) fprintf(f, "%s[%llu,%llu,%d]", i ? "," : "", (unsigned long long)g_pinned[i].ptr, (unsigned long long)g_pinned[i].size, g_pinned[i].kind);
  fprintf(f, "]},");
  fprintf(f, "\"classes\":[");
  for (int k = 0; k < K_COUNT; k++) fprintf(f, "%s\"%s\"", k ? "," : "", KLASS_NAME[k]);
  fprintf(f, "],\"threads\":[");
  int n = g_nthreads < MAX_THREADS ? g_nthreads : MAX_THREADS;
  first = 1;
  for (int i = 0; i < n; i++) {
    ThreadRec *r = g_threads[i];
    if (!r) continue;
    fprintf(f, "%s{\"tid\":%d,\"first_ns\":%llu,\"last_ns\":%llu,\"count\":[", first ? "" : ",", (int)r->tid,
            (unsigned long long)(r->first_ns ? r->first_ns - g_origin_mono : 0), (unsigned long long)(r->last_ns ? r->last_ns - g_origin_mono : 0));
    for (int k = 0; k < K_COUNT; k++) fprintf(f, "%s%llu", k ? "," : "", (unsigned long long)r->count[k]);
    fprintf(f, "],\"ns\":[");
    for (int k = 0; k < K_COUNT; k++) fprintf(f, "%s%llu", k ? "," : "", (unsigned long long)r->ns[k]);
    fprintf(f, "],\"bins\":{");
    int fk = 1;
    for (int k = 0; k < K_COUNT; k++) if (r->bins[k]) { fprintf(f, "%s\"%s\":", fk ? "" : ",", KLASS_NAME[k]); dump_bins(f, r->bins[k]); fk = 0; }
    fprintf(f, "}}");
    first = 0;
  }
  fprintf(f, "]}\n");
  fclose(f);
}

__attribute__((constructor)) static void init(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  g_origin_real = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
  g_origin_mono = mono_ns();
  const char *b = getenv("RV64_CUDA_COUNTERS_BIN_MS");
  if (b && atoi(b) > 0) g_bin_ns = (uint64_t)atoi(b) * 1000000ull;
  const char *t = getenv("RV64_MMAP_TRACE");
  if (t && *t == '1') {
    g_events = (MapEvent *)syscall(SYS_mmap, NULL, (size_t)MAX_EVENTS * sizeof(MapEvent), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (g_events == MAP_FAILED) g_events = NULL;
    void *warm[4];
    t_in_trace = 1;
    backtrace(warm, 4);  // loads libgcc_s before tracing starts
    t_in_trace = 0;
    g_trace = g_events != NULL;
  }
  atexit(dump_mmap_trace);
  atexit(dump);
}
