// rv64_sync_trace: LD_PRELOAD call-site tracer for host-blocking CUDA calls and kernel launches
// (stream enqueue, M6). Runtime arm of the sync lint: every cu{Stream,Event,Ctx}Synchronize, every
// blocking copy and every kernel launch is attributed to a call stack (hash of the return addresses)
// and, for launches, to the CUfunction name. Syncs are also logged as timestamped events so a node
// window can be cut out offline. Hooking is the measure shim's (dlsym -> cuGetProcAddress) and is
// pass-through: arguments and results are untouched, so proof bytes cannot change.
//
// Env: RV64_SYNC_TRACE_OUT=<dir>   -> <dir>/sync-trace-<pid>.json at exit (and on SIGUSR2).
//      RV64_SYNC_TRACE_DEPTH=40    -> frames per stack (max 64).
//      RV64_SYNC_TRACE_LAUNCH_STACKS=1 -> also hash launch stacks (default 1; 0 = per-function only).
// Build: gcc -O2 -shared -fPIC -I/usr/local/cuda/include -o librv64_sync_trace.so rv64_sync_trace.c -ldl -lpthread
// Symbolize: python3 tools/rv64-sync-trace/symbolize.py sync-trace-<pid>.json > report.json
#define _GNU_SOURCE
#include <cuda.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

enum Kind { K_STREAM_SYNC, K_EVENT_SYNC, K_CTX_SYNC, K_DTOH_SYNC, K_HTOD_SYNC, K_DTOH_ASYNC, K_LAUNCH, K_LAUNCH_EX, K_GRAPH, K_HOSTFN, K_COUNT };
static const char *KIND_NAME[K_COUNT] = {"cuStreamSynchronize", "cuEventSynchronize", "cuCtxSynchronize", "cuMemcpyDtoH", "cuMemcpyHtoD",
                                         "cuMemcpyDtoHAsync", "cuLaunchKernel", "cuLaunchKernelEx", "cuGraphLaunch", "cuLaunchHostFunc"};
static const char *SYM[K_COUNT] = {"cuStreamSynchronize", "cuEventSynchronize", "cuCtxSynchronize", "cuMemcpyDtoH", "cuMemcpyHtoD",
                                   "cuMemcpyDtoHAsync", "cuLaunchKernel", "cuLaunchKernelEx", "cuGraphLaunch", "cuLaunchHostFunc"};
static void *g_real[K_COUNT];
static _Atomic uint64_t g_count[K_COUNT], g_ns[K_COUNT];

static inline uint64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// ------------------------------------------------------------------ call-site table
#define MAX_DEPTH 64
#define SITE_BITS 16
#define MAX_SITES (1u << SITE_BITS)
typedef struct {
  uint64_t hash;
  int kind;
  int depth;
  uint64_t count, ns;
  void *frames[MAX_DEPTH];
} Site;
static Site *g_sites;
static uint32_t g_nsites;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_depth = 40, g_launch_stacks = 1;

// per-function launch histogram
#define MAX_FUNCS 16384
typedef struct { CUfunction f; uint64_t count; char name[160]; } Func;
static Func *g_funcs;
static uint32_t g_nfuncs;
typedef CUresult (*PFN_funcname)(const char **, CUfunction);
static PFN_funcname g_funcname;

// timestamped sync events
#define MAX_EVENTS (1u << 21)
typedef struct { uint64_t t0, ns; uint32_t site; int32_t tid; } Event;
static Event *g_events;
static _Atomic uint32_t g_nevents;
static uint64_t g_origin, g_origin_real;

static uint32_t site_of(int kind, uint64_t ns) {
  void *frames[MAX_DEPTH + 2];
  int n = backtrace(frames, g_depth + 2);
  uint64_t h = 1469598103934665603ull ^ (uint64_t)kind;
  for (int i = 2; i < n; i++) { h ^= (uint64_t)(uintptr_t)frames[i]; h *= 1099511628211ull; }
  pthread_mutex_lock(&g_mu);
  uint32_t slot = (uint32_t)(h >> (64 - SITE_BITS));
  for (uint32_t probe = 0; probe < MAX_SITES; probe++, slot = (slot + 1) & (MAX_SITES - 1)) {
    Site *s = &g_sites[slot];
    if (s->count == 0 && s->hash == 0) {
      if (g_nsites + 1 >= MAX_SITES * 3 / 4) break;
      s->hash = h; s->kind = kind; s->depth = n > 2 ? n - 2 : 0;
      memcpy(s->frames, frames + 2, sizeof(void *) * (size_t)s->depth);
      g_nsites++;
    }
    if (s->hash == h && s->kind == kind) {
      s->count++; s->ns += ns;
      pthread_mutex_unlock(&g_mu);
      return slot;
    }
  }
  pthread_mutex_unlock(&g_mu);
  return UINT32_MAX;
}

static uint32_t func_count(CUfunction f) {
  uint32_t found = UINT32_MAX;
  pthread_mutex_lock(&g_mu);
  uint32_t slot = (uint32_t)(((uintptr_t)f * 11400714819323198485ull) >> 50) & (MAX_FUNCS - 1);
  for (uint32_t probe = 0; probe < MAX_FUNCS; probe++, slot = (slot + 1) & (MAX_FUNCS - 1)) {
    Func *e = &g_funcs[slot];
    if (e->f == NULL) {
      if (g_nfuncs + 1 >= MAX_FUNCS * 3 / 4) break;
      e->f = f; g_nfuncs++;
      const char *name = NULL;
      if (g_funcname && g_funcname(&name, f) == CUDA_SUCCESS && name) snprintf(e->name, sizeof e->name, "%s", name);
    }
    if (e->f == f) { e->count++; found = slot; break; }
  }
  pthread_mutex_unlock(&g_mu);
  return found;
}

static void log_event(uint32_t site, uint64_t t0, uint64_t ns) {
  uint32_t i = atomic_fetch_add(&g_nevents, 1);
  if (i < MAX_EVENTS) g_events[i] = (Event){t0 - g_origin, ns, site, (int32_t)syscall(SYS_gettid)};
}

static inline void blocking(int kind, uint64_t t0, uint64_t t1) {
  atomic_fetch_add(&g_count[kind], 1);
  atomic_fetch_add(&g_ns[kind], t1 - t0);
  log_event(site_of(kind, t1 - t0), t0, t1 - t0);
}
static inline void launched(int kind, CUfunction f) {
  atomic_fetch_add(&g_count[kind], 1);
  uint32_t slot = f ? func_count(f) : 0x7fffffffu;
  uint32_t site = g_launch_stacks ? site_of(kind, 0) : UINT32_MAX;
  uint64_t t = mono_ns();
  (void)site;
  log_event(0x80000000u | slot, t, (uint64_t)kind);
}

#define REAL(k, T) ((T)g_real[k])
static CUresult w_StreamSync(CUstream h) { uint64_t t0 = mono_ns(); CUresult rc = REAL(K_STREAM_SYNC, CUresult (*)(CUstream))(h); blocking(K_STREAM_SYNC, t0, mono_ns()); return rc; }
static CUresult w_EventSync(CUevent e) { uint64_t t0 = mono_ns(); CUresult rc = REAL(K_EVENT_SYNC, CUresult (*)(CUevent))(e); blocking(K_EVENT_SYNC, t0, mono_ns()); return rc; }
static CUresult w_CtxSync(void) { uint64_t t0 = mono_ns(); CUresult rc = REAL(K_CTX_SYNC, CUresult (*)(void))(); blocking(K_CTX_SYNC, t0, mono_ns()); return rc; }
static CUresult w_DtoH(void *h, CUdeviceptr s, size_t n) { uint64_t t0 = mono_ns(); CUresult rc = REAL(K_DTOH_SYNC, CUresult (*)(void *, CUdeviceptr, size_t))(h, s, n); blocking(K_DTOH_SYNC, t0, mono_ns()); return rc; }
static CUresult w_HtoD(CUdeviceptr d, const void *h, size_t n) { uint64_t t0 = mono_ns(); CUresult rc = REAL(K_HTOD_SYNC, CUresult (*)(CUdeviceptr, const void *, size_t))(d, h, n); blocking(K_HTOD_SYNC, t0, mono_ns()); return rc; }
static CUresult w_DtoHAsync(void *h, CUdeviceptr s, size_t n, CUstream st) {
  CUresult rc = REAL(K_DTOH_ASYNC, CUresult (*)(void *, CUdeviceptr, size_t, CUstream))(h, s, n, st);
  atomic_fetch_add(&g_count[K_DTOH_ASYNC], 1);
  (void)site_of(K_DTOH_ASYNC, n);
  return rc;
}
static CUresult w_Launch(CUfunction f, unsigned gx, unsigned gy, unsigned gz, unsigned bx, unsigned by, unsigned bz, unsigned sh, CUstream s, void **p, void **x) {
  launched(K_LAUNCH, f);
  return REAL(K_LAUNCH, CUresult (*)(CUfunction, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, CUstream, void **, void **))(f, gx, gy, gz, bx, by, bz, sh, s, p, x);
}
static CUresult w_LaunchEx(const CUlaunchConfig *c, CUfunction f, void **p, void **x) { launched(K_LAUNCH_EX, f); return REAL(K_LAUNCH_EX, CUresult (*)(const CUlaunchConfig *, CUfunction, void **, void **))(c, f, p, x); }
static CUresult w_Graph(CUgraphExec g, CUstream s) { launched(K_GRAPH, NULL); return REAL(K_GRAPH, CUresult (*)(CUgraphExec, CUstream))(g, s); }
static CUresult w_HostFn(CUstream s, CUhostFn fn, void *u) { launched(K_HOSTFN, NULL); return REAL(K_HOSTFN, CUresult (*)(CUstream, CUhostFn, void *))(s, fn, u); }
static void *WRAP[K_COUNT] = {w_StreamSync, w_EventSync, w_CtxSync, w_DtoH, w_HtoD, w_DtoHAsync, w_Launch, w_LaunchEx, w_Graph, w_HostFn};

// ------------------------------------------------------------------ hook (same scheme as tools/rv64-cuda-counters)
typedef CUresult (*PFN_gpa2)(const char *, void **, int, cuuint64_t, CUdriverProcAddressQueryResult *);
typedef CUresult (*PFN_gpa1)(const char *, void **, int, cuuint64_t);
static PFN_gpa2 g_gpa2;
static PFN_gpa1 g_gpa1;
static CUresult hook_gpa2(const char *, void **, int, cuuint64_t, CUdriverProcAddressQueryResult *);

static void substitute(const char *symbol, void **pfn) {
  if (!pfn || !*pfn || !symbol) return;
  if (!strcmp(symbol, "cuGetProcAddress")) {
    if (!g_gpa2) g_gpa2 = (PFN_gpa2)*pfn;
    *pfn = (void *)hook_gpa2;
    return;
  }
  if (!strcmp(symbol, "cuFuncGetName") && !g_funcname) g_funcname = (PFN_funcname)*pfn;
  for (int k = 0; k < K_COUNT; k++)
    if (!strcmp(symbol, SYM[k])) {
      pthread_mutex_lock(&g_mu);
      if (!g_real[k]) g_real[k] = *pfn;
      int same = g_real[k] == *pfn;
      pthread_mutex_unlock(&g_mu);
      if (same) *pfn = WRAP[k];
      return;
    }
}
static void ensure_funcname(void) {
  if (g_funcname || !g_gpa2) return;
  void *p = NULL;
  CUdriverProcAddressQueryResult st;
  if (g_gpa2("cuFuncGetName", &p, 12030, CU_GET_PROC_ADDRESS_DEFAULT, &st) == CUDA_SUCCESS) g_funcname = (PFN_funcname)p;
}
static CUresult hook_gpa2(const char *symbol, void **pfn, int ver, cuuint64_t flags, CUdriverProcAddressQueryResult *st) {
  CUresult rc = g_gpa2(symbol, pfn, ver, flags, st);
  if (rc == CUDA_SUCCESS) { substitute(symbol, pfn); ensure_funcname(); }
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
  void *q = p;
  substitute(symbol, &q);
  return q;
}

// ------------------------------------------------------------------ dump
static void frame_json(FILE *f, void *addr) {
  Dl_info info;
  if (dladdr(addr, &info) && info.dli_fname) {
    fprintf(f, "[\"0x%lx\",\"%s\",\"0x%lx\"]", (unsigned long)(uintptr_t)addr, info.dli_fname,
            (unsigned long)((uintptr_t)addr - (uintptr_t)info.dli_fbase));
  } else {
    fprintf(f, "[\"0x%lx\",\"?\",\"0x0\"]", (unsigned long)(uintptr_t)addr);
  }
}
static pthread_mutex_t g_dump_mu = PTHREAD_MUTEX_INITIALIZER;
static void dump(void) {
  const char *dir = getenv("RV64_SYNC_TRACE_OUT");
  if (!dir || !g_sites) return;
  pthread_mutex_lock(&g_dump_mu);
  char path[4096];
  snprintf(path, sizeof path, "%s/sync-trace-%d.json", dir, (int)getpid());
  FILE *f = fopen(path, "w");
  if (!f) { pthread_mutex_unlock(&g_dump_mu); return; }
  pthread_mutex_lock(&g_mu);
  fprintf(f, "{\"schema\":\"rv64-sync-trace/v1\",\"pid\":%d,\"origin_mono_ns\":%lu,\"origin_realtime_ns\":%lu,\"totals\":{", (int)getpid(), (unsigned long)g_origin, (unsigned long)g_origin_real);
  for (int k = 0; k < K_COUNT; k++) fprintf(f, "%s\"%s\":{\"count\":%lu,\"ns\":%lu}", k ? "," : "", KIND_NAME[k], (unsigned long)g_count[k], (unsigned long)g_ns[k]);
  fprintf(f, "},\"sites\":[");
  int first = 1;
  for (uint32_t i = 0; i < MAX_SITES; i++) {
    Site *s = &g_sites[i];
    if (!s->count) continue;
    fprintf(f, "%s{\"id\":%u,\"kind\":\"%s\",\"count\":%lu,\"ns\":%lu,\"frames\":[", first ? "" : ",", i, KIND_NAME[s->kind], (unsigned long)s->count, (unsigned long)s->ns);
    for (int j = 0; j < s->depth; j++) { if (j) fputc(',', f); frame_json(f, s->frames[j]); }
    fprintf(f, "]}");
    first = 0;
  }
  fprintf(f, "],\"functions\":[");
  first = 1;
  for (uint32_t i = 0; i < MAX_FUNCS; i++) {
    Func *e = &g_funcs[i];
    if (!e->f) continue;
    fprintf(f, "%s[\"%s\",%lu,%u]", first ? "" : ",", e->name[0] ? e->name : "?", (unsigned long)e->count, i);
    first = 0;
  }
  uint32_t n = g_nevents < MAX_EVENTS ? g_nevents : MAX_EVENTS;
  fprintf(f, "],\"events\":[");
  for (uint32_t i = 0; i < n; i++) fprintf(f, "%s[%lu,%lu,%u,%d]", i ? "," : "", (unsigned long)g_events[i].t0, (unsigned long)g_events[i].ns, g_events[i].site, g_events[i].tid);
  fprintf(f, "]}\n");
  pthread_mutex_unlock(&g_mu);
  fclose(f);
  pthread_mutex_unlock(&g_dump_mu);
}
static void on_signal(int sig) { (void)sig; dump(); }

__attribute__((constructor)) static void init(void) {
  g_origin = mono_ns();
  { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); g_origin_real = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec; }
  const char *d = getenv("RV64_SYNC_TRACE_DEPTH");
  if (d) { g_depth = atoi(d); if (g_depth < 4) g_depth = 4; if (g_depth > MAX_DEPTH) g_depth = MAX_DEPTH; }
  const char *l = getenv("RV64_SYNC_TRACE_LAUNCH_STACKS");
  if (l) g_launch_stacks = atoi(l) != 0;
  g_sites = calloc(MAX_SITES, sizeof(Site));
  g_funcs = calloc(MAX_FUNCS, sizeof(Func));
  g_events = calloc(MAX_EVENTS, sizeof(Event));
  void *warm[4];
  backtrace(warm, 4);  // load libgcc_s before any hook fires
  signal(SIGUSR2, on_signal);
  atexit(dump);
}
