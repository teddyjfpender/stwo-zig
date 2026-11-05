// rv64_cuda_callsites: LD_PRELOAD call-site census for host-blocking CUDA calls
// (stream platform, M5). Answers "WHO issues the syncs and pageable copies",
// which the counter shim (tools/rv64-cuda-counters) only counts.
//
// Same hook as the counter shim: libstwo-rv64-native.so links cudart
// statically, static cudart resolves driver entry points through
// cuGetProcAddress obtained with dlsym(); we interpose dlsym, wrap
// cuGetProcAddress(_v2) and swap in wrappers for the census symbols. Arguments
// and results pass through untouched, so proof bytes cannot change.
//
// Every wrapped call is attributed to a call site = hash of its backtrace
// (CALLSITE_DEPTH frames). Per site: calls, bytes, pageable calls/bytes, ns.
// Dump at exit: $RV64_CUDA_CALLSITES_OUT/cuda-callsites-<pid>.json with raw
// frame addresses plus /proc/self/maps; scripts/rv64_m5_callsites.py
// symbolizes them (addr2line) and ranks sites.
//
// Build: gcc -O2 -shared -fPIC -I/usr/local/cuda/include -o librv64_cuda_callsites.so rv64_cuda_callsites.c -ldl -lpthread
#define _GNU_SOURCE
#include <cuda.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum Sym {
  S_StreamSynchronize, S_CtxSynchronize, S_EventSynchronize,
  S_MemcpyHtoDAsync, S_MemcpyDtoHAsync, S_MemcpyAsync, S_MemcpyHtoD, S_MemcpyDtoH,
  S_LaunchKernel,
  S_COUNT
};
static const char *SYM_NAME[S_COUNT] = {
  "cuStreamSynchronize", "cuCtxSynchronize", "cuEventSynchronize",
  "cuMemcpyHtoDAsync", "cuMemcpyDtoHAsync", "cuMemcpyAsync", "cuMemcpyHtoD", "cuMemcpyDtoH",
  "cuLaunchKernel",
};
static void *g_real[S_COUNT];
static int g_launch_sites;  // RV64_CUDA_CALLSITES_LAUNCH=1 also attributes launches (slower)

#define DEPTH 20
#define MAX_SITES 16384
typedef struct {
  uint64_t hash;
  int sym, depth;
  void *frames[DEPTH];
  uint64_t count, bytes, pageable, pageable_bytes, ns;
} Site;
static Site *g_sites;
static int g_nsites;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static __thread int t_busy;

static inline uint64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

typedef CUresult (*PFN_getattr)(void *, CUpointer_attribute, CUdeviceptr);
static PFN_getattr g_getattr;
static int is_pageable_host(const void *p) {
  if (!g_getattr || !p) return 0;
  unsigned int type = 0;
  return g_getattr(&type, CU_POINTER_ATTRIBUTE_MEMORY_TYPE, (CUdeviceptr)(uintptr_t)p) != CUDA_SUCCESS;
}

static void note(int sym, uint64_t t0, uint64_t t1, uint64_t bytes, int pageable) {
  if (!g_sites || t_busy) return;
  t_busy = 1;
  void *frames[DEPTH + 2];
  int n = backtrace(frames, DEPTH + 2);
  int skip = 2, depth = n - skip < DEPTH ? n - skip : DEPTH;
  if (depth < 0) depth = 0;
  uint64_t h = 1469598103934665603ull ^ (uint64_t)sym;
  for (int i = 0; i < depth; i++) { h ^= (uint64_t)(uintptr_t)frames[i + skip]; h *= 1099511628211ull; }
  pthread_mutex_lock(&g_mu);
  int found = -1;
  // Open addressing over MAX_SITES slots (power of two).
  for (uint64_t probe = 0; probe < MAX_SITES; probe++) {
    uint64_t slot = (h + probe) & (MAX_SITES - 1);
    if (g_sites[slot].count == 0) {
      g_sites[slot].hash = h;
      g_sites[slot].sym = sym;
      g_sites[slot].depth = depth;
      memcpy(g_sites[slot].frames, frames + skip, depth * sizeof(void *));
      g_nsites++;
      found = (int)slot;
      break;
    }
    if (g_sites[slot].hash == h) { found = (int)slot; break; }
  }
  if (found >= 0) {
    Site *s = &g_sites[found];
    s->count++;
    s->bytes += bytes;
    s->ns += t1 - t0;
    if (pageable) { s->pageable++; s->pageable_bytes += bytes; }
  }
  pthread_mutex_unlock(&g_mu);
  t_busy = 0;
}

#define REAL(s, T) ((T)g_real[s])
static CUresult w_StreamSynchronize(CUstream h) {
  uint64_t t0 = mono_ns(); CUresult rc = REAL(S_StreamSynchronize, CUresult (*)(CUstream))(h);
  note(S_StreamSynchronize, t0, mono_ns(), 0, 0); return rc;
}
static CUresult w_CtxSynchronize(void) {
  uint64_t t0 = mono_ns(); CUresult rc = REAL(S_CtxSynchronize, CUresult (*)(void))();
  note(S_CtxSynchronize, t0, mono_ns(), 0, 0); return rc;
}
static CUresult w_EventSynchronize(CUevent e) {
  uint64_t t0 = mono_ns(); CUresult rc = REAL(S_EventSynchronize, CUresult (*)(CUevent))(e);
  note(S_EventSynchronize, t0, mono_ns(), 0, 0); return rc;
}
static CUresult w_MemcpyHtoDAsync(CUdeviceptr d, const void *h, size_t n, CUstream s) {
  int pg = is_pageable_host(h); uint64_t t0 = mono_ns();
  CUresult rc = REAL(S_MemcpyHtoDAsync, CUresult (*)(CUdeviceptr, const void *, size_t, CUstream))(d, h, n, s);
  note(S_MemcpyHtoDAsync, t0, mono_ns(), n, pg); return rc;
}
static CUresult w_MemcpyDtoHAsync(void *h, CUdeviceptr src, size_t n, CUstream s) {
  int pg = is_pageable_host(h); uint64_t t0 = mono_ns();
  CUresult rc = REAL(S_MemcpyDtoHAsync, CUresult (*)(void *, CUdeviceptr, size_t, CUstream))(h, src, n, s);
  note(S_MemcpyDtoHAsync, t0, mono_ns(), n, pg); return rc;
}
static CUresult w_MemcpyAsync(CUdeviceptr d, CUdeviceptr src, size_t n, CUstream s) {
  int pg = is_pageable_host((const void *)(uintptr_t)d) || is_pageable_host((const void *)(uintptr_t)src);
  uint64_t t0 = mono_ns();
  CUresult rc = REAL(S_MemcpyAsync, CUresult (*)(CUdeviceptr, CUdeviceptr, size_t, CUstream))(d, src, n, s);
  note(S_MemcpyAsync, t0, mono_ns(), n, pg); return rc;
}
static CUresult w_MemcpyHtoD(CUdeviceptr d, const void *h, size_t n) {
  int pg = is_pageable_host(h); uint64_t t0 = mono_ns();
  CUresult rc = REAL(S_MemcpyHtoD, CUresult (*)(CUdeviceptr, const void *, size_t))(d, h, n);
  note(S_MemcpyHtoD, t0, mono_ns(), n, pg); return rc;
}
static CUresult w_MemcpyDtoH(void *h, CUdeviceptr src, size_t n) {
  int pg = is_pageable_host(h); uint64_t t0 = mono_ns();
  CUresult rc = REAL(S_MemcpyDtoH, CUresult (*)(void *, CUdeviceptr, size_t))(h, src, n);
  note(S_MemcpyDtoH, t0, mono_ns(), n, pg); return rc;
}
static CUresult w_LaunchKernel(CUfunction f, unsigned gx, unsigned gy, unsigned gz, unsigned bx, unsigned by,
                               unsigned bz, unsigned sh, CUstream s, void **p, void **x) {
  uint64_t t0 = mono_ns();
  CUresult rc = REAL(S_LaunchKernel, CUresult (*)(CUfunction, unsigned, unsigned, unsigned, unsigned, unsigned,
                                                  unsigned, unsigned, CUstream, void **, void **))(f, gx, gy, gz, bx, by, bz, sh, s, p, x);
  if (g_launch_sites) note(S_LaunchKernel, t0, mono_ns(), 0, 0);
  return rc;
}
static void *WRAP[S_COUNT] = {
  w_StreamSynchronize, w_CtxSynchronize, w_EventSynchronize,
  w_MemcpyHtoDAsync, w_MemcpyDtoHAsync, w_MemcpyAsync, w_MemcpyHtoD, w_MemcpyDtoH,
  w_LaunchKernel,
};

typedef CUresult (*PFN_gpa2)(const char *, void **, int, cuuint64_t, CUdriverProcAddressQueryResult *);
typedef CUresult (*PFN_gpa1)(const char *, void **, int, cuuint64_t);
static PFN_gpa2 g_gpa2;
static PFN_gpa1 g_gpa1;
static CUresult hook_gpa2(const char *, void **, int, cuuint64_t, CUdriverProcAddressQueryResult *);

static void substitute(const char *symbol, void **pfn) {
  if (!pfn || !*pfn || !symbol) return;
  if (!strcmp(symbol, "cuGetProcAddress")) {
    pthread_mutex_lock(&g_mu);
    if (!g_gpa2) g_gpa2 = (PFN_gpa2)*pfn;
    pthread_mutex_unlock(&g_mu);
    *pfn = (void *)hook_gpa2;
    return;
  }
  if (!strcmp(symbol, "cuPointerGetAttribute") && !g_getattr) g_getattr = (PFN_getattr)*pfn;
  for (int s = 0; s < S_COUNT; s++) {
    if (strcmp(symbol, SYM_NAME[s])) continue;
    pthread_mutex_lock(&g_mu);
    if (!g_real[s]) g_real[s] = *pfn;
    int same = g_real[s] == *pfn;
    pthread_mutex_unlock(&g_mu);
    if (same) *pfn = WRAP[s];
    return;
  }
}
static void ensure_getattr(void) {
  if (g_getattr || !g_gpa2) return;
  void *p = NULL;
  CUdriverProcAddressQueryResult st;
  if (g_gpa2("cuPointerGetAttribute", &p, 12000, CU_GET_PROC_ADDRESS_DEFAULT, &st) == CUDA_SUCCESS)
    g_getattr = (PFN_getattr)p;
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
  void *q = p;
  substitute(symbol, &q);
  return q;
}

static void dump(void) {
  const char *dir = getenv("RV64_CUDA_CALLSITES_OUT");
  if (!dir || !*dir || !g_sites) return;
  char path[4096];
  snprintf(path, sizeof path, "%s/cuda-callsites-%d.json", dir, (int)getpid());
  FILE *f = fopen(path, "w");
  if (!f) return;
  pthread_mutex_lock(&g_mu);
  fprintf(f, "{\"schema\":\"rv64-cuda-callsites/v1\",\"pid\":%d,\"sites\":[", (int)getpid());
  int first = 1;
  for (int i = 0; i < MAX_SITES; i++) {
    Site *s = &g_sites[i];
    if (!s->count) continue;
    fprintf(f, "%s{\"sym\":\"%s\",\"count\":%llu,\"bytes\":%llu,\"pageable\":%llu,\"pageable_bytes\":%llu,\"ns\":%llu,\"frames\":[",
            first ? "" : ",", SYM_NAME[s->sym], (unsigned long long)s->count, (unsigned long long)s->bytes,
            (unsigned long long)s->pageable, (unsigned long long)s->pageable_bytes, (unsigned long long)s->ns);
    for (int k = 0; k < s->depth; k++) fprintf(f, "%s\"%p\"", k ? "," : "", s->frames[k]);
    fprintf(f, "]}");
    first = 0;
  }
  pthread_mutex_unlock(&g_mu);
  fprintf(f, "],\"maps\":\"");
  FILE *m = fopen("/proc/self/maps", "r");
  if (m) {
    char line[4096];
    while (fgets(line, sizeof line, m)) {
      if (!strstr(line, "r-xp")) continue;
      for (char *c = line; *c; c++) {
        if (*c == '\n') fputs("\\n", f);
        else if (*c == '"' || *c == '\\') { fputc('\\', f); fputc(*c, f); }
        else fputc(*c, f);
      }
    }
    fclose(m);
  }
  fprintf(f, "\"}\n");
  fclose(f);
}

__attribute__((constructor)) static void init(void) {
  g_sites = calloc(MAX_SITES, sizeof(Site));
  const char *l = getenv("RV64_CUDA_CALLSITES_LAUNCH");
  g_launch_sites = l && *l == '1';
  void *warm[4];
  t_busy = 1;
  backtrace(warm, 4);  // load libgcc_s before the first wrapped call
  t_busy = 0;
  atexit(dump);
}
