#pragma once
// M4 arena stream: process-wide static device arena + pinned host staging.
// Design and measurements: vectors/reports/rv64-m4-20261104/arena/README.md.
//
// Opt-in, scheduling-only. Neither mechanism changes a kernel argument, a
// transcript word or the order of device work; proofs are byte-identical.
//
//   STWO_RV64_DEVICE_ARENA=0|1|auto|<bytes>[K|M|G]
//       1/auto: carve (free - reserve) once per device at first allocation.
//       <bytes>: carve exactly that much (a hard device cap; overrun returns
//       cudaErrorMemoryAllocation to the caller, which may evict idle PCS
//       cache and retry, but there is never a driver/pool fallback).
//   STWO_RV64_DEVICE_ARENA_RESERVE=<bytes>   left outside the arena (auto)
//   STWO_RV64_DEVICE_ARENA_STACK=<bytes>     per-thread stack limit set
//       before carving, so kernel local memory is reserved up front and the
//       driver never has to grow it into a full device (0 = leave as is).
//   STWO_RV64_DEVICE_ARENA_CHUNK=<bytes>      physical chunk (default 32M)
//   STWO_RV64_DEVICE_ARENA_SMALL_CHUNKS=<n>   small slab chunks (default 16)
//   STWO_RV64_DEVICE_ARENA_PREMAP=0|1         map the whole carve at init (1)
//   STWO_RV64_PINNED_STAGING=0|1             pinned H2D/D2H bounce rings
//   STWO_RV64_PINNED_STAGING_SLOT=<bytes>    slot size (default 16M), 4 slots
//
// Cross-context reuse: every context used to own a private async pool, so a
// freed range was only ever reused by the stream that freed it. The arena is
// shared by all contexts of a device, so a single-lane free records an event
// (a fence) on the freeing stream; a later allocation by a different stream
// waits on every incomplete fence overlapping its range (stream wait for a
// single-lane owner, host sync for a multi-lane owner). Multi-lane contexts
// already join every lane before freeing, so their frees need no fence.
#include <cuda.h>
#include <cuda_runtime_api.h>

#include "device_arena.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <set>
#include <unordered_map>
#include <vector>

namespace stwo::cuda::runtime::arena {

constexpr int kMaxDevices = 16;

struct Config {
  bool parsed = false;
  bool valid = true;
  bool enabled = false;
  uint64_t bytes = 0;  // 0 = auto
  uint64_t reserve = uint64_t(2) << 30;
  uint64_t stack = 12544;  // the stack-admission worst kernel of the image
  bool staging = false;
  uint64_t slot_bytes = uint64_t(16) << 20;
  uint64_t chunk = uint64_t(32) << 20;  // physical chunk (multiple of the VMM granularity)
  uint64_t small_chunks = 16;           // permanently mapped small slab (16 x 32 MiB)
  bool premap = true;                   // map the whole carve at init
};

inline bool parse_bytes(const char *text, uint64_t *out) {
  if (!text || !*text) return false;
  char *end = nullptr;
  const unsigned long long value = strtoull(text, &end, 10);
  if (end == text) return false;
  uint64_t scale = 1;
  if (*end == 'K' || *end == 'k') scale = uint64_t(1) << 10, ++end;
  else if (*end == 'M' || *end == 'm') scale = uint64_t(1) << 20, ++end;
  else if (*end == 'G' || *end == 'g') scale = uint64_t(1) << 30, ++end;
  if (*end != '\0') return false;
  if (value > UINT64_MAX / scale) return false;
  *out = uint64_t(value) * scale;
  return true;
}

inline Config parse_config() {
  Config c;
  c.parsed = true;
  if (const char *v = getenv("STWO_RV64_DEVICE_ARENA")) {
    if (!strcmp(v, "0")) c.enabled = false;
    else if (!strcmp(v, "1") || !strcmp(v, "auto")) c.enabled = true;
    else if (parse_bytes(v, &c.bytes) && c.bytes >= (uint64_t(1) << 20)) c.enabled = true;
    else c.valid = false;
  }
  if (const char *v = getenv("STWO_RV64_DEVICE_ARENA_RESERVE"))
    if (!parse_bytes(v, &c.reserve)) c.valid = false;
  if (const char *v = getenv("STWO_RV64_DEVICE_ARENA_STACK"))
    if (!parse_bytes(v, &c.stack)) c.valid = false;
  if (const char *v = getenv("STWO_RV64_PINNED_STAGING")) {
    if (!strcmp(v, "0")) c.staging = false;
    else if (!strcmp(v, "1")) c.staging = true;
    else c.valid = false;
  }
  if (const char *v = getenv("STWO_RV64_DEVICE_ARENA_CHUNK"))
    if (!parse_bytes(v, &c.chunk) || c.chunk < (uint64_t(2) << 20)) c.valid = false;
  if (const char *v = getenv("STWO_RV64_DEVICE_ARENA_SMALL_CHUNKS"))
    if (!parse_bytes(v, &c.small_chunks) || c.small_chunks == 0) c.valid = false;
  if (const char *v = getenv("STWO_RV64_DEVICE_ARENA_PREMAP")) {
    if (!strcmp(v, "0")) c.premap = false;
    else if (strcmp(v, "1")) c.valid = false;
  }
  if (const char *v = getenv("STWO_RV64_PINNED_STAGING_SLOT"))
    if (!parse_bytes(v, &c.slot_bytes) || c.slot_bytes < 4096) c.valid = false;
  if (!c.valid)
    fprintf(stderr, "GPU_ARENA_CONFIG_INVALID (STWO_RV64_DEVICE_ARENA*/STWO_RV64_PINNED_STAGING*)\n");
  return c;
}

inline const Config &config() {
  static const Config c = parse_config();
  return c;
}

struct Counters {
  std::atomic<uint64_t> pool_mallocs{0}, pool_trims{0}, pool_oom_recoveries{0};
  std::atomic<uint64_t> pageable_h2d{0}, pageable_h2d_bytes{0};
  std::atomic<uint64_t> pageable_d2h{0}, pageable_d2h_bytes{0};
  std::atomic<uint64_t> pinned_direct{0};
  std::atomic<uint64_t> staged_h2d{0}, staged_h2d_bytes{0};
  std::atomic<uint64_t> staged_d2h{0}, staged_d2h_bytes{0};
  std::atomic<uint64_t> staging_slot_waits{0}, staging_rings{0};
};
inline Counters &counters() {
  static Counters c;
  return c;
}

inline double now_ms() {
  using clock = std::chrono::steady_clock;
  static const clock::time_point start = clock::now();
  return std::chrono::duration<double, std::milli>(clock::now() - start).count();
}

// ---- VMM-backed static arena ----------------------------------------------
// Physical memory is carved ONCE per device as fixed-size chunks (cuMemCreate
// at init). Device addresses come from a large virtual reservation (4x the
// physical carve). A large allocation takes any free physical chunks and maps
// them behind a fresh virtual range, so physical fragmentation is impossible:
// a 18 GB request succeeds whenever 18 GB of chunks are free, wherever they
// are. Small allocations (< kSmallBytes) come from a permanently mapped slab
// at the start of the reservation. Overrun (no free chunk) returns
// cudaErrorMemoryAllocation; there is never a cudaMalloc/pool fallback.
//
// Reuse ordering: a single-lane free records an event. A freed small range
// is fenced as before. A freed large range keeps its mapping until its event
// completes (host-side deferral), so physical chunks and virtual addresses are
// only reused after the freeing stream has finished with them.

struct Fence {
  uint64_t offset, bytes;
  cudaEvent_t event;
  cudaStream_t stream;
};

struct Driver {
  bool loaded = false;
  cudaError_t status = cudaSuccess;
  decltype(&cuMemGetAllocationGranularity) granularity = nullptr;
  decltype(&cuMemCreate) create = nullptr;
  decltype(&cuMemAddressReserve) reserve = nullptr;
  decltype(&cuMemMap) map = nullptr;
  decltype(&cuMemUnmap) unmap = nullptr;
  decltype(&cuMemSetAccess) access = nullptr;
};

inline Driver &driver() {
  static Driver d;
  static std::once_flag once;
  std::call_once(once, [] {
    auto load = [](const char *name, void **out) {
      cudaDriverEntryPointQueryResult result{};
      const cudaError_t s = cudaGetDriverEntryPoint(name, out, cudaEnableDefault, &result);
      return s == cudaSuccess && result == cudaDriverEntryPointSuccess && *out;
    };
    bool ok = load("cuMemGetAllocationGranularity", reinterpret_cast<void **>(&d.granularity)) &&
              load("cuMemCreate", reinterpret_cast<void **>(&d.create)) &&
              load("cuMemAddressReserve", reinterpret_cast<void **>(&d.reserve)) &&
              load("cuMemMap", reinterpret_cast<void **>(&d.map)) &&
              load("cuMemUnmap", reinterpret_cast<void **>(&d.unmap)) &&
              load("cuMemSetAccess", reinterpret_cast<void **>(&d.access));
    d.loaded = ok;
    d.status = ok ? cudaSuccess : cudaErrorNotSupported;
    if (!ok) (void)cudaGetLastError();
  });
  return d;
}

inline cudaError_t cu(CUresult r) { return r == CUDA_SUCCESS ? cudaSuccess : cudaErrorMemoryAllocation; }

struct Device {
  std::mutex mutex;
  int ordinal = -1;
  char *base = nullptr;          // virtual reservation base
  uint64_t va_bytes = 0;
  uint64_t chunk = 0;            // physical chunk bytes
  uint64_t small_bytes = 0;      // permanently mapped slab at [0, small_bytes)
  OffsetArena *small = nullptr;  // offsets in [0, small_bytes)
  OffsetArena *arena = nullptr;  // virtual offsets in [small_bytes, va_bytes) minus small_bytes
  std::vector<CUmemGenericAllocationHandle> handles;
  std::vector<uint32_t> free_chunks;
  // Large region: one slot per chunk of virtual space. A slot is either
  // unmapped (-1) or backed by a physical chunk. Freed ranges stay mapped, so
  // the OffsetArena's coalescing best fit reuses them with no driver call.
  std::vector<int32_t> slot_chunk;
  std::set<uint32_t> mapped_free;  // mapped slots outside every live allocation
  std::unordered_map<uint64_t, uint64_t> live_bytes_by_offset;  // offset -> bytes | long bit
  uint64_t reuse_hits = 0, map_misses = 0, steals = 0, stolen_chunks = 0;
  CUmemAccessDesc access{};
  cudaError_t init_status = cudaSuccess;
  std::vector<Fence> fences;
  std::vector<cudaEvent_t> spare;
  uint64_t free_before = 0, free_after_stack = 0, total = 0, stack_before = 0, stack_after = 0;
  double init_ms = 0, created_at_ms = 0;
  uint64_t fence_records = 0, fence_same_stream = 0, fence_complete = 0;
  uint64_t fence_stream_waits = 0, fence_host_syncs = 0;
  uint64_t hw_printed = 0;
  // accounting
  uint64_t live = 0, live_hw = 0, live_long = 0, live_long_hw = 0, live_small = 0, live_small_hw = 0;
  uint64_t phys_chunks_hw = 0;  // chunks in use (small slab + mapped large) high-water
  uint64_t allocations = 0, releases = 0, overruns = 0, largest_overrun = 0, used_at_overrun = 0;
  uint64_t free_chunks_at_overrun = 0, small_spills = 0;
  uint64_t map_calls = 0, unmap_calls = 0, pending_host_syncs = 0;
  double map_ms = 0, unmap_ms = 0;
  uint64_t capacity() const { return uint64_t(handles.size()) * chunk; }
  uint64_t chunks_in_use() const { return handles.size() - free_chunks.size(); }
  CUdeviceptr slot_va(uint32_t slot) const {
    return reinterpret_cast<CUdeviceptr>(base) + small_bytes + uint64_t(slot) * chunk;
  }
};

inline std::mutex &registry_mutex() {
  static std::mutex m;
  return m;
}
inline Device **registry() {
  static Device *devices[kMaxDevices] = {};
  return devices;
}

inline void print_summaries();

inline void register_summary() {
  static std::once_flag once;
  std::call_once(once, [] { atexit(print_summaries); });
}

// The driver may leave through exit_group without running atexit handlers, so
// cumulative summaries are also printed at most every 2 s from the hot paths
// (outside any arena lock) and on context destroy. Readers take the last line.
inline void maybe_print() {
  static std::atomic<int64_t> last{0};
  const int64_t now = int64_t(now_ms());
  int64_t seen = last.load(std::memory_order_relaxed);
  if (now - seen < 2000) return;
  if (!last.compare_exchange_strong(seen, now, std::memory_order_relaxed)) return;
  print_summaries();
}

// Map `chunks` behind [offset, offset + chunks*chunk) and enable access
// (used once at init for the small slab).
inline cudaError_t map_range(Device *d, uint64_t offset, const std::vector<uint32_t> &chunks) {
  Driver &dr = driver();
  const double t0 = now_ms();
  const CUdeviceptr va = reinterpret_cast<CUdeviceptr>(d->base) + offset;
  for (size_t i = 0; i < chunks.size(); ++i) {
    const CUresult r = dr.map(va + i * d->chunk, d->chunk, 0, d->handles[chunks[i]], 0);
    ++d->map_calls;
    if (r != CUDA_SUCCESS) return cu(r);
  }
  const CUresult r = dr.access(va, chunks.size() * d->chunk, &d->access, 1);
  d->map_ms += now_ms() - t0;
  return cu(r);
}

// Back every listed (ascending, unmapped) slot with a free chunk; access is
// enabled once per contiguous run.
inline cudaError_t map_slots(Device *d, const std::vector<uint32_t> &slots) {
  Driver &dr = driver();
  const double t0 = now_ms();
  cudaError_t s = cudaSuccess;
  size_t run = 0;
  for (size_t i = 0; s == cudaSuccess && i < slots.size(); ++i) {
    const uint32_t chunk = d->free_chunks.back();
    s = cu(dr.map(d->slot_va(slots[i]), d->chunk, 0, d->handles[chunk], 0));
    ++d->map_calls;
    if (s != cudaSuccess) break;
    d->free_chunks.pop_back();
    d->slot_chunk[slots[i]] = int32_t(chunk);
    const bool last = i + 1 == slots.size() || slots[i + 1] != slots[i] + 1;
    if (last) {
      s = cu(dr.access(d->slot_va(slots[run]), uint64_t(i + 1 - run) * d->chunk, &d->access, 1));
      run = i + 1;
    }
  }
  d->map_ms += now_ms() - t0;
  return s;
}

// Unmap listed (ascending, mapped, free) slots, one call per contiguous run,
// and return their chunks.
inline cudaError_t unmap_slots(Device *d, const std::vector<uint32_t> &slots) {
  Driver &dr = driver();
  const double t0 = now_ms();
  cudaError_t s = cudaSuccess;
  size_t run = 0;
  for (size_t i = 0; s == cudaSuccess && i < slots.size(); ++i) {
    const bool last = i + 1 == slots.size() || slots[i + 1] != slots[i] + 1;
    if (!last) continue;
    s = cu(dr.unmap(d->slot_va(slots[run]), uint64_t(i + 1 - run) * d->chunk));
    ++d->unmap_calls;
    if (s != cudaSuccess) break;
    for (size_t j = run; j <= i; ++j) {
      d->free_chunks.push_back(uint32_t(d->slot_chunk[slots[j]]));
      d->slot_chunk[slots[j]] = -1;
      d->mapped_free.erase(slots[j]);
    }
    run = i + 1;
  }
  d->unmap_ms += now_ms() - t0;
  return s;
}

// Called on the owner thread with `ordinal` current. Creation is serialized.
inline Device *device(int ordinal, cudaError_t *status) {
  *status = cudaSuccess;
  if (ordinal < 0 || ordinal >= kMaxDevices) {
    *status = cudaErrorInvalidDevice;
    return nullptr;
  }
  std::lock_guard<std::mutex> guard(registry_mutex());
  Device *&slot = registry()[ordinal];
  if (slot) {
    *status = slot->init_status;
    return slot->init_status == cudaSuccess ? slot : nullptr;
  }
  register_summary();
  slot = new Device();
  Device *d = slot;
  d->ordinal = ordinal;
  const Config &c = config();
  const double t0 = now_ms();
  d->created_at_ms = t0;
  Driver &dr = driver();
  cudaError_t s = dr.status;
  size_t free_bytes = 0, total_bytes = 0;
  if (s == cudaSuccess) s = cudaMemGetInfo(&free_bytes, &total_bytes);
  d->free_before = free_bytes;
  d->total = total_bytes;
  size_t stack = 0;
  if (s == cudaSuccess) s = cudaDeviceGetLimit(&stack, cudaLimitStackSize);
  d->stack_before = stack;
  if (s == cudaSuccess && c.stack > stack)
    s = cudaDeviceSetLimit(cudaLimitStackSize, size_t(c.stack));
  if (s == cudaSuccess) s = cudaDeviceGetLimit(&stack, cudaLimitStackSize);
  d->stack_after = stack;
  if (s == cudaSuccess) s = cudaMemGetInfo(&free_bytes, &total_bytes);
  d->free_after_stack = free_bytes;
  CUmemAllocationProp prop{};
  prop.type = CU_MEM_ALLOCATION_TYPE_PINNED;
  prop.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
  prop.location.id = ordinal;
  size_t granularity = 0;
  if (s == cudaSuccess)
    s = cu(dr.granularity(&granularity, &prop, CU_MEM_ALLOC_GRANULARITY_RECOMMENDED));
  if (s == cudaSuccess && (granularity == 0 || c.chunk % granularity)) s = cudaErrorInvalidValue;
  d->chunk = c.chunk;
  uint64_t capacity = c.bytes;
  if (s == cudaSuccess && capacity == 0)
    capacity = free_bytes > c.reserve ? free_bytes - c.reserve : 0;
  const uint64_t count = s == cudaSuccess ? capacity / d->chunk : 0;
  if (s == cudaSuccess && (count < 4 || count * d->chunk > free_bytes)) s = cudaErrorMemoryAllocation;
  d->small_bytes = (c.small_chunks < count ? c.small_chunks : 1) * d->chunk;
  d->va_bytes = d->small_bytes + 4 * count * d->chunk;
  CUdeviceptr va = 0;
  if (s == cudaSuccess) s = cu(dr.reserve(&va, d->va_bytes, d->chunk, 0, 0));
  d->base = reinterpret_cast<char *>(va);
  d->handles.reserve(count);
  for (uint64_t i = 0; s == cudaSuccess && i < count; ++i) {
    CUmemGenericAllocationHandle h = 0;
    s = cu(dr.create(&h, d->chunk, &prop, 0));
    if (s == cudaSuccess) d->handles.push_back(h);
  }
  d->access.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
  d->access.location.id = ordinal;
  d->access.flags = CU_MEM_ACCESS_FLAGS_PROT_READWRITE;
  // Small slab: the first small_bytes/chunk handles, mapped forever.
  const uint64_t small_count = d->small_bytes / d->chunk;
  for (uint64_t i = d->handles.size(); i-- > small_count;) d->free_chunks.push_back(uint32_t(i));
  if (s == cudaSuccess) {
    std::vector<uint32_t> slab;
    for (uint64_t i = 0; i < small_count; ++i) slab.push_back(uint32_t(i));
    s = map_range(d, 0, slab);
  }
  if (s == cudaSuccess) {
    d->small = new OffsetArena(d->small_bytes);
    d->arena = new OffsetArena(d->va_bytes - d->small_bytes);
    d->slot_chunk.assign((d->va_bytes - d->small_bytes) / d->chunk, -1);
    // Static carve: map every physical chunk once, contiguously, at the low
    // end of the large region. Steady-state allocations then land in fully
    // mapped windows (no driver call); remapping happens only when the live
    // set fragments that window.
    if (c.premap) {
      std::vector<uint32_t> slots;
      for (uint32_t i = 0; i < d->free_chunks.size(); ++i) slots.push_back(i);
      s = map_slots(d, slots);
      for (uint32_t slot : slots) d->mapped_free.insert(slot);
    }
  }
  d->init_ms = now_ms() - t0;
  d->init_status = s;
  fprintf(stderr,
          "GPU_ARENA_INIT device=%d status=%d mode=vmm capacity_bytes=%llu chunk_bytes=%llu chunks=%llu "
          "small_slab_bytes=%llu va_bytes=%llu granularity=%zu reserve_bytes=%llu "
          "free_before_bytes=%llu free_after_stack_bytes=%llu total_bytes=%llu "
          "stack_before=%llu stack_after=%llu init_ms=%.3f t_ms=%.1f\n",
          ordinal, int(s), (unsigned long long)d->capacity(), (unsigned long long)d->chunk,
          (unsigned long long)d->handles.size(), (unsigned long long)d->small_bytes,
          (unsigned long long)d->va_bytes, granularity, (unsigned long long)c.reserve,
          (unsigned long long)d->free_before, (unsigned long long)d->free_after_stack,
          (unsigned long long)d->total, (unsigned long long)d->stack_before,
          (unsigned long long)d->stack_after, d->init_ms, t0);
  if (s != cudaSuccess) (void)cudaGetLastError();
  *status = s;
  return s == cudaSuccess ? d : nullptr;
}

inline bool overlaps(const Fence &f, uint64_t offset, uint64_t bytes) {
  return f.offset < offset + bytes && offset < f.offset + f.bytes;
}

// Drop completed small fences and reclaim completed large frees; caller
// holds d->mutex.
inline cudaError_t purge(Device *d) {
  size_t keep = 0;
  for (size_t i = 0; i < d->fences.size(); ++i) {
    const cudaError_t q = cudaEventQuery(d->fences[i].event);
    if (q == cudaSuccess) {
      d->spare.push_back(d->fences[i].event);
      ++d->fence_complete;
      continue;
    }
    if (q != cudaErrorNotReady) return q;
    d->fences[keep++] = d->fences[i];
  }
  d->fences.resize(keep);
  return cudaSuccess;
}

// Order a reused range [offset, offset+bytes) after every incomplete fence
// that overlaps it (stream wait for a single-lane owner, host sync otherwise).
inline cudaError_t order_range(Device *d, uint64_t offset, uint64_t bytes, cudaStream_t stream,
                               uint32_t lane_count) {
  for (const Fence &f : d->fences) {
    if (!overlaps(f, offset, bytes)) continue;
    if (f.stream == stream && lane_count == 1) {
      ++d->fence_same_stream;
      continue;
    }
    cudaError_t s = cudaEventQuery(f.event);
    if (s == cudaSuccess) continue;
    if (s != cudaErrorNotReady) return s;
    if (lane_count == 1) {
      s = cudaStreamWaitEvent(stream, f.event, 0);
      ++d->fence_stream_waits;
    } else {
      s = cudaEventSynchronize(f.event);
      ++d->fence_host_syncs;
    }
    if (s != cudaSuccess) return s;
  }
  return cudaSuccess;
}

inline void account_alloc(Device *d, uint64_t offset, uint64_t bytes, bool long_lived, bool small) {
  d->live_bytes_by_offset[offset] = bytes | (long_lived ? 1u : 0u);  // bytes are 512-aligned
  d->live += bytes;
  if (d->live > d->live_hw) d->live_hw = d->live;
  if (long_lived) {
    d->live_long += bytes;
    if (d->live_long > d->live_long_hw) d->live_long_hw = d->live_long;
  }
  if (small) {
    d->live_small += bytes;
    if (d->live_small > d->live_small_hw) d->live_small_hw = d->live_small;
  }
  if (d->chunks_in_use() > d->phys_chunks_hw) d->phys_chunks_hw = d->chunks_in_use();
  ++d->allocations;
}

inline cudaError_t allocate_small(Device *d, cudaStream_t stream, uint32_t lane_count,
                                  size_t bytes, bool long_lived, void **out, bool *done) {
  *done = false;
  uint64_t offset = 0, aligned = 0;
  if (!d->small->allocate(bytes, long_lived, &offset, &aligned)) {
    ++d->small_spills;
    return cudaSuccess;  // spill to the large path
  }
  const cudaError_t ordered = order_range(d, offset, aligned, stream, lane_count);
  if (ordered != cudaSuccess) {
    d->small->release(offset);
    return ordered;
  }
  account_alloc(d, offset, aligned, long_lived, true);
  *out = d->base + offset;
  *done = true;
  return cudaSuccess;
}

inline cudaError_t allocate(int ordinal, cudaStream_t stream, uint32_t lane_count,
                            size_t bytes, bool long_lived, void **out) {
  *out = nullptr;
  maybe_print();
  if (!config().valid) return cudaErrorInvalidValue;
  cudaError_t s = cudaSuccess;
  Device *d = device(ordinal, &s);
  if (!d) return s;
  std::lock_guard<std::mutex> guard(d->mutex);
  s = purge(d);
  if (s != cudaSuccess) return s;
  if (bytes < OffsetArena::kSmallBytes && bytes <= d->small_bytes / 8) {
    bool done = false;
    s = allocate_small(d, stream, lane_count, bytes, long_lived, out, &done);
    if (s != cudaSuccess || done) return s;
  }
  if (bytes > UINT64_MAX - d->chunk) return cudaErrorMemoryAllocation;
  const uint64_t n = (uint64_t(bytes) + d->chunk - 1) / d->chunk;
  // Virtual placement first (coalescing best fit; freed ranges stay mapped,
  // so a fitting freed hole needs no driver call). Then back any unmapped
  // slot of the range with a free chunk, stealing mapped free slots from
  // other holes (one unmap per run) only when no unmapped chunk is left.
  // Placement: the n-slot window, inside any free extent, that already has
  // the most mapped slots (a fully mapped window costs no driver call).
  // Ties: smaller extent, then lower address. Sliding count, O(free slots).
  uint64_t voff = 0;
  bool placed = false;
  {
    uint64_t best_mapped = 0, best_extent = UINT64_MAX, best_slot = 0;
    d->arena->for_each_free([&](uint64_t offset, uint64_t length) {
      const uint64_t a = offset / d->chunk, len = length / d->chunk;
      if (len < n) return;
      uint64_t mapped = 0;
      for (uint64_t k = a; k < a + n; ++k) mapped += d->slot_chunk[k] >= 0;
      uint64_t window_mapped = mapped, window_start = a;
      for (uint64_t start = a + 1; start + n <= a + len; ++start) {
        mapped += (d->slot_chunk[start + n - 1] >= 0) - (d->slot_chunk[start - 1] >= 0);
        if (mapped > window_mapped) {
          window_mapped = mapped;
          window_start = start;
        }
        if (window_mapped == n) break;
      }
      if (!placed || window_mapped > best_mapped ||
          (window_mapped == best_mapped && len < best_extent)) {
        placed = true;
        best_mapped = window_mapped;
        best_extent = len;
        best_slot = window_start;
      }
    });
    if (placed) {
      voff = best_slot * d->chunk;
      placed = d->arena->allocate_at(voff, n * d->chunk, long_lived);
    }
  }
  std::vector<uint32_t> missing;
  const uint32_t first = placed ? uint32_t(voff / d->chunk) : 0;
  if (placed)
    for (uint32_t slot = first; slot < first + n; ++slot)
      if (d->slot_chunk[slot] < 0) missing.push_back(slot);
  const uint64_t stealable = d->mapped_free.size() - (placed ? (n - missing.size()) : 0);
  if (!placed || missing.size() > d->free_chunks.size() + stealable) {
    if (placed) d->arena->release(voff);
    ++d->overruns;
    if (bytes > d->largest_overrun) {
      d->largest_overrun = bytes;
      d->used_at_overrun = d->live;
      d->free_chunks_at_overrun = d->free_chunks.size() + d->mapped_free.size();
    }
    fprintf(stderr,
            "GPU_ARENA_OVERRUN device=%d requested_bytes=%llu long=%d live_bytes=%llu "
            "capacity_bytes=%llu free_chunk_bytes=%llu mapped_free_bytes=%llu live=%zu t_ms=%.1f\n",
            ordinal, (unsigned long long)bytes, int(long_lived), (unsigned long long)d->live,
            (unsigned long long)d->capacity(),
            (unsigned long long)(d->free_chunks.size() * d->chunk),
            (unsigned long long)(d->mapped_free.size() * d->chunk),
            d->live_bytes_by_offset.size(), now_ms());
    return cudaErrorMemoryAllocation;
  }
  for (uint32_t slot = first; slot < first + n; ++slot) d->mapped_free.erase(slot);
  if (missing.size() > d->free_chunks.size()) {
    std::vector<uint32_t> victims;
    const size_t want = missing.size() - d->free_chunks.size();
    // Steal from the top of the virtual space: those slots sit in holes the
    // best fit reaches last.
    for (auto it = d->mapped_free.rbegin(); it != d->mapped_free.rend() && victims.size() < want; ++it)
      victims.push_back(*it);
    std::sort(victims.begin(), victims.end());
    for (uint32_t slot : victims) {
      for (const Fence &f : d->fences) {
        if (!overlaps(f, d->small_bytes + uint64_t(slot) * d->chunk, d->chunk)) continue;
        cudaError_t q = cudaEventQuery(f.event);
        if (q == cudaErrorNotReady) {
          q = cudaEventSynchronize(f.event);
          ++d->pending_host_syncs;
        }
        if (q != cudaSuccess) return q;
      }
    }
    s = unmap_slots(d, victims);
    if (s != cudaSuccess) return s;
    ++d->steals;
    d->stolen_chunks += victims.size();
  }
  if (missing.empty()) ++d->reuse_hits;
  else ++d->map_misses;
  s = map_slots(d, missing);
  const uint64_t offset = voff + d->small_bytes;
  if (s == cudaSuccess) s = order_range(d, offset, n * d->chunk, stream, lane_count);
  if (s != cudaSuccess) return s;
  account_alloc(d, offset, n * d->chunk, long_lived, false);
  if (d->phys_chunks_hw * d->chunk >= d->hw_printed + (uint64_t(1) << 30)) {
    d->hw_printed = d->phys_chunks_hw * d->chunk;
    fprintf(stderr, "GPU_ARENA_HW device=%d physical_high_water_bytes=%llu live_bytes=%llu long_bytes=%llu t_ms=%.1f\n",
            ordinal, (unsigned long long)(d->phys_chunks_hw * d->chunk),
            (unsigned long long)d->live, (unsigned long long)d->live_long, now_ms());
  }
  *out = d->base + offset;
  return cudaSuccess;
}

// `joined`: every lane of the freeing context has completed (multi-lane
// contexts join before free), so no fence or deferral is needed.
inline cudaError_t release(int ordinal, cudaStream_t stream, void *pointer, bool joined) {
  maybe_print();
  cudaError_t s = cudaSuccess;
  Device *d = device(ordinal, &s);
  if (!d) return s;
  std::lock_guard<std::mutex> guard(d->mutex);
  const uintptr_t p = reinterpret_cast<uintptr_t>(pointer);
  const uintptr_t b = reinterpret_cast<uintptr_t>(d->base);
  if (p < b || p >= b + d->va_bytes) return cudaErrorInvalidDevicePointer;
  const uint64_t offset = p - b;
  auto live = d->live_bytes_by_offset.find(offset);
  if (live == d->live_bytes_by_offset.end()) return cudaErrorInvalidDevicePointer;
  const uint64_t bytes = live->second & ~uint64_t(1);
  const bool long_lived = (live->second & 1) != 0;
  cudaEvent_t event = nullptr;
  if (!joined) {
    if (!d->spare.empty()) {
      event = d->spare.back();
      d->spare.pop_back();
    } else {
      s = cudaEventCreateWithFlags(&event, cudaEventDisableTiming);
      if (s != cudaSuccess) return s;
    }
    s = cudaEventRecord(event, stream);
    if (s != cudaSuccess) {
      d->spare.push_back(event);
      return s;
    }
    ++d->fence_records;
  }
  const bool small = offset < d->small_bytes;
  if (small) {
    if (event) d->fences.push_back({offset, bytes, event, stream});
    d->small->release(offset);
  } else {
    if (event) d->fences.push_back({offset, bytes, event, stream});
    const uint32_t first = uint32_t((offset - d->small_bytes) / d->chunk);
    for (uint32_t slot = first; slot < first + bytes / d->chunk; ++slot) d->mapped_free.insert(slot);
    d->arena->release(offset - d->small_bytes);
  }
  d->live_bytes_by_offset.erase(live);
  d->live -= bytes;
  if (small) d->live_small -= bytes;
  if (long_lived) d->live_long -= bytes;
  ++d->releases;
  return cudaSuccess;
}

inline bool owns(int ordinal, const void *pointer) {
  if (!config().enabled || ordinal < 0 || ordinal >= kMaxDevices) return false;
  Device *d = nullptr;
  {
    std::lock_guard<std::mutex> guard(registry_mutex());
    d = registry()[ordinal];
  }
  if (!d || !d->arena) return false;
  const uintptr_t p = reinterpret_cast<uintptr_t>(pointer);
  const uintptr_t b = reinterpret_cast<uintptr_t>(d->base);
  return p >= b && p < b + d->va_bytes;
}

// used: live bytes; reserved: the static physical carve (+ small slab).
inline bool usage(int ordinal, size_t used[2], size_t reserved[2]) {
  if (!config().enabled || ordinal < 0 || ordinal >= kMaxDevices) return false;
  Device *d = nullptr;
  {
    std::lock_guard<std::mutex> guard(registry_mutex());
    d = registry()[ordinal];
  }
  if (!d || !d->arena) {
    used[0] = used[1] = reserved[0] = reserved[1] = 0;
    return true;
  }
  std::lock_guard<std::mutex> guard(d->mutex);
  used[1] = size_t(d->live_long);
  used[0] = size_t(d->live - d->live_long);
  reserved[1] = used[1];
  reserved[0] = size_t(d->capacity() - d->live_long);
  return true;
}


// ---------------- pinned staging ----------------

struct Ring {
  char *host = nullptr;
  uint64_t slot_bytes = 0;
  static constexpr int kSlots = 4;
  cudaEvent_t events[kSlots] = {};
  bool armed[kSlots] = {};
  int current = 0;
  uint64_t bump = 0;
};

inline std::mutex &ring_mutex() {
  static std::mutex m;
  return m;
}
inline std::unordered_map<cudaStream_t, Ring *> &rings() {
  static std::unordered_map<cudaStream_t, Ring *> r;
  return r;
}

inline bool host_is_pageable(const void *pointer) {
  cudaPointerAttributes attributes{};
  const cudaError_t s = cudaPointerGetAttributes(&attributes, pointer);
  if (s != cudaSuccess) {
    (void)cudaGetLastError();
    return true;
  }
  return attributes.type == cudaMemoryTypeUnregistered;
}

inline cudaError_t ring_for(cudaStream_t stream, Ring **out) {
  std::lock_guard<std::mutex> guard(ring_mutex());
  auto it = rings().find(stream);
  if (it != rings().end()) {
    *out = it->second;
    return cudaSuccess;
  }
  register_summary();
  Ring *ring = new Ring();
  ring->slot_bytes = config().slot_bytes;
  cudaError_t s = cudaHostAlloc(reinterpret_cast<void **>(&ring->host),
                                ring->slot_bytes * Ring::kSlots, cudaHostAllocPortable);
  for (int i = 0; s == cudaSuccess && i < Ring::kSlots; ++i)
    s = cudaEventCreateWithFlags(&ring->events[i], cudaEventDisableTiming);
  if (s != cudaSuccess) {
    for (int i = 0; i < Ring::kSlots; ++i)
      if (ring->events[i]) cudaEventDestroy(ring->events[i]);
    if (ring->host) cudaFreeHost(ring->host);
    delete ring;
    return s;
  }
  rings().emplace(stream, ring);
  counters().staging_rings.fetch_add(1, std::memory_order_relaxed);
  *out = ring;
  return cudaSuccess;
}

// Move to the next slot, waiting for its last DMA.
inline cudaError_t ring_advance(Ring *ring) {
  ring->current = (ring->current + 1) % Ring::kSlots;
  ring->bump = 0;
  if (!ring->armed[ring->current]) return cudaSuccess;
  cudaError_t s = cudaEventQuery(ring->events[ring->current]);
  if (s == cudaErrorNotReady) {
    counters().staging_slot_waits.fetch_add(1, std::memory_order_relaxed);
    s = cudaEventSynchronize(ring->events[ring->current]);
  }
  if (s == cudaSuccess) ring->armed[ring->current] = false;
  return s;
}

// Same contract as a pageable cudaMemcpyAsync H2D: the source is consumed
// before return, the DMA is ordered on `stream`.
inline cudaError_t staged_h2d(cudaStream_t stream, void *destination, const void *source,
                              size_t bytes) {
  Ring *ring = nullptr;
  cudaError_t s = ring_for(stream, &ring);
  if (s != cudaSuccess) return s;
  char *dst = static_cast<char *>(destination);
  const char *src = static_cast<const char *>(source);
  counters().staged_h2d.fetch_add(1, std::memory_order_relaxed);
  counters().staged_h2d_bytes.fetch_add(bytes, std::memory_order_relaxed);
  while (bytes) {
    const uint64_t room = ring->slot_bytes - ring->bump;
    if (room == 0 || (ring->bump != 0 && room < bytes)) {
      s = ring_advance(ring);
      if (s != cudaSuccess) return s;
    } else if (ring->armed[ring->current] && ring->bump == 0) {
      // Fresh slot that still has DMA in flight from a previous lap.
      s = cudaEventSynchronize(ring->events[ring->current]);
      if (s != cudaSuccess) return s;
      ring->armed[ring->current] = false;
    }
    const uint64_t chunk = bytes < ring->slot_bytes - ring->bump ? bytes : ring->slot_bytes - ring->bump;
    char *slot = ring->host + uint64_t(ring->current) * ring->slot_bytes + ring->bump;
    memcpy(slot, src, chunk);
    s = cudaMemcpyAsync(dst, slot, chunk, cudaMemcpyHostToDevice, stream);
    if (s == cudaSuccess) s = cudaEventRecord(ring->events[ring->current], stream);
    if (s != cudaSuccess) return s;
    ring->armed[ring->current] = true;
    ring->bump = (ring->bump + chunk + 63) & ~uint64_t(63);
    if (ring->bump > ring->slot_bytes) ring->bump = ring->slot_bytes;
    dst += chunk;
    src += chunk;
    bytes -= chunk;
  }
  return cudaSuccess;
}

// Same contract as a pageable cudaMemcpyAsync D2H: returns only after the
// destination holds the data. Up to kSlots chunks are in flight.
inline cudaError_t staged_d2h(cudaStream_t stream, void *destination, const void *source,
                              size_t bytes) {
  Ring *ring = nullptr;
  cudaError_t s = ring_for(stream, &ring);
  if (s != cudaSuccess) return s;
  char *dst = static_cast<char *>(destination);
  const char *src = static_cast<const char *>(source);
  counters().staged_d2h.fetch_add(1, std::memory_order_relaxed);
  counters().staged_d2h_bytes.fetch_add(bytes, std::memory_order_relaxed);
  while (bytes) {
    int slots[Ring::kSlots];
    uint64_t sizes[Ring::kSlots];
    int issued = 0;
    while (bytes && issued < Ring::kSlots) {
      s = ring_advance(ring);
      if (s != cudaSuccess) return s;
      const uint64_t chunk = bytes < ring->slot_bytes ? bytes : ring->slot_bytes;
      char *slot = ring->host + uint64_t(ring->current) * ring->slot_bytes;
      s = cudaMemcpyAsync(slot, src, chunk, cudaMemcpyDeviceToHost, stream);
      if (s == cudaSuccess) s = cudaEventRecord(ring->events[ring->current], stream);
      if (s != cudaSuccess) return s;
      ring->armed[ring->current] = true;
      ring->bump = ring->slot_bytes;  // never pack H2D behind an unread D2H
      slots[issued] = ring->current;
      sizes[issued] = chunk;
      ++issued;
      src += chunk;
      bytes -= chunk;
    }
    for (int i = 0; i < issued; ++i) {
      s = cudaEventSynchronize(ring->events[slots[i]]);
      if (s != cudaSuccess) return s;
      ring->armed[slots[i]] = false;
      memcpy(dst, ring->host + uint64_t(slots[i]) * ring->slot_bytes, sizes[i]);
      dst += sizes[i];
    }
  }
  return cudaSuccess;
}

// Called by context destroy after every lane has joined.
inline void release_ring(cudaStream_t stream) {
  Ring *ring = nullptr;
  {
    std::lock_guard<std::mutex> guard(ring_mutex());
    auto it = rings().find(stream);
    if (it == rings().end()) return;
    ring = it->second;
    rings().erase(it);
  }
  for (int i = 0; i < Ring::kSlots; ++i) {
    if (ring->armed[i]) cudaEventSynchronize(ring->events[i]);
    cudaEventDestroy(ring->events[i]);
  }
  cudaFreeHost(ring->host);
  delete ring;
}

// The context's H2D/D2H entry: decides pinned-direct, staged or pageable.
inline cudaError_t copy_async(cudaStream_t stream, void *destination, const void *source,
                              size_t bytes, cudaMemcpyKind kind, bool capturing) {
  maybe_print();
  const void *host = kind == cudaMemcpyHostToDevice ? source : destination;
  const bool pageable = host_is_pageable(host);
  if (!pageable) {
    counters().pinned_direct.fetch_add(1, std::memory_order_relaxed);
  } else if (config().staging && config().valid && !capturing) {
    return kind == cudaMemcpyHostToDevice ? staged_h2d(stream, destination, source, bytes)
                                          : staged_d2h(stream, destination, source, bytes);
  } else if (kind == cudaMemcpyHostToDevice) {
    counters().pageable_h2d.fetch_add(1, std::memory_order_relaxed);
    counters().pageable_h2d_bytes.fetch_add(bytes, std::memory_order_relaxed);
  } else {
    counters().pageable_d2h.fetch_add(1, std::memory_order_relaxed);
    counters().pageable_d2h_bytes.fetch_add(bytes, std::memory_order_relaxed);
  }
  return cudaMemcpyAsync(destination, source, bytes, kind, stream);
}

inline void print_summaries() {
  // Host counters only: CUDA may already be shutting down at exit.
  Counters &c = counters();
  fprintf(stderr,
          "GPU_POOL_SUMMARY pool_mallocs=%llu pool_trims=%llu pool_oom_recoveries=%llu "
          "arena_enabled=%d staging_enabled=%d\n",
          (unsigned long long)c.pool_mallocs.load(), (unsigned long long)c.pool_trims.load(),
          (unsigned long long)c.pool_oom_recoveries.load(), int(config().enabled),
          int(config().staging));
  fprintf(stderr,
          "GPU_STAGING_SUMMARY pageable_h2d=%llu pageable_h2d_bytes=%llu pageable_d2h=%llu "
          "pageable_d2h_bytes=%llu pinned_direct=%llu staged_h2d=%llu staged_h2d_bytes=%llu "
          "staged_d2h=%llu staged_d2h_bytes=%llu slot_waits=%llu rings=%llu\n",
          (unsigned long long)c.pageable_h2d.load(), (unsigned long long)c.pageable_h2d_bytes.load(),
          (unsigned long long)c.pageable_d2h.load(), (unsigned long long)c.pageable_d2h_bytes.load(),
          (unsigned long long)c.pinned_direct.load(), (unsigned long long)c.staged_h2d.load(),
          (unsigned long long)c.staged_h2d_bytes.load(), (unsigned long long)c.staged_d2h.load(),
          (unsigned long long)c.staged_d2h_bytes.load(), (unsigned long long)c.staging_slot_waits.load(),
          (unsigned long long)c.staging_rings.load());
  for (int i = 0; i < kMaxDevices; ++i) {
    Device *d = nullptr;
    {
      std::lock_guard<std::mutex> guard(registry_mutex());
      d = registry()[i];
    }
    if (!d || !d->arena) continue;
    std::unique_lock<std::mutex> lock(d->mutex, std::try_to_lock);
    if (!lock.owns_lock()) continue;
    fprintf(stderr,
            "GPU_ARENA_SUMMARY device=%d mode=vmm capacity_bytes=%llu chunk_bytes=%llu "
            "physical_high_water_bytes=%llu live_high_water_bytes=%llu live_long_high_water_bytes=%llu "
            "live_small_high_water_bytes=%llu small_slab_bytes=%llu allocations=%llu releases=%llu "
            "overruns=%llu largest_overrun_bytes=%llu live_at_overrun_bytes=%llu "
            "free_chunks_at_overrun=%llu small_spills=%llu map_calls=%llu unmap_calls=%llu "
            "map_ms=%.3f unmap_ms=%.3f evict_host_syncs=%llu fence_records=%llu "
            "fence_same_stream=%llu fence_stream_waits=%llu fence_host_syncs=%llu fences_now=%zu "
            "reuse_hits=%llu map_misses=%llu steals=%llu stolen_chunks=%llu mapped_free_bytes=%llu "
            "init_ms=%.3f free_before_bytes=%llu free_after_stack_bytes=%llu stack_after=%llu t_ms=%.1f\n",
            i, (unsigned long long)d->capacity(), (unsigned long long)d->chunk,
            (unsigned long long)(d->phys_chunks_hw * d->chunk),
            (unsigned long long)d->live_hw, (unsigned long long)d->live_long_hw,
            (unsigned long long)d->live_small_hw, (unsigned long long)d->small_bytes,
            (unsigned long long)d->allocations, (unsigned long long)d->releases,
            (unsigned long long)d->overruns, (unsigned long long)d->largest_overrun,
            (unsigned long long)d->used_at_overrun, (unsigned long long)d->free_chunks_at_overrun,
            (unsigned long long)d->small_spills, (unsigned long long)d->map_calls,
            (unsigned long long)d->unmap_calls, d->map_ms, d->unmap_ms,
            (unsigned long long)d->pending_host_syncs, (unsigned long long)d->fence_records,
            (unsigned long long)d->fence_same_stream, (unsigned long long)d->fence_stream_waits,
            (unsigned long long)d->fence_host_syncs, d->fences.size(),
            (unsigned long long)d->reuse_hits, (unsigned long long)d->map_misses,
            (unsigned long long)d->steals, (unsigned long long)d->stolen_chunks,
            (unsigned long long)(d->mapped_free.size() * d->chunk), d->init_ms,
            (unsigned long long)d->free_before, (unsigned long long)d->free_after_stack,
            (unsigned long long)d->stack_after, now_ms());
  }
}

}  // namespace stwo::cuda::runtime::arena
