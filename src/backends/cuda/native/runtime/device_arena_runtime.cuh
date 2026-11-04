#pragma once
// M4 arena stream: process-wide static device arena + pinned host staging.
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
#include <cuda_runtime_api.h>

#include "device_arena.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atomic>
#include <chrono>
#include <mutex>
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

struct Fence {
  uint64_t offset, bytes;
  cudaEvent_t event;
  cudaStream_t stream;
};

struct Device {
  std::mutex mutex;
  int ordinal = -1;
  char *base = nullptr;
  OffsetArena *arena = nullptr;
  cudaError_t init_status = cudaSuccess;
  std::vector<Fence> fences;
  std::vector<cudaEvent_t> spare;
  uint64_t free_before = 0, free_after_stack = 0, total = 0, stack_before = 0, stack_after = 0;
  double init_ms = 0, created_at_ms = 0;
  uint64_t fence_records = 0, fence_same_stream = 0, fence_complete = 0;
  uint64_t fence_stream_waits = 0, fence_host_syncs = 0;
  uint64_t hw_printed = 0;
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
  size_t free_bytes = 0, total_bytes = 0;
  cudaError_t s = cudaMemGetInfo(&free_bytes, &total_bytes);
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
  uint64_t capacity = c.bytes;
  if (s == cudaSuccess && capacity == 0) {
    capacity = free_bytes > c.reserve ? free_bytes - c.reserve : 0;
    capacity &= ~((uint64_t(2) << 20) - 1);
  }
  if (s == cudaSuccess && (capacity == 0 || capacity > free_bytes)) s = cudaErrorMemoryAllocation;
  if (s == cudaSuccess) s = cudaMalloc(reinterpret_cast<void **>(&d->base), capacity);
  if (s == cudaSuccess) d->arena = new OffsetArena(capacity);
  d->init_ms = now_ms() - t0;
  d->init_status = s;
  fprintf(stderr,
          "GPU_ARENA_INIT device=%d status=%d capacity_bytes=%llu reserve_bytes=%llu "
          "free_before_bytes=%llu free_after_stack_bytes=%llu total_bytes=%llu "
          "stack_before=%llu stack_after=%llu init_ms=%.3f t_ms=%.1f\n",
          ordinal, int(s), (unsigned long long)capacity, (unsigned long long)c.reserve,
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

// Drop completed fences; caller holds d->mutex.
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

inline cudaError_t allocate(int ordinal, cudaStream_t stream, uint32_t lane_count,
                            size_t bytes, bool long_lived, void **out) {
  *out = nullptr;
  if (!config().valid) return cudaErrorInvalidValue;
  cudaError_t s = cudaSuccess;
  Device *d = device(ordinal, &s);
  if (!d) return s;
  std::lock_guard<std::mutex> guard(d->mutex);
  s = purge(d);
  if (s != cudaSuccess) return s;
  uint64_t offset = 0, aligned = 0;
  if (!d->arena->allocate(bytes, long_lived, &offset, &aligned)) {
    const Stats &st = d->arena->stats();
    fprintf(stderr,
            "GPU_ARENA_OVERRUN device=%d requested_bytes=%llu long=%d used_bytes=%llu "
            "capacity_bytes=%llu largest_free_bytes=%llu free_extents=%zu live=%zu t_ms=%.1f\n",
            ordinal, (unsigned long long)bytes, int(long_lived), (unsigned long long)st.used,
            (unsigned long long)st.capacity, (unsigned long long)d->arena->largest_free(),
            d->arena->free_extents(), d->arena->live_count(), now_ms());
    return cudaErrorMemoryAllocation;
  }
  for (const Fence &f : d->fences) {
    if (!overlaps(f, offset, aligned)) continue;
    if (f.stream == stream && lane_count == 1) {
      ++d->fence_same_stream;
      continue;
    }
    const cudaError_t q = cudaEventQuery(f.event);
    if (q == cudaSuccess) continue;
    if (q != cudaErrorNotReady) s = q;
    else if (lane_count == 1) {
      s = cudaStreamWaitEvent(stream, f.event, 0);
      ++d->fence_stream_waits;
    } else {
      s = cudaEventSynchronize(f.event);
      ++d->fence_host_syncs;
    }
    if (s != cudaSuccess) {
      d->arena->release(offset);
      return s;
    }
  }
  const Stats &st = d->arena->stats();
  if (st.high_water >= d->hw_printed + (uint64_t(1) << 30)) {
    d->hw_printed = st.high_water;
    fprintf(stderr, "GPU_ARENA_HW device=%d high_water_bytes=%llu long_bytes=%llu t_ms=%.1f\n",
            ordinal, (unsigned long long)st.high_water,
            (unsigned long long)st.used_class[2], now_ms());
  }
  *out = d->base + offset;
  return cudaSuccess;
}

// `joined`: every lane of the freeing context has completed (multi-lane
// contexts join before free), so no fence is needed.
inline cudaError_t release(int ordinal, cudaStream_t stream, void *pointer, bool joined) {
  cudaError_t s = cudaSuccess;
  Device *d = device(ordinal, &s);
  if (!d) return s;
  std::lock_guard<std::mutex> guard(d->mutex);
  const uintptr_t p = reinterpret_cast<uintptr_t>(pointer);
  const uintptr_t b = reinterpret_cast<uintptr_t>(d->base);
  if (p < b || p >= b + d->arena->capacity()) return cudaErrorInvalidDevicePointer;
  const uint64_t offset = p - b;
  uint64_t bytes = 0;
  if (!d->arena->live_bytes(offset, &bytes)) return cudaErrorInvalidDevicePointer;
  if (!joined) {
    cudaEvent_t event = nullptr;
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
    d->fences.push_back({offset, bytes, event, stream});
    ++d->fence_records;
  }
  d->arena->release(offset);
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
  return p >= b && p < b + d->arena->capacity();
}

// used[0]/reserved[0]: scratch (small+large); used[1]/reserved[1]: long.
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
  const Stats &st = d->arena->stats();
  used[1] = size_t(st.used_class[2]);
  used[0] = size_t(st.used - st.used_class[2]);
  reserved[1] = used[1];
  reserved[0] = size_t(st.capacity - used[1]);
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
    Device *d = registry()[i];
    if (!d || !d->arena) continue;
    const Stats &st = d->arena->stats();
    fprintf(stderr,
            "GPU_ARENA_SUMMARY device=%d capacity_bytes=%llu high_water_bytes=%llu "
            "high_water_small_bytes=%llu high_water_large_bytes=%llu high_water_long_bytes=%llu "
            "low_extent_bytes=%llu high_extent_bytes=%llu allocations=%llu releases=%llu "
            "overruns=%llu largest_overrun_bytes=%llu largest_free_at_overrun_bytes=%llu "
            "used_at_overrun_bytes=%llu fence_records=%llu fence_same_stream=%llu "
            "fence_stream_waits=%llu fence_host_syncs=%llu init_ms=%.3f "
            "free_before_bytes=%llu free_after_stack_bytes=%llu stack_after=%llu\n",
            i, (unsigned long long)st.capacity, (unsigned long long)st.high_water,
            (unsigned long long)st.high_water_class[0], (unsigned long long)st.high_water_class[1],
            (unsigned long long)st.high_water_class[2], (unsigned long long)st.low_extent,
            (unsigned long long)st.high_extent, (unsigned long long)st.allocations,
            (unsigned long long)st.releases, (unsigned long long)st.failures,
            (unsigned long long)st.largest_failure, (unsigned long long)st.largest_free_at_failure,
            (unsigned long long)st.used_at_failure, (unsigned long long)d->fence_records,
            (unsigned long long)d->fence_same_stream, (unsigned long long)d->fence_stream_waits,
            (unsigned long long)d->fence_host_syncs, d->init_ms,
            (unsigned long long)d->free_before, (unsigned long long)d->free_after_stack,
            (unsigned long long)d->stack_after);
  }
}

}  // namespace stwo::cuda::runtime::arena
