// In-process service over the SAME PCS pipeline used by the debug CLI.
#include "pcs_native.h"
#include "pcs_pipeline.cuh"
#include "pcs_idle_cache.h"
#include "pcs_oom_diagnostics.h"
#include <cstdlib>
#include "om31.cuh"
#include "runtime/context_options.h"
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>

extern "C" int stwo_exec_context_create_options(const StwoCudaContextOptions *,
                                                void **);
extern "C" int stwo_exec_context_destroy(void *);
extern "C" int stwo_exec_context_pool_current(void *, size_t *, size_t *);
extern "C" int stwo_exec_context_seal_read_only(void *, const void *, size_t);
extern "C" int stwo_exec_context_alloc_u32(void *, size_t, uint32_t **);
extern "C" int stwo_exec_context_alloc_u32_long(void *, size_t, uint32_t **);
extern "C" int stwo_exec_context_free_u32(void *, uint32_t *);
extern "C" int stwo_exec_context_memcpy_h2d_async(void *, void *, const void *,
                                                  size_t);
extern "C" int stwo_exec_context_memcpy_d2d_async(void *, void *, const void *,
                                                  size_t);

namespace {
using rv64_pcs_pipeline::Words;
namespace q = stwo::cuda::rv64::q;
std::atomic<uint64_t> next_token{1}, next_generation{1};
using Scope = std::array<uint32_t, 8>;
bool nonzero(const Scope &s) {
  for (auto v : s)
    if (v)
      return true;
  return false;
}
Scope scope_of(const uint32_t *p) {
  if (!p)
    throw std::runtime_error("missing lease scope");
  Scope result{};
  std::copy(p, p + 8, result.begin());
  return result;
}
struct Point {
  uint32_t x, y;
};
__device__ Point add(Point a, Point b) {
  return {q::sub(q::mul(a.x, b.x), q::mul(a.y, b.y)),
          q::add(q::mul(a.x, b.y), q::mul(a.y, b.x))};
}
__global__ void make_domain(uint32_t *out, uint32_t log, Point initial,
                            Point step) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  if (row >= (1u << log))
    return;
  const uint32_t index = __brev(row) >> (32 - log);
  const bool conjugate = index >= (1u << (log - 1));
  uint32_t exponent = index & ((1u << (log - 1)) - 1);
  Point value = initial;
  while (exponent) {
    if (exponent & 1)
      value = add(value, step);
    step = add(step, step);
    exponent >>= 1;
  }
  out[uint64_t(row) * 2] = value.x;
  out[uint64_t(row) * 2 + 1] = conjugate ? q::sub(0, value.y) : value.y;
}
struct ResidentOwner {
  void *ctx = nullptr;
  uint64_t token = 0, cap = 0, retained = 0, allocated_bytes = 0;
  struct Block {
    uint32_t *ptr;
    uint64_t words;
    bool used;
    uint64_t active_words;
    bool retirable;
  };
  struct Leased {
    StwoRv64GpuLease value;
    Scope scope;
    std::vector<Scope> immutable_scopes;
    bool sealed = false;
  };
  struct Domain {
    uint32_t log;
    Scope seed;
    StwoRv64Plane plane;
  };
  rv64_pcs_idle_cache::Limit idle_cache;
  std::vector<Block> blocks;
  std::vector<Leased> leases;
  std::vector<Domain> domains;
  std::vector<cudaEvent_t> events;
  std::vector<std::vector<uint32_t>> ingress;
  explicit ResidentOwner(uint32_t device, uint64_t byte_cap) : cap(byte_cap) {
    if (!cap)
      throw std::runtime_error("missing device byte admission");
    // Strict parse is before CUDA context/pool creation. Unset preserves the
    // established upper-cache policy and all default logs. Zero means no idle
    // upper-cache blocks; it does not disable or trim the runtime async pool.
    idle_cache = rv64_pcs_idle_cache::parse(
        std::getenv("STWO_RV64_PCS_IDLE_CACHE_BYTES"), cap);
    token = next_token.fetch_add(1);
    if (!token)
      throw std::runtime_error("context token exhausted");
    StwoCudaContextOptions options{1, device, 2, 32};
    const int status = stwo_exec_context_create_options(&options, &ctx);
    if (status) {
      if (ctx)
        (void)stwo_exec_context_destroy(ctx);
      ctx = nullptr;
      CHECK(status);
    }
  }
  void sync() { CHECK(stwo_exec_context_sync(ctx)); }
  void trimIdleCache() {
    if (!idle_cache.enabled) return;
    const auto result = rv64_pcs_idle_cache::trim(
        idle_cache, blocks, retained, [&](uint32_t *ptr) {
          CHECK(stwo_exec_context_free_u32(ctx, ptr));
        });
    if (result.released)
      std::printf("GPU_PCS_IDLE_CACHE cap_bytes=%llu before_bytes=%llu after_bytes=%llu released_blocks=%zu\n",
          static_cast<unsigned long long>(idle_cache.bytes),
          static_cast<unsigned long long>(result.before),
          static_cast<unsigned long long>(result.after), result.released);
  }

  void ensure(uint64_t bytes) {
    if (bytes > cap)
      throw std::runtime_error("device allocation exceeds admitted capacity");
    for (size_t i = 0; retained > cap - bytes && i < blocks.size();) {
      if (blocks[i].used) {
        ++i;
        continue;
      }
      CHECK(stwo_exec_context_free_u32(ctx, blocks[i].ptr));
      retained -= blocks[i].words * 4;
      blocks.erase(blocks.begin() + i);
    }
    if (retained > cap - bytes) {
      // Capture the live admission point before exception cleanup releases the
      // temporary planes. No query or synchronization is added on success.
      std::fprintf(stderr,
          "GPU_OWNER_LOGICAL_CAP requested_bytes=%llu retained_bytes=%llu cap_bytes=%llu token=%llu\n",
          static_cast<unsigned long long>(bytes),
          static_cast<unsigned long long>(retained),
          static_cast<unsigned long long>(cap),
          static_cast<unsigned long long>(token));
      throw std::runtime_error("live device leases exceed admitted capacity");
    }
  }
  // Failure-only queries: neither query changes the allocation error or custody.
  void logAllocationFailure(uint64_t words, const char *phase) noexcept {
    uint64_t idle = 0, active = 0, leased = 0;
    for (const auto &block : blocks)
      (block.used ? active : idle) += block.words * 4;
    for (const auto &lease : leases)
      leased += lease.value.count * 4;
    const auto pool = rv64_pcs_oom_diagnostics::poolSnapshot(
        [&](size_t *used, size_t *reserved) {
          return stwo_exec_context_pool_current(ctx, used, reserved);
        });
    int device_index = -1;
    const auto device_status = cudaGetDevice(&device_index);
    const auto default_pool = device_status == cudaSuccess
      ? rv64_pcs_oom_diagnostics::defaultPoolSnapshot<cudaMemPool_t>(
          [&](cudaMemPool_t *handle) {
            return int(cudaDeviceGetDefaultMemPool(handle, device_index));
          },
          [&](cudaMemPool_t handle, size_t *used, size_t *reserved) {
            const auto rc = cudaMemPoolGetAttribute(handle, cudaMemPoolAttrUsedMemCurrent, used);
            if (rc != cudaSuccess) return int(rc);
            return int(cudaMemPoolGetAttribute(handle, cudaMemPoolAttrReservedMemCurrent, reserved));
          })
      : rv64_pcs_oom_diagnostics::PoolSnapshot{0, 0, int(device_status)};
    size_t free_bytes = 0, total_bytes = 0;
    const auto memory_status = cudaMemGetInfo(&free_bytes, &total_bytes);
    std::fprintf(stderr,
      "GPU_OWNER_OOM requested_bytes=%llu retained_bytes=%llu "
      "lease_bytes=%llu idle_cache_bytes=%llu active_cache_bytes=%llu "
      "physical_free_bytes=%zu physical_total_bytes=%zu memory_rc=%d "
        "pool_used_bytes=%zu pool_reserved_bytes=%zu pool_rc=%d "
        "phase=%s context_token=%llu device_index=%d device_rc=%d "
        "default_pool_used_bytes=%zu default_pool_reserved_bytes=%zu default_pool_rc=%d\n",
      static_cast<unsigned long long>(words * 4),
      static_cast<unsigned long long>(retained),
      static_cast<unsigned long long>(leased),
      static_cast<unsigned long long>(idle),
      static_cast<unsigned long long>(active), free_bytes, total_bytes,
      int(memory_status), pool.used, pool.reserved, pool.status, phase,
        static_cast<unsigned long long>(token), device_index, int(device_status),
        default_pool.used, default_pool.reserved, default_pool.status);
    // A failed diagnostic query must not leave a stale host API error behind
    // when the caller tries its original, independently checked allocation retry.
    (void)cudaGetLastError();
  }
  // long_lived: immutable setup leases and cached domains, which outlive the
  // request; everything else is per-request scratch. Logical admission and
  // custody are unchanged; only the backing pool is segregated by lifetime.
  uint32_t *allocate(uint64_t words, bool long_lived = false) {
    if (!words || words > SIZE_MAX / 4)
      throw std::runtime_error("invalid device allocation");
    ensure(words * 4);
    uint32_t *ptr = nullptr;
    auto alloc = long_lived ? stwo_exec_context_alloc_u32_long : stwo_exec_context_alloc_u32;
    int status = alloc(ctx, words, &ptr);
    if (status == int(cudaErrorMemoryAllocation)) {
      (void)cudaGetLastError();
      logAllocationFailure(words, "initial");
      // Logical admission can succeed while idle PCS cache allocations still
      // occupy physical pages. They are not live witnesses: release only the
      // unused blocks, then let the context's bounded pool recovery retry.
      sync();
      for (size_t i = 0; i < blocks.size();) {
        if (blocks[i].used) { ++i; continue; }
        CHECK(stwo_exec_context_free_u32(ctx, blocks[i].ptr));
        retained -= blocks[i].words * 4;
        blocks.erase(blocks.begin() + i);
      }
      sync();
      status = alloc(ctx, words, &ptr);
      if (status == int(cudaErrorMemoryAllocation))
        logAllocationFailure(words, "after_idle_eviction_retry");
    }
    CHECK(status);
    retained += words * 4;
    return ptr;
  }
  StwoRv64Plane plane(uint64_t count, uint32_t coordinates) {
    if (!coordinates || count > SIZE_MAX / 4 / coordinates)
      throw std::runtime_error("plane overflow");
    const uint64_t words = count * coordinates;
    size_t selected = blocks.size();
    for (size_t i = 0; i < blocks.size(); ++i)
      if (!blocks[i].used && blocks[i].words >= words &&
          (selected == blocks.size() ||
           blocks[i].words < blocks[selected].words))
        selected = i;
    uint32_t *ptr;
    if (selected < blocks.size()) {
      blocks[selected].used = true;
      blocks[selected].active_words = words;
      blocks[selected].retirable = true;
      ptr = blocks[selected].ptr;
    } else {
      ptr = allocate(words);
      blocks.push_back({ptr, words, true, words, true});
    }
    allocated_bytes += words * 4;
    return {ptr, count, coordinates, 0};
  }
  StwoRv64Plane sourcePlane(uint64_t count,uint32_t coordinates) {
    const auto p=plane(count,coordinates);
    for(auto &block:blocks) if(block.ptr==p.words) { block.retirable=false;return p; }
    throw std::runtime_error("source reservation missing");
  }
  // Validate the entire phase transition before joining or changing custody.
  // Only whole active temporary reservations qualify, never leases/domains.
  void retirePlanes(const std::vector<StwoRv64Plane> &planes) {
    std::vector<size_t> selected;
    selected.reserve(planes.size());
    for (const auto &plane : planes) {
      if (!plane.words || !plane.coordinates || plane.reserved ||
          plane.stride > UINT64_MAX / plane.coordinates)
        throw std::runtime_error("invalid temporary retirement");
      const uint64_t words=plane.stride*plane.coordinates;
      size_t i=0;
      for (;i<blocks.size()&&blocks[i].ptr!=plane.words;++i) {}
      if (i==blocks.size() || !blocks[i].used || !blocks[i].retirable || blocks[i].active_words!=words ||
          std::find(selected.begin(),selected.end(),i)!=selected.end())
        throw std::runtime_error("foreign, stale, duplicate or partial temporary retirement");
      selected.push_back(i);
    }
    sync(); // Join both lanes once before any temporary can be reused.
    uint64_t words=0;
    for (auto i:selected) { words+=blocks[i].active_words;blocks[i].used=false;blocks[i].active_words=0; }
    std::printf("GPU_PCS_PHASE_RETIRE planes=%zu logical_words=%llu\n",selected.size(),static_cast<unsigned long long>(words));
    trimIdleCache();
  }
  void retirePlane(StwoRv64Plane plane) { retirePlanes({plane}); }
  void reset() {
    sync();
    ingress.clear();
    for (auto event : events)
      CHECK(cudaEventDestroy(event));
    events.clear();
    for (auto &block : blocks) {
      block.used = false;
      block.active_words = 0;
    }
    allocated_bytes = 0;
    trimIdleCache();
  }
  cudaEvent_t event() {
    cudaEvent_t e;
    CHECK(cudaEventCreate(&e));
    events.push_back(e);
    return e;
  }
  void upload(StwoRv64Plane destination, const std::vector<uint32_t> &values) {
    ingress.push_back(values);
    uploadBorrowed(destination, ingress.back().data(), values.size());
  }
  void uploadBorrowed(StwoRv64Plane destination, const uint32_t *data,
                      size_t words) {
    if (words > destination.stride * destination.coordinates ||
        (words && !data))
      throw std::runtime_error("ingress capacity");
    if (words)
      CHECK(stwo_exec_context_memcpy_h2d_async(ctx, destination.words, data,
                                               words * 4));
  }
  const Leased &find(const uint32_t *ptr, uint64_t words, uint64_t context,
                     uint64_t generation, const Scope &scope) const {
    if (context != token || !ptr || !words || words > SIZE_MAX / 4)
      throw std::runtime_error("invalid device lease range");
    const uintptr_t begin = reinterpret_cast<uintptr_t>(ptr);
    if (words > (UINTPTR_MAX - begin) / 4)
      throw std::runtime_error("device lease overflow");
    for (const auto &record : leases) {
      const uintptr_t base = reinterpret_cast<uintptr_t>(record.value.words);
      if (record.value.generation == generation &&
          (record.scope == scope || (record.value.kind == 4 &&
            std::find(record.immutable_scopes.begin(), record.immutable_scopes.end(), scope) != record.immutable_scopes.end())) &&
          begin >= base && begin + words * 4 <= base + record.value.count * 4)
        return record;
    }
    throw std::runtime_error("stale, foreign or wrong-scope device lease");
  }
  uint32_t validateCoefficient(rv64_pcs_pipeline::Coefficient source,
                               const uint32_t *scope) const {
    if (!source.kind) {
      if(source.size() && !source.data())throw std::runtime_error("missing host coefficients");
      return 0;
    }
    if(source.kind!=1)throw std::runtime_error("unsupported device column encoding");
    const auto &record=find(source.data(),source.size(),source.token,
                            source.generation,scope_of(scope));
    if(record.value.kind!=2 && record.value.kind!=4)
      throw std::runtime_error("device column is not coefficient storage");
    return record.value.kind;
  }
  void uploadCoefficient(StwoRv64Plane destination,
                         rv64_pcs_pipeline::Coefficient source,
                         const uint32_t *scope) {
    if (!source.kind) {
      uploadBorrowed(destination, source.data(), source.size());
      return;
    }
    // This also validates the whole coalesced range, not only its endpoints.
    (void)validateCoefficient(source,scope);
    CHECK(stwo_exec_context_memcpy_d2d_async(ctx, destination.words,
                                             source.data(), source.size() * 4));
  }
  StwoRv64Plane domain(uint32_t log, Words legacy, Words parameters) {
    if (legacy.size()) {
      auto p = sourcePlane(legacy.size(), 1);
      uploadBorrowed(p, legacy.data(), legacy.size());
      return p;
    }
    rv64_pcs_pipeline::sizeIs(parameters, 4);
    for (auto word : parameters)
      if (word >= 0x7fffffffu)
        throw std::runtime_error("noncanonical domain setup");
    Scope key{};
    std::copy(parameters.begin(), parameters.end(), key.begin());
    for (const auto &domain : domains)
      if (domain.log == log && domain.seed == key) {
        allocated_bytes += domain.plane.stride * 4;
        return domain.plane;
      }
    const uint64_t words = uint64_t(2) << log;
    auto *ptr = allocate(words, true);
    StwoRv64Plane result{ptr, words, 1, 0};
    void *raw = nullptr;
    CHECK(stwo_exec_context_lane_stream(ctx, 0, &raw));
    make_domain<<<((1u << log) + 127) / 128, 128, 0,
                  reinterpret_cast<cudaStream_t>(raw)>>>(
        ptr, log, {parameters[0], parameters[1]},
        {parameters[2], parameters[3]});
    CHECK(cudaPeekAtLastError());
    domains.push_back({log, key, result});
    allocated_bytes += words * 4;
    return result;
  }
  StwoRv64GpuLease lease(uint64_t words, uint32_t kind, const Scope &scope) {
    if (kind > 4 || (kind && !nonzero(scope)))
      throw std::runtime_error("invalid device lease namespace");
    auto *ptr = allocate(words, kind == 4);
    const uint64_t generation = next_generation.fetch_add(1);
    if (!generation)
      throw std::runtime_error("device lease generation exhausted");
    StwoRv64GpuLease value{token, generation, ptr, words, kind, 0};
    leases.push_back({value, scope, {}});
    return value;
  }
  void release(StwoRv64GpuLease &lease) {
    for (size_t i = 0; i < leases.size(); ++i) {
      const auto &value = leases[i].value;
      if (value.context_token == lease.context_token &&
          value.generation == lease.generation && value.words == lease.words &&
          value.count == lease.count && value.kind == lease.kind &&
          !lease.reserved) {
        if (value.kind == 4 && !leases[i].immutable_scopes.empty())
          throw std::runtime_error("immutable setup still borrowed by a request");
        // The context free joins every producer lane before retiring memory.
        // Joining here too doubled the per-lease global barriers; validate the
        // complete descriptor first, then use that one authoritative join.
        CHECK(stwo_exec_context_free_u32(ctx, value.words));
        retained -= value.count * 4;
        leases.erase(leases.begin() + i);
        lease = {};
        return;
      }
    }
    throw std::runtime_error("invalid or retired device lease");
  }
  ~ResidentOwner() {
    if (!ctx)
      return;
    // Borrowed host buffers cannot be released after an unconfirmed join.
    if (stwo_exec_context_sync(ctx))
      std::abort();
    for (auto &block : blocks)
      (void)stwo_exec_context_free_u32(ctx, block.ptr);
    for (auto &lease : leases)
      (void)stwo_exec_context_free_u32(ctx, lease.value.words);
    for (auto &domain : domains)
      (void)stwo_exec_context_free_u32(ctx, domain.plane.words);
    for (auto event : events)
      (void)cudaEventDestroy(event);
    (void)stwo_exec_context_destroy(ctx);
  }
};
struct Service {
  enum class Job { none, prove, callback, quit };
  uint32_t device;
  uint64_t cap;
  std::thread thread;
  std::mutex calls;
  std::mutex mutex;
  std::condition_variable changed;
  bool ready = false, done = false, poisoned = false;
  Job job = Job::none;
  int status = 0;
  std::string error;
  const StwoRv64PcsNativeRequest *request = nullptr;
  StwoRv64PcsNativeResult *result = nullptr;
  StwoRv64GpuCallback callback = nullptr;
  void *user = nullptr;
  ResidentOwner *owner = nullptr;
  Service(uint32_t device, uint64_t cap) : device(device), cap(cap) {
    thread = std::thread([this] { loop(); });
    std::unique_lock<std::mutex> lock(mutex);
    changed.wait(lock, [this] { return ready; });
  }
  void loop() {
    std::unique_ptr<ResidentOwner> storage;
    try {
      storage = std::make_unique<ResidentOwner>(device, cap);
      owner = storage.get();
    } catch (const std::exception &e) {
      error = e.what();
      status = int(cudaErrorUnknown);
      poisoned = true;
    }
    {
      std::lock_guard<std::mutex> lock(mutex);
      ready = true;
      changed.notify_all();
    }
    while (true) {
      {
        std::unique_lock<std::mutex> lock(mutex);
        changed.wait(lock, [this] { return job != Job::none; });
      }
      if (job == Job::quit)
        break;
      status = 0;
      try {
        if (poisoned || !owner)
          throw std::runtime_error("GPU session is poisoned");
        if (job == Job::callback) {
          const int code = callback(owner->ctx, owner->token, user);
          owner->sync();
          if (code)
            throw std::runtime_error("GPU callback failed: " +
                                     std::to_string(code));
        } else {
          if (!request || request->version != 1 || request->section_count != 17)
            throw std::runtime_error("native PCS ABI mismatch");
          rv64_pcs_pipeline::Input input;
          for (size_t i = 0; i < 17; ++i) {
            const auto s = request->sections[i];
            if (s.count > SIZE_MAX || (s.count && !s.words))
              throw std::runtime_error("invalid native metadata span");
            input.sections[i] = {s.words, size_t(s.count)};
          }
          if (request->coefficient_count > 65536 || !request->coefficients)
            throw std::runtime_error("native coefficient count");
          std::copy(request->scope, request->scope + 8, input.scope.begin());
          for (uint64_t i = 0; i < request->coefficient_count; ++i) {
            const auto c = request->coefficients[i];
            if (c.coefficient_log > 28 ||
                c.count != (uint64_t(1) << c.coefficient_log) || !c.words ||
                c.kind > 1)
              throw std::runtime_error("native coefficient shape");
            input.coefficients.push_back({{c.words, size_t(c.count)},
                                          c.kind,
                                          c.context_token,
                                          c.generation});
          }
          owner->reset();
          auto proof = rv64_pcs_pipeline::run(*owner, input);
          auto *words = new std::vector<uint32_t>(std::move(proof.words));
          *result = {words->data(),         words->size(),   proof.device_ns,
                     proof.requested_bytes, owner->retained, words};
          owner->reset();
        }
      } catch (const std::exception &e) {
        error = e.what();
        status = int(cudaErrorUnknown);
        poisoned = true;
        if (job == Job::prove && result && result->owner) {
          delete static_cast<std::vector<uint32_t> *>(result->owner);
          *result = {};
        }
        if (owner && stwo_exec_context_sync(owner->ctx))
          std::abort();
      }
      {
        std::lock_guard<std::mutex> lock(mutex);
        job = Job::none;
        done = true;
        changed.notify_all();
      }
    }
  }
  int invoke(Job kind) {
    done = false;
    job = kind;
    changed.notify_all();
    return 0;
  }
  ~Service() {
    {
      std::lock_guard<std::mutex> lock(mutex);
      job = Job::quit;
      changed.notify_all();
    }
    if (thread.joinable())
      thread.join();
  }
  bool isOwner() const {
    return std::this_thread::get_id() == thread.get_id() && owner;
  }
};
} // namespace
extern "C" int stwo_rv64_pcs_native_create(uint32_t device, uint64_t cap,
                                           void **out) {
  if (!out)
    return int(cudaErrorInvalidValue);
  *out = nullptr;
  try {
    auto s = std::make_unique<Service>(device, cap);
    if (s->status)
      return s->status;
    *out = s.release();
    return 0;
  } catch (...) {
    return int(cudaErrorUnknown);
  }
}
extern "C" int
stwo_rv64_pcs_native_prove(void *raw, const StwoRv64PcsNativeRequest *request,
                           StwoRv64PcsNativeResult *result) {
  if (!raw || !request || !result)
    return int(cudaErrorInvalidValue);
  *result = {};
  auto &s = *static_cast<Service *>(raw);
  if (s.isOwner())
    return int(cudaErrorInvalidResourceHandle);
  std::lock_guard<std::mutex> caller(s.calls);
  std::unique_lock<std::mutex> lock(s.mutex);
  s.changed.wait(lock, [&] { return s.job == Service::Job::none; });
  s.request = request;
  s.result = result;
  s.invoke(Service::Job::prove);
  s.changed.wait(lock, [&] { return s.done; });
  return s.status;
}
extern "C" void stwo_rv64_pcs_native_release(StwoRv64PcsNativeResult *result) {
  if (!result)
    return;
  delete static_cast<std::vector<uint32_t> *>(result->owner);
  *result = {};
}
extern "C" int stwo_rv64_pcs_native_destroy(void *raw) {
  delete static_cast<Service *>(raw);
  return 0;
}
extern "C" const char *stwo_rv64_pcs_native_error(void *raw) {
  return raw ? static_cast<Service *>(raw)->error.c_str()
             : "missing GPU session";
}
extern "C" int stwo_rv64_gpu_session_submit(void *raw,
                                            StwoRv64GpuCallback callback,
                                            void *user) {
  if (!raw || !callback)
    return int(cudaErrorInvalidValue);
  auto &s = *static_cast<Service *>(raw);
  if (s.isOwner())
    return int(cudaErrorInvalidResourceHandle);
  std::lock_guard<std::mutex> caller(s.calls);
  std::unique_lock<std::mutex> lock(s.mutex);
  s.changed.wait(lock, [&] { return s.job == Service::Job::none; });
  s.callback = callback;
  s.user = user;
  s.invoke(Service::Job::callback);
  s.changed.wait(lock, [&] { return s.done; });
  return s.status;
}
extern "C" int stwo_rv64_gpu_lease_allocate(void *raw, uint64_t words,
                                            uint32_t kind,
                                            const uint32_t scope[8],
                                            StwoRv64GpuLease *out) {
  if (!raw || !out)
    return int(cudaErrorInvalidValue);
  auto &s = *static_cast<Service *>(raw);
  if (!s.isOwner())
    return int(cudaErrorInvalidResourceHandle);
  try {
    *out = s.owner->lease(words, kind, scope_of(scope));
    return 0;
  } catch (const std::exception &e) {
    s.error = e.what();
    return int(cudaErrorInvalidValue);
  }
}
extern "C" int stwo_rv64_gpu_lease_validate_range(
    void *raw, const uint32_t *ptr, uint64_t words, uint64_t token,
    uint64_t generation, const uint32_t scope[8]) {
  if (!raw)
    return int(cudaErrorInvalidValue);
  auto &s = *static_cast<Service *>(raw);
  if (!s.isOwner())
    return int(cudaErrorInvalidResourceHandle);
  try {
    (void)s.owner->find(ptr, words, token, generation, scope_of(scope));
    return 0;
  } catch (const std::exception &e) {
    s.error = e.what();
    return int(cudaErrorInvalidValue);
  }
}
extern "C" int stwo_rv64_gpu_lease_validate(void *raw,
                                            const StwoRv64GpuLease *lease,
                                            const uint32_t scope[8]) {
  if (!raw || !lease || lease->reserved)
    return int(cudaErrorInvalidValue);
  auto &s = *static_cast<Service *>(raw);
  if (!s.isOwner())
    return int(cudaErrorInvalidResourceHandle);
  try {
    const auto &record = s.owner->find(lease->words, lease->count,
                                      lease->context_token, lease->generation,
                                      scope_of(scope));
    if (record.value.words != lease->words ||
        record.value.count != lease->count || record.value.kind != lease->kind)
      throw std::runtime_error("altered device lease descriptor");
    return 0;
  } catch (const std::exception &e) {
    s.error = e.what();
    return int(cudaErrorInvalidValue);
  }
}
extern "C" int stwo_rv64_gpu_lease_rebind(
    void *raw, const StwoRv64GpuLease *lease, const uint32_t from[8],
    const uint32_t to[8]) {
  if (!raw || !lease || lease->reserved || !from || !to)
    return int(cudaErrorInvalidValue);
  auto &s = *static_cast<Service *>(raw);
  if (!s.isOwner()) return int(cudaErrorInvalidResourceHandle);
  try {
    if (lease->kind == 4) throw std::runtime_error("immutable setup cannot change namespace");
    const Scope target = scope_of(to);
    if (!nonzero(target)) throw std::runtime_error("empty promoted lease scope");
    const auto &record = s.owner->find(lease->words, lease->count,
        lease->context_token, lease->generation, scope_of(from));
    if (record.value.words != lease->words || record.value.count != lease->count ||
        record.value.kind != lease->kind)
      throw std::runtime_error("altered promoted lease descriptor");
    // There is no allocation or mutation until the complete old descriptor
    // and both namespaces have been admitted. All registry access is confined
    // to this service's owner thread.
    for (auto &entry : s.owner->leases) {
      if (entry.value.generation == lease->generation) {
        entry.scope = target;
        return 0;
      }
    }
    throw std::runtime_error("retired promoted lease");
  } catch (const std::exception &e) {
    s.error = e.what();
    return int(cudaErrorInvalidValue);
  }
}
extern "C" int stwo_rv64_gpu_lease_release(void *raw, StwoRv64GpuLease *lease) {
  if (!raw || !lease)
    return int(cudaErrorInvalidValue);
  auto &s = *static_cast<Service *>(raw);
  if (!s.isOwner())
    return int(cudaErrorInvalidResourceHandle);
  try {
    s.owner->release(*lease);
    return 0;
  } catch (const std::exception &e) {
    s.error = e.what();
    return int(cudaErrorInvalidValue);
  }
}

// Immutable leases retain their setup namespace; request aliases are read-only
// custody permissions and never transfer ownership of the underlying allocation.
extern "C" int stwo_rv64_gpu_immutable_bind(void *raw, const StwoRv64GpuLease *lease,
 const uint32_t setup[8], const uint32_t request_scope[8]) {
 if (!raw || !lease || !setup || !request_scope) return int(cudaErrorInvalidValue);
 auto &s = *static_cast<Service *>(raw);
 if (!s.isOwner()) return int(cudaErrorInvalidResourceHandle);
 try {
  const Scope key=scope_of(setup), scope=scope_of(request_scope);
  if (!nonzero(scope) || lease->kind != 4 || lease->reserved) throw std::runtime_error("invalid immutable lease alias");
  const auto &found=s.owner->find(lease->words,lease->count,lease->context_token,lease->generation,key);
  if(found.scope != key || found.value.words != lease->words || found.value.count != lease->count || found.value.kind !=4 || !found.sealed)
   throw std::runtime_error("immutable lease identity mismatch");
  for(auto &record:s.owner->leases) if(record.value.generation==lease->generation) {
   if(std::find(record.immutable_scopes.begin(),record.immutable_scopes.end(),scope)==record.immutable_scopes.end()) {
    if(record.immutable_scopes.size()>=256) throw std::runtime_error("immutable request alias limit");
    record.immutable_scopes.push_back(scope);
   }
   return 0;
  }
  throw std::runtime_error("stale immutable lease");
 } catch(const std::exception &e) {s.error=e.what();return int(cudaErrorInvalidValue);}
}
extern "C" int stwo_rv64_gpu_immutable_unbind_scope(void *raw,const uint32_t scope_words[8]) {
 if(!raw || !scope_words) return int(cudaErrorInvalidValue);
 auto &s=*static_cast<Service *>(raw);
 if(!s.isOwner()) return int(cudaErrorInvalidResourceHandle);
 const Scope scope=scope_of(scope_words);
 for(auto &record:s.owner->leases) {
  auto &aliases=record.immutable_scopes;
  aliases.erase(std::remove(aliases.begin(),aliases.end(),scope),aliases.end());
 }
 return 0;
}
extern "C" int stwo_rv64_gpu_session_live_leases(void *raw,uint64_t counts[5],uint64_t *bytes) {
 if(!raw || !counts || !bytes) return int(cudaErrorInvalidValue);
 auto &s=*static_cast<Service *>(raw);
 if(!s.isOwner()) return int(cudaErrorInvalidResourceHandle);
 std::fill(counts,counts+5,0);*bytes=0;
 for(const auto &record:s.owner->leases) {++counts[record.value.kind];*bytes+=record.value.count*4;}
 return 0;
}

extern "C" int stwo_rv64_gpu_immutable_seal(void *raw,const StwoRv64GpuLease *lease,const uint32_t setup[8]) {
 if(!raw || !lease || !setup || lease->reserved || lease->kind!=4) return int(cudaErrorInvalidValue);
 auto &s=*static_cast<Service *>(raw);
 if(!s.isOwner()) return int(cudaErrorInvalidResourceHandle);
 try {
  const auto key=scope_of(setup);
  const auto &found=s.owner->find(lease->words,lease->count,lease->context_token,lease->generation,key);
  if(found.scope!=key || found.value.kind!=4 || found.value.words!=lease->words || found.value.count!=lease->count || !found.immutable_scopes.empty()) throw std::runtime_error("immutable seal descriptor mismatch");
  s.owner->sync();
  CHECK(stwo_exec_context_seal_read_only(s.owner->ctx,lease->words,lease->count*4));
  for(auto &record:s.owner->leases) if(record.value.generation==lease->generation) {record.sealed=true;return 0;}
  throw std::runtime_error("stale immutable seal");
 }catch(const std::exception &e){s.error=e.what();return int(cudaErrorInvalidValue);}
}

// Metadata framing capability; no CUDA context or proof state is touched.
extern "C" uint32_t stwo_rv64_pcs_request_version() { return 3; }
