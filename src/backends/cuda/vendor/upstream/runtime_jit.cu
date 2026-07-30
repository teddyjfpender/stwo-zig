// NVRTC-based JIT runtime for generated constraint kernels.
//
// Compiles CUDA C source at runtime and launches the fused constraint kernel.
// Compiled kernels are cached by their SEMANTIC HASH (a content hash of the program
// bytecode computed on the Rust side) — never by pointers or implicit scope, per the
// repository's cache-keying rule (pointer-keyed caches silently alias across
// alloc/free cycles and corrupt later proves).
//
// Tunables (all read once):
// - STWO_JIT_NVRTC_OPTS: comma-separated NVRTC options appended to the two built-in
//   flags (--gpu-architecture, --std=c++14), e.g. "STWO_JIT_NVRTC_OPTS=-G,--dopt=off".
// - STWO_JIT_LOG: diagnostics default ON; set to "0" to silence.
// - STWO_JIT_CACHE_DIR: PTX/CUBIN cache directory (empty string disables the disk cache).
// - STWO_JIT_CUBIN_CACHE: CUBIN (SASS) disk caching, default OFF; "1" opts in
//   (fleet cache-shipping pattern — see jit_cubin_cache_enabled for the measured tradeoff)
//   (kill switch). When ON, a cold compile emits a real-arch cubin via
//   nvrtcGetCUBIN and caches it keyed like the PTX; a subsequent cold process loads it
//   with cuModuleLoadData, which skips the driver's ptxas PTX->SASS assembly (the
//   documented 56.4 s per-module cold cost on the SN-PIE lane). Any failure or arch
//   mismatch falls back to the PTX path, so correctness never depends on it. Only
//   compile/cache MECHANICS change; the kernel's integer/modular outputs are identical
//   to the PTX path (same ptxas, exact M31 arithmetic — the same reasoning the
//   optimization-level relief valve already relies on).
// - STWO_JIT_PARALLEL_COMPILE: parallel NVRTC/module-load across a component's split
//   kernels, default ON; set to "0" to disable (kill switch), or to a positive integer
//   to cap the worker count. Compiled artifacts are a deterministic function of
//   (source, arch), so the populated cache is identical regardless of compile order or
//   concurrency — byte-identical by construction.

#include <cuda.h>
#include <cuda_runtime.h>
#include <nvrtc.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <sys/stat.h>
#include <cstdlib>
#include <chrono>

#include "resource_attestation.cuh"

// pedersen_table_init.cu exports (same archive), used to fill the per-module
// witness-deduce table globals. `m31` there is a typedef for uint32_t, so the
// unsigned* ABI here is identical. MUST be declared at global scope: inside the
// anonymous namespace below, `extern "C"` declarations still get internal
// linkage and never resolve to the real symbols (measured: rust-lld undefined
// `(anonymous namespace)::is_borrowed_pedersen_table_registered()`).
extern "C" bool is_borrowed_pedersen_table_registered();
extern "C" void get_pedersen_table_column_ptrs(unsigned **output_ptrs, uint32_t *out_n_rows);

// The embedded AOT pack lookup (src/aot_pack.rs, populated by build.rs from
// kernel_emit's cuda/generated/ sources): (cache_key, sm) -> offline -O3 cubin.
// GLOBAL scope: extern "C" inside an anonymous namespace gets INTERNAL linkage
// (the round-28 lesson, standard C13) and rust-lld fails on the Rust-side def.
extern "C" bool stwo_aot_lookup(uint64_t cache_key, unsigned sm_major, unsigned sm_minor,
                                const unsigned char **out_data, size_t *out_len);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_device(void *handle, int *out_device);

namespace {

enum class KernelOrigin : uint8_t { Aot = 0, Runtime = 1 };

constexpr uint32_t kPedersenPublicationAbiVersion = 2;
constexpr uint32_t kPedersenGlobalsAbsent = 0;
constexpr uint32_t kPedersenGlobalsPresent = 1;
constexpr uint32_t kPedersenPublicationAot = 1u << 0;
constexpr uint32_t kPedersenPublicationReadbackVerified = 1u << 1;
constexpr uint32_t kPedersenPublicationEventComplete = 1u << 2;
constexpr uint32_t kPedersenPublicationRequiredFlags =
    kPedersenPublicationAot | kPedersenPublicationReadbackVerified |
    kPedersenPublicationEventComplete;

// Process-local receipt for one loaded module's two Pedersen device globals.
// Content/source/cubin identities deliberately do not live here: Rust composes
// this live-address receipt with the registered table and embedded AOT authority.
struct StwoCudaPedersenModulePublication {
    uint32_t abi_version;
    uint32_t flags;
    uint32_t device_ordinal;
    uint32_t sm_major;
    uint32_t sm_minor;
    uint32_t pointer_count;
    uint32_t columns_symbol_bytes;
    uint32_t rows_symbol_bytes;
    uint32_t n_rows;
    uint32_t globals_state;
    uint64_t cache_key;
    uint64_t module_token;
    uint64_t function_token;
    uint64_t context_token;
    uint64_t columns_symbol_token;
    uint64_t rows_symbol_token;
    uint64_t completion_event_token;
    uint64_t column_pointers[56];
};
static_assert(sizeof(void *) == 8, "Pedersen module globals require 64-bit pointers");
static_assert(sizeof(StwoCudaPedersenModulePublication) == 544,
              "Pedersen publication ABI size");
static_assert(alignof(StwoCudaPedersenModulePublication) == 8,
              "Pedersen publication ABI alignment");
static_assert(offsetof(StwoCudaPedersenModulePublication, cache_key) == 40,
              "Pedersen publication cache-key offset");
static_assert(offsetof(StwoCudaPedersenModulePublication, column_pointers) == 96,
              "Pedersen publication pointer offset");

struct CachedFunction {
    CUmodule module;
    CUfunction function;
    KernelOrigin origin;
    std::string kernel_name;
    StwoCudaPedersenModulePublication pedersen_publication;
    CUevent pedersen_publication_event;
};

struct StwoCudaJitAotStats {
    uint64_t aot_loads;
    uint64_t aot_cache_hits;
    uint64_t aot_misses;
    uint64_t runtime_loads;
    uint64_t runtime_cache_hits;
    uint64_t strict_rejections;
};

constexpr uint32_t kInstalledAotFunctionAbiVersion = 2;
constexpr uint32_t kInstalledAotBorrowedPublished = 2;
constexpr uint32_t kAotFunctionPublicationAbiVersion = 1;
constexpr uint32_t kAotFunctionPublicationAot = 1;

struct StwoCudaAotFunctionPublication {
    uint32_t abi_version;
    uint32_t flags;
    uint32_t device_ordinal;
    uint32_t sm_major;
    uint32_t sm_minor;
    uint32_t reserved;
    uint64_t cache_key;
    uint64_t context_token;
    uint64_t module_token;
    uint64_t function_token;
};
static_assert(sizeof(StwoCudaAotFunctionPublication) == 56,
              "AOT function publication ABI size");
static_assert(offsetof(StwoCudaAotFunctionPublication, cache_key) == 24,
              "AOT function publication cache-key offset");

struct StwoCudaInstalledAotFunctionReceipt {
    uint32_t abi_version;
    uint32_t ownership;
    uint32_t device_ordinal;
    uint32_t sm_major;
    uint32_t sm_minor;
    uint32_t argument_count;
    uint32_t grid_x;
    uint32_t grid_y;
    uint32_t grid_z;
    uint32_t block_x;
    uint32_t block_y;
    uint32_t block_z;
    uint32_t dynamic_shared_bytes;
    uint32_t reserved;
    uint64_t context_token;
    uint64_t module_token;
    uint64_t function_token;
    uint64_t stream_token;
    StwoCudaFunctionAttributes function;
};
static_assert(sizeof(StwoCudaInstalledAotFunctionReceipt) == 128,
              "installed AOT receipt ABI size");
static_assert(offsetof(StwoCudaInstalledAotFunctionReceipt, context_token) == 56,
              "installed AOT context-token offset");
static_assert(offsetof(StwoCudaInstalledAotFunctionReceipt, function) == 88,
              "installed AOT function-resource offset");

struct InstalledAotFunction {
    void *exec_context;
    CUcontext context;
    CUmodule module;
    CUfunction function;
    CUstream stream;
    uint64_t cache_key;
    uint32_t expected_sm;
    uint32_t argument_count;
    uint32_t grid[3];
    uint32_t block[3];
    uint32_t dynamic_shared_bytes;
    std::string kernel_name;
};

struct StwoCudaCompositionWavePart {
    const uint32_t *const *trace_cols;
    const uint32_t *interaction_offsets;
    const uint32_t *base_params;
    const uint32_t *ext_params;
    const uint32_t *denom_inv;
    uint32_t log_n_rows;
    uint32_t rc_base;
};
static_assert(sizeof(StwoCudaCompositionWavePart) == 48,
              "composition wave part ABI");
static_assert(alignof(StwoCudaCompositionWavePart) == 8,
              "composition wave part alignment");

// Call only after the wrapper's zero-row no-op guard. Subtracting before
// dividing avoids the u32 overflow in `(value + divisor - 1) / divisor`.
constexpr uint32_t ceil_div_nonzero_u32(uint32_t value, uint32_t divisor) {
    return 1u + (value - 1u) / divisor;
}
constexpr uint32_t kU32Max = ~uint32_t{0};
static_assert(ceil_div_nonzero_u32(1u, 256u) == 1u, "ceil-div one row");
static_assert(ceil_div_nonzero_u32(255u, 256u) == 1u, "ceil-div partial block");
static_assert(ceil_div_nonzero_u32(256u, 256u) == 1u, "ceil-div full block");
static_assert(ceil_div_nonzero_u32(257u, 256u) == 2u, "ceil-div next block");
static_assert(ceil_div_nonzero_u32(kU32Max, 256u) == 16777216u,
              "ceil-div u32 maximum");

struct AotCounters {
    std::atomic<uint64_t> aot_loads{0};
    std::atomic<uint64_t> aot_cache_hits{0};
    std::atomic<uint64_t> aot_misses{0};
    std::atomic<uint64_t> runtime_loads{0};
    std::atomic<uint64_t> runtime_cache_hits{0};
    std::atomic<uint64_t> strict_rejections{0};
};

AotCounters &aot_counters() {
    static AotCounters counters;
    return counters;
}

std::atomic<bool> &require_aot() {
    static std::atomic<bool> required{false};
    return required;
}

// Admission closes exactly once. Operations admitted before that point may finish,
// including publishing or enqueueing a runtime module, but the strict-mode setter does
// not return until all of them have left their publication/launch scope. Operations
// entering after closure observe require_aot=true before resolving a function, so they
// can only load or launch AOT. This fences host enqueue, not asynchronous completion
// of arbitrary prior GPU work; callers must close admission before proof work begins.
struct StrictAotAdmission {
    std::mutex mutex;
    std::condition_variable drained;
    bool closed = false;
    size_t active_operations = 0;
};

StrictAotAdmission &strict_aot_admission() {
    static StrictAotAdmission admission;
    return admission;
}

class JitOperationAdmission {
  public:
    JitOperationAdmission() {
        // Strict lookups are the hot path. Once admission is closed, avoid taking
        // the mutex: the release/acquire pair also makes `closed` observable.
        if (require_aot().load(std::memory_order_acquire)) return;
        StrictAotAdmission &admission = strict_aot_admission();
        std::lock_guard<std::mutex> guard(admission.mutex);
        if (!admission.closed) {
            ++admission.active_operations;
            admitted_before_strict_ = true;
        }
    }

    ~JitOperationAdmission() {
        if (!admitted_before_strict_) return;
        StrictAotAdmission &admission = strict_aot_admission();
        std::lock_guard<std::mutex> guard(admission.mutex);
        if (--admission.active_operations == 0) admission.drained.notify_all();
    }

    JitOperationAdmission(const JitOperationAdmission &) = delete;
    JitOperationAdmission &operator=(const JitOperationAdmission &) = delete;

  private:
    bool admitted_before_strict_ = false;
};

void close_strict_aot_admission() {
    StrictAotAdmission &admission = strict_aot_admission();
    std::unique_lock<std::mutex> guard(admission.mutex);
    admission.closed = true;
    require_aot().store(true, std::memory_order_release);
    admission.drained.wait(guard, [&admission] {
        return admission.active_operations == 0;
    });
}

struct JitCacheKey {
    uint64_t cache_key;
    CUcontext context;

    bool operator==(const JitCacheKey &other) const {
        return cache_key == other.cache_key && context == other.context;
    }
};

struct JitCacheKeyHash {
    size_t operator()(const JitCacheKey &key) const {
        size_t first = std::hash<uint64_t>{}(key.cache_key);
        size_t second = std::hash<uintptr_t>{}(reinterpret_cast<uintptr_t>(key.context));
        return first ^ (second + 0x9e3779b9u + (first << 6) + (first >> 2));
    }
};

struct JitCache {
    // Guards `functions` and `key_mutexes` only — held briefly for map lookups/inserts,
    // NEVER across a compile, so distinct-key compiles run concurrently.
    std::mutex mutex;
    // (semantic hash, CUDA context) -> compiled function and its owning module.
    // One process may drive several GPUs; a CUfunction is never portable across
    // contexts even when its semantic key is identical.
    std::unordered_map<JitCacheKey, CachedFunction, JitCacheKeyHash> functions;
    // Same composite key for compile serialization: different contexts may load
    // the same cubin concurrently without ever aliasing their module globals.
    std::unordered_map<JitCacheKey, std::shared_ptr<std::mutex>, JitCacheKeyHash>
        key_mutexes;
    // Strict admission may replace a runtime-origin entry with the exact AOT
    // module. Prior launches are host-enqueue drained, but their asynchronous GPU
    // work is not globally synchronized. Retain replaced modules/events for the
    // CUDA-context lifetime rather than risking use-after-unload. This is the
    // current process cache's deliberate ownership model, not yet the replacement
    // backend's destructor-qualified InstalledProgram/BoundModuleInstance owner.
    std::vector<CachedFunction> retired;
};

JitCache &jit_cache() {
    static JitCache cache;
    return cache;
}

bool ensure_current_context(CUcontext *out) {
    if (out == nullptr) return false;
    *out = nullptr;
    if (cuCtxGetCurrent(out) != CUDA_SUCCESS) return false;
    if (*out != nullptr) return true;
    if (cudaFree(0) != cudaSuccess) return false;
    return cuCtxGetCurrent(out) == CUDA_SUCCESS && *out != nullptr;
}

// A runtime-origin entry is deliberately not a strict-mode cache hit. The caller
// continues through the per-key compile path, resolves the embedded AOT entry, and
// replaces this map slot. Missing AOT still fails closed in compile_kernel.
bool try_use_cached_function(const CachedFunction &cached, const char *kernel_name,
                             CUcontext context, CUfunction *out) {
    if (cached.kernel_name != kernel_name || cached.module == nullptr ||
        cached.function == nullptr) {
        return false;
    }
    if (require_aot().load(std::memory_order_acquire) &&
        cached.origin != KernelOrigin::Aot) {
        return false;
    }
    if (context == nullptr ||
        cached.pedersen_publication.context_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(context)) ||
        cached.pedersen_publication.module_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cached.module)) ||
        cached.pedersen_publication.function_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cached.function))) {
        return false;
    }
    if (cached.pedersen_publication.globals_state == kPedersenGlobalsPresent) {
        const uint32_t required = kPedersenPublicationReadbackVerified |
                                  kPedersenPublicationEventComplete |
                                  (cached.origin == KernelOrigin::Aot
                                       ? kPedersenPublicationAot
                                       : 0);
        if (cached.pedersen_publication.abi_version !=
                kPedersenPublicationAbiVersion ||
            cached.pedersen_publication.flags != required ||
            cached.pedersen_publication.pointer_count != 56 ||
            cached.pedersen_publication.columns_symbol_bytes != 448 ||
            cached.pedersen_publication.rows_symbol_bytes != 4 ||
            cached.pedersen_publication.n_rows == 0 ||
            cached.pedersen_publication.columns_symbol_token == 0 ||
            cached.pedersen_publication.rows_symbol_token == 0 ||
            cached.pedersen_publication.columns_symbol_token % alignof(uint64_t) != 0 ||
            cached.pedersen_publication.rows_symbol_token % alignof(uint32_t) != 0 ||
            cached.pedersen_publication_event == nullptr ||
            cached.pedersen_publication.completion_event_token !=
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(
                    cached.pedersen_publication_event))) {
            return false;
        }
    } else if (cached.pedersen_publication.globals_state != kPedersenGlobalsAbsent) {
        return false;
    }
    (cached.origin == KernelOrigin::Aot ? aot_counters().aot_cache_hits
                                        : aot_counters().runtime_cache_hits)
        .fetch_add(1, std::memory_order_relaxed);
    *out = cached.function;
    return true;
}

// Filesystem cache root: JIT-compiled kernels persist across processes, keyed by the
// program's CONTENT semantic hash + the GPU architecture (the same content-keying
// rule as the in-memory cache — never pointers, never implicit scope). Directory:
// $STWO_JIT_CACHE_DIR, else $HOME/.cache/stwo-jit. Disable the disk cache entirely
// with STWO_JIT_CACHE_DIR set to the empty string. Returns "" when disabled.
static std::string jit_cache_dir() {
    const char *dir = getenv("STWO_JIT_CACHE_DIR");
    if (dir != nullptr) {
        if (dir[0] == '\0') return std::string();
        return std::string(dir);
    }
    const char *home = getenv("HOME");
    if (home == nullptr) return std::string();
    return std::string(home) + "/.cache/stwo-jit";
}

// PTX artifact path. Relaxed-optimization builds get a distinct "_o0" artifact so
// optimized and unoptimized PTX for the same program never alias.
static std::string ptx_cache_path(uint64_t semantic_hash, int major, int minor,
                                  bool relax_opt) {
    std::string base = jit_cache_dir();
    if (base.empty()) return base;
    char name[128];
    snprintf(name, sizeof(name), "/sm%d%d_%016llx%s.ptx", major, minor,
             (unsigned long long)semantic_hash, relax_opt ? "_o0" : "");
    return base + name;
}

// CUBIN (SASS) artifact path — same keying as the PTX path, distinct extension. A
// cubin is architecture-SPECIFIC (real sm_XX), so the sm-tagged name means a cubin
// built for one GPU generation can never be loaded for another (a mismatched load
// fails and falls back to PTX).
static std::string cubin_cache_path(uint64_t semantic_hash, int major, int minor,
                                    bool relax_opt) {
    std::string base = jit_cache_dir();
    if (base.empty()) return base;
    char name[128];
    snprintf(name, sizeof(name), "/sm%d%d_%016llx%s.cubin", major, minor,
             (unsigned long long)semantic_hash, relax_opt ? "_o0" : "");
    return base + name;
}

// Process-global latch: set false the first time a cubin COMPILE fails, so the cubin
// path stops probing (a doomed sm_XX compile per kernel would otherwise regress cold
// start). Disk-cached cubins are still loaded regardless. Never reset — a toolkit's
// cubin capability does not change mid-process.
std::atomic<bool> &cubin_compile_supported() {
    static std::atomic<bool> supported{true};
    return supported;
}

// CUBIN disk caching: default OFF, opt in with STWO_JIT_CUBIN_CACHE=1. Measured
// (A40, session 1): nvrtcGetCUBIN pays full SASS generation at compile time — cold
// is ~11x the PTX path (1273.7s vs 115.7s on the 10-transfer statement set) — while
// a POPULATED cache gives a 13.8s fresh-process prove (JIT 0.5s, zero NVRTC/ptxas).
// The intended use is fleet cache-shipping: pre-populate once per sm arch during pod
// provisioning, then run with =1. Organic/one-shot runs should leave it off.
bool jit_cubin_cache_enabled() {
    static int enabled = -1;
    if (enabled < 0) {
        const char *env = getenv("STWO_JIT_CUBIN_CACHE");
        enabled = (env != nullptr && env[0] == '1' && env[1] == '\0') ? 1 : 0;
    }
    return enabled == 1;
}

// Parallel-compile setting, parsed once. Return value is the worker cap:
//   1  -> disabled (sequential; STWO_JIT_PARALLEL_COMPILE=0 or =1)
//   >1 -> explicit worker cap
//   0  -> auto (enabled, pick a bounded default at the call site)
int jit_parallel_compile_setting() {
    static int cached = -1;
    if (cached < 0) {
        const char *env = getenv("STWO_JIT_PARALLEL_COMPILE");
        if (env == nullptr || env[0] == '\0') {
            cached = 0;  // auto
        } else if (env[0] == '0' && env[1] == '\0') {
            cached = 1;  // kill switch -> sequential
        } else {
            int n = atoi(env);
            cached = (n >= 1) ? n : 0;
        }
    }
    return cached;
}

// Number of compile workers for a batch of `count` kernels (>= 1). Honors the kill
// switch / explicit cap; auto mode uses hardware concurrency bounded to 8 so many
// concurrent ptxas invocations (each memory-hungry) cannot thrash a small pod host.
uint32_t jit_parallel_compile_workers(uint32_t count) {
    if (count <= 1) return 1;
    int setting = jit_parallel_compile_setting();
    uint32_t workers;
    if (setting == 1) {
        workers = 1;
    } else if (setting == 0) {
        unsigned hc = std::thread::hardware_concurrency();
        workers = (hc == 0) ? 4u : (uint32_t)hc;
        if (workers > 8u) workers = 8u;
    } else {
        workers = (uint32_t)setting;
    }
    if (workers > count) workers = count;
    if (workers < 1) workers = 1;
    return workers;
}

// Diagnostics default ON (a hung compile must be attributable post-mortem);
// STWO_JIT_LOG=0 silences. The Rust orchestrator keys off the same variable.
bool jit_log_enabled() {
    static int enabled = -1;
    if (enabled < 0) {
        const char *env = getenv("STWO_JIT_LOG");
        enabled = (env != nullptr && env[0] == '0') ? 0 : 1;
    }
    return enabled == 1;
}

// Extra NVRTC options from STWO_JIT_NVRTC_OPTS (comma-separated), parsed once.
const std::vector<std::string> &extra_nvrtc_options() {
    static const std::vector<std::string> options = [] {
        std::vector<std::string> parsed;
        const char *env = getenv("STWO_JIT_NVRTC_OPTS");
        if (env != nullptr) {
            std::string raw(env);
            size_t start = 0;
            while (start <= raw.size()) {
                size_t end = raw.find(',', start);
                if (end == std::string::npos) end = raw.size();
                std::string opt = raw.substr(start, end - start);
                // Trim surrounding whitespace.
                size_t first = opt.find_first_not_of(" \t");
                size_t last = opt.find_last_not_of(" \t");
                if (first != std::string::npos) {
                    parsed.push_back(opt.substr(first, last - first + 1));
                }
                start = end + 1;
            }
        }
        return parsed;
    }();
    return options;
}

// NVRTC's `--dopt=off` is only accepted from CUDA 12; CUDA 11.x NVRTC rejects it with
// "invalid argument for option --dopt: off" (device optimization is opt-IN there — `off`
// is the default and not expressible as an argument). Passing it on 11.x FAILS the
// compile, which was the silent cause of the ec_op / partial_ec_mul / pedersen
// composition CPU-fallback: their oversized single-cone kernels take the relax path.
// The relax speedup itself is the ptxas `CU_JIT_OPTIMIZATION_LEVEL=0` applied at module
// load (unaffected by this), so on 11.x we simply omit the flag — device opt is already
// off by default. Cached per process; nvrtcVersion is cheap but called on hot paths.
static bool nvrtc_accepts_dopt_off() {
    static const bool ok = [] {
        int major = 0, minor = 0;
        return nvrtcVersion(&major, &minor) == NVRTC_SUCCESS && major >= 12;
    }();
    return ok;
}

// Stream-ordered allocations are not associated with a CUDA context:
// CU_POINTER_ATTRIBUTE_CONTEXT therefore returns a null context even while the
// allocation is valid and accessible. Prove the facts publication needs
// directly instead: current-device accessibility and a complete u32 range.
static bool is_current_device_u32_allocation(
    CUdeviceptr pointer,
    CUdevice device,
    size_t required_bytes
) {
    if (pointer == 0 || pointer % alignof(uint32_t) != 0 || required_bytes == 0) {
        return false;
    }
    cudaPointerAttributes attributes = {};
    if (cudaPointerGetAttributes(
            &attributes, reinterpret_cast<const void *>(pointer)) != cudaSuccess ||
        attributes.type != cudaMemoryTypeDevice ||
        attributes.device != static_cast<int>(device) ||
        reinterpret_cast<CUdeviceptr>(attributes.devicePointer) != pointer) {
        return false;
    }
    CUdeviceptr range_start = 0;
    size_t range_bytes = 0;
    return cuPointerGetAttribute(
               &range_start, CU_POINTER_ATTRIBUTE_RANGE_START_ADDR, pointer) ==
               CUDA_SUCCESS &&
           cuPointerGetAttribute(
               &range_bytes, CU_POINTER_ATTRIBUTE_RANGE_SIZE, pointer) ==
               CUDA_SUCCESS &&
           range_start == pointer && range_bytes >= required_bytes;
}

// Witness-JIT modules that embed computed EC deduces (ISA-V3 kinds 2/3,
// `stwo_wit_deduce.cuh`) declare per-module Pedersen table globals. Device
// globals never cross CUmodule boundaries, so publication is proved separately
// for every loaded module. A missing columns symbol is an explicit Absent state;
// every other lookup/copy/readback/event failure rejects the load.
static bool fill_witness_pedersen_globals(
    CUmodule module,
    const char *kernel_name,
    uint64_t cache_key,
    KernelOrigin origin,
    StwoCudaPedersenModulePublication *out,
    CUevent *out_event
) {
    if (module == nullptr || kernel_name == nullptr || out == nullptr ||
        out_event == nullptr) {
        return false;
    }
    *out = StwoCudaPedersenModulePublication{};
    *out_event = nullptr;

    CUcontext context = nullptr;
    CUdevice device = 0;
    int sm_major = 0;
    int sm_minor = 0;
    if (cuCtxGetCurrent(&context) != CUDA_SUCCESS || context == nullptr ||
        cuCtxGetDevice(&device) != CUDA_SUCCESS || device < 0 ||
        cuDeviceGetAttribute(&sm_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&sm_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
                             device) != CUDA_SUCCESS ||
        sm_major < 0 || sm_minor < 0) {
        return false;
    }

    out->abi_version = kPedersenPublicationAbiVersion;
    out->flags = origin == KernelOrigin::Aot ? kPedersenPublicationAot : 0;
    out->device_ordinal = static_cast<uint32_t>(device);
    out->sm_major = static_cast<uint32_t>(sm_major);
    out->sm_minor = static_cast<uint32_t>(sm_minor);
    out->cache_key = cache_key;
    out->module_token = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(module));
    out->context_token = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(context));
    if (out->module_token == 0 || out->context_token == 0) return false;

    CUdeviceptr cols_sym;
    size_t cols_size = 0;
    CUresult cols_result =
        cuModuleGetGlobal(&cols_sym, &cols_size, module, "g_stwo_wit_pedersen_cols");
    if (cols_result == CUDA_ERROR_NOT_FOUND) {
        CUdeviceptr absent_rows_sym = 0;
        size_t absent_rows_size = 0;
        if (cuModuleGetGlobal(&absent_rows_sym, &absent_rows_size, module,
                              "g_stwo_wit_pedersen_n_rows") != CUDA_ERROR_NOT_FOUND) {
            return false;
        }
        // `out` was zero-initialized. Absent therefore has no symbol/pointer/event
        // fields or completion flags, and the cold publication query (which
        // requires exact Present+AOT+readback+event state) can never upgrade it.
        out->globals_state = kPedersenGlobalsAbsent;
        return true;
    }
    if (cols_result != CUDA_SUCCESS) return false;

    CUdeviceptr rows_sym;
    size_t rows_size = 0;
    if (cuModuleGetGlobal(&rows_sym, &rows_size, module,
                          "g_stwo_wit_pedersen_n_rows") != CUDA_SUCCESS) {
        return false;
    }
    constexpr size_t kPointerCount = 56;
    constexpr size_t kColumnsBytes = kPointerCount * sizeof(uint64_t);
    constexpr size_t kRowsBytes = sizeof(uint32_t);
    if (cols_size != kColumnsBytes || rows_size != kRowsBytes ||
        cols_sym % alignof(uint64_t) != 0 || rows_sym % alignof(uint32_t) != 0) {
        fprintf(stderr,
                "stwo JIT: pedersen globals malformed for %s "
                "(cols_bytes=%zu rows_bytes=%zu cols_align=%llu rows_align=%llu)\n",
                kernel_name, cols_size, rows_size,
                (unsigned long long)(cols_sym % alignof(uint64_t)),
                (unsigned long long)(rows_sym % alignof(uint32_t)));
        return false;
    }
    if (!is_borrowed_pedersen_table_registered()) {
        // NO self-heal generation: the deduce-gate oracle falsified the
        // GPU-generated table (144/256 rows vs the host PEDERSEN_TABLE_18,
        // run 20260705T113615Z). The host-built table must be registered
        // first (borrowed mode via `register_borrowed_pedersen_table`);
        // otherwise fail the load closed — the caller falls back to the
        // host lane rather than reading a wrong table.
        fprintf(stderr,
                "stwo JIT: %s needs the pedersen table but none is registered "
                "(host-table registration required; GPU generation is quarantined)\n",
                kernel_name);
        return false;
    }
    unsigned *ptrs[56];
    uint32_t n_rows = 0;
    get_pedersen_table_column_ptrs(ptrs, &n_rows);
    // The deduce functions mask row indices with n_rows-1; a non-power-of-two
    // count would silently alias rows, so reject it here instead.
    static_assert(sizeof(ptrs) == kColumnsBytes,
                  "Pedersen columns symbol must be exactly 448 bytes");
    if (n_rows == 0 || (n_rows & (n_rows - 1)) != 0) {
        fprintf(stderr,
                "stwo JIT: pedersen table geometry malformed for %s (n_rows=%u)\n",
                kernel_name, n_rows);
        return false;
    }
    const size_t required_column_bytes =
        static_cast<size_t>(n_rows) * sizeof(uint32_t);
    for (size_t i = 0; i < kPointerCount; ++i) {
        CUdeviceptr pointer = static_cast<CUdeviceptr>(reinterpret_cast<uintptr_t>(ptrs[i]));
        if (!is_current_device_u32_allocation(
                pointer, device, required_column_bytes)) {
            fprintf(stderr,
                    "stwo JIT: pedersen column %zu is not a current-device u32 allocation "
                    "for %s\n",
                    i, kernel_name);
            return false;
        }
    }

    unsigned *readback_ptrs[56] = {};
    uint32_t readback_rows = 0;
    if (cuMemcpyHtoD(cols_sym, ptrs, sizeof(ptrs)) != CUDA_SUCCESS ||
        cuMemcpyHtoD(rows_sym, &n_rows, sizeof(n_rows)) != CUDA_SUCCESS ||
        cuMemcpyDtoH(readback_ptrs, cols_sym, sizeof(readback_ptrs)) != CUDA_SUCCESS ||
        cuMemcpyDtoH(&readback_rows, rows_sym, sizeof(readback_rows)) != CUDA_SUCCESS ||
        memcmp(readback_ptrs, ptrs, sizeof(ptrs)) != 0 || readback_rows != n_rows) {
        fprintf(stderr, "stwo JIT: failed filling pedersen table globals for %s\n",
                kernel_name);
        return false;
    }

    CUevent completion_event = nullptr;
    if (cuEventCreate(&completion_event, CU_EVENT_DISABLE_TIMING) != CUDA_SUCCESS ||
        completion_event == nullptr || cuEventRecord(completion_event, nullptr) != CUDA_SUCCESS ||
        cuEventSynchronize(completion_event) != CUDA_SUCCESS) {
        if (completion_event != nullptr) cuEventDestroy(completion_event);
        fprintf(stderr, "stwo JIT: failed fencing pedersen publication for %s\n",
                kernel_name);
        return false;
    }

    out->flags |= kPedersenPublicationReadbackVerified |
                  kPedersenPublicationEventComplete;
    out->pointer_count = static_cast<uint32_t>(kPointerCount);
    out->columns_symbol_bytes = static_cast<uint32_t>(cols_size);
    out->rows_symbol_bytes = static_cast<uint32_t>(rows_size);
    out->n_rows = n_rows;
    out->globals_state = kPedersenGlobalsPresent;
    out->columns_symbol_token = cols_sym;
    out->rows_symbol_token = rows_sym;
    out->completion_event_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(completion_event));
    for (size_t i = 0; i < kPointerCount; ++i) {
        out->column_pointers[i] =
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ptrs[i]));
    }
    *out_event = completion_event;
    return true;
}

// Central loaded-module admission. Every origin takes this path so the cache
// never contains a function without its owning module/context and explicit
// Pedersen-global state.
static bool bind_loaded_module(CUmodule module, const char *kernel_name,
                               uint64_t cache_key, KernelOrigin origin,
                               CachedFunction *out) {
    if (module == nullptr || kernel_name == nullptr || out == nullptr) return false;
    CUfunction function = nullptr;
    if (cuModuleGetFunction(&function, module, kernel_name) != CUDA_SUCCESS ||
        function == nullptr) {
        fprintf(stderr, "stwo JIT: kernel %s not found in loaded module\n", kernel_name);
        cuModuleUnload(module);
        return false;
    }
    StwoCudaPedersenModulePublication publication{};
    CUevent publication_event = nullptr;
    if (!fill_witness_pedersen_globals(module, kernel_name, cache_key, origin,
                                        &publication, &publication_event)) {
        cuModuleUnload(module);
        return false;
    }
    publication.function_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(function));
    if (publication.function_token == 0) {
        if (publication_event != nullptr) cuEventDestroy(publication_event);
        cuModuleUnload(module);
        return false;
    }
    *out = CachedFunction{module, function, origin, std::string(kernel_name), publication,
                          publication_event};
    return true;
}

// CUBIN (SASS) fast path: emit/reuse a real-arch cubin and load it with
// cuModuleLoadData, which does NOT run the driver's ptxas (the cubin is already SASS).
// This is what turns a cold process's per-module PTX->SASS assembly (measured 56.4 s on
// one SN-PIE module) into a device-side memcpy of the cached cubin.
//
// Returns true and sets *out on success. Returns false — leaving the caller to fall
// back to the PTX path — on ANY failure: nvrtcGetCUBIN unavailable, a compile error, a
// stale/corrupt cached cubin, or an architecture mismatch at load. Correctness is
// therefore never conditional on this path; only cold-start latency.
static bool try_cubin_path(const char *source, const char *kernel_name,
                           uint64_t semantic_hash, bool relax_opt,
                           const cudaDeviceProp &props,
                           std::chrono::steady_clock::time_point t_start,
                           CachedFunction *out) {
    std::vector<char> cubin;
    bool from_disk = false;
    std::string cache_file =
        cubin_cache_path(semantic_hash, props.major, props.minor, relax_opt);
    if (!cache_file.empty()) {
        if (FILE *f = fopen(cache_file.c_str(), "rb")) {
            fseek(f, 0, SEEK_END);
            long len = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (len > 0) {
                cubin.resize((size_t)len);
                if (fread(cubin.data(), 1, (size_t)len, f) != (size_t)len) cubin.clear();
            }
            fclose(f);
            from_disk = !cubin.empty();
        }
    }

    if (cubin.empty()) {
        // Regression guard: if a prior cubin COMPILE already failed this process (e.g.
        // nvrtc lacks cubin extraction, or the arch is too new for this toolkit), don't
        // pay a doomed sm_XX compile per kernel — go straight to PTX. Disk-cached cubins
        // from a healthy prior process are still loaded (this branch is the miss path).
        if (!cubin_compile_supported().load(std::memory_order_relaxed)) {
            return false;
        }
        // nvrtcGetCUBIN requires a REAL architecture target (sm_XX); a virtual
        // compute_XX target yields PTX only. Compile to sm_<major><minor>.
        nvrtcProgram program;
        if (nvrtcCreateProgram(&program, source, "stwo_jit.cu", 0, nullptr, nullptr) !=
            NVRTC_SUCCESS) {
            cubin_compile_supported().store(false, std::memory_order_relaxed);
            return false;
        }
        char arch_flag[64];
        snprintf(arch_flag, sizeof(arch_flag), "--gpu-architecture=sm_%d%d", props.major,
                 props.minor);
        std::vector<const char *> options = {arch_flag, "--std=c++14"};
        for (const std::string &opt : extra_nvrtc_options()) {
            options.push_back(opt.c_str());
        }
        if (relax_opt) {
            if (nvrtc_accepts_dopt_off()) options.push_back("--dopt=off");
        }
        if (jit_log_enabled()) {
            fprintf(stderr,
                    "stwo JIT: NVRTC cubin compile start kernel=%s key=%016llx "
                    "source_bytes=%zu n_options=%zu relax_opt=%d\n",
                    kernel_name, (unsigned long long)semantic_hash, strlen(source),
                    options.size(), relax_opt ? 1 : 0);
        }
        auto t_nvrtc = std::chrono::steady_clock::now();
        nvrtcResult compile_result =
            nvrtcCompileProgram(program, (int)options.size(), options.data());
        if (compile_result != NVRTC_SUCCESS) {
            if (jit_log_enabled()) {
                size_t log_size = 0;
                nvrtcGetProgramLogSize(program, &log_size);
                std::string log(log_size, '\0');
                nvrtcGetProgramLog(program, &log[0]);
                fprintf(stderr,
                        "stwo JIT: NVRTC cubin compile failed for %s (falling back to "
                        "PTX):\n%s\n",
                        kernel_name, log.c_str());
            }
            nvrtcDestroyProgram(&program);
            // An sm_XX compile failure is almost always a capability/arch issue that
            // recurs for every kernel (e.g. arch too new for this nvrtc) — latch it off.
            cubin_compile_supported().store(false, std::memory_order_relaxed);
            return false;
        }
        size_t cubin_size = 0;
        nvrtcResult size_result = nvrtcGetCUBINSize(program, &cubin_size);
        if (size_result != NVRTC_SUCCESS || cubin_size == 0) {
            nvrtcDestroyProgram(&program);
            cubin_compile_supported().store(false, std::memory_order_relaxed);
            return false;
        }
        cubin.resize(cubin_size);
        if (nvrtcGetCUBIN(program, cubin.data()) != NVRTC_SUCCESS) {
            nvrtcDestroyProgram(&program);
            cubin_compile_supported().store(false, std::memory_order_relaxed);
            return false;
        }
        nvrtcDestroyProgram(&program);
        if (jit_log_enabled()) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t_nvrtc)
                          .count();
            fprintf(stderr,
                    "stwo JIT: NVRTC cubin compile end kernel=%s nvrtc_ms=%lld "
                    "cubin_bytes=%zu\n",
                    kernel_name, (long long)ms, cubin.size());
        }
        if (!cache_file.empty()) {
            std::string dir = cache_file.substr(0, cache_file.find_last_of('/'));
            std::string parent = dir.substr(0, dir.find_last_of('/'));
            mkdir(parent.c_str(), 0755);
            mkdir(dir.c_str(), 0755);
            std::string tmp = cache_file + ".tmp";
            if (FILE *f = fopen(tmp.c_str(), "wb")) {
                fwrite(cubin.data(), 1, cubin.size(), f);
                fclose(f);
                rename(tmp.c_str(), cache_file.c_str());
            }
        }
    }

    // Ensure the runtime API's primary context is current for the driver API.
    cudaFree(0);
    if (jit_log_enabled()) {
        fprintf(stderr,
                "stwo JIT: cubin module load start kernel=%s cubin_bytes=%zu relax_opt=%d\n",
                kernel_name, cubin.size(), relax_opt ? 1 : 0);
    }
    auto t_load = std::chrono::steady_clock::now();
    CUmodule module;
    // cuModuleLoadData over cubin bytes: no ptxas. A mismatch (e.g. a stale disk cubin
    // for a different arch) fails here and the caller retries via PTX.
    if (cuModuleLoadData(&module, cubin.data()) != CUDA_SUCCESS) {
        if (jit_log_enabled()) {
            fprintf(stderr, "stwo JIT: cuModuleLoadData(cubin) failed for %s%s\n",
                    kernel_name, from_disk ? " (stale disk cubin?)" : "");
        }
        return false;
    }
    if (!bind_loaded_module(module, kernel_name, semantic_hash, KernelOrigin::Runtime,
                            out)) {
        return false;
    }
    if (jit_log_enabled()) {
        auto load_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - t_load)
                           .count();
        auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t_start)
                            .count();
        fprintf(stderr,
                "stwo JIT: %s ready in %lld ms (module_load_ms=%lld, %s cubin — no ptxas)\n",
                kernel_name, (long long)total_ms, (long long)load_ms,
                from_disk ? "disk" : "NVRTC");
    }
    return true;
}

// Compile `source` to a CUfunction. `relax_opt` is the oversized-kernel relief valve:
// it disables the expensive optimization stages at BOTH levels (nvrtc --dopt=off for
// the C++->PTX front end, ptxas CU_JIT_OPTIMIZATION_LEVEL=0 for the PTX->SASS module
// load) — the per-stage timing logs identify which one was actually spinning.
// Optimization level changes SASS scheduling only, never the integer/modular values
// the kernel computes.
bool compile_kernel(const char *source, const char *kernel_name, uint64_t semantic_hash,
                    bool relax_opt, CachedFunction *out) {
    auto t_start = std::chrono::steady_clock::now();
    bool from_disk = false;
    int device = 0;
    cudaGetDevice(&device);
    cudaDeviceProp props;
    cudaGetDeviceProperties(&props, device);

    // Tier 0: the embedded AOT pack — offline -O3 SASS compiled at BUILD time
    // (design §4). No NVRTC, no ptxas, no disk. A miss (drifted recording, new
    // arch) falls through to the runtime lanes below — that miss IS the drift
    // check. The emitted AOT pack carries the same cache key for oversized
    // kernels too, so `relax_opt` never bypasses tier 0.
    const unsigned char *blob = nullptr;
    size_t blob_len = 0;
    bool found_aot = stwo_aot_lookup(semantic_hash, (unsigned)props.major,
                                     (unsigned)props.minor, &blob, &blob_len);
    if (found_aot) {
        CUmodule module = nullptr;
        CUresult r = cuModuleLoadData(&module, blob);
        if (r == CUDA_SUCCESS) {
            if (bind_loaded_module(module, kernel_name, semantic_hash, KernelOrigin::Aot,
                                   out)) {
                if (jit_log_enabled()) {
                    fprintf(stderr,
                            "stwo JIT: AOT pack hit kernel=%s key=%016llx (embedded "
                            "sm_%d%d cubin)\n",
                            kernel_name, (unsigned long long)semantic_hash, props.major,
                            props.minor);
                }
                aot_counters().aot_loads.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
        }
        if (jit_log_enabled()) {
            fprintf(stderr,
                    "stwo JIT: AOT pack entry for key=%016llx failed to load (%d)\n",
                    (unsigned long long)semantic_hash, (int)r);
        }
    }
    aot_counters().aot_misses.fetch_add(1, std::memory_order_relaxed);
    if (require_aot().load(std::memory_order_acquire)) {
        aot_counters().strict_rejections.fetch_add(1, std::memory_order_relaxed);
        fprintf(stderr,
                "stwo JIT: strict AOT rejection kernel=%s key=%016llx sm_%d%d "
                "found_entry=%d\n",
                kernel_name, (unsigned long long)semantic_hash, props.major, props.minor,
                found_aot ? 1 : 0);
        return false;
    }

    // A null source is the strict resident warm-path sentinel: callers that
    // admitted an exact embedded entry do not materialize the huge CUDA TU.
    // Reaching here means the entry was absent/unloadable while strict mode was
    // not active, so fail rather than handing a null pointer to cache/NVRTC code.
    if (source == nullptr) {
        fprintf(stderr,
                "stwo JIT: source-free AOT resolution missed kernel=%s key=%016llx\n",
                kernel_name, (unsigned long long)semantic_hash);
        return false;
    }

    // Cubin fast path (skips ptxas at load). On any failure, fall through to PTX.
    if (jit_cubin_cache_enabled() &&
        [&]() {
            if (!try_cubin_path(source, kernel_name, semantic_hash, relax_opt, props,
                                t_start, out)) {
                return false;
            }
            return true;
        }()) {
        aot_counters().runtime_loads.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    std::vector<char> ptx;
    std::string cache_file = ptx_cache_path(semantic_hash, props.major, props.minor,
                                            relax_opt);
    if (!cache_file.empty()) {
        if (FILE *f = fopen(cache_file.c_str(), "rb")) {
            fseek(f, 0, SEEK_END);
            long len = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (len > 0) {
                ptx.resize((size_t)len);
                if (fread(ptx.data(), 1, (size_t)len, f) != (size_t)len) ptx.clear();
            }
            fclose(f);
            from_disk = !ptx.empty();
        }
    }

    if (ptx.empty()) {
        nvrtcProgram program;
        if (nvrtcCreateProgram(&program, source, "stwo_jit.cu", 0, nullptr, nullptr) !=
            NVRTC_SUCCESS) {
            return false;
        }
        char arch_flag[64];
        snprintf(arch_flag, sizeof(arch_flag), "--gpu-architecture=compute_%d%d",
                 props.major, props.minor);
        std::vector<const char *> options = {arch_flag, "--std=c++14"};
        for (const std::string &opt : extra_nvrtc_options()) {
            options.push_back(opt.c_str());
        }
        if (relax_opt) {
            if (nvrtc_accepts_dopt_off()) options.push_back("--dopt=off");
        }
        if (jit_log_enabled()) {
            fprintf(stderr,
                    "stwo JIT: NVRTC compile start kernel=%s key=%016llx "
                    "source_bytes=%zu n_options=%zu relax_opt=%d\n",
                    kernel_name, (unsigned long long)semantic_hash, strlen(source),
                    options.size(), relax_opt ? 1 : 0);
        }
        auto t_nvrtc = std::chrono::steady_clock::now();
        nvrtcResult compile_result =
            nvrtcCompileProgram(program, (int)options.size(), options.data());
        if (compile_result != NVRTC_SUCCESS) {
            size_t log_size = 0;
            nvrtcGetProgramLogSize(program, &log_size);
            std::string log(log_size, '\0');
            nvrtcGetProgramLog(program, &log[0]);
            fprintf(stderr, "stwo JIT: NVRTC compilation failed:\n%s\n", log.c_str());
            nvrtcDestroyProgram(&program);
            return false;
        }
        if (jit_log_enabled()) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t_nvrtc)
                          .count();
            fprintf(stderr, "stwo JIT: NVRTC compile end kernel=%s nvrtc_ms=%lld\n",
                    kernel_name, (long long)ms);
        }
        size_t ptx_size = 0;
        nvrtcGetPTXSize(program, &ptx_size);
        ptx.resize(ptx_size);
        nvrtcGetPTX(program, ptx.data());
        nvrtcDestroyProgram(&program);

        if (!cache_file.empty()) {
            // mkdir -p the cache dir (two levels at most), best-effort.
            std::string dir = cache_file.substr(0, cache_file.find_last_of('/'));
            std::string parent = dir.substr(0, dir.find_last_of('/'));
            mkdir(parent.c_str(), 0755);
            mkdir(dir.c_str(), 0755);
            std::string tmp = cache_file + ".tmp";
            if (FILE *f = fopen(tmp.c_str(), "wb")) {
                fwrite(ptx.data(), 1, ptx.size(), f);
                fclose(f);
                rename(tmp.c_str(), cache_file.c_str());
            }
        }
    }

    // Ensure the runtime API's primary context is current for the driver API.
    cudaFree(0);
    // PTX -> SASS happens here (the driver's ptxas): time it separately from the
    // NVRTC phase above so a pegged core is attributable to the right stage.
    if (jit_log_enabled()) {
        fprintf(stderr, "stwo JIT: module load start kernel=%s ptx_bytes=%zu relax_opt=%d\n",
                kernel_name, ptx.size(), relax_opt ? 1 : 0);
    }
    auto t_load = std::chrono::steady_clock::now();
    CUmodule module;
    CUresult load_result;
    if (relax_opt) {
        CUjit_option jit_options[] = {CU_JIT_OPTIMIZATION_LEVEL};
        void *jit_values[] = {(void *)(uintptr_t)0};
        load_result = cuModuleLoadDataEx(&module, ptx.data(), 1, jit_options, jit_values);
    } else {
        load_result = cuModuleLoadDataEx(&module, ptx.data(), 0, nullptr, nullptr);
    }
    if (load_result != CUDA_SUCCESS) {
        // Surface WHICH kernel and WHY: an oversized single-constraint cone (fp256 EC /
        // pedersen composition) can exceed ptxas's PTX->SASS limits here, which is the
        // silent cause of the CPU fallback for those components. Include the driver
        // error string + PTX size so the failure is attributable (registers/resources
        // vs a real ptxas error) instead of a bare "failed".
        const char *err_str = nullptr;
        cuGetErrorString(load_result, &err_str);
        fprintf(stderr,
                "stwo JIT: cuModuleLoadDataEx failed for %s: %s (ptx_bytes=%zu relax_opt=%d)\n",
                kernel_name, err_str ? err_str : "?", ptx.size(), relax_opt ? 1 : 0);
        return false;
    }
    if (!bind_loaded_module(module, kernel_name, semantic_hash, KernelOrigin::Runtime,
                            out)) {
        return false;
    }
    if (jit_log_enabled()) {
        auto load_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - t_load)
                           .count();
        auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t_start)
                            .count();
        fprintf(stderr, "stwo JIT: %s ready in %lld ms (module_load_ms=%lld, %s)\n",
                kernel_name, (long long)total_ms, (long long)load_ms,
                from_disk ? "disk PTX cache" : "NVRTC compile");
    }
    aot_counters().runtime_loads.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// Compile-or-cache-hit, shared by the launch and precompile entry points.
//
// Concurrency contract (enables STWO_JIT_PARALLEL_COMPILE): the global `cache.mutex`
// is held ONLY for the O(1) map lookups/inserts, never across the expensive
// compile_kernel, so requests for DISTINCT keys compile fully in parallel. Requests for
// the SAME key serialize on a per-key mutex, so a program is compiled at most once and
// two threads never race the module load — a strict superset of the old single-threaded
// behavior (with one worker the fast path and per-key lock are uncontended and the
// resulting cache is identical).
bool get_or_compile(const char *source, const char *kernel_name, uint64_t cache_key,
                    bool relax_opt, CUfunction *out) {
    if (kernel_name == nullptr || out == nullptr) return false;
    CUcontext context = nullptr;
    if (!ensure_current_context(&context)) return false;
    const JitCacheKey scoped_key{cache_key, context};
    JitCache &cache = jit_cache();

    // Fast path: already compiled by some prior request.
    {
        std::lock_guard<std::mutex> guard(cache.mutex);
        auto it = cache.functions.find(scoped_key);
        if (it != cache.functions.end()) {
            if (it->second.kernel_name != kernel_name) return false;
            if (try_use_cached_function(it->second, kernel_name, context, out)) return true;
        }
    }

    // Acquire (or create) this key's compile lock without holding the global lock
    // across the compile.
    std::shared_ptr<std::mutex> key_lock;
    {
        std::lock_guard<std::mutex> guard(cache.mutex);
        auto fit = cache.functions.find(scoped_key);
        if (fit != cache.functions.end()) {
            if (fit->second.kernel_name != kernel_name) return false;
            if (try_use_cached_function(fit->second, kernel_name, context, out)) return true;
        }
        std::shared_ptr<std::mutex> &slot = cache.key_mutexes[scoped_key];
        if (!slot) slot = std::make_shared<std::mutex>();
        key_lock = slot;
    }

    std::lock_guard<std::mutex> compile_guard(*key_lock);
    // Re-check under the per-key lock: a concurrent holder of this same lock may have
    // just finished compiling this exact key.
    {
        std::lock_guard<std::mutex> guard(cache.mutex);
        auto it = cache.functions.find(scoped_key);
        if (it != cache.functions.end()) {
            if (it->second.kernel_name != kernel_name) return false;
            if (try_use_cached_function(it->second, kernel_name, context, out)) return true;
        }
    }

    // This lifetime is the publication fence: strict admission cannot return while a
    // pre-admission compile can still load a module or insert it into the cache.
    JitOperationAdmission publication_admission;
    CachedFunction compiled{};
    if (!compile_kernel(source, kernel_name, cache_key, relax_opt, &compiled)) {
        return false;
    }
    if (compiled.kernel_name != kernel_name ||
        compiled.pedersen_publication.context_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(context))) {
        if (compiled.pedersen_publication_event != nullptr) {
            cuEventDestroy(compiled.pedersen_publication_event);
        }
        if (compiled.module != nullptr) cuModuleUnload(compiled.module);
        return false;
    }
    {
        std::lock_guard<std::mutex> guard(cache.mutex);
        auto existing = cache.functions.find(scoped_key);
        if (existing == cache.functions.end()) {
            cache.functions.emplace(scoped_key, std::move(compiled));
        } else {
            cache.retired.push_back(std::move(existing->second));
            existing->second = std::move(compiled);
        }
    }
    {
        std::lock_guard<std::mutex> guard(cache.mutex);
        *out = cache.functions.find(scoped_key)->second.function;
    }
    return true;
}

bool get_live_aot_function_publication(
    const char *kernel_name,
    uint64_t cache_key,
    StwoCudaAotFunctionPublication *out
) {
    if (out == nullptr) return false;
    *out = StwoCudaAotFunctionPublication{};
    if (kernel_name == nullptr) return false;

    CUcontext context = nullptr;
    CUdevice device = 0;
    int sm_major = 0;
    int sm_minor = 0;
    if (!ensure_current_context(&context) ||
        cuCtxGetDevice(&device) != CUDA_SUCCESS || device < 0 ||
        cuDeviceGetAttribute(&sm_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&sm_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
                             device) != CUDA_SUCCESS ||
        sm_major < 0 || sm_minor < 0) {
        return false;
    }

    JitCache &cache = jit_cache();
    std::lock_guard<std::mutex> guard(cache.mutex);
    auto found = cache.functions.find(JitCacheKey{cache_key, context});
    if (found == cache.functions.end()) return false;
    const CachedFunction &cached = found->second;
    if (cached.origin != KernelOrigin::Aot || cached.kernel_name != kernel_name ||
        cached.module == nullptr || cached.function == nullptr ||
        cached.pedersen_publication.context_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(context))) {
        return false;
    }
    *out = StwoCudaAotFunctionPublication{
        kAotFunctionPublicationAbiVersion,
        kAotFunctionPublicationAot,
        static_cast<uint32_t>(device),
        static_cast<uint32_t>(sm_major),
        static_cast<uint32_t>(sm_minor),
        0,
        cache_key,
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(context)),
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cached.module)),
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cached.function)),
    };
    return out->context_token != 0 && out->module_token != 0 &&
           out->function_token != 0;
}

bool get_live_pedersen_publication(
    const char *kernel_name,
    uint64_t cache_key,
    StwoCudaPedersenModulePublication *out
) {
    if (out == nullptr) return false;
    *out = StwoCudaPedersenModulePublication{};
    if (kernel_name == nullptr) return false;

    CUcontext context = nullptr;
    CUdevice device = 0;
    int sm_major = 0;
    int sm_minor = 0;
    if (!ensure_current_context(&context) ||
        cuCtxGetDevice(&device) != CUDA_SUCCESS || device < 0 ||
        cuDeviceGetAttribute(&sm_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&sm_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
                             device) != CUDA_SUCCESS ||
        sm_major < 0 || sm_minor < 0) {
        return false;
    }

    JitCache &cache = jit_cache();
    // Deliberately retain the cache lock through symbol resolution and DtoH
    // equality checks so this exact module cannot be replaced underneath the
    // receipt. This is a one-shot cold admission query before graph creation,
    // never part of the launch path.
    std::lock_guard<std::mutex> guard(cache.mutex);
    auto it = cache.functions.find(JitCacheKey{cache_key, context});
    if (it == cache.functions.end()) return false;
    const CachedFunction &cached = it->second;
    const StwoCudaPedersenModulePublication &receipt = cached.pedersen_publication;
    if (cached.origin != KernelOrigin::Aot || cached.kernel_name != kernel_name ||
        cached.module == nullptr || cached.function == nullptr ||
        cached.pedersen_publication_event == nullptr ||
        receipt.abi_version != kPedersenPublicationAbiVersion ||
        receipt.flags != kPedersenPublicationRequiredFlags ||
        receipt.globals_state != kPedersenGlobalsPresent ||
        receipt.device_ordinal != static_cast<uint32_t>(device) ||
        receipt.sm_major != static_cast<uint32_t>(sm_major) ||
        receipt.sm_minor != static_cast<uint32_t>(sm_minor) ||
        receipt.pointer_count != 56 || receipt.columns_symbol_bytes != 448 ||
        receipt.rows_symbol_bytes != 4 || receipt.n_rows == 0 ||
        receipt.cache_key != cache_key || receipt.module_token == 0 ||
        receipt.function_token == 0 || receipt.context_token == 0 ||
        receipt.columns_symbol_token == 0 ||
        receipt.rows_symbol_token == 0 || receipt.completion_event_token == 0 ||
        receipt.module_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cached.module)) ||
        receipt.function_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cached.function)) ||
        receipt.context_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(context)) ||
        receipt.completion_event_token != static_cast<uint64_t>(reinterpret_cast<uintptr_t>(
                                                 cached.pedersen_publication_event)) ||
        receipt.columns_symbol_token % alignof(uint64_t) != 0 ||
        receipt.rows_symbol_token % alignof(uint32_t) != 0 ||
        cuEventQuery(cached.pedersen_publication_event) != CUDA_SUCCESS) {
        return false;
    }

    CUdeviceptr columns_symbol = 0;
    CUdeviceptr rows_symbol = 0;
    size_t columns_bytes = 0;
    size_t rows_bytes = 0;
    if (cuModuleGetGlobal(&columns_symbol, &columns_bytes, cached.module,
                          "g_stwo_wit_pedersen_cols") != CUDA_SUCCESS ||
        cuModuleGetGlobal(&rows_symbol, &rows_bytes, cached.module,
                          "g_stwo_wit_pedersen_n_rows") != CUDA_SUCCESS ||
        columns_symbol != receipt.columns_symbol_token ||
        rows_symbol != receipt.rows_symbol_token || columns_bytes != 448 ||
        rows_bytes != 4) {
        return false;
    }

    uint64_t readback_pointers[56] = {};
    uint32_t readback_rows = 0;
    if (cuMemcpyDtoH(readback_pointers, columns_symbol, sizeof(readback_pointers)) !=
            CUDA_SUCCESS ||
        cuMemcpyDtoH(&readback_rows, rows_symbol, sizeof(readback_rows)) != CUDA_SUCCESS ||
        memcmp(readback_pointers, receipt.column_pointers,
               sizeof(readback_pointers)) != 0 ||
        readback_rows != receipt.n_rows) {
        return false;
    }
    *out = receipt;
    return true;
}

static int current_installed_binding(
    void *exec_context,
    uint32_t expected_sm,
    CUcontext *out_context,
    CUstream *out_stream,
    uint32_t *out_device,
    uint32_t *out_sm_major,
    uint32_t *out_sm_minor
) {
    if (exec_context == nullptr || expected_sm == 0 || out_context == nullptr ||
        out_stream == nullptr || out_device == nullptr || out_sm_major == nullptr ||
        out_sm_minor == nullptr) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    cudaError_t runtime_status = cudaFree(nullptr);
    if (runtime_status != cudaSuccess) return static_cast<int>(runtime_status);
    CUcontext context = nullptr;
    CUdevice device = 0;
    int context_device = -1;
    int sm_major = 0;
    int sm_minor = 0;
    void *stream = nullptr;
    CUcontext stream_context = nullptr;
    if (cuCtxGetCurrent(&context) != CUDA_SUCCESS || context == nullptr ||
        cuCtxGetDevice(&device) != CUDA_SUCCESS || device < 0 ||
        stwo_exec_context_device(exec_context, &context_device) != 0 ||
        context_device != static_cast<int>(device) ||
        stwo_exec_context_stream(exec_context, &stream) != 0 || stream == nullptr ||
        cuStreamGetCtx(reinterpret_cast<CUstream>(stream), &stream_context) != CUDA_SUCCESS ||
        stream_context != context ||
        cuDeviceGetAttribute(&sm_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&sm_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
                             device) != CUDA_SUCCESS ||
        sm_major < 0 || sm_minor < 0 ||
        static_cast<uint32_t>(sm_major) * 10u + static_cast<uint32_t>(sm_minor) !=
            expected_sm) {
        return CUDA_ERROR_INVALID_CONTEXT;
    }
    *out_context = context;
    *out_stream = reinterpret_cast<CUstream>(stream);
    *out_device = static_cast<uint32_t>(device);
    *out_sm_major = static_cast<uint32_t>(sm_major);
    *out_sm_minor = static_cast<uint32_t>(sm_minor);
    return CUDA_SUCCESS;
}

static int validate_installed_launch_facts(
    CUdevice device,
    CUfunction function,
    const uint32_t grid[3],
    const uint32_t block[3],
    uint32_t dynamic_shared_bytes
) {
    if (function == nullptr || grid == nullptr || block == nullptr ||
        grid[0] == 0 || grid[1] == 0 || grid[2] == 0 ||
        block[0] == 0 || block[1] == 0 || block[2] == 0) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    int max_threads_function = 0;
    int max_threads_device = 0;
    int max_block[3] = {};
    int max_grid[3] = {};
    if (cuFuncGetAttribute(&max_threads_function,
                           CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
                           function) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&max_threads_device,
                             CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&max_block[0], CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_X,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&max_block[1], CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Y,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&max_block[2], CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Z,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&max_grid[0], CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&max_grid[1], CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Y,
                             device) != CUDA_SUCCESS ||
        cuDeviceGetAttribute(&max_grid[2], CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Z,
                             device) != CUDA_SUCCESS) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    uint64_t threads = static_cast<uint64_t>(block[0]) * block[1] * block[2];
    if (threads > static_cast<uint64_t>(max_threads_function) ||
        threads > static_cast<uint64_t>(max_threads_device)) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    for (unsigned axis = 0; axis < 3; ++axis) {
        if (block[axis] > static_cast<uint32_t>(max_block[axis]) ||
            grid[axis] > static_cast<uint32_t>(max_grid[axis])) {
            return CUDA_ERROR_INVALID_VALUE;
        }
    }
    if (dynamic_shared_bytes != 0) {
        int max_dynamic_shared = 0;
        if (cuFuncGetAttribute(&max_dynamic_shared,
                               CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES,
                               function) != CUDA_SUCCESS ||
            dynamic_shared_bytes > static_cast<uint32_t>(max_dynamic_shared)) {
            return CUDA_ERROR_INVALID_VALUE;
        }
    }
    return CUDA_SUCCESS;
}

static int query_driver_function_attributes(
    CUfunction function,
    StwoCudaFunctionAttributes *out
) {
    if (function == nullptr || out == nullptr) return CUDA_ERROR_INVALID_VALUE;
    *out = StwoCudaFunctionAttributes{};
    int max_threads = 0;
    int registers = 0;
    int binary_version = 0;
    int ptx_version = 0;
    int local_bytes = 0;
    int static_shared_bytes = 0;
    if (cuFuncGetAttribute(&max_threads, CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
                           function) != CUDA_SUCCESS ||
        cuFuncGetAttribute(&registers, CU_FUNC_ATTRIBUTE_NUM_REGS, function) !=
            CUDA_SUCCESS ||
        cuFuncGetAttribute(&binary_version, CU_FUNC_ATTRIBUTE_BINARY_VERSION,
                           function) != CUDA_SUCCESS ||
        cuFuncGetAttribute(&ptx_version, CU_FUNC_ATTRIBUTE_PTX_VERSION, function) !=
            CUDA_SUCCESS ||
        cuFuncGetAttribute(&local_bytes, CU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES,
                           function) != CUDA_SUCCESS ||
        cuFuncGetAttribute(&static_shared_bytes, CU_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES,
                           function) != CUDA_SUCCESS ||
        max_threads < 0 || registers < 0 || binary_version < 0 || ptx_version < 0 ||
        local_bytes < 0 || static_shared_bytes < 0) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    out->abi_version = 1;
    out->max_threads_per_block = static_cast<uint32_t>(max_threads);
    out->registers_per_thread = static_cast<uint32_t>(registers);
    out->binary_version = static_cast<uint32_t>(binary_version);
    out->ptx_version = static_cast<uint32_t>(ptx_version);
    out->local_bytes = static_cast<uint64_t>(local_bytes);
    out->static_shared_bytes = static_cast<uint64_t>(static_shared_bytes);
    return CUDA_SUCCESS;
}

static void fill_installed_receipt(
    const InstalledAotFunction &installed,
    const StwoCudaFunctionAttributes &function,
    uint32_t ownership,
    uint32_t device,
    uint32_t sm_major,
    uint32_t sm_minor,
    StwoCudaInstalledAotFunctionReceipt *out
) {
    *out = StwoCudaInstalledAotFunctionReceipt{};
    out->abi_version = kInstalledAotFunctionAbiVersion;
    out->ownership = ownership;
    out->device_ordinal = device;
    out->sm_major = sm_major;
    out->sm_minor = sm_minor;
    out->argument_count = installed.argument_count;
    out->grid_x = installed.grid[0];
    out->grid_y = installed.grid[1];
    out->grid_z = installed.grid[2];
    out->block_x = installed.block[0];
    out->block_y = installed.block[1];
    out->block_z = installed.block[2];
    out->dynamic_shared_bytes = installed.dynamic_shared_bytes;
    out->context_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(installed.context));
    out->module_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(installed.module));
    out->function_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(installed.function));
    out->stream_token =
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(installed.stream));
    out->function = function;
}

static int create_borrowed_published_function(
    void *exec_context,
    const char *kernel_name,
    uint64_t cache_key,
    uint32_t expected_sm,
    uint64_t expected_module_token,
    uint64_t expected_function_token,
    uint64_t expected_context_token,
    uint32_t argument_count,
    const uint32_t grid[3],
    const uint32_t block[3],
    uint32_t dynamic_shared_bytes,
    void **out_handle,
    StwoCudaInstalledAotFunctionReceipt *out_receipt
) {
    if (kernel_name == nullptr || kernel_name[0] == '\0' ||
        expected_module_token == 0 || expected_function_token == 0 ||
        expected_context_token == 0 || argument_count == 0 ||
        out_handle == nullptr || out_receipt == nullptr) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    *out_handle = nullptr;
    *out_receipt = StwoCudaInstalledAotFunctionReceipt{};
    CUcontext context = nullptr;
    CUstream stream = nullptr;
    uint32_t device = 0;
    uint32_t sm_major = 0;
    uint32_t sm_minor = 0;
    int status = current_installed_binding(exec_context, expected_sm, &context, &stream,
                                           &device, &sm_major, &sm_minor);
    if (status != CUDA_SUCCESS ||
        expected_context_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(context))) {
        return CUDA_ERROR_INVALID_CONTEXT;
    }

    StwoCudaAotFunctionPublication publication{};
    if (!get_live_aot_function_publication(kernel_name, cache_key, &publication) ||
        publication.module_token != expected_module_token ||
        publication.function_token != expected_function_token ||
        publication.context_token != expected_context_token) {
        return CUDA_ERROR_NOT_FOUND;
    }

    JitCache &cache = jit_cache();
    std::lock_guard<std::mutex> guard(cache.mutex);
    auto found = cache.functions.find(JitCacheKey{cache_key, context});
    if (found == cache.functions.end()) return CUDA_ERROR_NOT_FOUND;
    const CachedFunction &cached = found->second;
    if (cached.origin != KernelOrigin::Aot || cached.kernel_name != kernel_name ||
        expected_module_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cached.module)) ||
        expected_function_token !=
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cached.function))) {
        return CUDA_ERROR_NOT_FOUND;
    }
    status = validate_installed_launch_facts(static_cast<CUdevice>(device), cached.function,
                                             grid, block, dynamic_shared_bytes);
    if (status != CUDA_SUCCESS) return status;
    StwoCudaFunctionAttributes function{};
    status = query_driver_function_attributes(cached.function, &function);
    if (status != CUDA_SUCCESS) return status;
    InstalledAotFunction *installed = new (std::nothrow) InstalledAotFunction{
        exec_context,
        context,
        cached.module,
        cached.function,
        stream,
        cache_key,
        expected_sm,
        argument_count,
        {grid[0], grid[1], grid[2]},
        {block[0], block[1], block[2]},
        dynamic_shared_bytes,
        std::string(kernel_name),
    };
    if (installed == nullptr) return CUDA_ERROR_OUT_OF_MEMORY;
    fill_installed_receipt(*installed, function, kInstalledAotBorrowedPublished, device,
                           sm_major, sm_minor, out_receipt);
    *out_handle = installed;
    return CUDA_SUCCESS;
}

static int launch_installed_function(
    InstalledAotFunction *installed,
    void *exec_context,
    void **arguments,
    uint32_t argument_count
) {
    if (installed == nullptr || exec_context == nullptr ||
        exec_context != installed->exec_context || arguments == nullptr ||
        argument_count != installed->argument_count) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    CUcontext context = nullptr;
    CUstream stream = nullptr;
    uint32_t device = 0;
    uint32_t sm_major = 0;
    uint32_t sm_minor = 0;
    int status = current_installed_binding(
        exec_context, installed->expected_sm, &context, &stream, &device, &sm_major,
        &sm_minor);
    if (status != CUDA_SUCCESS || context != installed->context ||
        stream != installed->stream) {
        return CUDA_ERROR_INVALID_CONTEXT;
    }
    CUstreamCaptureStatus capture_status = CU_STREAM_CAPTURE_STATUS_NONE;
    if (cuStreamIsCapturing(stream, &capture_status) != CUDA_SUCCESS ||
        capture_status != CU_STREAM_CAPTURE_STATUS_NONE) {
        return CUDA_ERROR_STREAM_CAPTURE_UNSUPPORTED;
    }

    auto launch = [&]() {
        return static_cast<int>(cuLaunchKernel(
            installed->function, installed->grid[0], installed->grid[1],
            installed->grid[2], installed->block[0], installed->block[1],
            installed->block[2], installed->dynamic_shared_bytes, installed->stream,
            arguments, nullptr));
    };
    JitCache &cache = jit_cache();
    std::lock_guard<std::mutex> guard(cache.mutex);
    auto found = cache.functions.find(JitCacheKey{installed->cache_key, context});
    if (found == cache.functions.end()) return CUDA_ERROR_NOT_FOUND;
    const CachedFunction &cached = found->second;
    if (cached.origin != KernelOrigin::Aot ||
        cached.kernel_name != installed->kernel_name ||
        cached.module != installed->module || cached.function != installed->function) {
        return CUDA_ERROR_NOT_FOUND;
    }
    return launch();
}

static int destroy_installed_function(InstalledAotFunction *installed) {
    if (installed == nullptr) return CUDA_ERROR_INVALID_VALUE;
    delete installed;
    return CUDA_SUCCESS;
}

}  // namespace

extern "C" int stwo_installed_aot_function_borrow_published_create(
    void *exec_context,
    const char *kernel_name,
    uint64_t cache_key,
    uint32_t expected_sm,
    uint64_t expected_module_token,
    uint64_t expected_function_token,
    uint64_t expected_context_token,
    uint32_t argument_count,
    uint32_t grid_x,
    uint32_t grid_y,
    uint32_t grid_z,
    uint32_t block_x,
    uint32_t block_y,
    uint32_t block_z,
    uint32_t dynamic_shared_bytes,
    void **out_handle,
    StwoCudaInstalledAotFunctionReceipt *out_receipt
) {
    const uint32_t grid[3] = {grid_x, grid_y, grid_z};
    const uint32_t block[3] = {block_x, block_y, block_z};
    return create_borrowed_published_function(
        exec_context, kernel_name, cache_key, expected_sm, expected_module_token,
        expected_function_token, expected_context_token, argument_count, grid,
        block, dynamic_shared_bytes, out_handle, out_receipt);
}

extern "C" int stwo_installed_aot_function_launch(
    void *handle,
    void *exec_context,
    void **arguments,
    uint32_t argument_count
) {
    return launch_installed_function(
        reinterpret_cast<InstalledAotFunction *>(handle), exec_context, arguments,
        argument_count);
}

extern "C" int stwo_installed_aot_function_destroy(void *handle) {
    return destroy_installed_function(
        reinterpret_cast<InstalledAotFunction *>(handle));
}

extern "C" void stwo_cuda_jit_set_require_aot(bool required) {
    // Strictness is monotonic. Relaxing it while other proof threads execute
    // would make fallback policy schedule-dependent.
    if (required) close_strict_aot_admission();
}

extern "C" void stwo_cuda_jit_get_aot_stats(StwoCudaJitAotStats *out) {
    if (out == nullptr) return;
    AotCounters &c = aot_counters();
    *out = StwoCudaJitAotStats{
        c.aot_loads.load(std::memory_order_relaxed),
        c.aot_cache_hits.load(std::memory_order_relaxed),
        c.aot_misses.load(std::memory_order_relaxed),
        c.runtime_loads.load(std::memory_order_relaxed),
        c.runtime_cache_hits.load(std::memory_order_relaxed),
        c.strict_rejections.load(std::memory_order_relaxed),
    };
}

extern "C" void stwo_cuda_jit_reset_aot_stats() {
    AotCounters &c = aot_counters();
    c.aot_loads.store(0, std::memory_order_relaxed);
    c.aot_cache_hits.store(0, std::memory_order_relaxed);
    c.aot_misses.store(0, std::memory_order_relaxed);
    c.runtime_loads.store(0, std::memory_order_relaxed);
    c.runtime_cache_hits.store(0, std::memory_order_relaxed);
    c.strict_rejections.store(0, std::memory_order_relaxed);
}

extern "C" bool stwo_cuda_jit_get_aot_function_publication(
    const char *kernel_name,
    uint64_t cache_key,
    StwoCudaAotFunctionPublication *out
) {
    return get_live_aot_function_publication(kernel_name, cache_key, out);
}

extern "C" bool stwo_cuda_jit_get_pedersen_module_publication(
    const char *kernel_name,
    uint64_t cache_key,
    StwoCudaPedersenModulePublication *out
) {
    return get_live_pedersen_publication(kernel_name, cache_key, out);
}

// Compile a kernel into the in-memory function cache (and the disk PTX cache) without
// launching it. The Rust orchestrator precompiles EVERY kernel of a split component
// before launching the first one, so a compile failure can still fall back to the CPU
// lane with an untouched accumulator.
extern "C" bool stwo_cuda_jit_precompile(
    const char *source,
    const char *kernel_name,
    uint64_t cache_key,
    bool relax_opt
) {
    CUfunction function = nullptr;
    return get_or_compile(source, kernel_name, cache_key, relax_opt, &function);
}

// Precompile a batch of kernels (a split component's kernel set, or any independent
// set) into the cache without launching. When STWO_JIT_PARALLEL_COMPILE is enabled
// (default), the batch is compiled across a bounded worker pool — NVRTC is thread-safe
// per-program and get_or_compile serializes only same-key work, so distinct kernels
// compile concurrently. Returns true iff EVERY kernel compiled; on the first failure
// remaining work stops and the caller falls back to the CPU lane exactly as the
// serial precompile loop did. The size governor is respected upstream: each kernel is
// already split and carries its own `relax_opt`, forwarded unchanged here.
//
// The set of populated cache entries is identical to a sequential precompile — the
// compiled artifact is a deterministic function of (source, arch, relax_opt) — so this
// is byte-identical by construction; only compile wall-time changes.
extern "C" bool stwo_cuda_jit_precompile_batch(
    const char *const *sources,
    const char *const *kernel_names,
    const uint64_t *cache_keys,
    const bool *relax_opts,
    uint32_t count
) {
    if (count == 0) return true;
    int requested_device = 0;
    if (cudaGetDevice(&requested_device) != cudaSuccess) return false;

    uint32_t workers = jit_parallel_compile_workers(count);
    if (workers <= 1) {
        for (uint32_t i = 0; i < count; ++i) {
            CUfunction function = nullptr;
            if (!get_or_compile(sources[i], kernel_names[i], cache_keys[i], relax_opts[i],
                                &function)) {
                return false;
            }
        }
        return true;
    }

    std::atomic<uint32_t> next(0);
    std::atomic<bool> ok(true);
    auto worker = [&]() {
        // CUDA device selection is thread-local. Bind every compile worker to
        // the caller's device before it forms the context-scoped cache key.
        if (cudaSetDevice(requested_device) != cudaSuccess) {
            ok.store(false, std::memory_order_relaxed);
            return;
        }
        for (;;) {
            if (!ok.load(std::memory_order_relaxed)) return;
            uint32_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= count) return;
            CUfunction function = nullptr;
            if (!get_or_compile(sources[i], kernel_names[i], cache_keys[i], relax_opts[i],
                                &function)) {
                ok.store(false, std::memory_order_relaxed);
                return;
            }
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(workers);
    for (uint32_t t = 0; t < workers; ++t) pool.emplace_back(worker);
    for (std::thread &th : pool) th.join();
    return ok.load(std::memory_order_relaxed);
}

// Compiles (cached by cache_key = semantic hash mixed with the Rust emitter's
// CODEGEN_VERSION) and launches the fused constraint kernel. Returns true once the
// kernel is enqueued on the legacy default stream; false means nothing was launched
// and the caller must use the CPU lane. No device synchronization happens here: the
// kernel's outputs are only ever consumed by later same-stream work or by
// synchronous D2H copies, both of which the legacy stream orders after this launch.
// `rc_base` is forwarded to the kernel: split kernels accumulate constraint j with
// random_coeff_powers[rc_base + j], the fused kernel passes 0.
extern "C" bool stwo_cuda_jit_eval_fused(
    const char *source,
    const char *kernel_name,
    uint64_t cache_key,
    const uint32_t *trace_values,
    const uint32_t *interaction_offsets,
    const uint32_t *base_params,
    const uint32_t *ext_params,
    const uint32_t *random_coeff_powers,
    const uint32_t *denom_inv,
    uint32_t *coord_0,
    uint32_t *coord_1,
    uint32_t *coord_2,
    uint32_t *coord_3,
    uint32_t row_count,
    uint32_t log_n_rows,
    uint32_t rc_base,
    bool relax_opt
) {
    // Span function resolution through enqueue. A runtime cache hit admitted before
    // strict closure cannot escape this wrapper and launch after admission returns.
    JitOperationAdmission launch_admission;
    CUfunction function = nullptr;
    if (!get_or_compile(source, kernel_name, cache_key, relax_opt, &function)) {
        return false;
    }
    if (row_count == 0) return true;

    void *args[] = {
        (void *)&trace_values, (void *)&interaction_offsets, (void *)&base_params,
        (void *)&ext_params,   (void *)&random_coeff_powers, (void *)&denom_inv,
        (void *)&coord_0,      (void *)&coord_1,             (void *)&coord_2,
        (void *)&coord_3,      (void *)&row_count,           (void *)&log_n_rows,
        (void *)&rc_base,
    };
    const unsigned block = 128;  // must match the generated kernel's __launch_bounds__
    const unsigned grid = ceil_div_nonzero_u32(row_count, block);
    // A launch failure happens before any device write, so returning false here still
    // permits the CPU fallback. After a successful enqueue the kernel updates the
    // accumulator in place; an asynchronous execution fault becomes a sticky context
    // error and aborts the prove at the next checked CUDA call — it must NOT fall
    // back (the accumulator state would be indeterminate), and it cannot, since we
    // already returned true.
    if (cuLaunchKernel(function, grid, 1, 1, block, 1, 1, 0, nullptr, args, nullptr) !=
        CUDA_SUCCESS) {
        fprintf(stderr, "stwo JIT: cuLaunchKernel failed for %s\n", kernel_name);
        return false;
    }
    return true;
}

// Resident explicit-stream form of the constraint launch. Setup has already
// resolved every key against the embedded AOT pack before graph capture; this
// call is allocation-free on a cache hit and never falls back to the default
// stream. The ABI otherwise remains byte-identical to the legacy entry point.
extern "C" bool stwo_cuda_jit_eval_fused_on(
    const char *source,
    const char *kernel_name,
    uint64_t cache_key,
    const uint32_t *trace_values,
    const uint32_t *interaction_offsets,
    const uint32_t *base_params,
    const uint32_t *ext_params,
    const uint32_t *random_coeff_powers,
    const uint32_t *denom_inv,
    uint32_t *coord_0,
    uint32_t *coord_1,
    uint32_t *coord_2,
    uint32_t *coord_3,
    uint32_t row_count,
    uint32_t log_n_rows,
    uint32_t rc_base,
    bool relax_opt,
    void *stream
) {
    // Same admission lifetime as the legacy-stream entry point above.
    JitOperationAdmission launch_admission;
    CUfunction function = nullptr;
    if (!get_or_compile(source, kernel_name, cache_key, relax_opt, &function)) {
        return false;
    }
    if (row_count == 0) return true;
    void *args[] = {
        (void *)&trace_values, (void *)&interaction_offsets, (void *)&base_params,
        (void *)&ext_params,   (void *)&random_coeff_powers, (void *)&denom_inv,
        (void *)&coord_0,      (void *)&coord_1,             (void *)&coord_2,
        (void *)&coord_3,      (void *)&row_count,           (void *)&log_n_rows,
        (void *)&rc_base,
    };
    const unsigned block = 128;
    const unsigned grid = ceil_div_nonzero_u32(row_count, block);
    if (cuLaunchKernel(function, grid, 1, 1, block, 1, 1, 0, (CUstream)stream, args,
                       nullptr) != CUDA_SUCCESS) {
        fprintf(stderr, "stwo resident AOT: cuLaunchKernel failed for %s\n", kernel_name);
        return false;
    }
    return true;
}

// Resident explicit-stream launch for one generated same-domain composition
// wave. The generated kernel bakes in the exact descriptor count and canonical
// call order, so this sibling ABI intentionally has no runtime part-count
// parameter which could drift or silently truncate work. Full-domain rows
// remain the trace stride; shard rows alone size the grid, and each coordinate
// pointer names the start of its disjoint shard-local output.
extern "C" bool stwo_cuda_jit_eval_composition_wave_on(
    const char *source,
    const char *kernel_name,
    uint64_t cache_key,
    const StwoCudaCompositionWavePart *parts,
    const uint32_t *random_coeff_powers,
    uint32_t *coord_0,
    uint32_t *coord_1,
    uint32_t *coord_2,
    uint32_t *coord_3,
    uint32_t full_domain_rows,
    uint32_t shard_start,
    uint32_t shard_rows,
    void *stream
) {
    if (full_domain_rows == 0 || shard_rows == 0 ||
        shard_start >= full_domain_rows ||
        shard_rows > full_domain_rows - shard_start) {
        return false;
    }
    JitOperationAdmission launch_admission;
    CUfunction function = nullptr;
    if (!get_or_compile(source, kernel_name, cache_key, false, &function)) {
        return false;
    }
    void *args[] = {
        (void *)&parts,               (void *)&random_coeff_powers,
        (void *)&coord_0,             (void *)&coord_1,
        (void *)&coord_2,             (void *)&coord_3,
        (void *)&full_domain_rows,     (void *)&shard_start,
        (void *)&shard_rows,
    };
    const unsigned block = 128;
    const unsigned grid = ceil_div_nonzero_u32(shard_rows, block);
    if (cuLaunchKernel(function, grid, 1, 1, block, 1, 1, 0, (CUstream)stream, args,
                       nullptr) != CUDA_SUCCESS) {
        fprintf(stderr, "stwo resident AOT: composition wave launch failed for %s\n",
                kernel_name);
        return false;
    }
    return true;
}

// Witness-JIT lane: compile (cached by cache_key = the witness program's semantic hash
// mixed with WITNESS_CODEGEN_VERSION on the Rust side) and launch a generated per-row
// witness kernel. The ABI is fixed by
// `stwo-backend-cuda::backend::jit_witness::codegen::compile_witness_to_cuda_source`:
//
//   void kernel(const unsigned *const *input_cols,   // [n_inputs][row]
//               const unsigned *const *table_bases,  // deduce_output LUTs, per table
//               const unsigned *table_strides,       // words per key, per table
//               unsigned *const *out_cols,           // [n_cols][row]
//               unsigned *const *mult_counts,        // atomic count tables, per table
//               unsigned *lookup_words,              // [k * row_count + row] word-major
//               unsigned *sub_words,                 // [k * row_count + row] word-major
//               unsigned row_count)
//
// One thread per row; the kernel guards `row >= row_count`. Every pointer table is a
// DEVICE-resident array of device pointers (the pointer-table trace ABI — no flatten
// copies, no u32 length overflow), exactly as the constraint lane passes trace
// pointer tables. block = 256 matches the generated `__launch_bounds__(256)`.
//
// Returns true once the kernel is enqueued on the legacy default stream; false means
// nothing was launched (compile or launch failure) and the caller falls back to the
// host writer with an untouched output. No device synchronization here: the output
// columns are consumed by later same-stream work or synchronous D2H copies. This lane
// is default OFF and pod-gated (STWO_CUDA_WITNESS_JIT); see KNOWN_ISSUES 2 for the
// governor that also protects it from the NVRTC/ptxas cliff.
extern "C" bool stwo_cuda_jit_witness_launch(
    const char *source,
    const char *kernel_name,
    uint64_t cache_key,
    const uint32_t *const *input_cols,
    const uint32_t *const *table_bases,
    const uint32_t *table_strides,
    uint32_t *const *out_cols,
    uint32_t *const *mult_counts,
    uint32_t *lookup_words,
    uint32_t *sub_words,
    uint32_t row_count,
    bool relax_opt,
    // Stage B′: stream to launch on (null = legacy default stream, the pre-B′
    // behaviour). When the caller fans lanes across pool streams it forks each
    // from legacy first and joins it back before any consumer — so a non-null
    // stream here only reorders independent lanes, never their data dependencies.
    void *stream
) {
    // Same admission lifetime as the constraint launch entry points above.
    JitOperationAdmission launch_admission;
    CUfunction function = nullptr;
    if (!get_or_compile(source, kernel_name, cache_key, relax_opt, &function)) {
        return false;
    }
    if (row_count == 0) {
        return true;  // nothing to launch; a 0-row component is a no-op success.
    }

    void *args[] = {
        (void *)&input_cols,   (void *)&table_bases, (void *)&table_strides,
        (void *)&out_cols,     (void *)&mult_counts, (void *)&lookup_words,
        (void *)&sub_words,    (void *)&row_count,
    };
    const unsigned block = 256;  // must match the generated kernel's __launch_bounds__
    const unsigned grid = ceil_div_nonzero_u32(row_count, block);
    if (cuLaunchKernel(function, grid, 1, 1, block, 1, 1, 0, (CUstream)stream, args, nullptr) !=
        CUDA_SUCCESS) {
        fprintf(stderr, "stwo witness-JIT: cuLaunchKernel failed for %s\n", kernel_name);
        return false;
    }
    return true;
}

// Strict-AOT two-phase witness launch. Both functions are resolved before the
// first output-mutating enqueue, then phase 0 and phase 1 are submitted to the
// same stream. The ordinary monolithic launch ABI above remains unchanged.
extern "C" bool stwo_cuda_jit_witness_phase_pair_launch(
    const char *const *kernel_names,
    const uint64_t *cache_keys,
    const uint32_t *const *input_cols,
    const uint32_t *const *table_bases,
    const uint32_t *table_strides,
    uint32_t *const *out_cols,
    uint32_t *const *mult_counts,
    uint32_t *lookup_words,
    uint32_t *sub_words,
    uint32_t *phase_scratch,
    uint32_t row_count,
    void *stream
) {
    if (!require_aot().load(std::memory_order_acquire) || kernel_names == nullptr ||
        cache_keys == nullptr || kernel_names[0] == nullptr || kernel_names[1] == nullptr) {
        return false;
    }

    JitOperationAdmission launch_admission;
    CUfunction functions[2] = {nullptr, nullptr};
    for (unsigned phase = 0; phase < 2; ++phase) {
        // Null source plus strict admission forbids disk PTX and NVRTC. Module
        // loading uses the same get_or_compile path for both phases, including
        // identical per-module witness table-global configuration.
        if (!get_or_compile(nullptr, kernel_names[phase], cache_keys[phase], false,
                            &functions[phase])) {
            return false;
        }
    }

    if (row_count == 0) return true;
    void *args[] = {
        (void *)&input_cols,    (void *)&table_bases,  (void *)&table_strides,
        (void *)&out_cols,      (void *)&mult_counts,  (void *)&lookup_words,
        (void *)&sub_words,     (void *)&phase_scratch, (void *)&row_count,
    };
    const unsigned block = 256;
    const unsigned grid = ceil_div_nonzero_u32(row_count, block);
    for (unsigned phase = 0; phase < 2; ++phase) {
        if (cuLaunchKernel(functions[phase], grid, 1, 1, block, 1, 1, 0,
                           (CUstream)stream, args, nullptr) != CUDA_SUCCESS) {
            fprintf(stderr, "stwo witness phase: cuLaunchKernel failed for %s\n",
                    kernel_names[phase]);
            return false;
        }
    }
    return true;
}
