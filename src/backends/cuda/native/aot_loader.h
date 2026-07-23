#ifndef STWO_ZIG_CUDA_NATIVE_AOT_LOADER_H
#define STWO_ZIG_CUDA_NATIVE_AOT_LOADER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t aot_loads;
    uint64_t aot_cache_hits;
    uint64_t aot_misses;
    uint64_t launches;
    uint64_t launch_failures;
} StwoNativeAotStats;

typedef struct {
    uint32_t abi_version;
    uint32_t abi_schema;
    uint32_t device_ordinal;
    uint32_t sm_major;
    uint32_t sm_minor;
    uint32_t grid[3];
    uint32_t block[3];
    uint32_t dynamic_shared_bytes;
    uint32_t argument_count;
    uint32_t registers_per_thread;
    uint32_t max_threads_per_block;
    uint32_t binary_version;
    uint64_t cache_key;
    uint64_t context_token;
    uint64_t module_token;
    uint64_t function_token;
    uint64_t stream_token;
} StwoNativeAotFunctionReceipt;

#ifdef __cplusplus
static_assert(sizeof(StwoNativeAotStats) == 40, "AOT stats ABI size");
static_assert(sizeof(StwoNativeAotFunctionReceipt) == 104, "AOT receipt ABI size");
static_assert(offsetof(StwoNativeAotFunctionReceipt, abi_schema) == 4,
              "AOT receipt schema offset");
static_assert(offsetof(StwoNativeAotFunctionReceipt, grid) == 20,
              "AOT receipt grid offset");
static_assert(offsetof(StwoNativeAotFunctionReceipt, cache_key) == 64,
              "AOT receipt cache-key offset");
#endif

int stwo_native_aot_loader_create(void *exec_context, void **out_loader);
int stwo_native_aot_loader_destroy(void *loader);

int stwo_native_aot_function_bind(
    void *loader,
    uint64_t cache_key,
    uint32_t abi_schema,
    const char *kernel_name,
    const uint32_t grid[3],
    const uint32_t block[3],
    uint32_t dynamic_shared_bytes,
    uint32_t argument_count,
    void **out_function,
    StwoNativeAotFunctionReceipt *out_receipt);

int stwo_native_aot_function_launch(
    void *function,
    void *const *arguments,
    uint32_t argument_count);

int stwo_native_aot_function_destroy(void *function);
int stwo_native_aot_loader_stats(void *loader, StwoNativeAotStats *out_stats);

#ifdef __cplusplus
}
#endif

#endif
