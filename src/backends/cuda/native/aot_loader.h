#ifndef STWO_ZIG_CUDA_NATIVE_AOT_LOADER_H
#define STWO_ZIG_CUDA_NATIVE_AOT_LOADER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STWO_NATIVE_AOT_FUNCTION_RECEIPT_ABI_VERSION 3u

typedef struct {
    uint64_t aot_loads;
    uint64_t aot_cache_hits;
    uint64_t aot_misses;
    uint64_t launches;
    uint64_t launch_failures;
} StwoNativeAotStats;

typedef struct {
    uint32_t abi_version;
    uint32_t verified;
    uint64_t cubin_bytes;
    uint8_t expected_sha256[32];
    uint8_t observed_sha256[32];
} StwoNativeAotVerificationReceipt;

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
    uint64_t local_bytes;
    uint64_t static_shared_bytes;
    uint64_t cache_key;
    uint64_t context_token;
    uint64_t module_token;
    uint64_t function_token;
    uint64_t stream_token;
    StwoNativeAotVerificationReceipt verification;
} StwoNativeAotFunctionReceipt;

#ifdef __cplusplus
static_assert(sizeof(StwoNativeAotStats) == 40, "AOT stats ABI size");
static_assert(sizeof(StwoNativeAotVerificationReceipt) == 80,
              "AOT verification receipt ABI size");
static_assert(offsetof(StwoNativeAotVerificationReceipt, cubin_bytes) == 8,
              "AOT verification receipt byte-count offset");
static_assert(offsetof(StwoNativeAotVerificationReceipt, expected_sha256) == 16,
              "AOT verification receipt expected-digest offset");
static_assert(offsetof(StwoNativeAotVerificationReceipt, observed_sha256) == 48,
              "AOT verification receipt observed-digest offset");
static_assert(sizeof(StwoNativeAotFunctionReceipt) == 200, "AOT receipt ABI size");
static_assert(offsetof(StwoNativeAotFunctionReceipt, abi_schema) == 4,
              "AOT receipt schema offset");
static_assert(offsetof(StwoNativeAotFunctionReceipt, grid) == 20,
              "AOT receipt grid offset");
static_assert(offsetof(StwoNativeAotFunctionReceipt, local_bytes) == 64,
              "AOT receipt local-byte offset");
static_assert(offsetof(StwoNativeAotFunctionReceipt, cache_key) == 80,
              "AOT receipt cache-key offset");
static_assert(offsetof(StwoNativeAotFunctionReceipt, verification) == 120,
              "AOT receipt verification offset");
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
