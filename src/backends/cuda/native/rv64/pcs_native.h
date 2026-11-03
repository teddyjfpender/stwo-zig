#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define STWO_RV64_PCS_NATIVE_VERSION 1u
#define STWO_RV64_PCS_SECTIONS 17u
typedef struct StwoRv64HostWords {
  const uint32_t *words;
  uint64_t count;
} StwoRv64HostWords;
typedef struct StwoRv64PcsNativeRequest {
  uint32_t version;
  uint32_t section_count;
  StwoRv64HostWords sections[STWO_RV64_PCS_SECTIONS];
  const struct StwoRv64PcsColumn *coefficients;
  uint64_t coefficient_count;
  uint32_t scope[8];
} StwoRv64PcsNativeRequest;
typedef struct StwoRv64PcsColumn {
  uint32_t kind; // 0 borrowed host coefficients; 1 retained device coefficients
  uint32_t coefficient_log;
  const uint32_t *words;
  uint64_t count;
  uint64_t context_token;
  uint64_t generation;
} StwoRv64PcsColumn;
typedef struct StwoRv64GpuLease {
  uint64_t context_token;
  uint64_t generation;
  uint32_t *words;
  uint64_t count;
  uint32_t kind; // 0 scratch, 1 MAIN trace, 2 coefficients, 3 narrow binding, 4 immutable setup
  uint32_t reserved;
} StwoRv64GpuLease;
typedef int (*StwoRv64GpuCallback)(void *native_context, uint64_t context_token,
                                   void *user);
typedef struct StwoRv64PcsNativeResult {
  const uint32_t *words;
  uint64_t count;
  uint64_t device_ns;
  uint64_t requested_bytes;
  uint64_t retained_bytes;
  void *owner;
} StwoRv64PcsNativeResult;
// The service thread owns the CUDA context. Callers may be distinct native
// prover workers; all input spans are borrowed until prove synchronously joins.
int stwo_rv64_pcs_native_create(uint32_t device, uint64_t byte_cap, void **out);
int stwo_rv64_pcs_native_prove(void *, const StwoRv64PcsNativeRequest *,
                               StwoRv64PcsNativeResult *);
void stwo_rv64_pcs_native_release(StwoRv64PcsNativeResult *);
int stwo_rv64_pcs_native_destroy(void *);
const char *stwo_rv64_pcs_native_error(void *);
// All callbacks execute on the persistent native CUDA context owner thread.
// Lease operations below are called INSIDE such a callback, not independently.
int stwo_rv64_gpu_session_submit(void *, StwoRv64GpuCallback, void *user);
int stwo_rv64_gpu_lease_allocate(void *, uint64_t words, uint32_t kind,
                                 const uint32_t scope[8], StwoRv64GpuLease *);
int stwo_rv64_gpu_lease_validate(void *, const StwoRv64GpuLease *,
                                 const uint32_t scope[8]);
// Owner-thread only. Promote an exact live lease from provisional MAIN scope
// to the scope containing the newly computed commitment. No pointer, kind,
// generation or extent changes; a failed validation leaves the record intact.
int stwo_rv64_gpu_lease_rebind(void *, const StwoRv64GpuLease *,
                               const uint32_t from[8], const uint32_t to[8]);
int stwo_rv64_gpu_lease_release(void *, StwoRv64GpuLease *);
int stwo_rv64_gpu_lease_validate_range(void *, const uint32_t *, uint64_t words,
                                     uint64_t context_token, uint64_t generation,
                                     const uint32_t scope[8]);
int stwo_rv64_gpu_immutable_bind(void *, const StwoRv64GpuLease *, const uint32_t setup[8], const uint32_t request_scope[8]);
int stwo_rv64_gpu_immutable_unbind_scope(void *, const uint32_t scope[8]);
int stwo_rv64_gpu_session_live_leases(void *, uint64_t counts[5], uint64_t *bytes);
#ifdef __cplusplus
}
static_assert(sizeof(StwoRv64HostWords) == 16, "host span ABI");
static_assert(sizeof(StwoRv64PcsNativeResult) == 48, "result ABI");
static_assert(sizeof(StwoRv64GpuLease) == 40 && sizeof(StwoRv64PcsColumn) == 40,
              "device lease ABI");
#endif
