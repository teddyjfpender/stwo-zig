#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Host-safe functions never submit a callback or call CUDA. The caller keeps
 * the context alive and serializes its planner transaction around reserve,
 * snapshot and finish. The runtime arena mutex independently enforces caps.
 * V1 singleton and V2 multi-owner enforcement cannot mix on one device. */
typedef struct StwoCudaOwnerSnapshotV2 {
    uint32_t version, device;
    uint64_t context_identity, ticket, capacity, chunk, small_slab;
    uint64_t global_live_large, global_live_small;
    uint64_t reserved_unused_large, reserved_unused_small;
    uint64_t owner_live_large, owner_live_small;
    uint64_t baseline_large, baseline_small, ceiling_large, ceiling_small;
    uint64_t active_reservations;
    uint64_t stable_live_large, stable_live_small, owner_new_live_large, owner_new_live_small;
    uint32_t entered, ended;
} StwoCudaOwnerSnapshotV2;
int stwo_exec_context_admission_configure_v2(void *, uint64_t);
int stwo_exec_context_admission_reserve_v2(void *, uint64_t, uint64_t, uint64_t, uint64_t, StwoCudaOwnerSnapshotV2 *);
int stwo_exec_context_admission_enter_v2(void *, uint64_t, const char *);
int stwo_exec_context_admission_end_v2(void *, uint64_t, StwoCudaOwnerSnapshotV2 *);
int stwo_exec_context_admission_cancel_v2(void *, uint64_t, uint64_t, StwoCudaOwnerSnapshotV2 *);
int stwo_exec_context_admission_finish_v2(void *, uint64_t, uint64_t, StwoCudaOwnerSnapshotV2 *);
int stwo_exec_context_admission_snapshot_v2(void *, uint64_t, StwoCudaOwnerSnapshotV2 *);
#ifdef __cplusplus
}
static_assert(sizeof(StwoCudaOwnerSnapshotV2) == 176, "owner admission V2 ABI");
#endif
