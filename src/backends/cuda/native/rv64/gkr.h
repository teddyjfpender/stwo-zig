#ifndef STWO_CUDA_RV64_GKR_H
#define STWO_CUDA_RV64_GKR_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
// Coordinate-major device plane. stride is capacity per coordinate; count is
// passed separately. coordinates=1 for base numerators or 8 for OM31.
typedef struct StwoRv64Plane {
    uint32_t* words;
    uint64_t stride;
    uint32_t coordinates;
    uint32_t reserved;
} StwoRv64Plane;
#ifdef __cplusplus
static_assert(sizeof(StwoRv64Plane) == 24 && alignof(StwoRv64Plane) == 8,
              "RV64 plane requires a 64-bit host ABI");
static_assert(offsetof(StwoRv64Plane, stride) == 8 &&
                  offsetof(StwoRv64Plane, coordinates) == 16,
              "RV64 plane offsets");
#endif
// All pointers are borrowed DEVICE allocations in context. No host reads,
// allocation, transfers, synchronization or default-stream dispatch. Caller
// orders readiness and joins before release/publication. Status is sticky and
// must be initialized to zero at ingress and checked after completion.
// active is a device boolean plane; inactive facts are exactly (0,1),
// independent of challenges. Zero weight alone does not mean padding.
// Projection challenges: AoS OM31 [offset, coefficient0, ...]. Tuples: SoA.
int stwo_rv64_gkr_project_on(void* context, uint32_t lane, StwoRv64Plane tuples,
                             StwoRv64Plane weights, StwoRv64Plane active, uint32_t count,
                             uint32_t arity, const uint32_t* challenges, StwoRv64Plane n,
                             StwoRv64Plane d, uint32_t* status);
// levels=1 or 2. Adjacent-pair fraction tree; output numerators are OM31.
int stwo_rv64_gkr_layer_on(void* context, uint32_t lane, StwoRv64Plane n, StwoRv64Plane d,
                           uint32_t count, uint32_t levels, StwoRv64Plane out_n,
                           StwoRv64Plane out_d);
// Half-split MLE fold, NOT adjacent-pair reduction. assignment is AoS OM31.
int stwo_rv64_gkr_fold_on(void* context, uint32_t lane, StwoRv64Plane n, StwoRv64Plane d,
                          uint32_t count, const uint32_t* assignment, StwoRv64Plane out_n,
                          StwoRv64Plane out_d);
// EqEvals.generate(y): (1-y[0])*eq(y[1..],boolean). y is AoS OM31.
int stwo_rv64_gkr_eq_on(void* context, uint32_t lane, const uint32_t* y, uint32_t variables,
                        StwoRv64Plane output);
// Sumcheck raw evaluations at0/2. eq has >=count/4 values. lambda is AoS
// OM31. Both scratch banks need 16*ceil((count/4)/128) u32 words. Output is
// 16 words: coordinate-major two OM31 values. Reduction order is fixed.
int stwo_rv64_gkr_sum_on(void* context, uint32_t lane, StwoRv64Plane n, StwoRv64Plane d,
                         uint32_t count, StwoRv64Plane eq, const uint32_t* lambda,
                         StwoRv64Plane scratch_a, StwoRv64Plane scratch_b,
                         StwoRv64Plane output);
// Opt-in secure-numerator split-grid variant. Same result/geometry/scratch;
// base numerators retain the existing specialized route. No timing claim.
int stwo_rv64_gkr_sum_split_on(void* context, uint32_t lane, StwoRv64Plane n, StwoRv64Plane d,
                               uint32_t count, StwoRv64Plane eq, const uint32_t* lambda,
                               StwoRv64Plane a, StwoRv64Plane b, StwoRv64Plane out);
// Gather the two final N and D rows into32 compact AoS words for proof
// assembly; no complete fold bank needs to cross the device boundary.
int stwo_rv64_gkr_pack_mask_on(void* context, uint32_t lane, StwoRv64Plane n, StwoRv64Plane d,
                               uint32_t* output);
int stwo_rv64_gkr_eq_fused_on(void*, uint32_t, const uint32_t*, uint32_t, StwoRv64Plane);
// Single-oracle sumcheck feedback state: 40 words; seed is native digest[8]
// plus draw count, claim is one OM31. Records are 44 words per round (4 AoS
// coefficients, challenge, trimmed length, ordinal and two reserved zeros).
int stwo_rv64_sumcheck_init_on(void* context, uint32_t lane, uint32_t* state,
                               const uint32_t* seed, const uint32_t* claim, uint32_t variables);
int stwo_rv64_sumcheck_round_on(void* context, uint32_t lane, uint32_t* state,
                                uint32_t variables, uint32_t expected, StwoRv64Plane raw,
                                const uint32_t* point, uint32_t* record);
#ifdef __cplusplus
}
#endif
#endif
