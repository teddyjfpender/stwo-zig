#ifndef STWO_CUDA_RV64_OUTER_FS_OPS_H
#define STWO_CUDA_RV64_OUTER_FS_OPS_H
#include <stdint.h>

// Enqueue on the context lane, without allocating or synchronizing. Inputs are
// two contiguous OM31 elements z, alpha (16 canonical M31 coordinates). Output
// matches Witness.Elements: z, alpha^0, ..., alpha^5 (56 coordinates). Status
// is caller-initialized device memory: bit 0 latches a noncanonical input and
// existing bits are preserved. On invalid input the output is not written.
// All ranges must be live, disjoint allocations in this context; the owner
// must additionally validate its generation/scope handles before calling.
extern "C" int stwo_rv64_outer_fs_lookup_params_on(void* context, uint32_t lane,
                                                  const uint32_t* z_alpha,
                                                  uint32_t* params,
                                                  uint32_t* status);
#endif
