// Native CPU authority catalog, reused by the persistent numerical service.
#include "real_composition_launches.h"
#include "rv64/composition_dispatch.cuh"
extern "C" int stwo_rv64_composition_role_on(void *ctx, uint32_t lane,
    const StwoRv64CompositionRole *job, uint32_t *launches) {
  return stwo::cuda::rv64::composition_dispatch(ctx,lane,job,launches,
      real_kernels,real_root_group_sizes,49);
}
