// Native service authority catalog. Linked only when truth residency is enabled.
#include "truth_composition_launches.h"
#include "rv64/composition_dispatch.cuh"
extern "C" int stwo_rv64_truth_composition_role_on(void *ctx,uint32_t lane,
    const StwoRv64CompositionRole *job,uint32_t *launches) {
  if (launches) *launches=0;
  if (!job || !launches || job->role>=7) return int(cudaErrorInvalidValue);
  const auto &catalog=truth_catalog[job->role];
  StwoRv64CompositionRole local=*job;
  local.role=0;
  uint32_t grouping=32;
  for (uint32_t i=0;i<catalog.count;++i) {
    uint32_t issued=0;
    const auto &part=catalog.parts[i];
    const int status=stwo::cuda::rv64::composition_dispatch(ctx,lane,&local,&issued,
        &part.kernel,&grouping,1,part.groups);
    if (status) return status;
    *launches+=issued;
  }
  return 0;
}
