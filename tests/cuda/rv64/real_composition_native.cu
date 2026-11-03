// Link with the same cached AOT objects as the actual composition helper.
// This entry is reused by the persistent native prover; no subprocess/readback.
#include "real_composition_launches.h"
#include "rv64/composition_dispatch.h"
#include "rv64/custody.cuh"
extern "C" int stwo_rv64_composition_role_on(
    void *ctx, uint32_t lane, const StwoRv64CompositionRole *job,
    uint32_t *launches) {
  using namespace stwo::cuda::rv64;
  if (launches) *launches = 0;
  if (!job || !launches || job->reserved || job->role >= 49 ||
      !real_kernels[job->role] || job->trace_log < 3 ||
      job->eval_log < job->trace_log || job->eval_log > 28 ||
      job->eval_log - job->trace_log > 2 || !job->row_count ||
      job->first_row >= (1u << job->eval_log) ||
      job->row_count > (1u << job->eval_log) - job->first_row ||
      !job->constraint_count || job->constraint_count > 65536 ||
      job->parameter_count > 65536 || !job->mask_count || job->mask_count > 65536)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  for (uint32_t tree = 0; tree < 3; ++tree) {
    if (!c.range(job->trees[tree], job->tree_words[tree], false)) return c.status;
  }
  if (!c.range(reinterpret_cast<const uint32_t *>(job->column_offsets), 2 * job->mask_count, false) ||
      !c.range(job->parameters, (job->parameter_count ? 8 * job->parameter_count : 1), false) ||
      !c.range(job->powers, 8 * job->constraint_count, false) ||
      !c.range(job->denominator_inverses, 1u << (job->eval_log - job->trace_log), false) ||
      !c.range(job->output, uint64_t(8) << job->eval_log, true)) return c.status;
  const uint32_t *a = job->trees[0], *b = job->trees[1], *d = job->trees[2],
                 *p = job->parameters, *pw = job->powers, *den = job->denominator_inverses;
  const uint64_t *offsets = job->column_offsets;
  uint32_t *out = job->output, tl = job->trace_log, el = job->eval_log,
           first = job->first_row, count = job->row_count;
  void *args[] = {&a, &b, &d, &offsets, &p, &pw, &den, &out, &tl, &el, &first, &count};
  const uint32_t group_size = real_root_group_sizes[job->role];
  const uint32_t groups = group_size ? (job->constraint_count + group_size - 1) / group_size : 1;
  const int status = int(cudaLaunchKernel(real_kernels[job->role],
      dim3((count + 127) / 128, groups), dim3(128), args, 0, c.stream));
  if (!status) *launches = 1;
  return status;
}
