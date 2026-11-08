#ifndef STWO_CUDA_RV64_DEEP_H
#define STWO_CUDA_RV64_DEEP_H
#include "gkr.h"
// Immutable PCS opening plan. A group contains one point and coefficient
// height. Sources remain compact; only eight weighted aggregate planes per
// group are extended. Metadata is setup, never a proof acceptance authority.
struct StwoRv64DeepSource {
  uint64_t offset;
  uint32_t tree, coefficient_log;
};
struct StwoRv64DeepTerm {
  uint32_t source, group, exponent, reserved;
};
struct StwoRv64DeepGroup {
  uint32_t begin, end, coefficient_log, evaluation_log;
  uint64_t coefficient_offset, evaluation_offset;
};
struct StwoRv64DeepPrepare {
  const uint32_t *trees[4];
  uint64_t tree_words[4];
  const StwoRv64DeepSource *sources;
  const StwoRv64DeepTerm *terms;
  const StwoRv64DeepGroup *groups;
  const uint32_t *points, *values, *alpha;
  uint32_t *weights, *linear, *coefficients, *valid, *status;
  uint64_t coefficient_words;
  uint32_t source_count, term_count, group_count, reserved;
};
struct StwoRv64DeepCombine {
  const StwoRv64DeepGroup *groups;
  const uint32_t *points, *linear, *evaluations, *domain_xy, *valid;
  StwoRv64Plane output;
  uint32_t *status;
  uint64_t evaluation_words;
  uint32_t group_count, output_log, reserved[2];
};
static_assert(sizeof(StwoRv64DeepSource) == 16 &&
                  sizeof(StwoRv64DeepTerm) == 16 &&
                  sizeof(StwoRv64DeepGroup) == 32 &&
                  sizeof(StwoRv64DeepPrepare) == 176 &&
                  sizeof(StwoRv64DeepCombine) == 104,
              "OM31 DEEP ABI");
// Enqueue only. All allocations belong to ctx; mutable ranges cannot alias.
// Grouping/powers and fixed domain must come from the admitted PCS plan.
// valid=0/status!=0 poisons numerical output; enqueue success is not
// acceptance.
extern "C" int stwo_rv64_deep_prepare_on(void *, uint32_t,
                                         const StwoRv64DeepPrepare *);
// Between calls, extend each group's eight coefficient planes through the
// existing base-field LDE, preserving group evaluation offsets and heights.
extern "C" int stwo_rv64_deep_combine_on(void *, uint32_t,
                                         const StwoRv64DeepCombine *);
#endif
