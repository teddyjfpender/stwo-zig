#ifndef STWO_CUDA_RV64_SAMPLES_H
#define STWO_CUDA_RV64_SAMPLES_H
#include "deep.h"
struct StwoRv64PointRecipe {
  uint32_t offset_x, offset_y, folds, coefficient_log;
};
struct StwoRv64SamplePoints {
  const uint32_t *parameter;
  const StwoRv64PointRecipe *recipes;
  // points[0] is the common base point, points[1..] are shifted sample points.
  uint32_t *points, *factors, *ready, *status;
  uint32_t count, reserved;
};
struct StwoRv64SampleEvaluation {
  const uint32_t *trees[4];
  uint64_t tree_words[4];
  const StwoRv64DeepSource *sources;
  const StwoRv64DeepTerm *terms;
  const StwoRv64PointRecipe *recipes;
  const uint32_t *factors, *point_ready;
  uint32_t *scratch_a, *scratch_b, *values, *valid, *status;
  uint64_t scratch_words, value_words;
  uint32_t source_count, term_capacity, group_count;
  uint32_t first, count, coefficient_log;
};
static_assert(sizeof(StwoRv64PointRecipe) == 16 &&
                  sizeof(StwoRv64SamplePoints) == 56 &&
                  sizeof(StwoRv64SampleEvaluation) == 184,
              "OM31 OODS sampling ABI");
// Recipes are independently derived setup, not producer-declared authority.
// factors are AoS OM31 [sample][28], in coefficient-bit order y,x,T2(x),...
// ready[0] binds the base-point derivation; ready[1..] qualify shifted points.
extern "C" int stwo_rv64_sample_points_on(void *, uint32_t,
                                          const StwoRv64SamplePoints *);
// Uniform coefficient-height batch; term output slots are contiguous and
// disjoint. Scratch is ceil(2^coefficient_log/1024)*count*8 words per bank.
// Sample values are AoS OM31 in original term order, suitable for DEEP.
extern "C" int stwo_rv64_sample_evaluate_on(void *, uint32_t,
                                            const StwoRv64SampleEvaluation *);
#endif
