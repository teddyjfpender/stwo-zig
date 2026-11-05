#ifndef STWO_CUDA_RV64_FRI_H
#define STWO_CUDA_RV64_FRI_H
#include "pcs.h"
struct StwoRv64FriOpen {
  StwoRv64Plane input;
  const uint32_t *tree, *queries;
  uint32_t *values, *paths, *status;
  uint64_t tree_words, value_words, path_words;
  uint32_t count, query_count, fold_step, leaf_log, shift, reserved;
};
static_assert(sizeof(StwoRv64FriOpen) == 112, "FRI opening ABI");
// Domain-prefixed native Blake2s tree, level-packed from leaves to root.
// Exact node count is 2*(count >> leaf_log)-1. Input is coordinate-major OM31.
extern "C" int stwo_rv64_fri_tree_on(void *, uint32_t, StwoRv64Plane, uint32_t,
                                     uint32_t, uint32_t *, uint64_t);
// Actual profiles use terminal degree bound zero. Validate every evaluation
// is the same canonical OM31 value before publishing its one coefficient.
extern "C" int stwo_rv64_fri_terminal_on(void *, uint32_t, StwoRv64Plane,
                                         uint32_t, uint32_t *, uint32_t *);
// Gather full folding cosets and leaf sibling paths for raw global queries.
// Sorting/deduplication is serialization after final GPU completion, with no
// numeric feedback. No full column/tree readback is necessary.
extern "C" int stwo_rv64_fri_open_on(void *, uint32_t, const StwoRv64FriOpen *);
#endif
