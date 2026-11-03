#pragma once
#include <stdint.h>
// AOT catalog selection is structural metadata admitted by the caller. Numeric
// arrays stay borrowed under this execution context until the lane joins.
struct StwoRv64CompositionRole {
  uint32_t role, trace_log, eval_log, first_row, row_count, reserved;
  const uint32_t *trees[3];
  uint64_t tree_words[3];
  const uint64_t *column_offsets;
  uint64_t mask_count;
  const uint32_t *parameters;
  uint64_t parameter_count;
  const uint32_t *powers;
  uint64_t constraint_count;
  const uint32_t *denominator_inverses;
  uint32_t *output;
};
extern "C" int stwo_rv64_composition_role_on(void *, uint32_t,
    const StwoRv64CompositionRole *, uint32_t *);
