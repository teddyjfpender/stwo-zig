#pragma once
#include <stddef.h>
#include <stdint.h>
struct StwoRv64CurveWitness {
  const uint32_t *inputs;
  uint32_t *main;
  uint32_t *byte_counts;
  uint32_t *status;
  uint64_t input_words, main_words;
  uint32_t calls, first_id, log, kind;
};
extern "C" int stwo_rv64_curve_witness_on(void *, uint32_t,
                                          const StwoRv64CurveWitness *);

static_assert(sizeof(StwoRv64CurveWitness) == 64);
static_assert(offsetof(StwoRv64CurveWitness, input_words) == 32);
static_assert(offsetof(StwoRv64CurveWitness, kind) == 60);
