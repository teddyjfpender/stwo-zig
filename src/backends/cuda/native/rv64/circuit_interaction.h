#pragma once
#include <stdint.h>
struct StwoCircuitOm31Fractions {
  const uint32_t *fixed, *main, *parameters;
  uint32_t *numerators, *denominators, *status;
  uint64_t fixed_words, main_words, numerator_words, denominator_words;
  uint32_t component, row_log, reserved[2];
};
static_assert(sizeof(StwoCircuitOm31Fractions)==96,"OM31 circuit fractions ABI");
// parameters: z then six powers of alpha, each canonical OM31 (8 words).
// Paired N/D planes are pair-major, coordinate-major, physical rows contiguous.
// Completion is the native cumulative-per-batch LogUp pipeline, not inverse
// witness publication. No public lookup closure is accepted by this formatter.
extern "C" int stwo_circuit_om31_fractions_on(void*,uint32_t,const StwoCircuitOm31Fractions*);
