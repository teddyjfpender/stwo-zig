#pragma once
#include <stdint.h>
// Consumes the coordinate-major domain accumulator and writes native
// chunk-major, coordinate-minor compact coefficients. All storage stays owned
// by the selected context through stream completion; no allocation or readback.
extern "C" int stwo_rv64_composition_finalize_on(void *, uint32_t, uint32_t *,
                                                 uint32_t *, uint32_t, uint32_t,
                                                 const uint32_t *, uint32_t,
                                                 uint32_t *);

// Add a smaller coordinate-major accumulator on the global lifted domain.
// Requires disjoint, context-owned canonical M31 storage; no allocation/readback.
extern "C" int stwo_rv64_composition_lift_add_on(
    void *, uint32_t, const uint32_t *, uint32_t, uint32_t *, uint32_t,
    uint32_t *);

struct StwoRv64CompositionBucket {
  const uint32_t *words;
  uint32_t log, reserved;
};
// Complete resident composition after AOT role evaluation: zero one global
// accumulator, merge all independently sized buckets, interpolate and split.
// Every range is validated before the first enqueue. No host field arithmetic.
extern "C" int stwo_rv64_composition_finish_on(
    void *, uint32_t, const StwoRv64CompositionBucket *, uint32_t,
    uint32_t *, uint32_t *, uint32_t, uint32_t, const uint32_t *, uint32_t,
    uint32_t *);

// Checked transcript-derived half-coset carry metadata, [half][log][8].
// Output is IR-ordered first,second,carry[8], each a column of 2^log rows.
extern "C" int stwo_rv64_composition_auxiliary_on(void *, uint32_t,
    const uint32_t *, uint32_t *, uint32_t, uint32_t *);
