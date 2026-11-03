#pragma once
#include <stdint.h>
// Consumes the coordinate-major domain accumulator and writes native
// chunk-major, coordinate-minor compact coefficients. All storage stays owned
// by the selected context through stream completion; no allocation or readback.
extern "C" int stwo_rv64_composition_finalize_on(void *, uint32_t, uint32_t *,
                                                 uint32_t *, uint32_t, uint32_t,
                                                 const uint32_t *, uint32_t,
                                                 uint32_t *);
