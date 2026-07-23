#pragma once

#include "fields_support.h"

static inline uint stwo_metal_get_circle_twiddle(device const uint *twiddles, uint index) {
    uint k = index >> 2u;
    uint slot = index & 3u;
    if (slot == 0u) {
        return twiddles[2u * k + 1u];
    }
    if (slot == 1u) {
        return stwo_metal_m31_neg(twiddles[2u * k + 1u]);
    }
    if (slot == 2u) {
        return stwo_metal_m31_neg(twiddles[2u * k]);
    }
    return twiddles[2u * k];
}
