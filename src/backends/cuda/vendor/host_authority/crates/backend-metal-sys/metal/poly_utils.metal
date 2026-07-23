#include "poly_support.h"

kernel void rescale_m31_values_u32(
    device uint *values [[buffer(0)]],
    constant uint &len [[buffer(1)]],
    constant uint &factor [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= len) {
        return;
    }

    values[index] = stwo_metal_m31_mul(values[index], factor);
}
