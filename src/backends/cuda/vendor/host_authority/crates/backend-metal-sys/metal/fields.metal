#include "fields_support.h"

kernel void invert_m31_values_u32(
    device uint *values [[buffer(0)]],
    constant uint &len [[buffer(1)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= len) {
        return;
    }

    values[index] = stwo_metal_m31_inv(values[index]);
}
