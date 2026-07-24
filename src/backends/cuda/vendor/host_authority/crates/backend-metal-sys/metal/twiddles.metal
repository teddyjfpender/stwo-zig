#include "fields_support.h"

struct StwoMetalTwiddleLevelParams {
    uint initial_x;
    uint initial_y;
    uint step_x;
    uint step_y;
    uint offset;
    uint level_log_size;
};

kernel void precompute_twiddle_level_u32(
    device uint *dst [[buffer(0)]],
    constant StwoMetalTwiddleLevelParams &params [[buffer(1)]],
    uint index [[thread_position_in_grid]]
) {
    if (params.level_log_size == 0u) {
        return;
    }

    const uint level_size = 1u << (params.level_log_size - 1u);
    if (index >= level_size) {
        return;
    }

    StwoMetalCirclePointM31 initial = StwoMetalCirclePointM31 {
        params.initial_x,
        params.initial_y,
    };
    StwoMetalCirclePointM31 step = StwoMetalCirclePointM31 {
        params.step_x,
        params.step_y,
    };
    uint exponent = stwo_metal_bit_reverse_index(index, params.level_log_size - 1u);
    StwoMetalCirclePointM31 twiddle =
        stwo_metal_circle_point_mul(initial, stwo_metal_circle_point_pow(step, exponent));
    dst[params.offset + index] = twiddle.x;
}
