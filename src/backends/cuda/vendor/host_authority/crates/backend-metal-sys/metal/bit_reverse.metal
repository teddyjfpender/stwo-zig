#include <metal_stdlib>

using namespace metal;

static uint bit_reverse_index(uint index, uint log_len) {
    uint reversed = 0;
    for (uint bit = 0; bit < log_len; ++bit) {
        reversed = (reversed << 1) | ((index >> bit) & 1u);
    }
    return reversed;
}

kernel void bit_reverse_u32(
    device uint *values [[buffer(0)]],
    constant uint &log_len [[buffer(1)]],
    uint index [[thread_position_in_grid]]
) {
    const uint len = 1u << log_len;
    if (index >= len) {
        return;
    }

    const uint reversed = bit_reverse_index(index, log_len);
    if (reversed > index) {
        const uint tmp = values[index];
        values[index] = values[reversed];
        values[reversed] = tmp;
    }
}

kernel void bit_reverse_u32x4(
    device uint *values [[buffer(0)]],
    constant uint &log_len [[buffer(1)]],
    uint index [[thread_position_in_grid]]
) {
    const uint len = 1u << log_len;
    if (index >= len) {
        return;
    }

    const uint reversed = bit_reverse_index(index, log_len);
    if (reversed > index) {
        const uint src_base = index * 4u;
        const uint dst_base = reversed * 4u;
        const uint4 tmp = uint4(
            values[src_base + 0u],
            values[src_base + 1u],
            values[src_base + 2u],
            values[src_base + 3u]
        );
        values[src_base + 0u] = values[dst_base + 0u];
        values[src_base + 1u] = values[dst_base + 1u];
        values[src_base + 2u] = values[dst_base + 2u];
        values[src_base + 3u] = values[dst_base + 3u];
        values[dst_base + 0u] = tmp.x;
        values[dst_base + 1u] = tmp.y;
        values[dst_base + 2u] = tmp.z;
        values[dst_base + 3u] = tmp.w;
    }
}
