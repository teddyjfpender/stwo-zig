#include <metal_stdlib>

using namespace metal;

static uint bit_reverse_index(uint index, uint log_len) {
    uint reversed = 0;
    for (uint bit = 0; bit < log_len; ++bit) {
        reversed = (reversed << 1) | ((index >> bit) & 1u);
    }
    return reversed;
}

static uint coset_index_to_circle_domain_index(uint coset_index, uint log_len) {
    const uint n = 1u << log_len;
    if ((coset_index & 1u) == 0u) {
        return coset_index >> 1u;
    }
    return ((2u * n) - coset_index) >> 1u;
}

kernel void permute_coset_to_circle_domain_bit_reversed_u32(
    device const uint *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant uint &log_len [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    const uint len = 1u << log_len;
    if (index >= len) {
        return;
    }

    const uint circle_index = coset_index_to_circle_domain_index(index, log_len);
    const uint target_index = bit_reverse_index(circle_index, log_len);
    dst[target_index] = src[index];
}
