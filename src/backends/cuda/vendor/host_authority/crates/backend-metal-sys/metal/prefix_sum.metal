#include "fields_support.h"

kernel void prefix_sum_circle_domain_order_to_coset_order_u32(
    device const uint *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant uint &len [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    uint half_len = len >> 1u;
    if (index >= half_len) {
        return;
    }

    dst[index * 2u] = src[index];
    dst[index * 2u + 1u] = src[len - 1u - index];
}

kernel void prefix_sum_coset_order_to_circle_domain_order_u32(
    device const uint *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant uint &len [[buffer(2)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= len) {
        return;
    }

    uint half_len = len >> 1u;
    if (index < half_len) {
        dst[index] = src[index << 1u];
    } else {
        uint i = index - half_len;
        dst[index] = src[len - 1u - (i << 1u)];
    }
}

kernel void prefix_sum_inclusive_step_u32(
    device const uint *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant uint &len [[buffer(2)]],
    constant uint &stride [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= len) {
        return;
    }

    uint value = src[index];
    if (index >= stride) {
        value = stwo_metal_m31_add(value, src[index - stride]);
    }
    dst[index] = value;
}

/// Parallel tree reduction of M31 values.
///
/// Grid: 1D, single threadgroup of up to 1024 threads.
/// Each thread sums a chunk of elements, then tree-reduce in threadgroup memory.
/// Output: single M31 sum at output[0].
kernel void reduce_sum_m31(
    device const uint *input [[buffer(0)]],
    device uint *output [[buffer(1)]],
    constant uint &n_elements [[buffer(2)]],
    uint tid [[thread_index_in_threadgroup]],
    uint tg_size [[threads_per_threadgroup]]
) {
    threadgroup uint shared[1024];

    uint chunk = (n_elements + tg_size - 1) / tg_size;
    uint start = tid * chunk;
    uint end = min(start + chunk, n_elements);

    uint local_sum = 0;
    for (uint i = start; i < end; i++) {
        local_sum = stwo_metal_m31_add(local_sum, input[i]);
    }
    shared[tid] = local_sum;

    for (uint stride = tg_size / 2; stride > 0; stride /= 2) {
        threadgroup_barrier(mem_flags::mem_threadgroup);
        if (tid < stride) {
            shared[tid] = stwo_metal_m31_add(shared[tid], shared[tid + stride]);
        }
    }

    if (tid == 0) {
        output[0] = shared[0];
    }
}

/// Sequential inclusive prefix sum with constant subtraction.
///
/// Grid: 1D with exactly 1 thread.
/// For each element: subtract cumsum_shift, accumulate running sum, write back.
/// The win comes from avoiding the GPU→CPU→GPU data transfer (~8MB readback
/// + ~8MB upload per column), not from parallelizing the O(n) scan.
kernel void prefix_sum_subtract_m31(
    device uint *data [[buffer(0)]],
    constant uint &cumsum_shift [[buffer(1)]],
    constant uint &n_elements [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid != 0) return;

    uint running_sum = 0;
    for (uint i = 0; i < n_elements; i++) {
        uint val = stwo_metal_m31_sub(data[i], cumsum_shift);
        running_sum = stwo_metal_m31_add(running_sum, val);
        data[i] = running_sum;
    }
}
