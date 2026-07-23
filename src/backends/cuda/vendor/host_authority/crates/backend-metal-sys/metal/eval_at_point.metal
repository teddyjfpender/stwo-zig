#include "secure_field_support.h"

static inline StwoMetalQm31 stwo_metal_load_qm31_packed(device const uint *values, uint index) {
    uint base = index * 4u;
    return StwoMetalQm31 {
        values[base + 0u],
        values[base + 1u],
        values[base + 2u],
        values[base + 3u],
    };
}

static inline void stwo_metal_store_qm31_packed(device uint *values, uint index, StwoMetalQm31 value) {
    uint base = index * 4u;
    values[base + 0u] = value.a;
    values[base + 1u] = value.b;
    values[base + 2u] = value.c;
    values[base + 3u] = value.d;
}

kernel void batch_eval_at_point_first_pass_u32(
    device const uint *flat_coeffs [[buffer(0)]],
    device const uint *factors [[buffer(1)]],
    device uint *temp [[buffer(2)]],
    constant uint &coeffs_log_len [[buffer(3)]],
    constant uint &blocks_per_poly [[buffer(4)]],
    uint2 threadgroup_pos [[threadgroup_position_in_grid]],
    uint tid [[thread_index_in_threadgroup]]
) {
    threadgroup uint coeffs[512];
    threadgroup StwoMetalQm31 level[256];

    const uint poly_idx = threadgroup_pos.y;
    const uint block_idx = threadgroup_pos.x;
    const uint coeffs_size = 1u << coeffs_log_len;
    const uint local_coeffs_size = coeffs_log_len > 9u ? 512u : coeffs_size;
    const uint poly_offset = poly_idx * coeffs_size;
    const uint block_offset = block_idx * 512u;

    if (tid < 256u) {
        const uint lhs_index = tid;
        const uint rhs_index = tid + 256u;
        coeffs[lhs_index] =
            lhs_index < local_coeffs_size ? flat_coeffs[poly_offset + block_offset + lhs_index] : 0u;
        coeffs[rhs_index] =
            rhs_index < local_coeffs_size ? flat_coeffs[poly_offset + block_offset + rhs_index] : 0u;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    uint level_size = local_coeffs_size >> 1u;
    int factor_idx = (int)coeffs_log_len - 1;

    if (tid < level_size) {
        const uint alpha = coeffs[2u * tid];
        const uint beta = coeffs[2u * tid + 1u];
        const StwoMetalQm31 factor = stwo_metal_load_qm31_packed(factors, (uint)factor_idx);
        level[tid] = StwoMetalQm31 {
            stwo_metal_m31_add(stwo_metal_m31_mul(beta, factor.a), alpha),
            stwo_metal_m31_mul(beta, factor.b),
            stwo_metal_m31_mul(beta, factor.c),
            stwo_metal_m31_mul(beta, factor.d),
        };
    }
    factor_idx -= 1;
    level_size >>= 1u;

    while (level_size > 0u) {
        threadgroup_barrier(mem_flags::mem_threadgroup);
        StwoMetalQm31 lhs = StwoMetalQm31 { 0u, 0u, 0u, 0u };
        StwoMetalQm31 rhs = StwoMetalQm31 { 0u, 0u, 0u, 0u };
        if (tid < level_size) {
            lhs = level[2u * tid];
            rhs = level[2u * tid + 1u];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
        if (tid < level_size) {
            const StwoMetalQm31 factor = stwo_metal_load_qm31_packed(factors, (uint)factor_idx);
            level[tid] = stwo_metal_qm31_add(lhs, stwo_metal_qm31_mul(rhs, factor));
        }
        factor_idx -= 1;
        level_size >>= 1u;
    }

    if (tid == 0u) {
        const uint output_index = poly_idx * blocks_per_poly + block_idx;
        stwo_metal_store_qm31_packed(temp, output_index, level[0]);
    }
}

// Indirect variant: reads polynomial coefficients through GPU virtual addresses
// instead of a flat concatenated buffer.  Each entry in `coeff_addrs` is the
// gpuAddress of a separate polynomial's coefficient MTLBuffer.  This avoids the
// CPU-side memcpy needed to build the flat staging buffer.
kernel void batch_eval_at_point_first_pass_indirect_u32(
    device const uint64_t *coeff_addrs [[buffer(0)]],
    device const uint *factors [[buffer(1)]],
    device uint *temp [[buffer(2)]],
    constant uint &coeffs_log_len [[buffer(3)]],
    constant uint &blocks_per_poly [[buffer(4)]],
    uint2 threadgroup_pos [[threadgroup_position_in_grid]],
    uint tid [[thread_index_in_threadgroup]]
) {
    threadgroup uint coeffs[512];
    threadgroup StwoMetalQm31 level[256];

    const uint poly_idx = threadgroup_pos.y;
    const uint block_idx = threadgroup_pos.x;
    const uint coeffs_size = 1u << coeffs_log_len;
    const uint local_coeffs_size = coeffs_log_len > 9u ? 512u : coeffs_size;
    const uint block_offset = block_idx * 512u;

    // Resolve the GPU virtual address for this polynomial's coefficient buffer.
    device const uint *poly_coeffs = (device const uint *)coeff_addrs[poly_idx];

    if (tid < 256u) {
        const uint lhs_index = tid;
        const uint rhs_index = tid + 256u;
        coeffs[lhs_index] =
            lhs_index < local_coeffs_size ? poly_coeffs[block_offset + lhs_index] : 0u;
        coeffs[rhs_index] =
            rhs_index < local_coeffs_size ? poly_coeffs[block_offset + rhs_index] : 0u;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    uint level_size = local_coeffs_size >> 1u;
    int factor_idx = (int)coeffs_log_len - 1;

    if (tid < level_size) {
        const uint alpha = coeffs[2u * tid];
        const uint beta = coeffs[2u * tid + 1u];
        const StwoMetalQm31 factor = stwo_metal_load_qm31_packed(factors, (uint)factor_idx);
        level[tid] = StwoMetalQm31 {
            stwo_metal_m31_add(stwo_metal_m31_mul(beta, factor.a), alpha),
            stwo_metal_m31_mul(beta, factor.b),
            stwo_metal_m31_mul(beta, factor.c),
            stwo_metal_m31_mul(beta, factor.d),
        };
    }
    factor_idx -= 1;
    level_size >>= 1u;

    while (level_size > 0u) {
        threadgroup_barrier(mem_flags::mem_threadgroup);
        StwoMetalQm31 lhs = StwoMetalQm31 { 0u, 0u, 0u, 0u };
        StwoMetalQm31 rhs = StwoMetalQm31 { 0u, 0u, 0u, 0u };
        if (tid < level_size) {
            lhs = level[2u * tid];
            rhs = level[2u * tid + 1u];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
        if (tid < level_size) {
            const StwoMetalQm31 factor = stwo_metal_load_qm31_packed(factors, (uint)factor_idx);
            level[tid] = stwo_metal_qm31_add(lhs, stwo_metal_qm31_mul(rhs, factor));
        }
        factor_idx -= 1;
        level_size >>= 1u;
    }

    if (tid == 0u) {
        const uint output_index = poly_idx * blocks_per_poly + block_idx;
        stwo_metal_store_qm31_packed(temp, output_index, level[0]);
    }
}


kernel void batch_eval_at_point_reduce_u32(
    device const uint *src [[buffer(0)]],
    device const uint *factors [[buffer(1)]],
    device uint *dst [[buffer(2)]],
    constant uint &input_stride [[buffer(3)]],
    constant uint &output_stride [[buffer(4)]],
    constant uint &factor_offset [[buffer(5)]],
    uint2 threadgroup_pos [[threadgroup_position_in_grid]],
    uint tid [[thread_index_in_threadgroup]]
) {
    threadgroup StwoMetalQm31 level[512];

    const uint poly_idx = threadgroup_pos.y;
    const uint block_idx = threadgroup_pos.x;
    const uint local_input_size = input_stride > 512u ? 512u : input_stride;
    const uint poly_offset = poly_idx * input_stride;
    const uint block_offset = block_idx * 512u;

    if (tid < 256u) {
        const uint lhs_index = tid;
        const uint rhs_index = tid + 256u;
        level[lhs_index] =
            lhs_index < local_input_size
                ? stwo_metal_load_qm31_packed(src, poly_offset + block_offset + lhs_index)
                : StwoMetalQm31 { 0u, 0u, 0u, 0u };
        level[rhs_index] =
            rhs_index < local_input_size
                ? stwo_metal_load_qm31_packed(src, poly_offset + block_offset + rhs_index)
                : StwoMetalQm31 { 0u, 0u, 0u, 0u };
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    uint level_size = local_input_size >> 1u;
    int current_factor = (int)factor_offset;
    while (level_size > 0u) {
        threadgroup_barrier(mem_flags::mem_threadgroup);
        StwoMetalQm31 lhs = StwoMetalQm31 { 0u, 0u, 0u, 0u };
        StwoMetalQm31 rhs = StwoMetalQm31 { 0u, 0u, 0u, 0u };
        if (tid < level_size) {
            lhs = level[2u * tid];
            rhs = level[2u * tid + 1u];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
        if (tid < level_size) {
            const StwoMetalQm31 factor = stwo_metal_load_qm31_packed(factors, (uint)current_factor);
            level[tid] = stwo_metal_qm31_add(lhs, stwo_metal_qm31_mul(rhs, factor));
        }
        current_factor -= 1;
        level_size >>= 1u;
    }

    if (tid == 0u) {
        const uint output_index = poly_idx * output_stride + block_idx;
        stwo_metal_store_qm31_packed(dst, output_index, level[0]);
    }
}

kernel void batch_eval_at_point_finalize_u32(
    device const uint *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant uint &src_stride [[buffer(2)]],
    constant uint &n_polys [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= n_polys) {
        return;
    }

    const StwoMetalQm31 value = stwo_metal_load_qm31_packed(src, index * src_stride);
    stwo_metal_store_qm31_packed(dst, index, value);
}
