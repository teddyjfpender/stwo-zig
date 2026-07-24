#include "secure_field_support.h"

kernel void fix_first_variable_base_field_u32(
    device const uint *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant StwoMetalQm31 &assignment [[buffer(2)]],
    constant uint &midpoint [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= midpoint) {
        return;
    }

    uint lhs = src[index];
    uint rhs = src[index + midpoint];
    stwo_metal_store_qm31(dst, index, stwo_metal_fold_base_mle_pair(lhs, rhs, assignment));
}

kernel void fix_first_variable_secure_field_u32x4(
    device const uint *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    constant StwoMetalQm31 &assignment [[buffer(2)]],
    constant uint &midpoint [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= midpoint) {
        return;
    }

    StwoMetalQm31 lhs = stwo_metal_load_qm31(src, index);
    StwoMetalQm31 rhs = stwo_metal_load_qm31(src, index + midpoint);
    stwo_metal_store_qm31(dst, index, stwo_metal_fold_secure_mle_pair(lhs, rhs, assignment));
}
