#include "secure_field_support.h"

kernel void pack_secure_column_coords_u32x4(
    device const uint *coord_0 [[buffer(0)]],
    device const uint *coord_1 [[buffer(1)]],
    device const uint *coord_2 [[buffer(2)]],
    device const uint *coord_3 [[buffer(3)]],
    device uint *dst [[buffer(4)]],
    uint index [[thread_position_in_grid]]
) {
    stwo_metal_store_qm31(
        dst,
        index,
        StwoMetalQm31 {
            coord_0[index],
            coord_1[index],
            coord_2[index],
            coord_3[index],
        }
    );
}

kernel void unpack_secure_column_coords_u32x4(
    device const uint *src [[buffer(0)]],
    device uint *coord_0 [[buffer(1)]],
    device uint *coord_1 [[buffer(2)]],
    device uint *coord_2 [[buffer(3)]],
    device uint *coord_3 [[buffer(4)]],
    uint index [[thread_position_in_grid]]
) {
    StwoMetalQm31 value = stwo_metal_load_qm31(src, index);
    coord_0[index] = value.a;
    coord_1[index] = value.b;
    coord_2[index] = value.c;
    coord_3[index] = value.d;
}

kernel void fri_fold_line_step_u32x4(
    device const uint *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    device const uint *inverse_x [[buffer(2)]],
    constant StwoMetalQm31 &alpha [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    uint pair_index = index;
    StwoMetalQm31 f_x = stwo_metal_load_qm31(src, pair_index * 2u);
    StwoMetalQm31 f_neg_x = stwo_metal_load_qm31(src, pair_index * 2u + 1u);
    uint inverse_factor = inverse_x[pair_index];

    stwo_metal_store_qm31(
        dst,
        pair_index,
        stwo_metal_fri_fold_pair(f_x, f_neg_x, inverse_factor, alpha)
    );
}

kernel void fri_fold_line_step_coords_u32x4(
    device const uint *src_0 [[buffer(0)]],
    device const uint *src_1 [[buffer(1)]],
    device const uint *src_2 [[buffer(2)]],
    device const uint *src_3 [[buffer(3)]],
    device uint *dst_0 [[buffer(4)]],
    device uint *dst_1 [[buffer(5)]],
    device uint *dst_2 [[buffer(6)]],
    device uint *dst_3 [[buffer(7)]],
    device const uint *inverse_x [[buffer(8)]],
    constant StwoMetalQm31 &alpha [[buffer(9)]],
    uint index [[thread_position_in_grid]]
) {
    uint pair_index = index;
    uint lhs_index = pair_index * 2u;
    uint rhs_index = lhs_index + 1u;
    StwoMetalQm31 folded = stwo_metal_fri_fold_pair(
        StwoMetalQm31 {
            src_0[lhs_index],
            src_1[lhs_index],
            src_2[lhs_index],
            src_3[lhs_index],
        },
        StwoMetalQm31 {
            src_0[rhs_index],
            src_1[rhs_index],
            src_2[rhs_index],
            src_3[rhs_index],
        },
        inverse_x[pair_index],
        alpha
    );
    dst_0[pair_index] = folded.a;
    dst_1[pair_index] = folded.b;
    dst_2[pair_index] = folded.c;
    dst_3[pair_index] = folded.d;
}
