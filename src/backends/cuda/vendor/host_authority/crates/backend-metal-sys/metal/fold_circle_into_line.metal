#include "secure_field_support.h"

kernel void fri_fold_circle_into_line_first_layer_u32x4(
    device const uint *src [[buffer(0)]],
    device uint *dst [[buffer(1)]],
    device const uint *inverse_y [[buffer(2)]],
    constant StwoMetalQm31 &alpha [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    uint pair_index = index;
    StwoMetalQm31 f_p = stwo_metal_load_qm31(src, pair_index * 2u);
    StwoMetalQm31 f_neg_p = stwo_metal_load_qm31(src, pair_index * 2u + 1u);
    uint inverse_factor = inverse_y[pair_index];

    stwo_metal_store_qm31(
        dst,
        pair_index,
        stwo_metal_fri_fold_pair(f_p, f_neg_p, inverse_factor, alpha)
    );
}

kernel void fri_fold_circle_into_line_accumulate_coords_u32x4(
    device const uint *src_0 [[buffer(0)]],
    device const uint *src_1 [[buffer(1)]],
    device const uint *src_2 [[buffer(2)]],
    device const uint *src_3 [[buffer(3)]],
    device uint *dst_0 [[buffer(4)]],
    device uint *dst_1 [[buffer(5)]],
    device uint *dst_2 [[buffer(6)]],
    device uint *dst_3 [[buffer(7)]],
    device const uint *inverse_y [[buffer(8)]],
    constant StwoMetalQm31 &alpha [[buffer(9)]],
    constant StwoMetalQm31 &alpha_sq [[buffer(10)]],
    uint index [[thread_position_in_grid]]
) {
    uint pair_index = index;
    uint lhs_index = pair_index * 2u;
    uint rhs_index = lhs_index + 1u;
    StwoMetalQm31 f_p = StwoMetalQm31 {
        src_0[lhs_index],
        src_1[lhs_index],
        src_2[lhs_index],
        src_3[lhs_index],
    };
    StwoMetalQm31 f_neg_p = StwoMetalQm31 {
        src_0[rhs_index],
        src_1[rhs_index],
        src_2[rhs_index],
        src_3[rhs_index],
    };
    uint inverse_factor = inverse_y[pair_index];
    StwoMetalQm31 folded = stwo_metal_fri_fold_pair(f_p, f_neg_p, inverse_factor, alpha);
    StwoMetalQm31 accumulated = stwo_metal_qm31_add(
        stwo_metal_qm31_mul(
            StwoMetalQm31 {
                dst_0[pair_index],
                dst_1[pair_index],
                dst_2[pair_index],
                dst_3[pair_index],
            },
            alpha_sq
        ),
        folded
    );

    dst_0[pair_index] = accumulated.a;
    dst_1[pair_index] = accumulated.b;
    dst_2[pair_index] = accumulated.c;
    dst_3[pair_index] = accumulated.d;
}

kernel void fri_fold_circle_into_line_first_layer_coords_u32x4(
    device const uint *src_0 [[buffer(0)]],
    device const uint *src_1 [[buffer(1)]],
    device const uint *src_2 [[buffer(2)]],
    device const uint *src_3 [[buffer(3)]],
    device uint *dst_0 [[buffer(4)]],
    device uint *dst_1 [[buffer(5)]],
    device uint *dst_2 [[buffer(6)]],
    device uint *dst_3 [[buffer(7)]],
    device const uint *inverse_y [[buffer(8)]],
    constant StwoMetalQm31 &alpha [[buffer(9)]],
    uint index [[thread_position_in_grid]]
) {
    uint pair_index = index;
    uint lhs_index = pair_index * 2u;
    uint rhs_index = lhs_index + 1u;
    StwoMetalQm31 f_p = StwoMetalQm31 {
        src_0[lhs_index],
        src_1[lhs_index],
        src_2[lhs_index],
        src_3[lhs_index],
    };
    StwoMetalQm31 f_neg_p = StwoMetalQm31 {
        src_0[rhs_index],
        src_1[rhs_index],
        src_2[rhs_index],
        src_3[rhs_index],
    };
    uint inverse_factor = inverse_y[pair_index];
    StwoMetalQm31 folded = stwo_metal_fri_fold_pair(f_p, f_neg_p, inverse_factor, alpha);

    dst_0[pair_index] = folded.a;
    dst_1[pair_index] = folded.b;
    dst_2[pair_index] = folded.c;
    dst_3[pair_index] = folded.d;
}
