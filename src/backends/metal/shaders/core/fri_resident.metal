#include <metal_stdlib>
using namespace metal;

#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/blake2s.metal"
#include "stwo_zig/m31.metal"
#include "stwo_zig/extension_fields.metal"
#endif

inline Qm31Value fri_load_planar(device const uint *arena, uint base, uint stride, uint index) {
    return {
        arena[base + index], arena[base + stride + index],
        arena[base + 2u * stride + index], arena[base + 3u * stride + index],
    };
}

inline uint fri_circle_twiddle(device const uint *twiddles, uint offset, uint index) {
    uint k = index >> 2u;
    uint a = twiddles[offset + 2u * k];
    uint b = twiddles[offset + 2u * k + 1u];
    switch (index & 3u) {
        case 0u: return b;
        case 1u: return m31_neg(b);
        case 2u: return m31_neg(a);
        default: return a;
    }
}

inline Qm31Value fri_fold_pair(Qm31Value left, Qm31Value right, uint inverse, Qm31Value alpha) {
    return qm_add(qm_add(left, right), qm_mul(alpha, qm_mul_m31(qm_sub(left, right), inverse)));
}

kernel void stwo_zig_fri_fold3_resident(
    device uint *arena [[buffer(0)]],
    constant uint &twiddle_base [[buffer(1)]],
    constant uint &twiddle_offset_0 [[buffer(2)]],
    constant uint &twiddle_offset_1 [[buffer(3)]],
    constant uint &twiddle_offset_2 [[buffer(4)]],
    constant uint &input_base [[buffer(5)]],
    constant uint &input_stride [[buffer(6)]],
    constant uint &alpha_base [[buffer(7)]],
    constant uint &output_base [[buffer(8)]],
    constant uint &output_stride [[buffer(9)]],
    constant uint &n [[buffer(10)]],
    constant uint &first_circle [[buffer(11)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= (n >> 3u)) return;
    Qm31Value alpha0 = { arena[alpha_base], arena[alpha_base + 1u], arena[alpha_base + 2u], arena[alpha_base + 3u] };
    Qm31Value alpha1 = qm_mul(alpha0, alpha0);
    Qm31Value alpha2 = qm_mul(alpha1, alpha1);
    Qm31Value stage0[4];
    for (uint k = 0u; k < 4u; ++k) {
        uint out = 4u * index + k;
        uint inverse = first_circle != 0u
            ? fri_circle_twiddle(arena, twiddle_base + twiddle_offset_0, out)
            : arena[twiddle_base + twiddle_offset_0 + out];
        stage0[k] = fri_fold_pair(
            fri_load_planar(arena, input_base, input_stride, 2u * out),
            fri_load_planar(arena, input_base, input_stride, 2u * out + 1u),
            inverse,
            alpha0
        );
    }
    Qm31Value stage1[2];
    for (uint k = 0u; k < 2u; ++k) {
        uint out = 2u * index + k;
        stage1[k] = fri_fold_pair(
            stage0[2u * k], stage0[2u * k + 1u],
            arena[twiddle_base + twiddle_offset_1 + out], alpha1
        );
    }
    Qm31Value result = fri_fold_pair(
        stage1[0], stage1[1], arena[twiddle_base + twiddle_offset_2 + index], alpha2
    );
    arena[output_base + index] = result.a;
    arena[output_base + output_stride + index] = result.b;
    arena[output_base + 2u * output_stride + index] = result.c;
    arena[output_base + 3u * output_stride + index] = result.d;
}

kernel void stwo_zig_fri_fold2_resident(
    device uint *arena [[buffer(0)]],
    constant uint &twiddle_base [[buffer(1)]],
    constant uint &twiddle_offset_0 [[buffer(2)]],
    constant uint &twiddle_offset_1 [[buffer(3)]],
    constant uint &input_base [[buffer(4)]],
    constant uint &input_stride [[buffer(5)]],
    constant uint &alpha_base [[buffer(6)]],
    constant uint &output_base [[buffer(7)]],
    constant uint &output_stride [[buffer(8)]],
    constant uint &n [[buffer(9)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= (n >> 2u)) return;
    Qm31Value alpha0 = { arena[alpha_base], arena[alpha_base + 1u], arena[alpha_base + 2u], arena[alpha_base + 3u] };
    Qm31Value alpha1 = qm_mul(alpha0, alpha0);
    Qm31Value stage0[2];
    for (uint k = 0u; k < 2u; ++k) {
        uint out = 2u * index + k;
        stage0[k] = fri_fold_pair(
            fri_load_planar(arena, input_base, input_stride, 2u * out),
            fri_load_planar(arena, input_base, input_stride, 2u * out + 1u),
            arena[twiddle_base + twiddle_offset_0 + out], alpha0
        );
    }
    Qm31Value result = fri_fold_pair(
        stage0[0], stage0[1], arena[twiddle_base + twiddle_offset_1 + index], alpha1
    );
    arena[output_base + index] = result.a;
    arena[output_base + output_stride + index] = result.b;
    arena[output_base + 2u * output_stride + index] = result.c;
    arena[output_base + 3u * output_stride + index] = result.d;
}

kernel void stwo_zig_fri_packed_leaves_resident(
    device uint *arena [[buffer(0)]],
    constant uint &evaluation_base [[buffer(1)]],
    constant uint &coordinate_stride [[buffer(2)]],
    constant uint &evaluation_size [[buffer(3)]],
    constant uint &log_rows_per_leaf [[buffer(4)]],
    constant uint &destination_base [[buffer(5)]],
    constant uint *leaf_seed [[buffer(6)]],
    constant uint &prefix_bytes [[buffer(7)]],
    uint leaf [[thread_position_in_grid]]
) {
    uint leaf_count = evaluation_size >> log_rows_per_leaf;
    if (leaf >= leaf_count) return;
    uint state[8], message[16];
    if (prefix_bytes == 0u) blake2s_init_hash(state);
    else blake2s_init_seeded(state, leaf_seed);
    for (uint i = 0u; i < 16u; ++i) message[i] = 0u;
    if (log_rows_per_leaf == 0u) {
        for (uint coordinate = 0u; coordinate < 4u; ++coordinate)
            message[coordinate] = arena[evaluation_base + coordinate * coordinate_stride + leaf];
        blake2s_compress(state, message, prefix_bytes + 16u, true);
    } else {
        for (uint offset = 0u; offset < 4u; ++offset) {
            for (uint coordinate = 0u; coordinate < 4u; ++coordinate) {
                message[coordinate + 4u * offset] =
                    arena[evaluation_base + coordinate * coordinate_stride + 4u * leaf + offset];
            }
        }
        blake2s_compress(state, message, prefix_bytes + 64u, true);
    }
    for (uint i = 0u; i < 8u; ++i) arena[destination_base + leaf * 8u + i] = state[i];
}

kernel void stwo_zig_fri_final_line_resident(
    device uint *arena [[buffer(0)]],
    constant uint &evaluation_base [[buffer(1)]],
    constant uint &coordinate_stride [[buffer(2)]],
    constant uint &inverse_x [[buffer(3)]],
    constant uint &coefficient_base [[buffer(4)]],
    constant uint &degree_error [[buffer(5)]],
    uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u) return;
    Qm31Value left = fri_load_planar(arena, evaluation_base, coordinate_stride, 0u);
    Qm31Value right = fri_load_planar(arena, evaluation_base, coordinate_stride, 1u);
    Qm31Value c0 = qm_mul_m31(qm_add(left, right), 1073741824u);
    Qm31Value c1 = qm_mul_m31(qm_mul_m31(qm_sub(left, right), inverse_x), 1073741824u);
    arena[coefficient_base] = c0.a;
    arena[coefficient_base + 1u] = c0.b;
    arena[coefficient_base + 2u] = c0.c;
    arena[coefficient_base + 3u] = c0.d;
    arena[coefficient_base + 4u] = c1.a;
    arena[coefficient_base + 5u] = c1.b;
    arena[coefficient_base + 6u] = c1.c;
    arena[coefficient_base + 7u] = c1.d;
    arena[degree_error] = (c1.a | c1.b | c1.c | c1.d) != 0u ? 1u : 0u;
}
