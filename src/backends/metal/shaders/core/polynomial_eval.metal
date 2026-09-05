#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/base.metal"
#include "stwo_zig/m31.metal"
#include "stwo_zig/extension_fields.metal"
#include "stwo_zig/abi_types.metal"
#include "stwo_zig/circle.metal"
#endif

kernel void stwo_zig_eval_basis(
    device const uint *factors [[buffer(0)]],
    device const PolynomialBasisTask *tasks [[buffer(1)]],
    constant uint &task_count [[buffer(2)]],
    device Qm31Value *basis [[buffer(3)]],
    uint lane [[thread_index_in_threadgroup]],
    uint2 group_shape [[threads_per_threadgroup]],
    uint2 group [[threadgroup_position_in_grid]]
) {
    uint group_width = group_shape.x;
    uint task_index = group.y;
    if (task_index >= task_count) return;
    PolynomialBasisTask task = tasks[task_index];
    uint block = group.x;
    uint block_start = block * group_width;
    if (block_start >= task.basis_length) return;

    // Keep a generic construction for any future narrower pipeline. Each
    // threadgroup owns one contiguous basis block, exposing independent blocks
    // across the full GPU instead of serializing them behind barriers.
    if (group_width != 256u) {
        uint coefficient_index = block_start + lane;
        if (coefficient_index < task.basis_length) {
            Qm31Value value = { 1u, 0u, 0u, 0u };
            uint bits = coefficient_index;
            for (uint bit = 0; bit < task.log_size && bits != 0u; ++bit) {
                if ((bits & 1u) != 0u) {
                    uint factor_base = task.factor_offset + bit * 4u;
                    Qm31Value factor = { factors[factor_base], factors[factor_base + 1u],
                                         factors[factor_base + 2u], factors[factor_base + 3u] };
                    value = qm_mul(value, factor);
                }
                bits >>= 1u;
            }
            basis[task.basis_offset + coefficient_index] = value;
        }
        return;
    }

    // Split each basis index into a lane-local low byte and a block index. The
    // low product is intentionally recomputed per block: the extra arithmetic
    // buys thousands of independent threadgroups and removes two serialized
    // barriers per 256 coefficients.
    Qm31Value low_value = { 1u, 0u, 0u, 0u };
    uint low_bits = lane;
    for (uint bit = 0; bit < min(task.log_size, 8u) && low_bits != 0u; ++bit) {
        if ((low_bits & 1u) != 0u) {
            uint factor_base = task.factor_offset + bit * 4u;
            Qm31Value factor = { factors[factor_base], factors[factor_base + 1u],
                                 factors[factor_base + 2u], factors[factor_base + 3u] };
            low_value = qm_mul(low_value, factor);
        }
        low_bits >>= 1u;
    }

    threadgroup Qm31Value high_value;
    if (lane == 0u) {
        Qm31Value value = { 1u, 0u, 0u, 0u };
        uint high_bits = block;
        for (uint bit = 8u; bit < task.log_size && high_bits != 0u; ++bit) {
            if ((high_bits & 1u) != 0u) {
                uint factor_base = task.factor_offset + bit * 4u;
                Qm31Value factor = { factors[factor_base], factors[factor_base + 1u],
                                     factors[factor_base + 2u], factors[factor_base + 3u] };
                value = qm_mul(value, factor);
            }
            high_bits >>= 1u;
        }
        high_value = value;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint coefficient_index = (block << 8u) + lane;
    if (coefficient_index < task.basis_length) {
        basis[task.basis_offset + coefficient_index] = block == 0u
            ? low_value
            : qm_mul(low_value, high_value);
    }
}

kernel void stwo_zig_eval_polynomials(
    device const uint *coefficients [[buffer(0)]],
    device const Qm31Value *basis [[buffer(1)]],
    device const PolynomialEvalTask *tasks [[buffer(2)]],
    constant uint &task_count [[buffer(3)]],
    device uint *output [[buffer(4)]],
    uint lane [[thread_index_in_threadgroup]],
    uint group_width [[threads_per_threadgroup]],
    uint task_index [[threadgroup_position_in_grid]]
) {
    if (task_index >= task_count) return;
    PolynomialEvalTask task = tasks[task_index];
    Qm31Value partial_value = { 0u, 0u, 0u, 0u };
    for (uint coefficient_index = lane; coefficient_index < task.coefficient_length; coefficient_index += group_width) {
        partial_value = qm_add(
            partial_value,
            qm_mul_m31(basis[task.basis_offset + coefficient_index],
                       coefficients[task.coefficient_offset + coefficient_index])
        );
    }
    threadgroup Qm31Value partials[256];
    partials[lane] = partial_value;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint stride = group_width >> 1u; stride != 0u; stride >>= 1u) {
        if (lane < stride) partials[lane] = qm_add(partials[lane], partials[lane + stride]);
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    if (lane == 0u) {
        uint output_base = task.output_index * 4u;
        output[output_base] = partials[0].a;
        output[output_base + 1u] = partials[0].b;
        output[output_base + 2u] = partials[0].c;
        output[output_base + 3u] = partials[0].d;
    }
}

inline bool sampled_qm_is_zero(Qm31Value value) {
    return value.a == 0u && value.b == 0u && value.c == 0u && value.d == 0u;
}

inline Qm31Value sampled_qm_neg(Qm31Value value) {
    return { m31_neg(value.a), m31_neg(value.b),
             m31_neg(value.c), m31_neg(value.d) };
}

/// Materializes one canonical circle domain in bit-reversed storage order.
/// The buffer is reused by every sampled point at this exact log size.
kernel void stwo_zig_sampled_barycentric_domain_v1(
    device CircleM31Value *domain [[buffer(0)]],
    constant uint &size [[buffer(1)]],
    constant uint &log_size [[buffer(2)]],
    constant uint &half_coset_initial_index [[buffer(3)]],
    constant uint &half_coset_step_size [[buffer(4)]],
    uint storage_index [[thread_position_in_grid]]
) {
    if (storage_index >= size) return;
    uint natural = reverse_bits(storage_index) >> (32u - log_size);
    uint half_size = size >> 1u;
    ulong positive = (ulong)half_coset_initial_index +
        (ulong)half_coset_step_size * (ulong)(natural < half_size
            ? natural
            : natural - half_size);
    constexpr ulong circle_order = 1ul << 31u;
    ulong exponent = natural < half_size ? positive : circle_order - positive;
    domain[storage_index] = circle_pow((uint)(exponent & (circle_order - 1ul)));
}

kernel void stwo_zig_sampled_barycentric_scale_v1(
    constant Qm31Value &point_x [[buffer(0)]],
    constant Qm31Value &point_y [[buffer(1)]],
    constant Qm31Value &si0 [[buffer(2)]],
    constant CircleM31Value &vanishing_rotation [[buffer(3)]],
    constant uint &log_size [[buffer(4)]],
    device Qm31Value *scales [[buffer(5)]],
    uint index [[thread_position_in_grid]]
) {
    if (index != 0u) return;
    Qm31Value x = qm_sub(
        qm_mul_m31(point_x, vanishing_rotation.x),
        qm_mul_m31(point_y, vanishing_rotation.y));
    for (uint level = 1u; level < log_size; ++level) {
        Qm31Value square = qm_mul(x, x);
        x = qm_sub(qm_add(square, square), { 1u, 0u, 0u, 0u });
    }
    scales[0] = qm_mul(si0, x);
    scales[1] = sampled_qm_neg(scales[0]);
}

/// Writes `h.y` and `1+h.x`. The inverse-si factor is carried by the two
/// parity scales, exactly matching the canonical CUDA/reference identity.
kernel void stwo_zig_sampled_barycentric_parts_v1(
    device const CircleM31Value *domain [[buffer(0)]],
    constant Qm31Value &point_x [[buffer(1)]],
    constant Qm31Value &point_y [[buffer(2)]],
    device Qm31Value *numerators [[buffer(3)]],
    device Qm31Value *factors [[buffer(4)]],
    device atomic_uint *invalid [[buffer(5)]],
    constant uint &size [[buffer(6)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= size) return;
    CircleM31Value p = domain[index];
    Qm31Value hx = qm_add(qm_mul_m31(point_x, p.x),
                          qm_mul_m31(point_y, p.y));
    Qm31Value hy = qm_sub(qm_mul_m31(point_y, p.x),
                          qm_mul_m31(point_x, p.y));
    Qm31Value factor = qm_add({ 1u, 0u, 0u, 0u }, hx);
    if (sampled_qm_is_zero(hy) || sampled_qm_is_zero(factor)) {
        atomic_store_explicit(invalid, 1u, memory_order_relaxed);
    }
    numerators[index] = hy;
    factors[index] = factor;
}

kernel void stwo_zig_sampled_barycentric_inverse_direct_v1(
    device Qm31Value *values [[buffer(0)]],
    constant uint &size [[buffer(1)]],
    uint index [[thread_position_in_grid]]
) {
    if (index < size) values[index] = qm_inv(values[index]);
}

/// One 32KiB inverse tree per 1024 values.  Only 32 expensive inversions are
/// performed per block; every other node uses exact QM31 multiplication.
kernel void stwo_zig_sampled_barycentric_inverse_tree_v1(
    device Qm31Value *values [[buffer(0)]],
    uint lane [[thread_index_in_threadgroup]],
    uint block [[threadgroup_position_in_grid]]
) {
    threadgroup Qm31Value leaves[1024];
    threadgroup Qm31Value tree[992];
    uint offset = block * 1024u;
    leaves[lane] = values[offset + lane];
    leaves[lane + 512u] = values[offset + lane + 512u];
    threadgroup_barrier(mem_flags::mem_threadgroup);

    tree[lane] = qm_mul(leaves[2u * lane], leaves[2u * lane + 1u]);
    uint child_offset = 0u;
    uint parent_offset = 512u;
    uint nodes = 256u;
    for (uint level = 1u; level < 5u; ++level) {
        threadgroup_barrier(mem_flags::mem_threadgroup);
        if (lane < nodes) {
            tree[parent_offset + lane] = qm_mul(
                tree[child_offset + 2u * lane],
                tree[child_offset + 2u * lane + 1u]);
        }
        child_offset = parent_offset;
        parent_offset += nodes;
        nodes >>= 1u;
    }

    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (lane < 32u) tree[child_offset + lane] = qm_inv(tree[child_offset + lane]);

    nodes = 32u;
    parent_offset = child_offset - 64u;
    for (uint level = 5u; level < 9u; ++level) {
        threadgroup_barrier(mem_flags::mem_threadgroup);
        if (lane < nodes) {
            Qm31Value left = tree[parent_offset + 2u * lane];
            tree[parent_offset + 2u * lane] = qm_mul(
                tree[child_offset + lane],
                tree[parent_offset + 2u * lane + 1u]);
            tree[parent_offset + 2u * lane + 1u] = qm_mul(
                tree[child_offset + lane], left);
        }
        nodes <<= 1u;
        child_offset = parent_offset;
        parent_offset -= 2u * nodes;
    }

    threadgroup_barrier(mem_flags::mem_threadgroup);
    Qm31Value pair_inverse = tree[lane];
    values[offset + 2u * lane] = qm_mul(pair_inverse, leaves[2u * lane + 1u]);
    values[offset + 2u * lane + 1u] = qm_mul(pair_inverse, leaves[2u * lane]);
}

kernel void stwo_zig_sampled_barycentric_finish_v1(
    device const Qm31Value *numerator_inverses [[buffer(0)]],
    device Qm31Value *weights [[buffer(1)]],
    device const Qm31Value *scales [[buffer(2)]],
    constant uint &size [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    if (index < size) {
        weights[index] = qm_mul(
            qm_mul(weights[index], numerator_inverses[index]),
            scales[index & 1u]);
    }
}

kernel void stwo_zig_sampled_barycentric_evaluate_many_v1(
    device const uint *columns [[buffer(0)]],
    device const ulong *column_offsets [[buffer(1)]],
    device const Qm31Value *weights [[buffer(2)]],
    constant uint &size [[buffer(3)]],
    constant uint &reduction_blocks [[buffer(4)]],
    device Qm31Value *partial_sums [[buffer(5)]],
    uint lane [[thread_index_in_threadgroup]],
    uint2 group_shape [[threads_per_threadgroup]],
    uint2 group [[threadgroup_position_in_grid]]
) {
    uint group_width = group_shape.x;
    uint block = group.x;
    uint column = group.y;
    device const uint *values = columns + column_offsets[column];
    Qm31Value sum = { 0u, 0u, 0u, 0u };
    ulong index = (ulong)block * (ulong)group_width + (ulong)lane;
    ulong stride = (ulong)group_width * (ulong)reduction_blocks;
    while (index < (ulong)size) {
        sum = qm_add(sum, qm_mul_m31(weights[index], values[index]));
        index += stride;
    }
    threadgroup Qm31Value partials[256];
    partials[lane] = sum;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint width = group_width >> 1u; width != 0u; width >>= 1u) {
        if (lane < width) partials[lane] = qm_add(partials[lane], partials[lane + width]);
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    if (lane == 0u) {
        partial_sums[(ulong)column * (ulong)reduction_blocks + block] = partials[0];
    }
}

kernel void stwo_zig_sampled_barycentric_reduce_v1(
    device const Qm31Value *partial_sums [[buffer(0)]],
    constant uint &reduction_blocks [[buffer(1)]],
    device const uint *output_indices [[buffer(2)]],
    device Qm31Value *output [[buffer(3)]],
    constant uint &output_count [[buffer(4)]],
    uint lane [[thread_index_in_threadgroup]],
    uint group_width [[threads_per_threadgroup]],
    uint column [[threadgroup_position_in_grid]]
) {
    Qm31Value sum = { 0u, 0u, 0u, 0u };
    ulong base = (ulong)column * (ulong)reduction_blocks;
    for (uint index = lane; index < reduction_blocks; index += group_width) {
        sum = qm_add(sum, partial_sums[base + index]);
    }
    threadgroup Qm31Value partials[256];
    partials[lane] = sum;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint width = group_width >> 1u; width != 0u; width >>= 1u) {
        if (lane < width) partials[lane] = qm_add(partials[lane], partials[lane + width]);
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    uint output_index = output_indices[column];
    if (lane == 0u && output_index < output_count) output[output_index] = partials[0];
}
