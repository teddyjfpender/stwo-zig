//! Stable structured ABI identities embedded in the Native CUDA AOT index.

pub const KernelSchema = enum(u32) {
    ordinary_constraint_v1 = 1,
    recorded_witness_v1 = 2,
    composition_wave_v2 = 3,
    native_constraint_slab_v1 = 4,
    native_constant_qm31_v1 = 5,
    native_seeded_xorshift_trace_v1 = 6,
    native_m31_permutation_trace_v1 = 7,
    native_indexed_recurrence_trace_v1 = 8,
    native_circle_affine_state_trace_v1 = 9,
    native_state_machine_statement_v1 = 10,
    native_state_machine_constraint_v1 = 11,
    native_plonk_logup_constraint_v1 = 12,
    native_m31_permutation_trace_v2 = 13,
    native_poseidon_constraint_v1 = 14,
    native_xor_logup_constraint_v1 = 15,
    native_xor_logup_trace_v1 = 16,
    native_blake_constraint_v1 = 17,
    native_m31_permutation_trace_v3 = 18,
    native_blake_exact_trace_v1 = 19,
    native_blake_exact_interaction_v1 = 20,
    native_blake_exact_trace_v2 = 21,
    cairo_eval_part_v1 = 22,
    secure_polynomial_equations_v1 = 23,
    secure_polynomial_fractions_v1 = 24,
    secure_range_inverse_v1 = 25,
    secure_scan_v1 = 26,
    secure_mean_v1 = 27,
    secure_word_witness_v4 = 28,
    secure_range_witness_v4 = 29,
};

test "CUDA AOT schema identities are explicit and nonzero" {
    const std = @import("std");
    inline for (std.meta.fields(KernelSchema)) |field| {
        try std.testing.expect(field.value != 0);
    }
}
