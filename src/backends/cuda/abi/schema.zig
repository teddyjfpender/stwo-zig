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
};

test "CUDA AOT schema identities are explicit and nonzero" {
    const std = @import("std");
    inline for (std.meta.fields(KernelSchema)) |field| {
        try std.testing.expect(field.value != 0);
    }
}
