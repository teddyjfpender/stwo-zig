//! Authenticated resident trace recipes.

pub const blake_exact = @import("blake_exact.zig");
pub const circle_affine_state = @import("circle_affine_state.zig");
pub const indexed_recurrence = @import("indexed_recurrence.zig");
pub const m31_permutation = @import("m31_permutation.zig");
pub const seeded_xorshift = @import("seeded_xorshift.zig");
pub const xor_logup = @import("xor_logup.zig");

test {
    _ = blake_exact;
    _ = circle_affine_state;
    _ = indexed_recurrence;
    _ = m31_permutation;
    _ = seeded_xorshift;
    _ = xor_logup;
}
