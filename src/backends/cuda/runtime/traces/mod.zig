//! Authenticated resident trace recipes.

pub const indexed_recurrence = @import("indexed_recurrence.zig");
pub const m31_permutation = @import("m31_permutation.zig");
pub const seeded_xorshift = @import("seeded_xorshift.zig");

test {
    _ = indexed_recurrence;
    _ = m31_permutation;
    _ = seeded_xorshift;
}
