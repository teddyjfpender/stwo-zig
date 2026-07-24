//! Authenticated resident trace recipes.

pub const m31_permutation = @import("m31_permutation.zig");
pub const seeded_xorshift = @import("seeded_xorshift.zig");

test {
    _ = m31_permutation;
    _ = seeded_xorshift;
}
