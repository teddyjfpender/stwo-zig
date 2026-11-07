//! Exact zero-column detection. This is an arithmetic shortcut, never a
//! sparsity hint supplied by a prover or a change to polynomial geometry.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
pub fn isZero(values: []const M31) bool {
    // Tiny transforms cost less than a separate scan. Nonzero columns usually
    // leave this check after their first vector, while zero fixed/high-limb
    // columns avoid all FFT passes.
    if (values.len < 256) return false;
    return std.mem.allEqual(u8, std.mem.sliceAsBytes(values), 0);
}
test "circle poly zero-column shortcut checks every byte including final lane" {
    var values: [1024]M31 = @splat(M31.zero());
    try std.testing.expect(isZero(&values));
    for ([_]usize{ 0, 1, 255, 256, 511, 1023 }) |at| {
        values[at] = M31.one();
        try std.testing.expect(!isZero(&values));
        values[at] = M31.zero();
    }
    try std.testing.expect(!isZero(values[0..128]));
}
