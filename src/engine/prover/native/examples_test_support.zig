//! Small assertion helpers shared by native workload registry tests.

const std = @import("std");

pub fn expectDigest(
    actual: [32]u8,
    expected_hex: *const [64]u8,
) !void {
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}
