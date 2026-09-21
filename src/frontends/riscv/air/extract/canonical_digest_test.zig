//! Canonical identity must survive representation changes and reject bad DAGs.
const std = @import("std");
const identity = @import("canonical_digest.zig");
const Node = @import("symbolic.zig").Node;

test "canonical expression identity ignores unrelated nodes and insertion order" {
    const allocator = std.testing.allocator;
    const first = try identity.expressions(allocator, &.{
        .{ .op = .column, .value = 0 },
        .{ .op = .constant, .value = 7 },
        .{ .op = .sub, .lhs = 0, .rhs = 1 },
    }, 1);
    defer allocator.free(first);
    const second = try identity.expressions(allocator, &.{
        .{ .op = .constant, .value = 999 },
        .{ .op = .constant, .value = 7 },
        .{ .op = .column, .value = 0 },
        .{ .op = .sub, .lhs = 2, .rhs = 1 },
        .{ .op = .sub, .lhs = 1, .rhs = 2 },
        .{ .op = .add, .lhs = 2, .rhs = 1 },
    }, 1);
    defer allocator.free(second);
    try std.testing.expectEqualSlices(u8, &first[2], &second[3]);
    try std.testing.expect(!std.mem.eql(u8, &first[2], &second[4]));
    try std.testing.expect(!std.mem.eql(u8, &first[2], &second[5]));
}

test "canonical expression identity rejects malformed operands and field values" {
    for ([_]Node{
        .{ .op = .constant, .value = 0x7fff_ffff },
        .{ .op = .column, .value = 1 },
        .{ .op = .constant, .value = 1, .lhs = 1 },
        .{ .op = .neg, .lhs = 0 },
        .{ .op = .mul, .lhs = 0, .rhs = 0 },
    }) |invalid| {
        try std.testing.expectError(error.InvalidCanonicalExpression, identity.expressions(std.testing.allocator, &.{invalid}, 1));
    }
}
