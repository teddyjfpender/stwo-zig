const std = @import("std");
const tree = @import("../air/memory_commitment/blake3_byte_tree.zig");
test "BLAKE3 Span memory byte tree preserves sparse defaults and full digest roots" {
    const hasher = tree.TreeHasher.init(.memory);
    const empty = try hasher.root(&.{});
    try std.testing.expectEqual(empty, try hasher.root(&.{ .{ .index = 0, .value = 0 }, .{ .index = tree.ADDRESS_LIMIT - 1, .value = 0 } }));
    var expected = hasher.leaf(255);
    const address: u32 = 0x1234567;
    for (0..tree.DEPTH) |height| {
        const sibling = hasher.defaults[tree.DEPTH - height];
        expected = if ((address >> @intCast(height)) & 1 == 0) hasher.pair(expected, sibling) else hasher.pair(sibling, expected);
    }
    try std.testing.expectEqual(expected, try hasher.root(&.{.{ .index = address, .value = 255 }}));
    try std.testing.expect(!std.meta.eql(expected, try hasher.root(&.{.{ .index = address + 1, .value = 255 }})));
    const program = tree.TreeHasher.init(.program);
    try std.testing.expect(!std.meta.eql(empty, try program.root(&.{})));
    try std.testing.expectError(error.NonByteLeaf, hasher.root(&.{.{ .index = 1, .value = 256 }}));
    try std.testing.expectError(error.ByteAddressOutOfRange, hasher.root(&.{.{ .index = tree.ADDRESS_LIMIT, .value = 1 }}));
    try std.testing.expectError(error.UnsortedOrDuplicateByte, hasher.root(&.{ .{ .index = 1, .value = 1 }, .{ .index = 1, .value = 2 } }));
}
