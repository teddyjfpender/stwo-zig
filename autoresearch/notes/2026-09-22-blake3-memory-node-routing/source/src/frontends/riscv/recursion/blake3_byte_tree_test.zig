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

test "BLAKE3 Span memory node routes both full child digests through typed hash" {
    const witness = @import("air/blake3_frame_witness.zig");
    const routing = @import("air/blake3_frame_route.zig");
    const boundary = @import("air/blake3_boundary.zig");
    const support = @import("air/blake3_hash_test_support.zig");
    const M = @import("stwo_core").fields.m31.M31;
    const a = std.testing.allocator;
    const hasher = tree.TreeHasher.init(.memory);
    const left = hasher.leaf(12);
    const right = hasher.leaf(250);
    const frame = tree.Frame{ .node = .{ .kind = .memory, .left = left, .right = right } };
    const expected = frame.hash();
    const callers = [_]witness.Binding{ .{ .role = .left, .caller = .{ .circuit = 31, .first_wire = 0 } }, .{ .role = .right, .caller = .{ .circuit = 32, .first_wire = 0 } } };
    var live = try witness.prepareDigestFrame(a, 33, frame, &callers, expected.bytes);
    defer live.deinit();
    const placeholders = tree.Frame{ .node = .{ .kind = .memory, .left = .{ .bytes = @splat(0) }, .right = .{ .bytes = @splat(0) } } };
    var trusted = try witness.trustedDigestFrame(a, 33, placeholders, &callers, expected.bytes);
    defer trusted.deinit();
    try std.testing.expectEqual(expected.bytes, live.digest.?);
    for (live.route_rows, trusted.route_rows) |row, fixed| try std.testing.expectEqualSlices(M, row[12..], fixed[12..]);
    var producers: [16]boundary.Row = undefined;
    for ([_]tree.Digest{ left, right }, 0..) |digest, child| for (0..8) |word| {
        producers[child * 8 + word] = try boundary.logicalRow(callers[child].caller.circuit, @intCast(word), M.fromCanonical(live.source_uses[child][word]), std.mem.readInt(u32, digest.bytes[word * 4 ..][0..4], .little));
    };
    const rows = @import("air/blake3_hash_witness.zig").Rows{ .allocator = a, .g_rows = live.rows.g_rows, .xor_rows = live.rows.xor_rows, .boundary_rows = live.rows.boundary_rows };
    try std.testing.expect(try support.closedRouted(&rows, live.route_rows, &producers));
    producers[15][0] = producers[15][0].add(M.one());
    try std.testing.expect(!try support.closedRouted(&rows, live.route_rows, &producers));
    try std.testing.expectError(error.InvalidBlake3FrameCaller, routing.buildWithPayload(a, 33, frame, callers[0..1], null));
}
