const std = @import("std");
const tree = @import("blake3_state_tree.zig");

test "BLAKE3 subtree batch matches independent openings at every height" {
    for ([_]tree.Kind{ .memory, .program, .io }) |kind| {
        const hasher = tree.TreeHasher.init(kind);
        const last = tree.indexLimit(kind) - 1;
        const leaves = [_]tree.Leaf{
            .{ .index = 0, .value = 9 }, .{ .index = 1, .value = 0 },
            .{ .index = 7, .value = 0x123456 }, .{ .index = 65537, .value = 35 },
            .{ .index = last, .value = 63 },
        };
        for ([_][]const tree.Leaf{ &.{}, &leaves }) |source| {
            for ([_]u32{ 0, 6, 65537, last }) |address| {
                const opening = try hasher.opening(source, address);
                var coordinates: [tree.DEPTH + 1]tree.Coordinate = undefined;
                var roots: [coordinates.len]tree.Digest = undefined;
                for (coordinates[0..tree.DEPTH], 0..) |*coordinate, level| {
                    coordinate.* = .{ .level = @intCast(level), .index = (address >> @intCast(level)) ^ 1 };
                }
                coordinates[tree.DEPTH] = .{ .level = tree.DEPTH, .index = 0 };
                try hasher.subtreeRoots(source, &coordinates, &roots);
                for (roots[0..tree.DEPTH], opening.siblings) |actual, expected| {
                    try std.testing.expectEqualSlices(u8, &expected.bytes, &actual.bytes);
                }
                try std.testing.expectEqualSlices(u8, &opening.root.bytes, &roots[tree.DEPTH].bytes);
            }
        }
    }
}

test "BLAKE3 subtree batch rejects complete malformed requests before writing" {
    const hasher = tree.TreeHasher.init(.memory);
    const sentinel = tree.Digest{ .bytes = @splat(0xa5) };
    var roots: [2]tree.Digest = @splat(sentinel);
    const good = tree.Coordinate{ .level = 0, .index = 0 };
    try std.testing.expectError(error.InvalidStateSubtreeCoordinate, hasher.subtreeRoots(&.{}, &.{ good, .{ .level = 31, .index = 0 } }, &roots));
    try std.testing.expectError(error.InvalidStateSubtreeCoordinate, hasher.subtreeRoots(&.{}, &.{ good, .{ .level = 30, .index = 1 } }, &roots));
    try std.testing.expectError(error.InvalidStateSubtreeCoordinate, hasher.subtreeRoots(&.{}, &.{ good, .{ .level = 0, .index = tree.ADDRESS_LIMIT } }, &roots));
    try std.testing.expectError(error.InvalidStateSubtreeDestination, hasher.subtreeRoots(&.{}, &.{good}, &roots));
    try std.testing.expectError(error.UnsortedOrDuplicateByte, hasher.subtreeRoots(&.{ .{ .index = 1, .value = 0 }, .{ .index = 0, .value = 1 } }, &.{ good, good }, &roots));
    try std.testing.expectError(error.StateIndexOutOfRange, hasher.subtreeRoots(&.{.{ .index = tree.MEMORY_WORD_LIMIT, .value = 0 }}, &.{ good, good }, &roots));
    for (roots) |actual| try std.testing.expectEqualSlices(u8, &sentinel.bytes, &actual.bytes);
    const program = tree.TreeHasher.init(.program);
    try std.testing.expectError(error.NonCanonicalProgramField, program.subtreeRoots(&.{.{ .index = 0, .value = 0x7fffffff }}, &.{ good, good }, &roots));
    try hasher.subtreeRoots(&.{}, &.{}, &.{});
}

test "BLAKE3 subtree batch sparse frontier scaling diagnostic" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_FRONTIER_PROFILE")) return;
    const a = std.testing.allocator;
    const Graph = @import("../../prover/blake3_shared_path_topology.zig").Graph;
    const hasher = tree.TreeHasher.init(.memory);
    var leaves: [64]tree.Leaf = undefined;
    var addresses: [leaves.len]u32 = undefined;
    for (&leaves, &addresses, 0..) |*leaf, *address, i| {
        address.* = @as(u32, @intCast(i)) * 1048577;
        leaf.* = .{ .index = address.*, .value = @intCast(i + 1) };
    }
    var graph = try Graph.init(a, &addresses);
    defer graph.deinit();
    const roots = try a.alloc(tree.Digest, graph.frontier.len);
    defer a.free(roots);
    var timer = try std.time.Timer.start();
    try hasher.subtreeRoots(&leaves, graph.frontier, roots);
    const batch_ns = timer.read();
    timer.reset();
    for (graph.frontier, roots) |coordinate, digest| {
        const opposite = (coordinate.index ^ 1) << @as(u5, @intCast(coordinate.level));
        if (opposite >= tree.MEMORY_WORD_LIMIT) continue;
        const opening = try hasher.opening(&leaves, opposite);
        try std.testing.expectEqualSlices(u8, &opening.siblings[coordinate.level].bytes, &digest.bytes);
    }
    const repeated_ns = timer.read();
    std.debug.print("BLAKE3_FRONTIER_SCALING leaves={d} frontier={d} batch_ns={d} repeated_ns={d}\n", .{ leaves.len, graph.frontier.len, batch_ns, repeated_ns });
}
