//! Real STARK coverage for a public subtree joined to private memory siblings.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const path = @import("blake3_public_subtree_path.zig");
const route = @import("blake3_byte_route.zig");
const word = @import("blake3_private_word.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ route, word });
test "public subtree path proves private siblings and rejects a changed admitted root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const hasher = tree.TreeHasher.init(.memory);
    const snapshot = [_]tree.Leaf{ .{ .index = 0, .value = 77 }, .{ .index = 4, .value = 255 }, .{ .index = 5, .value = 0x12345678 }, .{ .index = 7, .value = 13 }, .{ .index = 123456, .value = 42 } };
    const opening = try hasher.opening(&snapshot, 4);
    var subroots: [1]tree.Digest = undefined;
    try hasher.subtreeRoots(&snapshot, &.{.{ .level = 2, .index = 1 }}, &subroots);
    const statement = path.Statement{ .namespace = 100, .sibling_namespace = 200, .address = 4, .height = 2, .subtree = subroots[0], .root = opening.root };
    var live = try path.prepare(a, statement, &opening.siblings);
    defer live.deinit();
    const logs = [_]u32{ log(live.g_rows.len), log(live.xor_rows.len), log(live.boundary_rows.len), log(live.route_rows.len), log(live.word_rows.len) };
    const rows = .{ try f.padded(f.g, a, live.g_rows, logs[0]), try f.padded(f.xor, a, live.xor_rows, logs[1]), try f.padded(f.boundary, a, live.boundary_rows, logs[2]), try f.padded(route, a, live.route_rows, logs[3]), try f.padded(word, a, live.word_rows, logs[4]) };
    const trusted = try preprocessing(a, statement, logs);
    var wrong = statement;
    wrong.root.bytes[31] ^= 0x80;
    const false_pp = try preprocessing(a, wrong, logs);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
    wrong = statement;
    wrong.subtree.bytes[0] ^= 1;
    try std.testing.expectError(error.InvalidPublicSubtreeRoot, path.prepare(a, wrong, &opening.siblings));
}
fn log(n: usize) u32 {
    return @max(1, std.math.log2_int_ceil(usize, n));
}
fn preprocessing(a: std.mem.Allocator, statement: path.Statement, logs: [5]u32) ![]f.Column {
    var fixed = try path.trusted(a, statement);
    defer fixed.deinit();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.route_rows, fixed.word_rows }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
