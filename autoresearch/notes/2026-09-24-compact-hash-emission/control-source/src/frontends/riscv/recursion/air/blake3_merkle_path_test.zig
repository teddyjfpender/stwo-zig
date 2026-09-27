const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const path = @import("blake3_merkle_path_witness.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ path.route, path.word });
const M31 = f.M31;
const leaves = [4][2]M31{
    .{ M31.fromCanonical(11), M31.fromCanonical(13) }, .{ M31.fromCanonical(17), M31.fromCanonical(19) },
    .{ M31.fromCanonical(23), M31.fromCanonical(29) }, .{ M31.fromCanonical(2147483646), M31.zero() },
};
const Tree = struct {
    leaf: [4][32]u8,
    parent: [2][32]u8,
    root: [32]u8,
    fn init() Tree {
        var self: Tree = undefined;
        for (leaves, &self.leaf) |values, *digest| {
            var h = f.Hasher.defaultWithInitialState();
            h.updateLeaf(&values);
            digest.* = h.finalize();
        }
        for (&self.parent, 0..) |*digest, i| digest.* = f.Hasher.hashChildren(.{ .left = self.leaf[2 * i], .right = self.leaf[2 * i + 1] });
        self.root = f.Hasher.hashChildren(.{ .left = self.parent[0], .right = self.parent[1] });
        return self;
    }
    fn siblings(self: Tree, index: usize) [2][32]u8 {
        return .{ self.leaf[index ^ 1], self.parent[(index / 2) ^ 1] };
    }
};
test "BLAKE3 private sibling word semantics pin and reject out of range bytes" {
    const a = std.testing.allocator;
    const digest = try path.word.computeSemanticDigest(a);
    try std.testing.expectEqualSlices(u8, &path.word.SEMANTIC_DIGEST, &digest);
    var d = try path.word.build(a);
    defer d.deinit();
    const plan = try f.binding.Binding(path.word).authenticate(&d);
    const direct = try @import("direct_constraint_program.zig").authenticate(&d.arena, path.word.SEMANTIC_DIGEST, path.word.LOGICAL_INPUT_COUNT);
    var exported = try @import("framework_polynomial_export_v1.zig").exportLocalPrepared(path.word, a, &direct, &plan);
    defer exported.deinit();
    var row = try path.word.logicalRow(7, 8, 2, 0xffffffff);
    const good = plan.preparedEntries(row);
    _ = try f.schema.indexSecure(.range_check_8_8, good[1].values[0..2]);
    row[0] = M31.fromCanonical(256);
    const bad = plan.preparedEntries(row);
    try std.testing.expectError(error.ValueOutOfRange, f.schema.indexSecure(.range_check_8_8, bad[1].values[0..2]));
}
test "BLAKE3 path witnesses match every native direction and keep siblings private" {
    const a = std.testing.allocator;
    const tree = Tree.init();
    for (0..4) |i| {
        const s = path.Statement{ .namespace = 17, .leaf = &leaves[i], .index = @intCast(i), .depth = 2, .root = tree.root };
        var live = try path.prepare(a, s, &tree.siblings(i));
        defer live.deinit();
        var trusted = try path.trusted(a, s);
        defer trusted.deinit();
        try std.testing.expectEqualSlices(u8, &tree.root, &live.computed_root.?);
        try std.testing.expect(trusted.computed_root == null);
        inline for (F.Airs, .{ live.g_rows, live.xor_rows, live.boundary_rows, live.route_rows, live.word_rows }, .{ trusted.g_rows, trusted.xor_rows, trusted.boundary_rows, trusted.route_rows, trusted.word_rows }) |Air, actual, fixed| for (actual, fixed) |left, right| try std.testing.expectEqualSlices(M31, left[Air.PHYSICAL_MAIN_COLUMN_COUNT..], right[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        var changed = tree.siblings(i);
        changed[0][31] ^= 0x80;
        var altered = try path.prepare(a, s, &changed);
        defer altered.deinit();
        try std.testing.expect(!std.mem.eql(u8, &tree.root, &altered.computed_root.?));
    }
    const leaf_statement = path.Statement{ .namespace = 17, .leaf = &leaves[0], .index = 0, .depth = 0, .root = tree.leaf[0] };
    var single = try path.prepare(a, leaf_statement, &.{});
    defer single.deinit();
    try std.testing.expectEqualSlices(u8, &tree.leaf[0], &single.computed_root.?);
    var malformed = leaf_statement;
    malformed.index = 1;
    try std.testing.expectError(error.InvalidBlake3MerklePath, path.trusted(a, malformed));
    try std.testing.expectError(error.InvalidBlake3MerklePath, path.prepare(a, leaf_statement, &tree.siblings(0)));
    try std.testing.checkAllAllocationFailures(a, allocationProbe, .{});
}
fn allocationProbe(a: std.mem.Allocator) !void {
    const tree = Tree.init();
    var prepared = try path.prepare(a, .{ .namespace = 17, .leaf = &leaves[2], .index = 2, .depth = 2, .root = tree.root }, &tree.siblings(2));
    defer prepared.deinit();
}
test "BLAKE3 private sibling paths verify in complete CPU proofs" {
    const tree = Tree.init();
    for ([_]u5{ 0, 2 }) |depth| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const s = path.Statement{ .namespace = 17, .leaf = &leaves[2], .index = if (depth == 0) 0 else 2, .depth = depth, .root = if (depth == 0) tree.leaf[2] else tree.root };
        const siblings = tree.siblings(2);
        var live = try path.prepare(a, s, siblings[0..depth]);
        defer live.deinit();
        const logs = live.logs();
        const rows = .{ try f.padded(path.g, a, live.g_rows, logs[0]), try f.padded(path.xor, a, live.xor_rows, logs[1]), try f.padded(path.boundary, a, live.boundary_rows, logs[2]), try f.padded(path.route, a, live.route_rows, logs[3]), try f.padded(path.word, a, live.word_rows, logs[4]) };
        const trusted = try preprocessing(a, s);
        var wrong = s;
        wrong.root[0] ^= 1;
        const false_pp = try preprocessing(a, wrong);
        try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
    }
}
fn preprocessing(a: std.mem.Allocator, s: path.Statement) ![]f.Column {
    var fixed = try path.trusted(a, s);
    defer fixed.deinit();
    const logs = fixed.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.route_rows, fixed.word_rows }, 0..) |Air, data, i| try f.project(Air, a, data, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
