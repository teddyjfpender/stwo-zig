//! One raw-query statement determines both transcript outputs and Merkle paths.
const std = @import("std");
const f = @import("../blake3_proof_fixture.zig");
const query = @import("../blake3_query_witness.zig");
const path = @import("../blake3_merkle_path_witness.zig");
const mapping = @import("../blake3_query_path_plan.zig");
const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ query.mask, path.route, path.word });
const leaves = [2][2]f.M31{ .{ f.M31.fromCanonical(17), f.M31.fromCanonical(19) }, .{ f.M31.fromCanonical(23), f.M31.fromCanonical(29) } };
const Tree = struct {
    leaf: [2][32]u8,
    root: [32]u8,
    fn init() Tree {
        var result: Tree = undefined;
        for (leaves, &result.leaf) |values, *digest| {
            var h = f.Hasher.defaultWithInitialState();
            h.updateLeaf(&values);
            digest.* = h.finalize();
        }
        result.root = f.Hasher.hashChildren(.{ .left = result.leaf[0], .right = result.leaf[1] });
        return result;
    }
};
const Data = struct {
    gs: []f.g.Row,
    xs: []f.xor.Row,
    bs: []f.boundary.Row,
    ms: []query.mask.Row,
    rs: []path.route.Row,
    ws: []path.word.Row,
    fn logs(self: Data) [6]u32 {
        return .{ log(self.gs.len), log(self.xs.len), log(self.bs.len), log(self.ms.len), log(self.rs.len), log(self.ws.len) };
    }
    fn log(n: usize) u32 {
        return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
    }
};
test "BLAKE3 raw queries admit exactly their canonical private sibling paths in one proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var channel = f.core.channel.blake3.Channel{};
    const native = try f.core.queries.drawQueries(&channel, a, 1, 9);
    var raw: [9]u32 = undefined;
    for (&raw, native) |*value, index| value.* = @intCast(index);
    var plan = try mapping.build(a, &raw, 1, 0);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.queries.positions.len);
    const tree = Tree.init();
    const live = try assemble(a, true, &raw, plan.queries.positions, tree.root);
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.gs, logs[0]), try f.padded(f.xor, a, live.xs, logs[1]), try f.padded(f.boundary, a, live.bs, logs[2]), try f.padded(query.mask, a, live.ms, logs[3]), try f.padded(path.route, a, live.rs, logs[4]), try f.padded(path.word, a, live.ws, logs[5]) };
    const trusted = try preprocessing(a, &raw, plan.queries.positions, tree.root);
    try std.testing.expectError(error.InvalidBlake3QueryPaths, preprocessing(a, &raw, &.{1}, tree.root));
    try std.testing.expectError(error.InvalidBlake3QueryPaths, preprocessing(a, &raw, &.{ 1, 0 }, tree.root));
    var wrong = tree.root;
    wrong[9] ^= 0x80;
    const false_pp = try preprocessing(a, &raw, plan.queries.positions, wrong);
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, raw: []const u32, positions: []const usize, root: [32]u8) ![]f.Column {
    const data = try assemble(a, false, raw, positions, root);
    const logs = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.gs, data.xs, data.bs, data.ms, data.rs, data.ws }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
fn assemble(a: std.mem.Allocator, comptime live: bool, raw: []const u32, positions: []const usize, root: [32]u8) !Data {
    var plan = try mapping.build(a, raw, 1, 0);
    defer plan.deinit();
    try plan.admit(positions);
    const initial = (f.core.channel.blake3.Channel{}).digestBytes();
    const s = query.Statement{ .namespace = 1101, .state = initial, .state_source = .{ .circuit = 1100, .first_wire = 0 }, .start = 0, .log_domain_size = 1, .values = raw };
    var batch = if (live) try query.prepare(a, s) else try query.trusted(a, s);
    defer batch.deinit();
    var gs: std.ArrayList(f.g.Row) = .empty;
    var xs: std.ArrayList(f.xor.Row) = .empty;
    var bs: std.ArrayList(f.boundary.Row) = .empty;
    var rs: std.ArrayList(path.route.Row) = .empty;
    var ws: std.ArrayList(path.word.Row) = .empty;
    try gs.appendSlice(a, batch.g_rows);
    try xs.appendSlice(a, batch.xor_rows);
    try bs.appendSlice(a, batch.boundary_rows);
    try rs.appendSlice(a, batch.route_rows);
    for (batch.state_uses, 0..) |uses, i| try bs.append(a, try f.boundary.logicalRow(1100, @intCast(i), f.M31.fromCanonical(uses), std.mem.readInt(u32, initial[4 * i ..][0..4], .little)));
    for (plan.queries.positions, 0..) |index, i| {
        const statement = path.Statement{ .namespace = @intCast(1200 + 3 * i), .leaf = &leaves[index], .index = @intCast(index), .depth = 1, .root = root };
        var merkle = if (live) try path.prepare(a, statement, &.{Tree.init().leaf[index ^ 1]}) else try path.trusted(a, statement);
        defer merkle.deinit();
        try gs.appendSlice(a, merkle.g_rows);
        try xs.appendSlice(a, merkle.xor_rows);
        try bs.appendSlice(a, merkle.boundary_rows);
        try rs.appendSlice(a, merkle.route_rows);
        try ws.appendSlice(a, merkle.word_rows);
    }
    return .{ .gs = try gs.toOwnedSlice(a), .xs = try xs.toOwnedSlice(a), .bs = try bs.toOwnedSlice(a), .ms = try a.dupe(query.mask.Row, batch.mask_rows), .rs = try rs.toOwnedSlice(a), .ws = try ws.toOwnedSlice(a) };
}
