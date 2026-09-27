//! Three hash graphs and typed byte routing authenticate one Merkle parent.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const route = @import("blake3_byte_route.zig");
const node = @import("blake3_node_route.zig");
const graph = @import("blake3_hash_plan.zig");
const hash = @import("blake3_hash_witness.zig");
const F = @import("blake3_fixture_roster.zig").WithBridge(route);
const M31 = f.M31;
const LeafValues = [2][4]M31{
    .{ M31.zero(), M31.one(), M31.fromCanonical(2147483646), M31.fromCanonical(19) },
    .{ M31.fromCanonical(23), M31.fromCanonical(29), M31.fromCanonical(31), M31.fromCanonical(2147483645) },
};
fn messages(a: std.mem.Allocator) ![2][]const u8 {
    return .{
        try (f.core.channel.blake3.Frame{ .leaf = &LeafValues[0] }).encode(a),
        try (f.core.channel.blake3.Frame{ .leaf = &LeafValues[1] }).encode(a),
    };
}
const PARENT: u32 = 503;
const Data = struct {
    gs: []f.g.Row,
    xs: []f.xor.Row,
    bs: []f.boundary.Row,
    routes: []route.Row,
    fn logs(self: Data) [4]u32 {
        return .{ log(self.gs.len), log(self.xs.len), log(self.bs.len), log(self.routes.len) };
    }
    fn log(n: usize) u32 {
        return @max(1, std.math.log2_int_ceil(usize, n));
    }
};
test "BLAKE3 routed Merkle proof authenticates both private child digests" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var digests: [2][32]u8 = undefined;
    for (LeafValues, &digests) |values, *digest| {
        var leaf = f.Hasher.defaultWithInitialState();
        leaf.updateLeaf(&values);
        digest.* = leaf.finalize();
    }
    const expected = f.Hasher.hashChildren(.{ .left = digests[0], .right = digests[1] });
    const live = try assemble(a, true, expected);
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.gs, logs[0]), try f.padded(f.xor, a, live.xs, logs[1]), try f.padded(f.boundary, a, live.bs, logs[2]), try f.padded(route, a, live.routes, logs[3]) };
    const trusted = try preprocessing(a, expected);
    var wrong = expected;
    wrong[0] ^= 1;
    const false_pp = try preprocessing(a, wrong);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, digest: [32]u8) ![]f.Column {
    const data = try assemble(a, false, digest);
    const logs = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.gs, data.xs, data.bs, data.routes }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
// Arena-owned fixture. The trusted branch never computes child digest values.
fn assemble(a: std.mem.Allocator, comptime live: bool, root: [32]u8) !Data {
    const child_messages = try messages(a);
    var callers: [2]node.Caller = undefined;
    for (&callers, child_messages, 0..) |*caller, message, i| {
        var plan = try graph.build(a, message.len);
        defer plan.deinit();
        for (plan.output, 0..) |wire, j| if (wire != plan.output[0] + j) return error.NoncontiguousRoot;
        caller.* = .{ .circuit = @intCast(501 + i), .first_wire = plan.output[0] };
    }
    var routing = try node.build(a, PARENT, callers);
    defer routing.deinit();
    var children: [2]hash.Rows = undefined;
    var digests: [2][32]u8 = undefined;
    for (child_messages, callers, &children, &digests, routing.child_uses) |message, caller, *child, *digest, counts| {
        if (live) {
            std.crypto.hash.Blake3.hash(message, digest, .{});
            child.* = (try hash.prepare(a, caller.circuit, message, digest.*)).rows;
        } else child.* = try hash.trustedRows(a, caller.circuit, message, @splat(0));
        // Root outputs are no longer public sinks. Their authenticating copy
        // consumers are exactly those counted by the canonical routing plan.
        for (counts, 0..) |count, i| child.xor_rows[child.xor_rows.len - 16 + i][17] = M31.fromCanonical(count);
        child.boundary_rows = child.boundary_rows[0 .. child.boundary_rows.len - 8];
    }
    var parent = if (live) blk: {
        const bytes = try (f.core.channel.blake3.Frame{ .node = .{ .left = digests[0], .right = digests[1] } }).encode(a);
        break :blk (try hash.prepare(a, PARENT, bytes, root)).rows;
    } else try hash.trustedShapeRows(a, PARENT, node.frameLength(), root);
    var parent_plan = try graph.build(a, node.frameLength());
    defer parent_plan.deinit();
    var constants: std.ArrayList(f.boundary.Row) = .empty;
    for (parent_plan.sources, parent.boundary_rows[0..parent_plan.sources.len]) |source, row| if (source.value == .constant) try constants.append(a, row);
    try constants.appendSlice(a, parent.boundary_rows[parent_plan.sources.len..]);
    parent.boundary_rows = try constants.toOwnedSlice(a);
    const routed = try a.alloc(route.Row, routing.schedules.len);
    for (routed, routing.schedules) |*row, schedule| row.* = if (live) try node.witnessRow(schedule, callers, digests) else try route.fixedRow(schedule);
    return .{
        .gs = try std.mem.concat(a, f.g.Row, &.{ children[0].g_rows, children[1].g_rows, parent.g_rows }),
        .xs = try std.mem.concat(a, f.xor.Row, &.{ children[0].xor_rows, children[1].xor_rows, parent.xor_rows }),
        .bs = try std.mem.concat(a, f.boundary.Row, &.{ children[0].boundary_rows, children[1].boundary_rows, parent.boundary_rows }),
        .routes = routed,
    };
}
