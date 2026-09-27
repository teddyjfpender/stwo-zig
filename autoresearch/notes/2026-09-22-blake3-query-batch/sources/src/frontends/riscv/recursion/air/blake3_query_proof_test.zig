//! A native absorption produces private state for a partial raw query batch.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const draw = @import("blake3_query_witness.zig");
const graph = @import("blake3_hash_plan.zig");
const hash = @import("blake3_hash_witness.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ draw.mask, draw.route });
const Data = struct {
    gs: []f.g.Row,
    xs: []f.xor.Row,
    bs: []f.boundary.Row,
    cs: []draw.mask.Row,
    rs: []draw.route.Row,
    fn logs(self: Data) [5]u32 {
        return .{ log(self.gs.len), log(self.xs.len), log(self.bs.len), log(self.cs.len), log(self.rs.len) };
    }
    fn log(n: usize) u32 {
        return @max(1, std.math.log2_int_ceil(usize, n));
    }
};
test "BLAKE3 raw query indices verify in a complete CPU draw proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var channel = f.core.channel.blake3.Channel{};
    channel.mixU64(198);
    const native = try f.core.queries.drawQueries(&channel, a, 20, 9);
    var expected: [9]u32 = undefined;
    for (&expected, native) |*value, word| value.* = @intCast(word);
    try std.testing.expectEqual(@as(u64, 2), channel.n_draws);
    const live = try assemble(a, true, expected);
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.gs, logs[0]), try f.padded(f.xor, a, live.xs, logs[1]), try f.padded(f.boundary, a, live.bs, logs[2]), try f.padded(draw.mask, a, live.cs, logs[3]), try f.padded(draw.route, a, live.rs, logs[4]) };
    const trusted = try preprocessing(a, expected);
    var wrong = expected;
    wrong[8] ^= 1;
    const false_pp = try preprocessing(a, wrong);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, expected: [9]u32) ![]f.Column {
    const data = try assemble(a, false, expected);
    const logs = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.gs, data.xs, data.bs, data.cs, data.rs }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
fn assemble(a: std.mem.Allocator, comptime live: bool, expected: [9]u32) !Data {
    const initial = (f.core.channel.blake3.Channel{}).digestBytes();
    const bytes = try (f.core.channel.blake3.Frame{ .integer = .{ .state = initial, .value = 198 } }).encode(a);
    defer a.free(bytes);
    var plan = try graph.build(a, bytes.len);
    defer plan.deinit();
    for (plan.output, 0..) |wire, i| if (wire != plan.output[0] + i) return error.NoncontiguousRoot;
    var producer: hash.Rows = undefined;
    var state: [32]u8 = @splat(0);
    if (live) {
        const prepared = try hash.prepare(a, 801, bytes, @splat(0));
        producer = prepared.rows;
        state = prepared.digest;
    } else producer = try hash.trustedRows(a, 801, bytes, @splat(0));
    defer producer.deinit();
    const statement = draw.Statement{ .namespace = 802, .state = state, .start = 0, .log_domain_size = 20, .values = &expected, .state_source = .{ .circuit = 801, .first_wire = plan.output[0] } };
    var challenge = if (live) try draw.prepare(a, statement) else try draw.trusted(a, statement);
    defer challenge.deinit();
    for (challenge.state_uses, 0..) |count, i| producer.xor_rows[producer.xor_rows.len - 16 + i][17] = f.M31.fromCanonical(count);
    return .{
        .gs = try std.mem.concat(a, f.g.Row, &.{ producer.g_rows, challenge.g_rows }),
        .xs = try std.mem.concat(a, f.xor.Row, &.{ producer.xor_rows, challenge.xor_rows }),
        .bs = try std.mem.concat(a, f.boundary.Row, &.{ producer.boundary_rows[0 .. producer.boundary_rows.len - 8], challenge.boundary_rows }),
        .cs = try a.dupe(draw.mask.Row, challenge.mask_rows),
        .rs = try a.dupe(draw.route.Row, challenge.route_rows),
    };
}
