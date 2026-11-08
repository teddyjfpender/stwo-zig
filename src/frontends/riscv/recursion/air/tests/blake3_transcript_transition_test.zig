//! Two native absorptions with an authenticated private intermediate state.
const std = @import("std");
const f = @import("../blake3_proof_fixture.zig");
const frame_hash = @import("../blake3_frame_witness.zig");
const route = frame_hash.route;
const graph = @import("../blake3_hash_plan.zig");
const hash = @import("../blake3_hash_witness.zig");
const F = @import("../blake3_fixture_roster.zig").WithBridge(route);
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
test "BLAKE3 transcript absorption proves with private intermediate state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var channel = f.core.channel.blake3.Channel{};
    channel.mixU64(198);
    channel.mixU64(42);
    const expected = channel.digestBytes();
    const live = try assemble(a, true, expected);
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.gs, logs[0]), try f.padded(f.xor, a, live.xs, logs[1]), try f.padded(f.boundary, a, live.bs, logs[2]), try f.padded(route, a, live.routes, logs[3]) };
    const trusted = try preprocessing(a, expected);
    var wrong = expected;
    wrong[19] ^= 0x80;
    const false_pp = try preprocessing(a, wrong);
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, digest: [32]u8) ![]f.Column {
    const data = try assemble(a, false, digest);
    const logs = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.gs, data.xs, data.bs, data.routes }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
fn assemble(a: std.mem.Allocator, comptime live: bool, root: [32]u8) !Data {
    const initial = (f.core.channel.blake3.Channel{}).digestBytes();
    const bytes = try (f.core.channel.blake3.Frame{ .integer = .{ .state = initial, .value = 198 } }).encode(a);
    defer a.free(bytes);
    var plan = try graph.build(a, bytes.len);
    defer plan.deinit();
    for (plan.output, 0..) |wire, i| if (wire != plan.output[0] + i) return error.NoncontiguousRoot;
    const bindings = [_]frame_hash.Binding{.{ .role = .state, .caller = .{ .circuit = 701, .first_wire = plan.output[0] } }};
    var first: hash.Rows = undefined;
    var intermediate: [32]u8 = @splat(0);
    if (live) {
        const prepared = try hash.prepare(a, 701, bytes, @splat(0));
        first = prepared.rows;
        intermediate = prepared.digest;
    } else first = try hash.trustedRows(a, 701, bytes, @splat(0));
    defer first.deinit();
    const frame = f.core.channel.blake3.Frame{ .integer = .{ .state = intermediate, .value = 42 } };
    var second = if (live) try frame_hash.prepare(a, 702, frame, &bindings, root) else try frame_hash.trusted(a, 702, frame, &bindings, root);
    defer second.deinit();
    for (second.source_uses[0], 0..) |count, i| first.xor_rows[first.xor_rows.len - 16 + i][17] = f.M31.fromCanonical(count);
    return .{
        .gs = try std.mem.concat(a, f.g.Row, &.{ first.g_rows, second.rows.g_rows }),
        .xs = try std.mem.concat(a, f.xor.Row, &.{ first.xor_rows, second.rows.xor_rows }),
        .bs = try std.mem.concat(a, f.boundary.Row, &.{ first.boundary_rows[0 .. first.boundary_rows.len - 8], second.rows.boundary_rows }),
        .routes = try a.dupe(route.Row, second.route_rows),
    };
}
