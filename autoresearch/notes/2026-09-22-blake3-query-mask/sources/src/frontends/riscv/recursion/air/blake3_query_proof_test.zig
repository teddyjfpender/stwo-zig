//! Raw query extraction from a canonical draw, without field rejection.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const mask = @import("blake3_query_mask.zig");
const hash = @import("blake3_hash_witness.zig");
const graph = @import("blake3_hash_plan.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{mask});
const Data = struct {
    rows: hash.Rows,
    queries: []mask.Row,
    fn logs(self: Data) [4]u32 {
        return self.rows.logs() ++ .{@as(u32, 3)};
    }
};
test "BLAKE3 raw query indices verify in a complete CPU draw proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var channel = f.core.channel.blake3.Channel{};
    const frame = f.core.channel.blake3.Frame{ .draw = .{ .state = channel.digestBytes(), .index = 0 } };
    const bytes = try frame.encode(a);
    const native = channel.drawU32s();
    var expected: [8]u32 = undefined;
    for (&expected, native) |*value, word| value.* = word & 0xfffff;
    const live = try assemble(a, true, bytes, expected);
    const logs = live.logs();
    const rows = .{ try f.padded(f.g, a, live.rows.g_rows, logs[0]), try f.padded(f.xor, a, live.rows.xor_rows, logs[1]), try f.padded(f.boundary, a, live.rows.boundary_rows, logs[2]), try f.padded(mask, a, live.queries, logs[3]) };
    const trusted = try preprocessing(a, bytes, expected);
    var wrong = expected;
    wrong[3] ^= 0x80000;
    const false_pp = try preprocessing(a, bytes, wrong);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, trusted, false_pp);
}
fn preprocessing(a: std.mem.Allocator, bytes: []const u8, expected: [8]u32) ![]f.Column {
    const data = try assemble(a, false, bytes, expected);
    const logs = data.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ data.rows.g_rows, data.rows.xor_rows, data.rows.boundary_rows, data.queries }, 0..) |Air, rows, i| try f.project(Air, a, rows, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
fn assemble(a: std.mem.Allocator, comptime live: bool, bytes: []const u8, expected: [8]u32) !Data {
    var rows: hash.Rows = undefined;
    var digest: [32]u8 = undefined;
    if (live) {
        const prepared = try hash.prepare(a, 1001, bytes, @splat(0));
        rows = prepared.rows;
        digest = prepared.digest;
    } else rows = try hash.trustedRows(a, 1001, bytes, @splat(0));
    var plan = try graph.build(a, bytes.len);
    defer plan.deinit();
    const queries = try a.alloc(mask.Row, 8);
    for (queries, expected, plan.output, 0..) |*row, value, source, i| {
        const schedule = mask.Schedule{ .source_circuit = 1001, .source_wire = source, .destination_circuit = 1002, .destination_wire = @intCast(i), .uses = 1, .log_domain_size = 20 };
        row.* = if (live) try mask.logicalRow(schedule, std.mem.readInt(u32, digest[4 * i ..][0..4], .little)) else try mask.fixedRow(schedule);
        rows.boundary_rows[rows.boundary_rows.len - 8 + i] = try f.boundary.logicalRow(1002, @intCast(i), f.M31.one().neg(), value);
    }
    return .{ .rows = rows, .queries = queries };
}
