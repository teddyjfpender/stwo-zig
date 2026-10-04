const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const projection = @import("../blake3_projection_links.zig");
const Query = @import("../blake3_query_links.zig").Query;
test "BLAKE3 projected index ports preserve native geometry and fixed alias-independent wiring" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var links: [5]Query = undefined;
    for (&links, 0..) |*q, i| {
        q.* = .{ .source = .{ .circuit = 1, .wire = @intCast(i) } };
        for (&q.bits, 0..) |*bit, j| bit.deep = @intCast(31 * i + j);
    }
    const all_logs = [_][]const u32{ &.{ 1, 4, 4, 6 }, &.{ 1, 16, 31, 31 } };
    for ([_]u32{ 6, 31 }, all_logs) |lifting, logs| {
        const limit = (@as(usize, 1) << @intCast(lifting)) - 1;
        const raw = [_]usize{ 0, 1, 2, limit - 1, limit };
        const changed = [_]usize{ limit, limit, 0, 0, 1 };
        const live = try projection.build(a, lifting, logs, &raw, &links);
        const other = try projection.build(a, lifting, logs, &changed, &links);
        try std.testing.expectEqualDeep(live.ports, other.ports);
        try std.testing.expectEqualSlices([31]u32, live.bit_reads, other.bit_reads);
        inline for (.{ projection.route, projection.pack }, .{ live.routed, live.packing }, .{ other.routed, other.packing }, .{ live.fixed_routed, live.fixed_packed }) |Air, rows, changed_rows, fixed| {
            try std.testing.expectEqual(rows.len, changed_rows.len);
            for (rows, changed_rows, fixed) |r, c, p| {
                try std.testing.expectEqualSlices(M, r[Air.PHYSICAL_MAIN_COLUMN_COUNT..], c[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
                try std.testing.expectEqualSlices(M, r[Air.PHYSICAL_MAIN_COLUMN_COUNT..], p[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
            }
        }
        var geometry = try @import("../blake3_lifted_leaf_plan.zig").build(a, logs);
        defer geometry.deinit();
        for (logs, 0..) |log, c| for (raw, 0..) |position, q| {
            const endpoint = live.ports[log].?[q];
            const row = live.routed[endpoint.wire];
            var actual: u32 = 0;
            for (row[8..12], 0..) |byte, i| actual |= byte.v << @as(u5, @intCast(i * 8));
            try std.testing.expectEqual(try geometry.columnIndex(c, @intCast(position)), actual);
        };
        var d = try projection.route.build(a);
        defer d.deinit();
        for (live.routed) |row| {
            try std.testing.expect(try satisfied(a, &d, row));
            var bad = row;
            bad[8] = bad[8].add(M.one());
            try std.testing.expect(!try satisfied(a, &d, bad));
        }
    }
    var invalid = projection.route.AffineSchedule{ .sources = .{ null, null }, .destination = .{ .circuit = 2, .wire = 0 }, .uses = 1 };
    invalid.coefficients[0][0] = M.one();
    try std.testing.expectError(error.InvalidBlake3ByteRoute, projection.route.fixedAffine(invalid));
    invalid.sources[0] = invalid.destination;
    try std.testing.expectError(error.InvalidBlake3ByteRoute, projection.route.fixedAffine(invalid));
    try std.testing.expectError(error.InvalidProjectionLink, projection.build(a, 6, &.{7}, &.{0}, links[0..1]));
    try std.testing.expectError(error.InvalidProjectionLink, projection.build(a, 6, &.{6}, &.{64}, links[0..1]));
}
fn satisfied(a: std.mem.Allocator, d: *const projection.route.Definition, row: projection.route.Row) !bool {
    const values = try @import("../test_support.zig").evaluateArena(a, &d.arena, &row);
    defer a.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[@import("../../../air/lang/mod.zig").types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
