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
    const all_logs = [_][]const u32{ &.{ 1, 4, 4, 6 }, &.{ 1, 16, 31, 31 }, &.{ 1, 4, 7, 8 } };
    for ([_]u32{ 6, 31, 4 }, all_logs) |lifting, logs| {
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
        for (logs) |log| {
            const positions = try core.pcs.utils.prepareTreeQueryPositions(a, &raw, lifting, log);
            for (positions, 0..) |expected, q| {
                const endpoint = live.ports[log].?[q];
                const row = live.routed[endpoint.wire];
                var actual: u32 = 0;
                for (row[8..12], 0..) |byte, i| actual |= byte.v << @as(u5, @intCast(i * 8));
                try std.testing.expectEqual(@as(u32, @intCast(expected)), actual);
            }
        }
        var storage = try @import("../stable_graph_arena_v1.zig").Owned.init(a);
        defer storage.deinit();
        var cold = try @import("../block_v5_recursive_parent_fixed_pcs_ports_v1.zig").ProjectionFixed.init(&storage, lifting, logs, &links);
        defer cold.rows.deinit();
        try std.testing.expectEqualDeep(live.ports, cold.ports);
        try std.testing.expectEqualSlices([31]u32, live.bit_reads, cold.bit_reads);
        const RowStorage = @import("../blake3_parent_row_storage.zig");
        for (live.fixed_packed, try cold.rows.metadata(11)) |row, fixed| try std.testing.expectEqualDeep(RowStorage.compactFixed(projection.pack, row), fixed);
        for (live.fixed_routed, try cold.rows.metadata(7)) |row, fixed| try std.testing.expectEqualDeep(RowStorage.compactFixed(projection.route, row), fixed);
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
    try std.testing.expectError(error.InvalidProjectionLink, projection.build(a, 6, &.{32}, &.{0}, links[0..1]));
    try std.testing.expectError(error.InvalidProjectionLink, projection.build(a, 6, &.{6}, &.{64}, links[0..1]));
}

test "BLAKE3 trace direction expansion exhaustively matches original PCS query mapping" {
    const a = std.testing.allocator;
    const Links = @import("../blake3_query_links.zig");
    for (1..9) |lifting_usize| {
        const lifting: u32 = @intCast(lifting_usize);
        const raw = try a.alloc(usize, @as(usize, 1) << @intCast(lifting));
        defer a.free(raw);
        for (raw, 0..) |*value, i| value.* = i;
        for (0..11) |height_usize| {
            const height: u32 = @intCast(height_usize);
            const expected = try core.pcs.utils.prepareTreeQueryPositions(a, raw, lifting, height);
            defer a.free(expected);
            var query = Query{ .source = .{ .circuit = 1, .wire = 0 } };
            for (&query.bits, 0..) |*bit, i| bit.deep = @intCast(i);
            var map = Links.Prepared{ .arena = std.heap.ArenaAllocator.init(a), .queries = @constCast((&query)[0..1]), .fri_derived = &.{} };
            defer map.deinit();
            const directions = try map.traceDirections(a, 0, lifting, height);
            defer a.free(directions);
            for (raw, expected) |position, want| {
                var got: usize = 0;
                for (directions, 0..) |endpoint, bit| got |= ((position >> @intCast(endpoint.wire)) & 1) << @intCast(bit);
                try std.testing.expectEqual(want, got);
            }
            if (height > lifting) {
                // Every inserted zero consumes the DEEP-constrained zero bit.
                for (directions[1 .. height - lifting + 1]) |endpoint| try std.testing.expectEqual(lifting, endpoint.wire);
                try std.testing.expectEqual(@as(u32, 8 * (height - lifting)), query.path_uses[lifting]);
            }
        }
    }
    try std.testing.expectError(error.InvalidParentQueryLink, Links.traceBit(0, 5, 1));
    try std.testing.expectError(error.InvalidParentQueryLink, Links.traceBit(4, 32, 1));
    try std.testing.expectError(error.InvalidParentQueryLink, Links.traceBit(4, 4, 4));
}
fn satisfied(a: std.mem.Allocator, d: *const projection.route.Definition, row: projection.route.Row) !bool {
    const values = try @import("../test_support.zig").evaluateArena(a, &d.arena, &row);
    defer a.free(values);
    for (d.arena.constraintsView()) |constraint| if (!values[@import("../../../air/lang/mod.zig").types.idIndex(constraint.root)].isZero()) return false;
    return true;
}
