const std = @import("std");
const storage = @import("blake3_parent_row_storage.zig");
const join = @import("blake3_parent_join.zig");
const boundary = @import("blake3_boundary.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const committed = @import("framework_interaction.zig").committedRow;
test "BLAKE3 memory update proves disjoint parent column join" {
    const a = std.testing.allocator;
    var left = try fixture(a, 1, 3, 42);
    defer left.deinit();
    var right = try fixture(a, 101, 2, 200);
    defer right.deinit();
    const ranges = [2]join.Range{ .{ .first = 1, .end = 2 }, .{ .first = 101, .end = 102 } };
    var combined = try join.join(a, &left, &right, ranges);
    defer combined.deinit();
    try std.testing.expectEqual(@as(usize, 5), combined.fixed[2].len);
    try std.testing.expectEqual(@as(usize, 5), combined.input_count);
    for ([_]u32{ 42, 43, 44, 200, 201 }, 0..) |value, i| {
        try std.testing.expectEqual(value, combined.main[2][0].values[committed(i, 3)].toU32());
        try std.testing.expectEqual(if (i < 3) @as(u32, 1) else 101, combined.fixed[2][i][5 - boundary.PHYSICAL_MAIN_COLUMN_COUNT].toU32());
    }
    for (5..8) |i| try std.testing.expect(combined.main[2][0].values[committed(i, 3)].isZero());
    try std.testing.expectError(error.OverlappingParentNamespaces, join.join(a, &left, &right, .{ ranges[0], ranges[0] }));
    right.fixed[2][0][5 - boundary.PHYSICAL_MAIN_COLUMN_COUNT] = M.one();
    try std.testing.expectError(error.InvalidParentCustodyNamespace, join.join(a, &left, &right, ranges));
    right.fixed[2][0][5 - boundary.PHYSICAL_MAIN_COLUMN_COUNT] = M.fromCanonical(101);
    const values = right.main[2][0].values;
    right.main[2][0].values = &.{};
    try std.testing.expectError(error.InvalidParentJoinColumns, join.join(a, &left, &right, ranges));
    right.main[2][0].values = values;
    try std.testing.expectEqual(@as(u32, 42), left.main[2][0].values[committed(0, 2)].toU32());
}
fn fixture(a: std.mem.Allocator, circuit: u32, count: usize, first: u32) !storage.Prepared {
    var result = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = count };
    inline for (0..storage.Airs.len) |i| result.fixed[i] = &.{};
    errdefer result.deinit();
    result.fixed[2] = try a.alloc(storage.FixedRow(boundary), count);
    for (result.fixed[2], 0..) |*row, i| row.* = storage.compactFixed(boundary, try boundary.logicalRow(circuit, @intCast(i), M.one(), first + @as(u32, @intCast(i))));
    inline for (storage.Airs, 0..) |Air, i| {
        const log: u32 = if (result.fixed[i].len < 2) 1 else std.math.log2_int_ceil(usize, result.fixed[i].len);
        result.main[i] = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (result.main[i]) |*column| column.* = .{ .log_size = log, .values = &.{} };
        for (result.main[i], 0..) |*column, c| {
            const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
            column.values = values;
            @memset(values, M.zero());
            if (comptime i == 2) for (0..count) |logical| {
                values[committed(logical, log)] = (try boundary.logicalRow(circuit, @intCast(logical), M.one(), first + @as(u32, @intCast(logical))))[c];
            };
        }
    }
    return result;
}

test "BLAKE3 memory update proves tiled join matches logical rows and padding" {
    const a = std.testing.allocator;
    for ([_][2]usize{ .{ 0, 0 }, .{ 0, 3 }, .{ 3, 0 }, .{ 1, 1 }, .{ 3, 5 }, .{ 7, 2 }, .{ 513, 1025 }, .{ 1024, 1024 } }) |counts| {
        var left = try fixture(a, 1, counts[0], 42);
        defer left.deinit();
        var right = try fixture(a, 101, counts[1], 200);
        defer right.deinit();
        var combined = try join.join(a, &left, &right, .{ .{ .first = 1, .end = 2 }, .{ .first = 101, .end = 102 } });
        defer combined.deinit();
        inline for (storage.Airs, 0..) |_, i| {
            const n = left.fixed[i].len + right.fixed[i].len;
            for (combined.main[i], 0..) |column, c| {
                for (0..column.values.len) |logical| {
                    const expected = if (logical < left.fixed[i].len)
                        left.main[i][c].values[committed(logical, left.main[i][c].log_size)]
                    else if (logical < n)
                        right.main[i][c].values[committed(logical - left.fixed[i].len, right.main[i][c].log_size)]
                    else
                        M.zero();
                    try std.testing.expectEqual(expected, column.values[committed(logical, column.log_size)]);
                }
            }
        }
    }
}
