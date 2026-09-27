const std = @import("std");
const storage = @import("blake3_parent_row_storage.zig");
const append = @import("blake3_parent_append.zig");
const boundary = @import("blake3_boundary.zig");
const M = @import("stwo_core").fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const committed = @import("framework_interaction.zig").committedRow;
test "BLAKE3 memory update proves parent append preserves values across domain growth" {
    try checkAppend(false);
    try checkAppend(true);
}
fn checkAppend(comptime compact: bool) !void {
    const a = std.testing.allocator;
    var prepared = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..storage.Airs.len) |i| prepared.fixed[i] = &.{};
    defer prepared.deinit();
    prepared.fixed[2] = try a.alloc(storage.FixedRow(boundary), 3);
    for (prepared.fixed[2], 0..) |*row, i| row.* = storage.compactFixed(boundary, try boundary.logicalRow(99, @intCast(i), M.one(), @intCast(42 + i)));
    prepared.main[2] = try a.alloc(Column, 4);
    for (prepared.main[2]) |*column| column.* = .{ .log_size = 2, .values = &.{} };
    for (prepared.main[2], 0..) |*column, c| {
        const values = try a.alloc(M, 4);
        column.values = values;
        @memset(values, M.zero());
        for (0..prepared.fixed[2].len) |i| values[committed(i, 2)] = (try boundary.logicalRow(99, @intCast(i), M.one(), @intCast(42 + i)))[c];
    }
    var extra = [_]boundary.Row{ try boundary.logicalRow(99, 3, M.one(), 45), try boundary.logicalRow(99, 4, M.one(), 46) };
    const fixed = extra;
    var chunks = append.init();
    defer append.deinit(a, &chunks);
    const metadata = [_]storage.FixedRow(boundary){ storage.compactFixed(boundary, fixed[0]), storage.compactFixed(boundary, fixed[1]) };
    try chunks[2].append(a, if (compact) .{ .live = &extra, .fixed_compact = &metadata } else .{ .live = &extra, .fixed = &fixed });
    try append.append(&prepared, &chunks);
    try std.testing.expectEqual(@as(usize, 5), prepared.fixed[2].len);
    for (prepared.main[2], 0..) |column, c| {
        try std.testing.expectEqual(@as(u32, 3), column.log_size);
        for (0..8) |row| {
            const expected: u32 = if (row < 5 and c == 0) @intCast(42 + row) else 0;
            try std.testing.expectEqual(expected, column.values[committed(row, 3)].toU32());
        }
    }
    const old = prepared.main[2].ptr;
    extra[1][boundary.PHYSICAL_MAIN_COLUMN_COUNT] = M.zero();
    try std.testing.expectError(error.InvalidParentAppend, append.append(&prepared, &chunks));
    try std.testing.expectEqual(old, prepared.main[2].ptr);
    try std.testing.expectEqual(@as(usize, 5), prepared.fixed[2].len);
    // Namespace checks inspect relation circuit fields, not unrelated values.
    inline for (storage.Airs, 0..) |Air, i| {
        if (i != 2) {
            prepared.main[i] = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
            for (prepared.main[i]) |*column| column.* = .{ .log_size = 1, .values = &.{} };
        }
    }
    const namespace = @import("blake3_parent_namespace.zig");
    try namespace.rejectRange(&prepared, 40, 50); // Public byte constants occupy this range.
    try std.testing.expectError(error.InvalidParentCustodyNamespace, namespace.rejectRange(&prepared, 90, 100));
    // The older linear AIR carries the selected circuit in a main column.
    prepared.fixed[5] = try a.alloc(storage.FixedRow(storage.Airs[5]), 1);
    prepared.fixed[5][0] = @splat(M.zero());
    const circuits = try a.alloc(M, 2);
    prepared.main[5][1].values = circuits;
    circuits[0] = M.fromCanonical(1_000_000_000);
    circuits[1] = M.zero();
    try std.testing.expectError(error.InvalidParentCustodyNamespace, namespace.rejectRange(&prepared, 1_000_000_000, 1_100_000_000));
}
