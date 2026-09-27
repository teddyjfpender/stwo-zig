//! Shared differential checks for adapters writing borrowed hash main columns.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const frame = @import("blake3_frame_witness.zig");
const hash = @import("blake3_hash_witness.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const framework = @import("framework_interaction.zig");
const binding = @import("universal_relation_binding.zig");

/// The supplied allocator owns these outputs independently of adapter receipts.
pub fn allocate(a: std.mem.Allocator, g_count: usize, xor_count: usize) !frame.MainColumns {
    return .{ .g_rows = try buffer(g, a, g_count), .xor_rows = try buffer(xor, a, xor_count) };
}
fn buffer(comptime Air: type, a: std.mem.Allocator, count: usize) !hash.MainColumnBuffer(Air) {
    const log = std.math.log2_int_ceil(usize, count + 3);
    var out = hash.MainColumnBuffer(Air){ .columns = undefined, .metadata = try a.alloc(Air.Row, count), .log_size = log, .first = 3 };
    for (&out.columns) |*column| {
        column.* = try a.alloc(M, @as(usize, 1) << @intCast(log));
        @memset(column.*, M.fromCanonical(123));
    }
    return out;
}
pub fn expectRows(out: frame.MainColumns, expected: anytype, fixed: @TypeOf(expected)) !void {
    const rows = if (@hasField(@TypeOf(expected), "rows")) expected.rows else expected;
    const trusted = if (@hasField(@TypeOf(fixed), "rows")) fixed.rows else fixed;
    inline for (.{ g, xor }, .{ out.g_rows, out.xor_rows }, .{ rows.g_rows, rows.xor_rows }, .{ trusted.g_rows, trusted.xor_rows }) |Air, dst, live_rows, trusted_rows| {
        const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
        var view = Runtime.ColumnRows{ .columns = @splat(&.{}), .first = dst.first, .count = live_rows.len, .main_count = Air.PHYSICAL_MAIN_COLUMN_COUNT, .metadata = dst.metadata };
        for (view.columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], dst.columns) |*column, fields| column.* = fields;
        try view.validate(dst.log_size);
        for (live_rows, trusted_rows, 0..) |row, trusted_row, i| {
            try std.testing.expectEqualDeep(row, view.read(i, dst.log_size));
            try std.testing.expectEqualSlices(M, trusted_row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], dst.metadata[i][Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
            for (dst.metadata[i][0..Air.PHYSICAL_MAIN_COLUMN_COUNT]) |value| try std.testing.expect(value.isZero());
        }
        for (0..dst.columns[0].len) |logical| if (logical < dst.first or logical >= dst.first + live_rows.len) {
            for (dst.columns) |column| try std.testing.expectEqual(@as(u32, 123), column[framework.committedRow(logical, dst.log_size)].v);
        };
    }
}
pub fn expectReceipts(expected: anytype, actual: @TypeOf(expected)) !void {
    if (@hasField(@TypeOf(actual), "hash_rows_are_metadata")) {
        try std.testing.expect(actual.hash_rows_are_metadata);
        try std.testing.expect(!expected.hash_rows_are_metadata);
    }
    inline for (std.meta.fields(@TypeOf(expected))) |field| {
        if (comptime std.mem.eql(u8, field.name, "rows")) {
            try expectReceipts(expected.rows, actual.rows);
        } else if (comptime !std.mem.eql(u8, field.name, "arena") and !std.mem.eql(u8, field.name, "row_allocator") and !std.mem.eql(u8, field.name, "hash_rows_are_metadata") and !std.mem.eql(u8, field.name, "g_rows") and !std.mem.eql(u8, field.name, "xor_rows")) {
            try std.testing.expectEqualDeep(@field(expected, field.name), @field(actual, field.name));
        }
    }
}
pub fn poison(out: frame.MainColumns) void {
    @memset(out.g_rows.columns[0], M.fromCanonical(987));
}
pub fn expectPoison(out: frame.MainColumns) !void {
    for (out.g_rows.columns[0]) |value| try std.testing.expectEqual(@as(u32, 987), value.v);
}
