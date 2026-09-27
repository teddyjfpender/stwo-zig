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
    var out = hash.MainColumnBuffer(Air){ .columns = undefined, .metadata = try a.alloc(@import("blake3_hash_metadata.zig").Row(Air), count), .log_size = log, .first = 3 };
    for (&out.columns) |*column| {
        column.* = try a.alloc(M, @as(usize, 1) << @intCast(log));
        @memset(column.*, M.fromCanonical(123));
    }
    return out;
}
pub fn expectRows(out: frame.MainColumns, expected: anytype, fixed: @TypeOf(expected)) !void {
    const rows = if (@hasField(@TypeOf(expected), "rows")) expected.rows else expected;
    const trusted = if (@hasField(@TypeOf(fixed), "rows")) fixed.rows else fixed;
    const metadata: ?@import("blake3_hash_metadata.zig").Rows = if (@hasField(@TypeOf(fixed), "hash_metadata")) fixed.hash_metadata else null;
    inline for (.{ g, xor }, .{ out.g_rows, out.xor_rows }, .{ rows.g_rows, rows.xor_rows }, .{ trusted.g_rows, trusted.xor_rows }, 0..) |Air, dst, live_rows, trusted_rows, cohort| {
        const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
        var view = Runtime.ColumnRows{ .columns = @splat(&.{}), .first = dst.first, .count = live_rows.len, .main_count = Air.PHYSICAL_MAIN_COLUMN_COUNT, .compact_metadata = std.mem.bytesAsSlice(@import("stwo_core").fields.m31.M31, std.mem.sliceAsBytes(dst.metadata)) };
        for (view.columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], dst.columns) |*column, fields| column.* = fields;
        try view.validate(dst.log_size);
        const tails = if (metadata) |m| (if (cohort == 0) m.g_rows else m.xor_rows) else null;
        try std.testing.expectEqual(live_rows.len, if (tails) |v| v.len else trusted_rows.len);
        for (live_rows, 0..) |row, i| {
            try std.testing.expectEqualDeep(row, view.read(i, dst.log_size));
            const tail = if (tails) |v| &v[i] else trusted_rows[i][Air.PHYSICAL_MAIN_COLUMN_COUNT..];
            try std.testing.expectEqualSlices(M, tail, &dst.metadata[i]);
        }
        for (0..dst.columns[0].len) |logical| if (logical < dst.first or logical >= dst.first + live_rows.len) {
            for (dst.columns) |column| try std.testing.expectEqual(@as(u32, 123), column[framework.committedRow(logical, dst.log_size)].v);
        };
    }
}
pub fn expectReceipts(expected: anytype, actual: @TypeOf(expected)) !void {
    if (@hasField(@TypeOf(actual), "hash_metadata")) {
        try std.testing.expect(actual.hash_metadata != null);
        try std.testing.expect(expected.hash_metadata == null);
    }
    inline for (std.meta.fields(@TypeOf(expected))) |field| {
        if (comptime std.mem.eql(u8, field.name, "rows")) {
            try expectReceipts(expected.rows, actual.rows);
        } else if (comptime !std.mem.eql(u8, field.name, "arena") and !std.mem.eql(u8, field.name, "row_allocator") and !std.mem.eql(u8, field.name, "hash_metadata") and !std.mem.eql(u8, field.name, "g_rows") and !std.mem.eql(u8, field.name, "xor_rows")) {
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

/// Compare independently generated compact preprocessing with the full-row oracle.
pub fn expectFixedMetadata(expected: anytype, actual: @import("blake3_hash_metadata.zig").Rows) !void {
    inline for (.{ g, xor }, .{ expected.g_rows, expected.xor_rows }, .{ actual.g_rows, actual.xor_rows }) |Air, rows, fixed| {
        try std.testing.expectEqual(rows.len, fixed.len);
        for (rows, fixed) |row, tail| try std.testing.expectEqualSlices(M, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], &tail);
    }
}
