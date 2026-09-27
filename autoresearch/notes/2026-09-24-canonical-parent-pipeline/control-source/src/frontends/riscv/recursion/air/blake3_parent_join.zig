//! Two isolated child-verifier witnesses to one final column layout. No expanded
//! logical main rows are materialized. Span/key admission belongs to the caller.
const std = @import("std");
const core = @import("stwo_core");
const storage = @import("blake3_parent_row_storage.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const committed = @import("framework_interaction.zig").committedRow;
pub const Range = struct {
    first: u32,
    end: u32,
    fn validate(self: Range) !void {
        if (self.first >= self.end or self.end > core.fields.m31.Modulus) return error.InvalidParentJoinNamespace;
    }
};
pub fn join(a: std.mem.Allocator, left: *const storage.Prepared, right: *const storage.Prepared, ranges: [2]Range) !storage.Prepared {
    for (ranges) |range| try range.validate();
    if (ranges[0].first < ranges[1].end and ranges[1].first < ranges[0].end) return error.OverlappingParentNamespaces;
    for ([_]*const storage.Prepared{ left, right }, ranges) |source, range| {
        try validateColumns(source);
        try @import("blake3_parent_namespace.zig").rejectRange(source, 0, range.first);
        try @import("blake3_parent_namespace.zig").rejectRange(source, range.end, core.fields.m31.Modulus);
    }
    var result = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = try std.math.add(usize, left.input_count, right.input_count) };
    inline for (0..storage.Airs.len) |i| result.fixed[i] = &.{};
    errdefer result.deinit();
    inline for (storage.Airs, 0..) |Air, i| {
        const count = try std.math.add(usize, left.fixed[i].len, right.fixed[i].len);
        if (count > (1 << 30)) return error.InvalidParentJoinColumns;
        const log: u32 = if (count < 2) 1 else std.math.log2_int_ceil(usize, count);
        result.fixed[i] = try a.alloc(storage.FixedRow(Air), count);
        @memcpy(result.fixed[i][0..left.fixed[i].len], left.fixed[i]);
        @memcpy(result.fixed[i][left.fixed[i].len..], right.fixed[i]);
        result.main[i] = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (result.main[i]) |*column| column.* = .{ .log_size = log, .values = &.{} };
        for (result.main[i], 0..) |*column, c| {
            const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
            column.values = values;
            @memset(values, M.zero());
            var first: usize = 0;
            for ([_]*const storage.Prepared{ left, right }) |source| {
                const input = source.main[i][c];
                for (0..source.fixed[i].len) |row| values[committed(first + row, log)] = input.values[committed(row, input.log_size)];
                first += source.fixed[i].len;
            }
        }
    }
    return result;
}
fn validateColumns(parent: *const storage.Prepared) !void {
    inline for (storage.Airs, 0..) |Air, i| {
        const count = parent.fixed[i].len;
        if (count > (1 << 30) or parent.main[i].len != Air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidParentJoinColumns;
        const log: u32 = if (count < 2) 1 else std.math.log2_int_ceil(usize, count);
        for (parent.main[i]) |column| {
            if (column.log_size != log or column.values.len != @as(usize, 1) << @intCast(log)) return error.InvalidParentJoinColumns;
        }
    }
}
