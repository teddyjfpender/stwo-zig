//! Preserve ordinary native quotient views while replacing coefficient-backed
//! contributions with four folded coordinate planes per sample/domain group.
//! The returned headers borrow both input columns and the folded plan.
const std = @import("std");
const core = @import("stwo_core");
const Column = @import("../quotient_column_geometry.zig").ColumnEvaluation;
const row = @import("../quotient_row_executor.zig");
const planning = @import("planning.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const Promoted = struct { columns: []Column, plan: planning.ColumnContributionPlan };

pub fn promote(a: std.mem.Allocator, columns: []const Column, original: planning.ColumnContributionPlan, folded: []const row.CombinedContributionView) !Promoted {
    const count = try std.math.add(usize, columns.len, try std.math.mul(usize, folded.len, 4));
    const headers = try a.alloc(Column, count);
    errdefer a.free(headers);
    @memcpy(headers[0..columns.len], columns);
    var active: std.ArrayList(usize) = .empty;
    defer active.deinit(a);
    var ranges: std.ArrayList(row.ColumnContributionRange) = .empty;
    defer ranges.deinit(a);
    var contributions: std.ArrayList(row.ColumnContribution) = .empty;
    defer contributions.deinit(a);
    for (original.active_column_indices, original.ranges) |index, range| {
        if (index >= columns.len or range.start > original.contributions.len or range.len > original.contributions.len - range.start) return error.ShapeMismatch;
        if (columns[index].coefficient_values != null) continue;
        try active.append(a, index);
        try ranges.append(a, .{ .start = contributions.items.len, .len = range.len });
        try contributions.appendSlice(a, original.contributions[range.start..][0..range.len]);
    }
    for (folded, 0..) |view, group| {
        const size = view.coordinates[0].len;
        if (size == 0 or !std.math.isPowerOfTwo(size)) return error.ShapeMismatch;
        const log: u32 = @intCast(std.math.log2_int(usize, size));
        for (view.coordinates, 0..) |values, coord| {
            if (values.len != size) return error.ShapeMismatch;
            const index = columns.len + group * 4 + coord;
            headers[index] = .{ .log_size = log, .values = values };
            var unit = [_]M31{M31.zero()} ** 4;
            unit[coord] = M31.one();
            try active.append(a, index);
            try ranges.append(a, .{ .start = contributions.items.len, .len = 1 });
            try contributions.append(a, .{ .batch_index = view.batch_index, .value_coeff = QM31.fromM31Array(unit) });
        }
    }
    const active_owned = try active.toOwnedSlice(a);
    errdefer a.free(active_owned);
    const ranges_owned = try ranges.toOwnedSlice(a);
    errdefer a.free(ranges_owned);
    return .{ .columns = headers, .plan = .{ .active_column_indices = active_owned, .ranges = ranges_owned, .contributions = try contributions.toOwnedSlice(a) } };
}
