//! Borrowed direct-column plan for bounded quotient tiles.

const std = @import("std");
const row_executor = @import("quotient_row_executor.zig");

pub const Plan = struct {
    views: []row_executor.LiftingColumnView,
    ranges: []row_executor.ColumnContributionRange,

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.views);
        allocator.free(self.ranges);
        self.* = undefined;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    flat_columns: anytype,
    active_column_indices: []const usize,
    contribution_ranges: []const row_executor.ColumnContributionRange,
    nonzero_columns: []const bool,
    lifting_log_size: u32,
    exclude_shift_at_least: ?std.math.Log2Int(usize),
) !Plan {
    if (active_column_indices.len != contribution_ranges.len or
        flat_columns.len != nonzero_columns.len)
    {
        return error.ShapeMismatch;
    }

    var included_count: usize = 0;
    for (active_column_indices) |column_index| {
        if (column_index >= flat_columns.len or column_index >= nonzero_columns.len) {
            return error.ShapeMismatch;
        }
        if (!nonzero_columns[column_index]) continue;
        const column = flat_columns[column_index];
        if (column.log_size > lifting_log_size) return error.InvalidColumnLogSize;
        const log_shift = lifting_log_size - column.log_size;
        if (log_shift >= @bitSizeOf(usize)) return error.InvalidColumnLogSize;
        const shift_amt: std.math.Log2Int(usize) = @intCast(log_shift + 1);
        if (exclude_shift_at_least) |minimum| {
            if (shift_amt >= minimum) continue;
        }
        included_count += 1;
    }
    const views = try allocator.alloc(row_executor.LiftingColumnView, included_count);
    errdefer allocator.free(views);
    const ranges = try allocator.alloc(row_executor.ColumnContributionRange, included_count);
    errdefer allocator.free(ranges);

    var write_index: usize = 0;
    for (active_column_indices, contribution_ranges) |column_index, contribution_range| {
        if (!nonzero_columns[column_index]) continue;
        const column = flat_columns[column_index];
        const log_shift = lifting_log_size - column.log_size;
        const shift_amt: std.math.Log2Int(usize) = @intCast(log_shift + 1);
        if (exclude_shift_at_least) |minimum| {
            if (shift_amt >= minimum) continue;
        }
        views[write_index] = .{
            .values = column.values,
            .shift_amt = shift_amt,
            .is_direct = column.log_size == lifting_log_size,
        };
        ranges[write_index] = contribution_range;
        write_index += 1;
    }
    std.debug.assert(write_index == included_count);
    return .{ .views = views, .ranges = ranges };
}
