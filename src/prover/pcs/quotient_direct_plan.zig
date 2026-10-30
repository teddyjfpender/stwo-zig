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

/// Complement an exact compact selection. Split a column's original range
/// into contiguous unselected runs so the row kernel remains branch-free.
/// The plan still borrows the original contribution array and column values.
pub fn buildExcludingSelected(
    allocator: std.mem.Allocator,
    flat_columns: anytype,
    active_column_indices: []const usize,
    contribution_ranges: []const row_executor.ColumnContributionRange,
    nonzero_columns: []const bool,
    lifting_log_size: u32,
    selected: []const u8,
) !Plan {
    if (active_column_indices.len != contribution_ranges.len or flat_columns.len != nonzero_columns.len) return error.ShapeMismatch;
    var count: usize = 0;
    var views: []row_executor.LiftingColumnView = &.{};
    var ranges: []row_executor.ColumnContributionRange = &.{};
    errdefer allocator.free(views);
    errdefer allocator.free(ranges);
    for (0..2) |pass| {
        var at: usize = 0;
        for (active_column_indices, contribution_ranges) |column_index, range| {
            if (column_index >= flat_columns.len) return error.ShapeMismatch;
            const end = std.math.add(usize, range.start, range.len) catch return error.ShapeMismatch;
            if (end > selected.len * 8) return error.ShapeMismatch;
            if (!nonzero_columns[column_index]) continue;
            const column = flat_columns[column_index];
            if (column.log_size > lifting_log_size or lifting_log_size - column.log_size >= @bitSizeOf(usize) - 1) return error.InvalidColumnLogSize;
            var cursor = range.start;
            while (cursor < end) {
                while (cursor < end and isSelected(selected, cursor)) : (cursor += 1) {}
                const first = cursor;
                while (cursor < end and !isSelected(selected, cursor)) : (cursor += 1) {}
                if (first == cursor) continue;
                if (pass == 1) {
                    views[at] = .{ .values = column.values, .shift_amt = @intCast(lifting_log_size - column.log_size + 1), .is_direct = column.log_size == lifting_log_size };
                    ranges[at] = .{ .start = first, .len = cursor - first };
                }
                at += 1;
            }
        }
        if (pass == 0) {
            count = at;
            views = try allocator.alloc(row_executor.LiftingColumnView, count);
            ranges = try allocator.alloc(row_executor.ColumnContributionRange, count);
        } else std.debug.assert(at == count);
    }
    return .{ .views = views, .ranges = ranges };
}

fn isSelected(bits: []const u8, index: usize) bool {
    return bits[index / 8] & (@as(u8, 1) << @as(u3, @intCast(index % 8))) != 0;
}
