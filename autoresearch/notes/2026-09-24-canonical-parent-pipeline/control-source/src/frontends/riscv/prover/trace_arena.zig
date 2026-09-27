//! Contiguous, backend-shaped ownership for a RISC-V trace.
//!
//! The generic witness path produces independently owned columns in protocol
//! order. Metal's circle LDE can avoid its source upload only when every
//! equal-log-size group is already one contiguous run. `prepare` allocates that
//! final storage before generation; `packOwned` is the compatibility bridge for
//! producers that still materialize independent columns.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;

pub const Error = error{
    InvalidTraceShape,
    ArenaTooLarge,
    UnsupportedArenaAlignment,
};

const max_arena_words: usize = 1 << 31;

const Group = struct {
    log_size: u32,
    offset: usize,
    column_count: usize,
};

/// One descriptor array borrowing one owned allocation.
pub const Packed = struct {
    columns: []ColumnEvaluation,
    backing_buffers: [][]M31,

    pub fn deinit(self: *Packed, allocator: std.mem.Allocator) void {
        allocator.free(self.columns);
        for (self.backing_buffers) |buffer| allocator.free(buffer);
        allocator.free(self.backing_buffers);
        self.* = undefined;
    }
};

fn pageWords() usize {
    return @max(@as(usize, 1), std.heap.pageSize() / @sizeOf(M31));
}

/// Allocates an empty, backend-shaped arena from protocol-order log sizes.
///
/// Columns retain their protocol-visible descriptor order. Equal-log-size
/// storage is contiguous in first-appearance order, which is the invariant
/// `pcs.columns.preparation.arenaGroupRun` checks before binding a source arena
/// directly as Metal's coefficient input.
pub fn prepare(
    allocator: std.mem.Allocator,
    log_sizes: []const u32,
) (Error || std.mem.Allocator.Error)!Packed {
    if (log_sizes.len == 0) return Error.InvalidTraceShape;

    var groups = std.ArrayList(Group).empty;
    defer groups.deinit(allocator);
    const column_groups = try allocator.alloc(usize, log_sizes.len);
    defer allocator.free(column_groups);
    for (log_sizes, column_groups) |log_size, *column_group| {
        if (log_size >= @bitSizeOf(usize)) return Error.InvalidTraceShape;
        var group_index: ?usize = null;
        for (groups.items, 0..) |group, index| {
            if (group.log_size == log_size) {
                group_index = index;
                break;
            }
        }
        if (group_index) |index| {
            groups.items[index].column_count += 1;
            column_group.* = index;
        } else {
            try groups.append(allocator, .{
                .log_size = log_size,
                .offset = 0,
                .column_count = 1,
            });
            column_group.* = groups.items.len - 1;
        }
    }

    const page_words = pageWords();
    var cursor: usize = 0;
    for (groups.items) |*group| {
        cursor = std.mem.alignForward(usize, cursor, page_words);
        group.offset = cursor;
        const rows = std.math.shl(usize, 1, group.log_size);
        const span = std.math.mul(usize, group.column_count, rows) catch
            return Error.ArenaTooLarge;
        cursor = std.math.add(usize, cursor, span) catch return Error.ArenaTooLarge;
        if (cursor > max_arena_words) return Error.ArenaTooLarge;
    }
    const arena_words = std.mem.alignForward(usize, cursor, page_words);
    if (arena_words == 0 or arena_words > max_arena_words) return Error.ArenaTooLarge;

    const columns = try allocator.alloc(ColumnEvaluation, log_sizes.len);
    errdefer allocator.free(columns);
    const arena = try allocator.alloc(M31, arena_words);
    errdefer allocator.free(arena);

    // `newBufferWithBytesNoCopy` requires the aliased allocation itself to be
    // page aligned. An allocator that cannot provide that keeps the established
    // fragmented path; it must never reach Metal as a falsely claimed arena.
    if (@intFromPtr(arena.ptr) % std.heap.pageSize() != 0)
        return Error.UnsupportedArenaAlignment;

    const group_cursors = try allocator.alloc(usize, groups.items.len);
    defer allocator.free(group_cursors);
    for (groups.items, group_cursors) |group, *group_cursor| {
        group_cursor.* = group.offset;
    }

    for (columns, log_sizes, column_groups) |*column, log_size, group_index| {
        const rows = @as(usize, 1) << @intCast(log_size);
        const offset = group_cursors[group_index];
        column.* = .{ .log_size = log_size, .values = arena[offset..][0..rows] };
        group_cursors[group_index] += rows;
    }
    const backing_buffers = try allocator.alloc([]M31, 1);
    backing_buffers[0] = arena;
    return .{ .columns = columns, .backing_buffers = backing_buffers };
}

/// Packs and consumes independently owned columns on success.
pub fn packOwned(
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
) (Error || std.mem.Allocator.Error)!Packed {
    const log_sizes = try allocator.alloc(u32, owned_columns.len);
    defer allocator.free(log_sizes);
    for (owned_columns, log_sizes) |column, *log_size| {
        column.validate() catch return Error.InvalidTraceShape;
        log_size.* = column.log_size;
    }
    const result = try prepare(allocator, log_sizes);

    // Every fallible operation is complete. Copy one source at a time and
    // release it immediately, so resident pages replace fragmented pages
    // instead of doubling the live trace at the ownership boundary.
    for (owned_columns, result.columns) |source, destination| {
        @memcpy(@constCast(destination.values), source.values);
        allocator.free(@constCast(source.values));
    }
    allocator.free(owned_columns);
    return result;
}

test "RISC-V trace arena preserves descriptor order and groups storage" {
    const allocator = std.testing.allocator;
    const logs = [_]u32{ 12, 10, 12, 11, 10 };
    const columns = try allocator.alloc(ColumnEvaluation, logs.len);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(@constCast(column.values));
        allocator.free(columns);
    }
    for (logs, columns, 0..) |log_size, *column, index| {
        const values = try allocator.alloc(M31, @as(usize, 1) << @intCast(log_size));
        @memset(values, M31.fromU64(index + 1));
        column.* = .{ .log_size = log_size, .values = values };
        initialized += 1;
    }

    var arena_result = try packOwned(allocator, columns);
    defer arena_result.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), arena_result.backing_buffers.len);
    for (arena_result.columns, logs, 0..) |column, log_size, index| {
        try std.testing.expectEqual(log_size, column.log_size);
        try std.testing.expect(column.values[0].eql(M31.fromU64(index + 1)));
    }
    try std.testing.expectEqual(
        arena_result.columns[0].values.ptr + arena_result.columns[0].values.len,
        arena_result.columns[2].values.ptr,
    );
    try std.testing.expectEqual(
        arena_result.columns[1].values.ptr + arena_result.columns[1].values.len,
        arena_result.columns[4].values.ptr,
    );
}
