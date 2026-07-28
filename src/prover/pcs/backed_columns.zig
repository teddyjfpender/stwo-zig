//! Ownership helpers for column descriptors borrowing shared arenas.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const ColumnEvaluation = @import("commitment_tree.zig").ColumnEvaluation;

pub fn detach(
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
) ![]ColumnEvaluation {
    const detached = try allocator.alloc(ColumnEvaluation, columns.len);
    var initialized: usize = 0;
    errdefer {
        for (detached[0..initialized]) |column| allocator.free(column.values);
        allocator.free(detached);
    }
    for (columns, 0..) |column, index| {
        detached[index] = .{
            .log_size = column.log_size,
            .values = try allocator.dupe(M31, column.values),
        };
        initialized += 1;
    }
    return detached;
}

pub fn free(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    backing_buffers: [][]M31,
) void {
    allocator.free(columns);
    for (backing_buffers) |buffer| allocator.free(buffer);
    allocator.free(backing_buffers);
}

/// The outcome of offering a shared backing to a backend.
pub const Adoption = struct {
    columns: []ColumnEvaluation,
    /// Non-null when the backend keeps the single contiguous arena. Its
    /// lifetime then travels with the prepared coefficients.
    arena: ?[]M31,
};

/// Backends that declare `adopts_source_trace_arena` bind one contiguous
/// source arena directly; every other backend gets ordinary per-column
/// ownership, because generic code frees each slice independently.
pub fn adoptOrDetach(
    comptime B: type,
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    backing_buffers: [][]M31,
) !Adoption {
    const adopts = comptime @hasDecl(B, "adopts_source_trace_arena") and
        B.adopts_source_trace_arena;
    if (adopts and backing_buffers.len == 1) {
        const arena = backing_buffers[0];
        allocator.free(backing_buffers);
        return .{ .columns = columns, .arena = arena };
    }
    const detached = detach(allocator, columns) catch |err| {
        free(allocator, columns, backing_buffers);
        return err;
    };
    free(allocator, columns, backing_buffers);
    return .{ .columns = detached, .arena = null };
}

/// Releases source columns after an adoption decision: an adopted arena owns
/// its column values, so only the descriptor array is freed.
pub fn freeSource(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    arena: ?[]M31,
) void {
    if (arena == null) {
        for (columns) |column| if (column.values.len != 0) allocator.free(column.values);
    }
    allocator.free(columns);
}
