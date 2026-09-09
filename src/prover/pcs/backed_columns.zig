//! Ownership helpers for column descriptors borrowing shared arenas.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const ColumnEvaluation = @import("stwo_prover_api").ColumnEvaluation;

/// Repack independently owned columns for an adopting backend. Logical order
/// is unchanged; each native-height group becomes one aligned coefficient run.
/// All fallible work precedes the first ownership transfer. On failure the
/// caller still owns every input; on success it owns the returned arena list.
pub fn packOwnedByLog(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    comptime alignment: std.mem.Alignment,
) ![][]M31 {
    var group_words = [_]usize{0} ** @bitSizeOf(usize);
    for (columns) |column| {
        try column.validate();
        group_words[column.log_size] = try std.math.add(usize, group_words[column.log_size], column.values.len);
    }
    const alignment_words = @max(1, alignment.toByteUnits() / @sizeOf(M31));
    var offsets: [@bitSizeOf(usize)]usize = undefined;
    var total_words: usize = 0;
    for (group_words, &offsets) |words, *offset| {
        if (words != 0) {
            const rounded = try std.math.add(usize, total_words, alignment_words - 1);
            total_words = rounded & ~(alignment_words - 1);
        }
        offset.* = total_words;
        total_words = try std.math.add(usize, total_words, words);
    }
    const buffers = try allocator.alloc([]M31, 1);
    errdefer allocator.free(buffers);
    // Retain the original M31-aligned allocation for ordinary arena teardown.
    // Only the interior coefficient runs require stronger device alignment.
    const raw = try allocator.alloc(M31, try std.math.add(usize, total_words, alignment_words - 1));
    buffers[0] = raw;
    const address = @intFromPtr(raw.ptr);
    const aligned_address = std.mem.alignForward(usize, address, @max(@alignOf(M31), alignment.toByteUnits()));
    const arena = raw[(aligned_address - address) / @sizeOf(M31) ..][0..total_words];
    for (columns) |*column| {
        const destination = arena[offsets[column.log_size]..][0..column.values.len];
        @memcpy(destination, column.values);
        allocator.free(column.values);
        offsets[column.log_size] += destination.len;
        column.values = destination;
    }
    return buffers;
}

/// Backing slices erase their allocation alignment. Keep it with the owner
/// and use the original value for both successful and error-path teardown.
pub fn freeBuffers(allocator: std.mem.Allocator, buffers: [][]M31, alignment: std.mem.Alignment) void {
    for (buffers) |buffer| if (buffer.len != 0)
        allocator.rawFree(std.mem.sliceAsBytes(buffer), alignment, @returnAddress());
    allocator.free(buffers);
}

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
