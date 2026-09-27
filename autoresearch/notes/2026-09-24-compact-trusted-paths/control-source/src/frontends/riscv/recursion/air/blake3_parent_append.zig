//! Transactional extension of retained parent columns. Existing domains are
//! remapped only when growth changes their committed row permutation.
const std = @import("std");
const core = @import("stwo_core");
const storage = @import("blake3_parent_row_storage.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const committed = @import("framework_interaction.zig").committedRow;
pub fn Chunk(comptime Air: type) type {
    return struct { live: []const Air.Row, fixed: []const Air.Row };
}
pub const Chunks = blk: {
    var types: [storage.Airs.len]type = undefined;
    for (storage.Airs, &types) |Air, *T| T.* = std.ArrayList(Chunk(Air));
    break :blk std.meta.Tuple(&types);
};
pub fn init() Chunks {
    var result: Chunks = undefined;
    inline for (0..storage.Airs.len) |i| result[i] = .empty;
    return result;
}
pub fn deinit(a: std.mem.Allocator, chunks: *Chunks) void {
    inline for (0..storage.Airs.len) |i| chunks[i].deinit(a);
}
pub fn append(target: *storage.Prepared, chunks: *const Chunks) !void {
    const a = target.allocator;
    var replacement = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = target.input_count };
    inline for (0..storage.Airs.len) |i| replacement.fixed[i] = &.{};
    defer replacement.deinit();
    inline for (storage.Airs, 0..) |Air, i| cohort: {
        var count = target.fixed[i].len;
        for (chunks[i].items) |chunk| {
            if (chunk.live.len != chunk.fixed.len) return error.InvalidParentAppend;
            count = try std.math.add(usize, count, chunk.live.len);
            for (chunk.live, chunk.fixed) |live, fixed| for (live[Air.PHYSICAL_MAIN_COLUMN_COUNT..], fixed[Air.PHYSICAL_MAIN_COLUMN_COUNT..]) |value, trusted| {
                if (!value.eql(trusted)) return error.InvalidParentAppend;
            };
        }
        if (count == target.fixed[i].len) break :cohort;
        if (count > (1 << 30)) return error.InvalidParentAppend;
        const log: u32 = @max(1, std.math.log2_int_ceil(usize, count));
        const size = @as(usize, 1) << @intCast(log);
        replacement.fixed[i] = try a.alloc(storage.FixedRow(Air), count);
        @memcpy(replacement.fixed[i][0..target.fixed[i].len], target.fixed[i]);
        if (target.main[i].len != Air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidParentAppend;
        replacement.main[i] = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (replacement.main[i]) |*column| column.* = .{ .log_size = log, .values = &.{} };
        for (replacement.main[i], target.main[i], 0..) |*column, old, col| {
            if (old.log_size > 30 or old.values.len != @as(usize, 1) << @intCast(old.log_size) or target.fixed[i].len > old.values.len) return error.InvalidParentAppend;
            const values = try a.alloc(M, size);
            column.values = values;
            if (log == old.log_size) {
                @memcpy(values, old.values);
            } else {
                @memset(values, M.zero());
                for (0..target.fixed[i].len) |row| values[committed(row, log)] = old.values[committed(row, old.log_size)];
            }
            var at = target.fixed[i].len;
            for (chunks[i].items) |chunk| {
                for (chunk.live) |row| {
                    values[committed(at, log)] = row[col];
                    at += 1;
                }
            }
        }
        var at = target.fixed[i].len;
        for (chunks[i].items) |chunk| {
            for (replacement.fixed[i][at..][0..chunk.fixed.len], chunk.fixed) |*destination, row| destination.* = storage.compactFixed(Air, row);
            at += chunk.fixed.len;
        }
    }
    // Exchange only after every allocation, geometry and fixed-column check.
    inline for (0..storage.Airs.len) |i| if (replacement.main[i].len != 0) {
        std.mem.swap([]Column, &target.main[i], &replacement.main[i]);
        std.mem.swap([]storage.FixedRow(storage.Airs[i]), &target.fixed[i], &replacement.fixed[i]);
    };
}
