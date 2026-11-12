//! Split the large G cohort at a power-of-two boundary before key admission.
const std = @import("std");
const core = @import("stwo_core");
const storage = @import("blake3_parent_row_storage.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const G = @import("blake3_g_call.zig");
const rowIndex = @import("framework_interaction.zig").committedRow;
pub const SHARDS = blk: {
    var indices: [storage.G_SHARD_COUNT]usize = undefined;
    indices[0] = 0;
    for (indices[1..], 0..) |*index, i| index.* = storage.Airs.len - (storage.G_SHARD_COUNT - 1) + i;
    break :blk indices;
};
pub const REMAINDER = SHARDS[1];

/// Original physical G partition geometry, shared by live rows and fixed-only
/// setup. No witness columns or successful proof are inputs.
pub const Geometry = struct { counts: [SHARDS.len]usize, logs: [SHARDS.len]u32 };
pub fn geometry(count: usize) !Geometry {
    return geometryAbove(count, 1 << 20);
}
fn geometryAbove(count: usize, minimum: usize) !Geometry {
    if (count > 1 << 24) return error.HashPartitionCapacityExceeded;
    if (count <= minimum) {
        var counts: [SHARDS.len]usize = @splat(0);
        var logs: [SHARDS.len]u32 = @splat(1);
        counts[0] = count;
        logs[0] = if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
        return .{ .counts = counts, .logs = logs };
    }
    var counts: [SHARDS.len]usize = @splat(0);
    var logs: [SHARDS.len]u32 = @splat(1);
    // Bound the largest domain as well as total padding: composition and FRI
    // scratch scale with the largest component, not just the sum of rows.
    const per_shard = std.math.divCeil(usize, count, SHARDS.len) catch unreachable;
    const max_log = @max(1, std.math.log2_int_ceil(usize, per_shard));
    if (max_log > 24) return error.HashPartitionCapacityExceeded;
    var remaining = count;
    for (&counts, &logs, 0..) |*active, *log, shard| {
        active.* = if (shard == SHARDS.len - 1 or remaining <= 1) remaining else @as(usize, 1) << @intCast(@min(max_log, std.math.log2_int(usize, remaining - 1)));
        log.* = if (active.* <= 1) 1 else @intCast(std.math.log2_int_ceil(usize, active.*));
        if (log.* > 24) return error.HashPartitionCapacityExceeded;
        remaining -= active.*;
    }
    return .{ .counts = counts, .logs = logs };
}
pub fn partition(rows: *storage.Prepared) !void {
    return partitionAbove(rows, 1 << 20);
}
fn partitionAbove(rows: *storage.Prepared, minimum: usize) !void {
    const count = rows.fixed[0].len;
    if (count <= minimum) return;
    inline for (SHARDS[1..]) |index| if (rows.fixed[index].len != 0) return;
    const a = rows.allocator;
    if (rows.main[0].len != G.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidBlake3ParentRows;
    const old_log = rows.main[0][0].log_size;
    const old_size = @as(usize, 1) << @intCast(old_log);
    if (count > old_size) return error.InvalidBlake3ParentRows;
    for (rows.main[0]) |column| if (column.log_size != old_log or column.values.len != old_size) return error.InvalidBlake3ParentRows;
    const shape = try geometryAbove(count, minimum);
    const counts = shape.counts;
    const logs = shape.logs;
    var main: [SHARDS.len][]Column = @splat(&.{});
    var fixed: [SHARDS.len][]storage.FixedRow(G) = @splat(&.{});
    errdefer for (main, fixed) |columns, metadata| {
        for (columns) |column| a.free(column.values);
        a.free(columns);
        a.free(metadata);
    };
    var offset: usize = 0;
    for (logs, counts, 0..) |log, active, shard| {
        fixed[shard] = try a.dupe(storage.FixedRow(G), rows.fixed[0][offset..][0..active]);
        main[shard] = try a.alloc(Column, G.PHYSICAL_MAIN_COLUMN_COUNT);
        for (main[shard]) |*column| column.* = .{ .log_size = log, .values = &.{} };
        const size = @as(usize, 1) << @intCast(log);
        // One shared permutation, not a bit-reversal calculation per cell.
        const indices = try a.alloc(u32, size);
        defer a.free(indices);
        for (indices, 0..) |*source, i| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(i, log), log);
            source.* = if (logical < active) @intCast(rowIndex(offset + logical, old_log)) else std.math.maxInt(u32);
        }
        for (main[shard], rows.main[0]) |*column, old| {
            const values = try a.alloc(M, size);
            column.values = values;
            for (values, indices) |*value, index| value.* = if (index == std.math.maxInt(u32)) M.zero() else old.values[index];
        }
        offset += active;
    }
    // Publish only after all partitions are complete.
    inline for (SHARDS, 0..) |index, shard| {
        for (rows.main[index]) |column| a.free(column.values);
        a.free(rows.main[index]);
        a.free(rows.fixed[index]);
        rows.main[index] = main[shard];
        rows.fixed[index] = fixed[shard];
    }
}

fn fixture(a: std.mem.Allocator, count: usize) !storage.Prepared {
    var rows = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (storage.Airs, 0..) |_, i| rows.fixed[i] = &.{};
    errdefer rows.deinit();
    const log: u32 = @intCast(std.math.log2_int_ceil(usize, count));
    rows.fixed[0] = try a.alloc(storage.FixedRow(G), count);
    for (rows.fixed[0], 0..) |*fixed, i| fixed.* = @splat(M.fromCanonical(@intCast(i + 1)));
    rows.main[0] = try a.alloc(Column, G.PHYSICAL_MAIN_COLUMN_COUNT);
    for (rows.main[0]) |*column| column.* = .{ .log_size = log, .values = &.{} };
    for (rows.main[0], 0..) |*column, c| {
        const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
        column.values = values;
        @memset(values, M.zero());
        for (0..count) |r| values[rowIndex(r, log)] = M.fromCanonical(@intCast(1000 * c + r + 1));
    }
    return rows;
}

test "G partition preserves logical rows and padding across domain boundaries" {
    for ([_]usize{ 9, 16, 17, 31, 32, 33, 63, 64, 65, 129 }) |count| {
        var rows = try fixture(std.testing.allocator, count);
        defer rows.deinit();
        try partitionAbove(&rows, 0);
        const bound = @max(1, std.math.log2_int_ceil(usize, try std.math.divCeil(usize, count, SHARDS.len)));
        inline for (SHARDS) |shard| try std.testing.expect(rows.main[shard][0].log_size <= bound);
        const pointer = rows.main[0].ptr;
        try partitionAbove(&rows, 0);
        try std.testing.expectEqual(pointer, rows.main[0].ptr);
        var offset: usize = 0;
        inline for (SHARDS) |shard| {
            for (rows.fixed[shard], 0..) |fixed, r| try std.testing.expectEqual(@as(u32, @intCast(offset + r + 1)), fixed[0].v);
            for (rows.main[shard], 0..) |column, c| {
                for (0..column.values.len) |r| {
                    const expected = if (r < rows.fixed[shard].len) M.fromCanonical(@intCast(1000 * c + offset + r + 1)) else M.zero();
                    try std.testing.expect(expected.eql(column.values[rowIndex(r, column.log_size)]));
                }
            }
            offset += rows.fixed[shard].len;
        }
        try std.testing.expectEqual(count, offset);
    }
}

test "G partition allocation failures leave source rows usable" {
    for ([_]usize{ 0, 2, 6, 90, 166, 256, 330 }) |failure| {
        var allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var rows = try fixture(allocator.allocator(), 33);
        defer rows.deinit();
        const pointer = rows.main[0].ptr;
        allocator.fail_index = allocator.alloc_index + failure;
        try std.testing.expectError(error.OutOfMemory, partitionAbove(&rows, 0));
        try std.testing.expectEqual(pointer, rows.main[0].ptr);
        try std.testing.expectEqual(@as(usize, 33), rows.fixed[0].len);
        try std.testing.expectEqual(@as(usize, 0), rows.fixed[REMAINDER].len);
        allocator.fail_index = std.math.maxInt(usize);
        try partitionAbove(&rows, 0);
    }
}
