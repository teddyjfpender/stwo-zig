//! Verifier-owned SHA topology, projected without a placeholder witness trace.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const provider = @import("sha256_compression_rows.zig");
const source = @import("sha256_packed_source.zig");
const framework = @import("../../recursion/air/framework_interaction.zig");
const caller = @import("sha256_memory_caller.zig");

pub fn append(a: std.mem.Allocator, count: usize, include_caller: bool, columns: *std.ArrayList(Column)) !void {
    const geometry = try provider.Geometry.init(count);
    const original = columns.items.len;
    errdefer {
        for (columns.items[original..]) |column| a.free(column.values);
        columns.shrinkRetainingCapacity(original);
    }
    inline for (0..4) |index| {
        const pattern = try fixedPattern(index);
        try appendPattern(a, &pattern, count, geometry.logs[index], columns);
    }
    if (include_caller) {
        const pattern = try fixedPattern(4);
        try appendPattern(a, &pattern, count, try callerLog(count), columns);
    }
}

/// One canonical compression's fixed metadata, independent of all private input.
pub fn fixedPattern(comptime index: usize) ![@import("sha256_component_profile.zig").rows_per_call[index]][@import("sha256_component_profile.zig").Airs[index].PREPROCESSED_COLUMN_COUNT]M {
    const profile = @import("sha256_component_profile.zig");
    const Air = profile.Airs[index];
    if (comptime index == 4) return .{.{M.one()}};
    var pattern: [profile.rows_per_call[index]][Air.PREPROCESSED_COLUMN_COUNT]M = undefined;
    for (&pattern, 0..) |*fixed, row_index| {
        const row = switch (index) {
            0 => try source.row(1, @intCast(row_index), 0, &provider.topology.uses),
            1 => try provider.Schedule.fixedRow(1, provider.topology.expansion[row_index], &provider.topology.uses),
            2 => try provider.Round.fixedRow(1, provider.topology.rounds[row_index], &provider.topology.uses),
            3 => try provider.FeedForward.fixedRow(1, provider.topology.feed_forward[row_index], &provider.topology.uses),
            else => unreachable,
        };
        fixed.* = row[Air.PHYSICAL_MAIN_COLUMN_COUNT..].*;
    }
    return pattern;
}

pub const callerLog = @import("sha256_component_profile.zig").callerLog;

fn appendPattern(a: std.mem.Allocator, pattern: anytype, count: usize, log: u32, columns: *std.ArrayList(Column)) !void {
    if (log == 0 or log > 24) return error.ShaTraceTooLarge;
    const active = try std.math.mul(usize, pattern.len, count);
    const size = @as(usize, 1) << @intCast(log);
    if (active > size) return error.InvalidShaPreprocessing;
    for (0..pattern[0].len) |column_index| {
        const values = try a.alloc(M, size);
        columns.append(a, .{ .log_size = log, .values = values }) catch |err| {
            a.free(values);
            return err;
        };
        // Physical-order writes keep each final column sequential in memory.
        for (values, 0..) |*value, physical| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, log), log);
            value.* = if (logical < active) pattern[logical % pattern.len][column_index] else M.zero();
        }
    }
}

fn parityCase(a: std.mem.Allocator, count: usize) !void {
    var actual: std.ArrayList(Column) = .empty;
    defer {
        for (actual.items) |column| a.free(column.values);
        actual.deinit(a);
    }
    try append(a, count, true, &actual);
    var rows = try provider.fixed(a, count);
    defer rows.deinit();
    const tuple = rows.tuple();
    var offset: usize = 0;
    inline for (.{ source, provider.Schedule, provider.Round, provider.FeedForward }, 0..) |Air, index| {
        for (0..Air.PREPROCESSED_COLUMN_COUNT) |column_index| {
            const column = actual.items[offset + column_index];
            for (tuple[index], 0..) |row, logical| {
                try std.testing.expectEqual(row[Air.PHYSICAL_MAIN_COLUMN_COUNT + column_index], column.values[framework.committedRow(logical, column.log_size)]);
            }
        }
        offset += Air.PREPROCESSED_COLUMN_COUNT;
    }
    try std.testing.expectEqual(offset + caller.PREPROCESSED_COLUMN_COUNT, actual.items.len);
    const active = actual.items[offset];
    for (0..active.values.len) |logical| try std.testing.expectEqual(if (logical < count) M.one() else M.zero(), active.values[framework.committedRow(logical, active.log_size)]);
}

test "SHA provider preprocessing matches independent topology and releases every failed allocation" {
    for ([_]usize{ 0, 3 }) |count| {
        try parityCase(std.testing.allocator, count);
        try std.testing.checkAllAllocationFailures(std.testing.allocator, parityCase, .{count});
    }
    try parityCase(std.testing.allocator, 16);
    for ([_]usize{ 1, 16, 64, 1024 }) |count| {
        const geometry = try provider.Geometry.init(count);
        var placeholder_bytes: usize = 0;
        var fixed_bytes: usize = 0;
        inline for (.{ source, provider.Schedule, provider.Round, provider.FeedForward }, 0..) |Air, index| {
            const rows = @as(usize, 1) << @intCast(geometry.logs[index]);
            placeholder_bytes += rows * @sizeOf(Air.Row);
            fixed_bytes += rows * Air.PREPROCESSED_COLUMN_COUNT * @sizeOf(M);
        }
        // Old preprocessing retained both the placeholder rows and final fixed
        // columns. The new path owns only the latter, plus constant-size stack
        // metadata. These are exact value-buffer sizes, not process peaks.
        std.debug.print("SHA_PREPROCESSING calls={d} removed_placeholder_bytes={d} final_fixed_value_bytes={d}\n", .{ count, placeholder_bytes, fixed_bytes });
    }
}
