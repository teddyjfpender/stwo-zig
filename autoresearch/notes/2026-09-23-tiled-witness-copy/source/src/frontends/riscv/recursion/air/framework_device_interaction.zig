//! Backend-neutral ingress for typed interaction generation. Admitted plans
//! own equations; this adapter only projects logical rows into committed columns.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const binding = @import("universal_relation_binding.zig");
const exporter = @import("framework_polynomial_export_v1.zig");
const framework = @import("framework_interaction.zig");

/// Destination is already zeroed so absent logical rows retain AIR padding.
pub fn writeColumns(comptime Air: type, rows: []const [Air.LOGICAL_INPUT_COUNT]M31, log: u32, tree: usize, destination: []const []M31) void {
    writeColumnsAt(Air, rows, log, tree, destination, 0);
}

/// Caller admits the chunk range; destination padding is already zeroed.
pub fn writeColumnsAt(comptime Air: type, rows: []const [Air.LOGICAL_INPUT_COUNT]M31, log: u32, tree: usize, destination: []const []M31, logical_first: usize) void {
    const start: usize = if (tree == 0) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
    const size = @as(usize, 1) << @intCast(log);
    std.debug.assert(logical_first <= size and rows.len <= size - logical_first);
    // Chunked witness emission must scale with the chunk, not the full trace.
    // Repeated full-domain scans make many small appends quadratic in trace size.
    if (rows.len < size / 2) {
        if (std.process.hasEnvVarConstant("STWO_ZIG_ROW_MAJOR_WITNESS_COPY")) {
            for (rows, 0..) |row, offset| {
                const committed = framework.committedRow(logical_first + offset, log);
                for (destination, 0..) |column, index| column[committed] = row[start + index];
            }
            return;
        }
        // Keep one destination column active at a time. Row-major scatter
        // cycles through every column allocation and copies full logical rows.
        // Bound index scratch independently of the trace and chunk sizes.
        const chunk_tile = 128;
        var first: usize = 0;
        while (first < rows.len) : (first += chunk_tile) {
            const count = @min(chunk_tile, rows.len - first);
            var targets: [chunk_tile]usize = undefined;
            for (targets[0..count], 0..) |*target, offset|
                target.* = framework.committedRow(logical_first + first + offset, log);
            for (destination, 0..) |column, index| {
                for (targets[0..count], 0..) |target, offset|
                    column[target] = rows[first + offset][start + index];
            }
        }
        return;
    }
    const tile_size = 32;
    var first: usize = 0;
    while (first < size) : (first += tile_size) {
        const count = @min(tile_size, size - first);
        var logical_rows: [tile_size]usize = undefined;
        for (logical_rows[0..count], 0..) |*logical, offset| {
            logical.* = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(first + offset, log), log);
        }
        for (destination, 0..) |column, index| {
            for (logical_rows[0..count], column[first..][0..count]) |logical, *cell| {
                if (logical >= logical_first and logical - logical_first < rows.len) cell.* = rows[logical - logical_first][start + index];
            }
        }
    }
}

test "BLAKE3 execution commitment chunk projection preserves untouched rows and offsets" {
    const Air = struct {
        pub const LOGICAL_INPUT_COUNT = 7;
        pub const PHYSICAL_MAIN_COLUMN_COUNT = 3;
    };
    const log = 5;
    const size = 1 << log;
    var rows: [size][Air.LOGICAL_INPUT_COUNT]M31 = undefined;
    for (&rows, 0..) |*row, i| for (row, 0..) |*value, j| {
        value.* = M31.fromU64(1 + i * 11 + j);
    };
    for (0..2) |tree| {
        const start: usize = if (tree == 0) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
        for (0..size + 1) |first| {
            for (0..size - first + 1) |length| {
                var storage: [3][size]M31 = @splat(@splat(M31.fromU64(999)));
                const columns = [_][]M31{ &storage[0], &storage[1], &storage[2] };
                writeColumnsAt(Air, rows[first..][0..length], log, tree, &columns, first);
                // Inverse domain mapping is independent of the scatter path.
                for (0..size) |physical| {
                    const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, log), log);
                    for (columns, 0..) |column, index| {
                        const expected = if (logical >= first and logical - first < length) rows[logical][start + index] else M31.fromU64(999);
                        try std.testing.expectEqual(expected, column[physical]);
                    }
                }
            }
        }
    }
}

test "BLAKE3 execution commitment chunk projection spans wide tiles" {
    const Air = struct {
        pub const LOGICAL_INPUT_COUNT = 140;
        pub const PHYSICAL_MAIN_COLUMN_COUNT = 124;
    };
    const a = std.testing.allocator;
    const log = 10;
    const size = 1 << log;
    const rows = try a.alloc([Air.LOGICAL_INPUT_COUNT]M31, size);
    defer a.free(rows);
    for (rows, 0..) |*row, i| for (row, 0..) |*value, j| {
        value.* = M31.fromU64(1 + i * 149 + j);
    };
    const storage = try a.alloc([size]M31, Air.PHYSICAL_MAIN_COLUMN_COUNT);
    defer a.free(storage);
    var columns: [Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&columns, storage) |*column, *values| column.* = values;
    for (0..2) |tree| {
        const start: usize = if (tree == 0) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
        const count: usize = if (tree == 0) Air.LOGICAL_INPUT_COUNT - start else Air.PHYSICAL_MAIN_COLUMN_COUNT;
        for ([_][2]usize{ .{ 0, 0 }, .{ 7, 129 }, .{ 128, 255 }, .{ 501, 511 } }) |range| {
            for (columns[0..count]) |column| @memset(column, M31.fromU64(999));
            writeColumnsAt(Air, rows[range[0]..][0..range[1]], log, tree, columns[0..count], range[0]);
            for (0..size) |physical| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, log), log);
                for (columns[0..count], 0..) |column, index| {
                    const expected = if (logical >= range[0] and logical - range[0] < range[1]) rows[logical][start + index] else M31.fromU64(999);
                    try std.testing.expectEqual(expected, column[physical]);
                }
            }
        }
    }
}

pub fn generateInto(
    comptime Backend: type,
    comptime Air: type,
    allocator: std.mem.Allocator,
    direct: *const @import("direct_constraint_program.zig").Program,
    plan: *const binding.Binding(Air).Plan,
    rows: []const [Air.LOGICAL_INPUT_COUNT]M31,
    profile: []const M31,
    log: u32,
    relations: *const @import("universal_challenges.zig").UniversalRelations,
    destination: []const []M31,
) !QM31 {
    if (log == 0 or log > 24) return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(log);
    const counts = [_]usize{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT };
    if (rows.len > size or profile.len != Air.LOGICAL_INPUT_COUNT - counts[0] - counts[1])
        return error.InvalidTraceShape;
    var program = try exporter.exportLocalPrepared(Air, allocator, direct, plan);
    defer program.deinit();
    const parameters = try exporter.exportRelationParameters(allocator, plan, relations);
    defer allocator.free(parameters);
    const storage = try allocator.alloc(M31, try std.math.mul(usize, counts[0] + counts[1], size));
    defer allocator.free(storage);
    @memset(storage, M31.zero());
    var columns: [Air.PREPROCESSED_COLUMN_COUNT + Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
    const sources = [2][]const []M31{ columns[0..counts[0]], columns[counts[0]..] };
    for (sources, 0..) |tree, index| writeColumns(Air, rows, log, index, tree);
    return Backend.generateFrameworkInteractionInto(allocator, &program, &counts, sources, .{
        .trace_log_size = log,
        .profile_values = profile,
        .relation_values = parameters,
    }, destination) catch |err| switch (err) {
        error.FrameworkInteractionZeroDenominator => error.ZeroDenominator,
        else => err,
    };
}

pub fn testColumnProjection() !void {
    const Air = struct {
        pub const LOGICAL_INPUT_COUNT = 11;
        pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 4;
    };
    for ([_]u32{ 1, 4, 5, 6, 9 }) |log| {
        const size = @as(usize, 1) << @intCast(log);
        const rows = try std.testing.allocator.alloc([Air.LOGICAL_INPUT_COUNT]M31, size);
        defer std.testing.allocator.free(rows);
        for (rows, 0..) |*row, i| for (row, 0..) |*value, j| {
            value.* = M31.fromU64(i * 19 + j + 1);
        };
        for ([_]usize{ 0, 1, size / 2, size - 1, size }) |length| {
            for (0..2) |tree| {
                var columns: [4][]M31 = undefined;
                const data = try std.testing.allocator.alloc(M31, 4 * size);
                defer std.testing.allocator.free(data);
                @memset(data, M31.zero());
                for (&columns, 0..) |*column, i| column.* = data[i * size ..][0..size];
                writeColumns(Air, rows[0..length], log, tree, &columns);
                const start: usize = if (tree == 0) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
                for (0..size) |logical| for (columns, 0..) |column, i| {
                    const expected = if (logical < length) rows[logical][start + i] else M31.zero();
                    try std.testing.expectEqual(expected, column[framework.committedRow(logical, log)]);
                };
            }
        }
    }
}
