//! Backend-neutral row geometry and value columns for Cairo memory tables.
//!
//! This is a direct transcription of the pinned Rust writers. It owns no
//! multiplicities and performs no interpolation, so CPU, SIMD, and accelerator
//! backends can share one logical-row contract.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const memory = @import("../common/memory.zig");
const execution_tables = @import("execution_tables.zig");

pub const lane_count: usize = 16;
pub const address_split: usize = 16;
pub const address_column_count: usize = address_split * 2;
pub const big_limb_count: usize = execution_tables.BIG_LIMB_COUNT;
pub const big_column_count: usize = big_limb_count + 1;
pub const small_limb_count: usize = execution_tables.SMALL_LIMB_COUNT;
pub const small_column_count: usize = small_limb_count + 1;
pub const max_big_rows: usize = 1 << 24;

pub const Error = error{
    AllocationSizeOverflow,
    InvalidComponent,
    InvalidColumn,
    InvalidEncoding,
    InvalidRowCount,
};

/// Number of scalar multiplicity slots allocated by Rust's packed column.
pub fn packedCount(value_count: usize) Error!usize {
    const packs = std.math.divCeil(usize, value_count, lane_count) catch
        return Error.AllocationSizeOverflow;
    return std.math.mul(usize, packs, lane_count) catch
        return Error.AllocationSizeOverflow;
}

/// Rows in each of the 16 `(id, multiplicity)` address chunks.
pub fn addressRowCount(input: *const adapter.ProverInput) Error!usize {
    const value_count = input.memory.address_to_id.len -| 1;
    const rows = std.math.divCeil(usize, value_count, address_split) catch
        return Error.AllocationSizeOverflow;
    return @max(try powerOfTwoRows(rows), lane_count);
}

pub fn bigComponentCount(input: *const adapter.ProverInput) Error!usize {
    const rows = try packedCount(input.memory.f252_values.len);
    const natural = std.math.divCeil(usize, rows, max_big_rows) catch
        return Error.AllocationSizeOverflow;
    return @max(natural, 1);
}

pub fn bigRowCount(input: *const adapter.ProverInput, component: usize) Error!usize {
    const packed_rows = try packedCount(input.memory.f252_values.len);
    const component_count = try bigComponentCount(input);
    if (component >= component_count) return Error.InvalidComponent;
    const start = std.math.mul(usize, component, max_big_rows) catch
        return Error.AllocationSizeOverflow;
    return @max(
        try powerOfTwoRows(@min(max_big_rows, packed_rows -| start)),
        lane_count,
    );
}

pub fn smallRowCount(input: *const adapter.ProverInput) Error!usize {
    const rows = try packedCount(input.memory.small_values.len);
    if (rows == 0) return Error.InvalidRowCount;
    return powerOfTwoRows(rows);
}

/// Writes one of the 28 canonical 9-bit value columns for a big component.
pub fn writeBigValueColumn(
    input: *const adapter.ProverInput,
    component: usize,
    column: usize,
    destination: []u32,
) Error!void {
    if (column >= big_limb_count) return Error.InvalidColumn;
    if (destination.len != try bigRowCount(input, component)) return Error.InvalidRowCount;
    const start = std.math.mul(usize, component, max_big_rows) catch
        return Error.AllocationSizeOverflow;
    for (destination, 0..) |*value, row| {
        const value_index = start + row;
        if (value_index >= input.memory.f252_values.len) {
            value.* = 0;
            continue;
        }
        const words = input.memory.f252_values[value_index];
        if (words[7] >> 28 != 0 or value_index >= memory.LARGE_MEMORY_VALUE_ID_BASE)
            return Error.InvalidEncoding;
        value.* = execution_tables.limb(
            input,
            execution_tables.MEMORY_VALUE_TABLE,
            memory.EncodedMemoryValueId.f252(@intCast(value_index)).raw,
            @intCast(column),
        );
    }
}

/// Writes one of the 8 canonical 9-bit small-value columns.
pub fn writeSmallValueColumn(
    input: *const adapter.ProverInput,
    column: usize,
    destination: []u32,
) Error!void {
    if (column >= small_limb_count) return Error.InvalidColumn;
    if (destination.len != try smallRowCount(input)) return Error.InvalidRowCount;
    for (destination, 0..) |*value, row| {
        if (row >= input.memory.small_values.len) {
            value.* = 0;
            continue;
        }
        const small = input.memory.small_values[row];
        if (small > input.memory.config.small_max or small >> 72 != 0 or
            row >= memory.LARGE_MEMORY_VALUE_ID_BASE)
            return Error.InvalidEncoding;
        value.* = execution_tables.limb(
            input,
            execution_tables.MEMORY_VALUE_TABLE,
            memory.EncodedMemoryValueId.small(@intCast(row)).raw,
            @intCast(column),
        );
    }
}

fn powerOfTwoRows(rows: usize) Error!usize {
    if (rows <= 1) return 1;
    return std.math.ceilPowerOfTwo(usize, rows) catch Error.AllocationSizeOverflow;
}

fn testInput(
    f252_values: []memory.F252,
    small_values: []u128,
) adapter.ProverInput {
    var input: adapter.ProverInput = undefined;
    input.memory = .{
        .config = .{},
        .address_to_id = &.{},
        .f252_values = f252_values,
        .small_values = small_values,
    };
    return input;
}

test "Cairo memory tables: Rust row geometry pads packed values before powers of two" {
    var big = [_]memory.F252{[_]u32{0} ** 8} ** 17;
    var small = [_]u128{0} ** 33;
    var input = testInput(&big, &small);
    try std.testing.expectEqual(@as(usize, 32), try packedCount(big.len));
    try std.testing.expectEqual(@as(usize, 1), try bigComponentCount(&input));
    try std.testing.expectEqual(@as(usize, 32), try bigRowCount(&input, 0));
    try std.testing.expectEqual(@as(usize, 64), try smallRowCount(&input));
}

test "Cairo memory tables: empty big values use one SIMD padding component" {
    var input = testInput(&.{}, &.{0});
    try std.testing.expectEqual(@as(usize, 1), try bigComponentCount(&input));
    try std.testing.expectEqual(lane_count, try bigRowCount(&input, 0));
    var column: [lane_count]u32 = undefined;
    try writeBigValueColumn(&input, 0, 0, &column);
    try std.testing.expectEqualSlices(u32, &([_]u32{0} ** lane_count), &column);
}

test "Cairo memory tables: value columns use 9-bit limbs and zero padding" {
    var big = [_]memory.F252{.{ 0x0003_fe00, 0, 0, 0, 0, 0, 0, 0 }};
    var small = [_]u128{0x3fe00};
    var input = testInput(&big, &small);
    var big_column: [lane_count]u32 = undefined;
    var small_column: [lane_count]u32 = undefined;
    try writeBigValueColumn(&input, 0, 1, &big_column);
    try writeSmallValueColumn(&input, 1, &small_column);
    try std.testing.expectEqual(@as(u32, 511), big_column[0]);
    try std.testing.expectEqual(@as(u32, 511), small_column[0]);
    try std.testing.expectEqual(@as(u32, 0), big_column[1]);
    try std.testing.expectEqual(@as(u32, 0), small_column[1]);
}

test "Cairo memory tables: noncanonical values fail closed" {
    var big = [_]memory.F252{.{ 0, 0, 0, 0, 0, 0, 0, 0x1000_0000 }};
    var small = [_]u128{@as(u128, 1) << 72};
    var input = testInput(&big, &small);
    var column: [lane_count]u32 = undefined;
    try std.testing.expectError(Error.InvalidEncoding, writeBigValueColumn(&input, 0, 0, &column));
    try std.testing.expectError(Error.InvalidEncoding, writeSmallValueColumn(&input, 0, &column));
}
