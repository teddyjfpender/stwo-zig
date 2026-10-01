//! Backend-neutral access to Cairo witness execution tables.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const memory_mod = @import("../common/memory.zig");
const program = @import("program.zig");

pub const ADDRESS_TO_ID_TABLE: u32 = 0;
pub const MEMORY_VALUE_TABLE: u32 = 1;
pub const BIG_LIMB_COUNT: u32 = 28;
pub const SMALL_LIMB_COUNT: u32 = 8;

/// Adapts canonical prover memory to the witness interpreter without copying
/// the column-major execution tables materialized by accelerator backends.
pub fn fromInput(input: *const adapter.ProverInput) program.TableContext {
    return .{
        .context = @ptrCast(@constCast(input)),
        .limb_fn = tableLimbOpaque,
    };
}

pub fn limb(input: *const adapter.ProverInput, table: u32, row: u32, limb_index: u32) u32 {
    return switch (table) {
        ADDRESS_TO_ID_TABLE => addressToId(input, row),
        MEMORY_VALUE_TABLE => memoryValueLimb(input, row, limb_index),
        else => 0,
    };
}

fn tableLimbOpaque(context: *anyopaque, table: u32, row: u32, limb_index: u32) u32 {
    const input: *const adapter.ProverInput = @ptrCast(@alignCast(context));
    return limb(input, table, row, limb_index);
}

fn addressToId(input: *const adapter.ProverInput, address: u32) u32 {
    if (address >= input.memory.address_to_id.len) return 0;
    return input.memory.address_to_id[address].raw;
}

fn memoryValueLimb(input: *const adapter.ProverInput, encoded_raw: u32, limb_index: u32) u32 {
    const tag = encoded_raw >> 30;
    const value_index = encoded_raw & 0x3fff_ffff;
    if (tag == 1) {
        if (limb_index >= BIG_LIMB_COUNT or value_index >= input.memory.f252_values.len) return 0;
        return wordsLimb(&input.memory.f252_values[value_index], limb_index);
    }
    if (limb_index >= SMALL_LIMB_COUNT or value_index >= input.memory.small_values.len) return 0;
    return smallLimb(input.memory.small_values[value_index], limb_index);
}

fn wordsLimb(words: []const u32, limb_index: u32) u32 {
    const bit_offset = limb_index * 9;
    const word_index = bit_offset / 32;
    const shift: u5 = @intCast(bit_offset % 32);
    var value = words[word_index] >> shift;
    if (shift > 23 and word_index + 1 < words.len) {
        const remaining: u5 = @intCast(32 - @as(u6, shift));
        value |= words[word_index + 1] << remaining;
    }
    return value & 0x1ff;
}

fn smallLimb(value: u128, limb_index: u32) u32 {
    const shift: u7 = @intCast(limb_index * 9);
    return @truncate((value >> shift) & 0x1ff);
}

fn testInput(memory: memory_mod.Memory) adapter.ProverInput {
    var input: adapter.ProverInput = undefined;
    input.memory = memory;
    return input;
}

/// Independent transcription of `stwo_zig_execution_table_split_resident`.
fn metalSplitReference(words: []const u32, limb_count: usize, output: []u32) void {
    var bits_left: u32 = 32;
    var word_index: usize = 0;
    var word = words[0];
    for (output[0..limb_count]) |*limb_value| {
        if (bits_left > 9) {
            limb_value.* = word & 0x1ff;
            word >>= 9;
            bits_left -= 9;
        } else {
            limb_value.* = word;
            word_index += 1;
            word = if (word_index < words.len) words[word_index] else 0;
            if (bits_left < 9) {
                limb_value.* |= (word << @intCast(bits_left)) & 0x1ff;
                word >>= @intCast(9 - bits_left);
            }
            bits_left += 23;
        }
    }
}

test "Cairo execution tables: address table preserves encoded IDs" {
    const addresses = [_]memory_mod.EncodedMemoryValueId{
        memory_mod.EncodedMemoryValueId.small(3),
        memory_mod.EncodedMemoryValueId.f252(5),
        memory_mod.EncodedMemoryValueId.EMPTY,
        .{ .raw = 0x8000_0000 },
    };
    var input = testInput(.{
        .config = .{},
        .address_to_id = @constCast(&addresses),
        .f252_values = &.{},
        .small_values = &.{},
    });
    const tables = fromInput(&input);

    for (addresses, 0..) |encoded, address| {
        try std.testing.expectEqual(encoded.raw, tables.limb(ADDRESS_TO_ID_TABLE, @intCast(address), 17));
    }
    try std.testing.expectEqual(@as(u32, 0), tables.limb(ADDRESS_TO_ID_TABLE, addresses.len, 0));
    try std.testing.expectEqual(@as(u32, 0), tables.limb(9, 0, 0));
}

test "Cairo execution tables: big limbs match Metal across word boundaries" {
    const values = [_]memory_mod.F252{.{
        0xf800_0000,
        0x8000_000a,
        0x0000_00a5,
        0x7654_3210,
        0xfedc_ba98,
        0x0123_4567,
        0x89ab_cdef,
        0x0fed_cba9,
    }};
    var input = testInput(.{
        .config = .{},
        .address_to_id = &.{},
        .f252_values = @constCast(&values),
        .small_values = &.{},
    });
    const tables = fromInput(&input);
    var expected: [BIG_LIMB_COUNT]u32 = undefined;
    metalSplitReference(&values[0], expected.len, &expected);

    for (expected, 0..) |expected_limb, limb_index| {
        try std.testing.expectEqual(
            expected_limb,
            tables.limb(MEMORY_VALUE_TABLE, memory_mod.EncodedMemoryValueId.f252(0).raw, @intCast(limb_index)),
        );
    }
    try std.testing.expectEqual(@as(u32, 351), expected[3]);
    try std.testing.expectEqual(@as(u32, 331), expected[7]);
    try std.testing.expectEqual(@as(u32, 0), tables.limb(MEMORY_VALUE_TABLE, 0x4000_0001, 0));
    try std.testing.expectEqual(@as(u32, 0), tables.limb(MEMORY_VALUE_TABLE, 0x4000_0000, BIG_LIMB_COUNT));
}

test "Cairo execution tables: small limbs and encoded tags match Metal" {
    const small_value = (@as(u128, 0xa5) << 64) | (@as(u128, 0xa) << 32) | 0xf800_0000;
    const small_values = [_]u128{small_value};
    var input = testInput(.{
        .config = .{},
        .address_to_id = &.{},
        .f252_values = &.{},
        .small_values = @constCast(&small_values),
    });
    const tables = fromInput(&input);
    const words = [_]u32{
        @truncate(small_value),
        @truncate(small_value >> 32),
        @truncate(small_value >> 64),
        @truncate(small_value >> 96),
    };
    var expected: [SMALL_LIMB_COUNT]u32 = undefined;
    metalSplitReference(&words, expected.len, &expected);

    for (expected, 0..) |expected_limb, limb_index| {
        try std.testing.expectEqual(
            expected_limb,
            tables.limb(MEMORY_VALUE_TABLE, memory_mod.EncodedMemoryValueId.small(0).raw, @intCast(limb_index)),
        );
    }
    try std.testing.expectEqual(@as(u32, 351), expected[3]);
    // Bits 63..71 of the small value: 0xa5 << 1 (bit 63 is clear).
    try std.testing.expectEqual(@as(u32, 330), expected[7]);

    // Metal treats every tag except 1 as the small-value table selector.
    try std.testing.expectEqual(expected[3], tables.limb(MEMORY_VALUE_TABLE, 0x8000_0000, 3));
    try std.testing.expectEqual(expected[3], tables.limb(MEMORY_VALUE_TABLE, 0xc000_0000, 3));
    try std.testing.expectEqual(@as(u32, 0), tables.limb(MEMORY_VALUE_TABLE, memory_mod.DEFAULT_ID, 0));
    try std.testing.expectEqual(@as(u32, 0), tables.limb(MEMORY_VALUE_TABLE, 1, 0));
    try std.testing.expectEqual(@as(u32, 0), tables.limb(MEMORY_VALUE_TABLE, 0, SMALL_LIMB_COUNT));
}
