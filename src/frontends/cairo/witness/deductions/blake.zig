//! Exact host semantics for the official Cairo Blake witness deductions.

const std = @import("std");
const program = @import("../program.zig");

const address_to_id_table: u32 = 0;
const memory_value_table: u32 = 1;
const large_value_tag: u32 = 0x4000_0000;
const empty_value_id: u32 = large_value_tag - 1;

const sigma = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

const g_indices = [8][4]u8{
    .{ 0, 4, 8, 12 },
    .{ 1, 5, 9, 13 },
    .{ 2, 6, 10, 14 },
    .{ 3, 7, 11, 15 },
    .{ 0, 5, 10, 15 },
    .{ 1, 6, 11, 12 },
    .{ 2, 7, 8, 13 },
    .{ 3, 4, 9, 14 },
};

pub fn applyTripleXor(args: []const u32, outputs: []u32) !void {
    if (args.len != 3 or outputs.len != 1) return error.InvalidDeductionShape;
    outputs[0] = args[0] ^ args[1] ^ args[2];
}

pub fn applyG(args: []const u32, outputs: []u32) !void {
    if (args.len != 6 or outputs.len != 4) return error.InvalidDeductionShape;
    const mixed = mix(args[0], args[1], args[2], args[3], args[4], args[5]);
    @memcpy(outputs, &mixed);
}

pub fn applyRoundSigma(args: []const u32, outputs: []u32) !void {
    if (args.len != 1 or outputs.len != 16) return error.InvalidDeductionShape;
    if (args[0] >= sigma.len) return error.InvalidBlakeRound;
    for (outputs, sigma[args[0]]) |*output, value| output.* = value;
}

pub fn applyRound(
    args: []const u32,
    outputs: []u32,
    tables: program.TableContext,
) !void {
    if (args.len != 19 or outputs.len != 19) return error.InvalidDeductionShape;
    const round = args[1];
    if (round >= sigma.len) return error.InvalidBlakeRound;

    var state: [16]u32 = undefined;
    @memcpy(&state, args[2..18]);
    var message: [16]u32 = undefined;
    for (&message, sigma[round]) |*word, message_index| {
        word.* = try readSmall(tables, args[18] + @as(u32, message_index));
    }
    for (g_indices, 0..) |indices, index| {
        const mixed = mix(
            state[indices[0]],
            state[indices[1]],
            state[indices[2]],
            state[indices[3]],
            message[index * 2],
            message[index * 2 + 1],
        );
        for (indices, 0..) |state_index, mixed_index| {
            state[state_index] = mixed[mixed_index];
        }
    }

    outputs[0] = args[0];
    outputs[1] = round + 1;
    @memcpy(outputs[2..18], &state);
    outputs[18] = args[18];
}

fn readSmall(tables: program.TableContext, address: u32) !u32 {
    const encoded = tables.limb(address_to_id_table, address, 0);
    if (encoded == empty_value_id or encoded >= large_value_tag) {
        return error.BlakeMessageNotSmall;
    }
    return tables.limb(memory_value_table, encoded, 0) |
        (tables.limb(memory_value_table, encoded, 1) << 9) |
        (tables.limb(memory_value_table, encoded, 2) << 18) |
        ((tables.limb(memory_value_table, encoded, 3) & 0x1f) << 27);
}

fn mix(a0: u32, b0: u32, c0: u32, d0: u32, m0: u32, m1: u32) [4]u32 {
    var a = a0;
    var b = b0;
    var c = c0;
    var d = d0;
    a +%= b +% m0;
    d = std.math.rotr(u32, d ^ a, 16);
    c +%= d;
    b = std.math.rotr(u32, b ^ c, 12);
    a +%= b +% m1;
    d = std.math.rotr(u32, d ^ a, 8);
    c +%= d;
    b = std.math.rotr(u32, b ^ c, 7);
    return .{ a, b, c, d };
}

test "Blake triple xor uses full-width words" {
    var output: [1]u32 = undefined;
    try applyTripleXor(&.{ 0xffff_0000, 0x0f0f_0f0f, 0x1234_5678 }, &output);
    try std.testing.expectEqual(@as(u32, 0xe2c4_5967), output[0]);
}

test "Blake G and sigma match the official scalar semantics" {
    var g: [4]u32 = undefined;
    try applyG(
        &.{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x01234567, 0x89abcdef },
        &g,
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 0x4ccdb43f, 0xf3996220, 0x503c1b84, 0xe463a437 },
        &g,
    );
    var selected: [16]u32 = undefined;
    try applyRoundSigma(&.{1}, &selected);
    for (selected, sigma[1]) |actual, expected| try std.testing.expectEqual(expected, actual);
}
