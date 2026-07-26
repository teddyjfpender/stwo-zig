//! Exact host implementation of Stwo-Cairo's Poseidon witness deductions.

const std = @import("std");
const claim_registry = @import("../../air/official_claim_registry.zig");
const felt252 = @import("felt252.zig");
const round_keys = @import("poseidon_round_keys.zig");

comptime {
    if (!std.mem.eql(u8, round_keys.source_revision, claim_registry.source_revision.stwo_cairo))
        @compileError("Poseidon round keys do not match the pinned Stwo-Cairo revision");
}

pub const word_count: usize = 10;
const bits_per_word: usize = 27;
const word_mask: u256 = (1 << bits_per_word) - 1;

pub const Error = felt252.Error || error{
    InvalidRound,
    InvalidWordCount,
    InvalidWidth27Word,
};

pub fn applyRoundKeys(args: []const u32, outputs: []u32) Error!void {
    if (args.len != 1 or outputs.len != 3 * word_count)
        return error.InvalidWordCount;
    const keys = try keysForRound(args[0]);
    for (keys, 0..) |key, index| encode(key, outputs[index * word_count ..][0..word_count]);
}

pub fn applyCube(args: []const u32, outputs: []u32) Error!void {
    if (args.len != word_count or outputs.len != word_count)
        return error.InvalidWordCount;
    encode(cube(try decode(args)), outputs);
}

pub fn applyFullRound(args: []const u32, outputs: []u32) Error!void {
    if (args.len != 2 + 3 * word_count or outputs.len != args.len)
        return error.InvalidWordCount;
    const keys = try keysForRound(args[1]);
    const x = cube(try decode(args[2..][0..word_count]));
    const y = cube(try decode(args[2 + word_count ..][0..word_count]));
    const z = cube(try decode(args[2 + 2 * word_count ..][0..word_count]));

    const y1_zm1 = felt252.sub(y, z);
    const x1_ym1_z1 = felt252.sub(x, y1_zm1);
    const x1_y1_zm1 = felt252.add(x, y1_zm1);
    const x1_y1 = felt252.add(x, y);
    const x2_y2 = felt252.add(x1_y1, x1_y1);

    outputs[0] = args[0];
    outputs[1] = incrementM31(args[1]);
    encode(
        felt252.add(felt252.add(x2_y2, x1_ym1_z1), keys[0]),
        outputs[2..][0..word_count],
    );
    encode(
        felt252.add(x1_ym1_z1, keys[1]),
        outputs[2 + word_count ..][0..word_count],
    );
    encode(
        felt252.add(felt252.sub(x1_y1_zm1, z), keys[2]),
        outputs[2 + 2 * word_count ..][0..word_count],
    );
}

pub fn applyThreePartialRounds(args: []const u32, outputs: []u32) Error!void {
    if (args.len != 2 + 4 * word_count or outputs.len != args.len)
        return error.InvalidWordCount;
    const keys = try keysForRound(args[1]);
    var state = [4]u256{
        try decode(args[2..][0..word_count]),
        try decode(args[2 + word_count ..][0..word_count]),
        try decode(args[2 + 2 * word_count ..][0..word_count]),
        try decode(args[2 + 3 * word_count ..][0..word_count]),
    };
    for (keys) |key| state = partialRound(state, key);

    outputs[0] = args[0];
    outputs[1] = incrementM31(args[1]);
    for (state, 0..) |value, index| {
        encode(value, outputs[2 + index * word_count ..][0..word_count]);
    }
}

fn partialRound(state: [4]u256, half_key: u256) [4]u256 {
    const z03 = state[0];
    const z1 = state[1];
    const z13 = state[2];
    const z2 = state[3];
    const z23 = cube(z2);
    const z03_z13 = felt252.add(z03, z13);
    const z03_z13_z1 = felt252.add(z03_z13, z1);
    const longsum = felt252.add(
        felt252.sub(felt252.add(z03_z13_z1, z2), z23),
        half_key,
    );
    const half_z3 = felt252.add(
        felt252.add(felt252.add(longsum, z03_z13_z1), z03_z13),
        z03,
    );
    return .{ z13, z2, z23, felt252.add(half_z3, half_z3) };
}

fn keysForRound(round: u32) Error![3]u256 {
    if (round >= round_keys.values.len) return error.InvalidRound;
    var result: [3]u256 = undefined;
    for (round_keys.values[round], &result) |limbs, *value| {
        value.* = @as(u256, limbs[0]) |
            (@as(u256, limbs[1]) << 64) |
            (@as(u256, limbs[2]) << 128) |
            (@as(u256, limbs[3]) << 192);
    }
    return result;
}

fn decode(words: []const u32) Error!u256 {
    if (words.len != word_count) return error.InvalidWordCount;
    var value: u256 = 0;
    for (words, 0..) |word, index| {
        const limit: u32 = if (index == word_count - 1) 1 << 9 else 1 << bits_per_word;
        if (word >= limit) return error.InvalidWidth27Word;
        value |= @as(u256, word) << @intCast(index * bits_per_word);
    }
    if (value >= felt252.prime) return error.NonCanonicalFelt;
    return value;
}

fn encode(value: u256, words: []u32) void {
    std.debug.assert(value < felt252.prime);
    std.debug.assert(words.len == word_count);
    for (words, 0..) |*word, index| {
        word.* = @intCast((value >> @intCast(index * bits_per_word)) & word_mask);
    }
}

fn cube(value: u256) u256 {
    return felt252.mul(felt252.mul(value, value), value);
}

fn incrementM31(value: u32) u32 {
    const modulus = (@as(u32, 1) << 31) - 1;
    return if (value == modulus - 1) 0 else value + 1;
}

test "Poseidon cube preserves the official width-27 representation" {
    var input = [_]u32{0} ** word_count;
    var output: [word_count]u32 = undefined;
    input[0] = 3;
    try applyCube(&input, &output);
    try std.testing.expectEqual(@as(u32, 27), output[0]);
    for (output[1..]) |word| try std.testing.expectEqual(@as(u32, 0), word);
}

test "Poseidon deductions reject invalid rounds and width-27 words" {
    var round_output: [3 * word_count]u32 = undefined;
    try std.testing.expectError(error.InvalidRound, applyRoundKeys(&.{35}, &round_output));
    var input = [_]u32{0} ** word_count;
    var output: [word_count]u32 = undefined;
    input[word_count - 1] = 1 << 9;
    try std.testing.expectError(error.InvalidWidth27Word, applyCube(&input, &output));
}
