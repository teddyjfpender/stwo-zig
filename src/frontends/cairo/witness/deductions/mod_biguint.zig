//! Exact scalar implementation of the official Cairo modulo-builtin bigint boundary.

const std = @import("std");
const felt252 = @import("felt252.zig");

const felt_count: usize = 4;
const felt_words: usize = felt252.word_count;
const operand_words: usize = felt_count * felt_words;
const mod_word_bits: usize = 96;
const quotient_words: usize = 32;
const quotient_word_bits: usize = 12;
const mod_word_mask: u256 = (@as(u256, 1) << mod_word_bits) - 1;
const quotient_word_mask: u384 = (@as(u384, 1) << quotient_word_bits) - 1;

pub const Error = felt252.Error || error{
    InvalidWordCount,
    DivisionByZero,
    QuotientOverflow,
};

pub fn applyAddIsZero(args: []const u32, outputs: []u32) Error!void {
    if (args.len != 3 * operand_words or outputs.len != 1)
        return error.InvalidWordCount;

    const a = try decodeOperand(args[0..operand_words]);
    const b = try decodeOperand(args[operand_words .. 2 * operand_words]);
    const c = try decodeOperand(args[2 * operand_words ..]);
    outputs[0] = @intFromBool(a +% b -% c == 0);
}

pub fn applyMulQuotient(args: []const u32, outputs: []u32) Error!void {
    if (args.len != 4 * operand_words or outputs.len != quotient_words)
        return error.InvalidWordCount;

    const p = try decodeOperand(args[0..operand_words]);
    const a = try decodeOperand(args[operand_words .. 2 * operand_words]);
    const b = try decodeOperand(args[2 * operand_words .. 3 * operand_words]);
    const c = try decodeOperand(args[3 * operand_words ..]);
    if (p == 0) return error.DivisionByZero;

    const numerator = @as(u768, a) * @as(u768, b) -% @as(u768, c);
    const quotient = numerator / @as(u768, p);
    if (quotient > std.math.maxInt(u384)) return error.QuotientOverflow;
    encodeQuotient(@intCast(quotient), outputs);
}

fn decodeOperand(words: []const u32) felt252.Error!u384 {
    std.debug.assert(words.len == operand_words);
    var value: u384 = 0;
    for (0..felt_count) |index| {
        const start = index * felt_words;
        const felt = try felt252.decode(words[start .. start + felt_words]);
        value |= @as(u384, felt & mod_word_mask) << @intCast(index * mod_word_bits);
    }
    return value;
}

fn encodeQuotient(value: u384, words: []u32) void {
    std.debug.assert(words.len == quotient_words);
    for (words, 0..) |*word, index| {
        word.* = @intCast((value >> @intCast(index * quotient_word_bits)) & quotient_word_mask);
    }
}

fn setOperand(buffer: []u32, operand_index: usize, value: u256) void {
    const start = operand_index * operand_words;
    @memset(buffer[start .. start + operand_words], 0);
    felt252.encode(value, buffer[start .. start + felt_words]);
}

test "add-mod zero test preserves wrapping BigUInt384 semantics" {
    var args = [_]u32{0} ** (3 * operand_words);
    var output: [1]u32 = undefined;
    setOperand(&args, 0, 5);
    setOperand(&args, 1, 7);
    setOperand(&args, 2, 12);
    try applyAddIsZero(&args, &output);
    try std.testing.expectEqual(@as(u32, 1), output[0]);

    setOperand(&args, 2, 11);
    try applyAddIsZero(&args, &output);
    try std.testing.expectEqual(@as(u32, 0), output[0]);
}

test "mul-mod quotient emits little-endian 12-bit words" {
    var args = [_]u32{0} ** (4 * operand_words);
    var output: [quotient_words]u32 = undefined;
    setOperand(&args, 0, 7);
    setOperand(&args, 1, 9);
    setOperand(&args, 2, 11);
    setOperand(&args, 3, 1);
    try applyMulQuotient(&args, &output);
    try std.testing.expectEqual(@as(u32, 14), output[0]);
    try std.testing.expectEqualSlices(u32, &([_]u32{0} ** 31), output[1..]);
}
