//! Exact scalar arithmetic for Cairo's canonical 252-bit field representation.

const std = @import("std");

pub const word_count: usize = 28;
const bits_per_word: usize = 9;
const word_mask: u256 = (1 << bits_per_word) - 1;

/// P = 2^251 + 17 * 2^192 + 1.
pub const prime: u256 = (@as(u256, 1) << 251) +
    (@as(u256, 17) << 192) + 1;

pub const Error = error{
    InvalidFeltWord,
    NonCanonicalFelt,
    DivisionByZero,
};

pub const Operation = enum {
    add,
    sub,
    mul,
    div,
};

pub fn apply(operation: Operation, args: []const u32, outputs: []u32) Error!void {
    if (args.len != 2 * word_count or outputs.len != word_count)
        return error.InvalidFeltWord;

    const lhs = try decode(args[0..word_count]);
    const rhs = try decode(args[word_count..]);
    const value = switch (operation) {
        .add => add(lhs, rhs),
        .sub => sub(lhs, rhs),
        .mul => mul(lhs, rhs),
        .div => try div(lhs, rhs),
    };
    encode(value, outputs);
}

pub fn decode(words: []const u32) Error!u256 {
    if (words.len != word_count) return error.InvalidFeltWord;
    var value: u256 = 0;
    for (words, 0..) |word, index| {
        if (word > word_mask) return error.InvalidFeltWord;
        value |= @as(u256, word) << @intCast(index * bits_per_word);
    }
    if (value >= prime) return error.NonCanonicalFelt;
    return value;
}

pub fn encode(value: u256, words: []u32) void {
    std.debug.assert(value < prime);
    std.debug.assert(words.len == word_count);
    for (words, 0..) |*word, index| {
        word.* = @intCast((value >> @intCast(index * bits_per_word)) & word_mask);
    }
}

pub fn add(lhs: u256, rhs: u256) u256 {
    const sum = @as(u257, lhs) + rhs;
    return @intCast(sum % @as(u257, prime));
}

pub fn sub(lhs: u256, rhs: u256) u256 {
    return if (lhs >= rhs) lhs - rhs else prime - (rhs - lhs);
}

pub fn mul(lhs: u256, rhs: u256) u256 {
    return @intCast((@as(u512, lhs) * rhs) % @as(u512, prime));
}

pub fn div(lhs: u256, rhs: u256) Error!u256 {
    if (rhs == 0) return error.DivisionByZero;
    return mul(lhs, inverse(rhs));
}

fn inverse(value: u256) u256 {
    var exponent = prime - 2;
    var factor = value;
    var result: u256 = 1;
    while (exponent != 0) : (exponent >>= 1) {
        if (exponent & 1 != 0) result = mul(result, factor);
        factor = mul(factor, factor);
    }
    return result;
}

test "Cairo deductions: felt words roundtrip canonical boundary values" {
    var words: [word_count]u32 = undefined;
    encode(prime - 1, &words);
    try std.testing.expectEqual(prime - 1, try decode(&words));
    words[word_count - 1] = 512;
    try std.testing.expectError(error.InvalidFeltWord, decode(&words));
}

test "Cairo deductions: felt arithmetic is canonical" {
    try std.testing.expectEqual(@as(u256, 0), add(prime - 1, 1));
    try std.testing.expectEqual(prime - 1, sub(0, 1));
    try std.testing.expectEqual(@as(u256, 42), mul(prime - 1, prime - 42));
    try std.testing.expectEqual(@as(u256, 9), try div(63, 7));
    try std.testing.expectError(error.DivisionByZero, div(1, 0));
}
