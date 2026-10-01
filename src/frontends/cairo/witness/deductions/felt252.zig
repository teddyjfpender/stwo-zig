//! Exact scalar arithmetic for Cairo's canonical 252-bit field representation.

const std = @import("std");

pub const word_count: usize = 28;
const bits_per_word: usize = 9;
const word_mask: u256 = (1 << bits_per_word) - 1;

/// P = 2^251 + 17 * 2^192 + 1.
pub const prime: u256 = @import("stwo_core").fields.stark_prime;

const NativeModulus = std.crypto.ff.Modulus(256);
const native_modulus = blk: {
    @setEvalBranchQuota(100000);
    break :blk NativeModulus.fromPrimitive(u256, prime) catch unreachable;
};

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

pub fn wordAt(value: u256, index: usize) Error!u32 {
    if (value >= prime) return error.NonCanonicalFelt;
    if (index >= word_count) return error.InvalidFeltWord;
    return @intCast((value >> @intCast(index * bits_per_word)) & word_mask);
}

pub fn add(lhs: u256, rhs: u256) u256 {
    // Canonical operands sum to less than 2p, which fits in u256.
    std.debug.assert(lhs < prime and rhs < prime);
    const sum = lhs + rhs;
    return if (sum >= prime) sum - prime else sum;
}

pub fn sub(lhs: u256, rhs: u256) u256 {
    std.debug.assert(lhs < prime and rhs < prime);
    return if (lhs >= rhs) lhs - rhs else prime - (rhs - lhs);
}

pub fn mul(lhs: u256, rhs: u256) u256 {
    // Keep canonical limbs at the ABI boundary. The standard field performs
    // native-limb Montgomery reduction instead of a 512-bit long division.
    // Existing callers accepting arbitrary u256 operands retain modular semantics.
    const a = NativeModulus.Fe.fromPrimitive(u256, native_modulus, if (lhs < prime) lhs else lhs % prime) catch unreachable;
    const b = NativeModulus.Fe.fromPrimitive(u256, native_modulus, if (rhs < prime) rhs else rhs % prime) catch unreachable;
    return native_modulus.mul(a, b).toPrimitive(u256) catch unreachable;
}

pub fn div(lhs: u256, rhs: u256) Error!u256 {
    if (rhs == 0) return error.DivisionByZero;
    return mul(lhs, inverse(rhs));
}

fn inverse(value: u256) u256 {
    // Binary extended GCD. Keep u = value*x and v = value*y (mod p)
    // throughout, with canonical coefficients. Unlike Fermat exponentiation,
    // this needs no 512-bit product or division in the inversion loop.
    std.debug.assert(value != 0 and value < prime);
    var u = value;
    var v = prime;
    var x: u256 = 1;
    var y: u256 = 0;
    while (u != 1 and v != 1) {
        while (u & 1 == 0) {
            u >>= 1;
            x = half(x);
        }
        while (v & 1 == 0) {
            v >>= 1;
            y = half(y);
        }
        if (u >= v) {
            u -= v;
            x = sub(x, y);
        } else {
            v -= u;
            y = sub(y, x);
        }
    }
    return if (u == 1) x else y;
}

fn half(value: u256) u256 {
    return if (value & 1 == 0) value >> 1 else (value + prime) >> 1;
}

/// Independent Fermat reference retained solely for arithmetic qualification.
fn inverseReference(value: u256) u256 {
    var exponent = prime - 2;
    var factor = value;
    var result: u256 = 1;
    while (exponent != 0) : (exponent >>= 1) {
        if (exponent & 1 != 0) result = mul(result, factor);
        factor = mul(factor, factor);
    }
    return result;
}

test "Cairo felt inverse agrees with Fermat at limb and prime boundaries" {
    for ([_]u256{ 1, 2, 3, 7, 1 << 63, (1 << 64) - 1, 1 << 128, (1 << 192) + 17, prime / 2, prime - 2, prime - 1 }) |value| {
        const actual = inverse(value);
        try std.testing.expect(actual < prime);
        try std.testing.expectEqual(inverseReference(value), actual);
        try std.testing.expectEqual(@as(u256, 1), mul(value, actual));
    }
    var random = std.Random.DefaultPrng.init(0xca110);
    for (0..48) |_| {
        const value = random.random().int(u256) % (prime - 1) + 1;
        try std.testing.expectEqual(inverseReference(value), inverse(value));
        try std.testing.expectEqual(@as(u256, 1), mul(value, inverse(value)));
    }
}

test "Cairo deductions: felt words roundtrip canonical boundary values" {
    var words: [word_count]u32 = undefined;
    encode(prime - 1, &words);
    try std.testing.expectEqual(prime - 1, try decode(&words));
    words[word_count - 1] = 512;
    try std.testing.expectError(error.InvalidFeltWord, decode(&words));
    try std.testing.expectEqual(@as(u32, 511), try wordAt(511, 0));
    try std.testing.expectError(error.InvalidFeltWord, wordAt(0, word_count));
}

test "Cairo deductions: felt arithmetic is canonical" {
    try std.testing.expectEqual(@as(u256, 0), add(prime - 1, 1));
    try std.testing.expectEqual(prime - 1, sub(0, 1));
    try std.testing.expectEqual(@as(u256, 42), mul(prime - 1, prime - 42));
    try std.testing.expectEqual(@as(u256, 9), try div(63, 7));
    try std.testing.expectError(error.DivisionByZero, div(1, 0));
}

test "Cairo felt native multiplication matches independent wide reduction" {
    const edges = [_]u256{ 0, 1, 2, (1 << 64) - 1, 1 << 128, 1 << 192, prime / 2, prime - 1, prime, prime + 1, std.math.maxInt(u256) };
    for (edges) |lhs| for (edges) |rhs| {
        const expected: u256 = @intCast((@as(u512, lhs) * rhs) % @as(u512, prime));
        try std.testing.expectEqual(expected, mul(lhs, rhs));
    };
    var random = std.Random.DefaultPrng.init(0xca110);
    for (0..4096) |_| {
        const lhs = random.random().int(u256);
        const rhs = random.random().int(u256);
        const expected: u256 = @intCast((@as(u512, lhs) * rhs) % @as(u512, prime));
        try std.testing.expectEqual(expected, mul(lhs, rhs));
    }
}

pub fn applyDivBatch(batch: @import("../program.zig").DeduceBatch) !void {
    try batch.validate();
    if (batch.arg_count != 2 * word_count or batch.output_count != word_count)
        return error.InvalidFeltWord;
    const capacity = @import("../deduction_contract.zig").max_batch_rows;
    var numerators: [capacity]u256 = undefined;
    var denominators: [capacity]u256 = undefined;
    var prefixes: [capacity]u256 = undefined;
    var start: usize = 0;
    while (start < batch.rows) {
        const count = @min(capacity, batch.rows - start);
        var product: u256 = 1;
        for (0..count) |row| {
            const args = batch.rowArgs(start + row);
            numerators[row] = try decode(args[0..word_count]);
            denominators[row] = try decode(args[word_count..]);
            if (denominators[row] == 0) return error.DivisionByZero;
            prefixes[row] = product;
            product = mul(product, denominators[row]);
        }
        var inverse_product = try div(1, product);
        var row = count;
        while (row != 0) {
            row -= 1;
            const inverse_denominator = mul(inverse_product, prefixes[row]);
            encode(mul(numerators[row], inverse_denominator), batch.rowOutputs(start + row));
            inverse_product = mul(inverse_product, denominators[row]);
        }
        start += count;
    }
}
