//! Four-limb REDC for canonical BN254 Montgomery operands. No allocation,
//! division or inverse in the hot path. The caller checks canonical bounds.
const std = @import("std");
pub const MODULUS: u256 = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
const MASK: u256 = std.math.maxInt(u64);
const LIMBS = limbs(MODULUS);
const NEG_INVERSE: u64 = blk: {
    var inverse: u64 = 1;
    for (0..6) |_| inverse *%= 2 -% LIMBS[0] *% inverse;
    break :blk 0 -% inverse;
};
fn limbs(value: u256) [4]u64 {
    var result: [4]u64 = undefined;
    for (&result, 0..) |*word, i| word.* = @truncate(value >> @intCast(64 * i));
    return result;
}
/// Returns a*b*2^-256 mod p for a,b < p. REDC(T) < 2p, so one final
/// subtraction suffices; p has 254 bits and the result has no fifth limb.
pub fn product(a: u256, b: u256) u256 {
    std.debug.assert(a < MODULUS and b < MODULUS);
    const x = limbs(a);
    const y = limbs(b);
    var t: [9]u64 = @splat(0);
    for (0..4) |i| {
        var carry: u128 = 0;
        for (0..4) |j| {
            const sum = @as(u128, x[i]) * y[j] + t[i + j] + carry;
            t[i + j] = @truncate(sum);
            carry = sum >> 64;
        }
        t[i + 4] = @intCast(carry);
    }
    for (0..4) |i| {
        const factor = t[i] *% NEG_INVERSE;
        var carry: u128 = 0;
        for (0..4) |j| {
            const sum = @as(u128, factor) * LIMBS[j] + t[i + j] + carry;
            t[i + j] = @truncate(sum);
            carry = sum >> 64;
        }
        var k = i + 4;
        while (carry != 0) : (k += 1) {
            std.debug.assert(k < t.len);
            const sum = @as(u128, t[k]) + carry;
            t[k] = @truncate(sum);
            carry = sum >> 64;
        }
        std.debug.assert(t[i] == 0);
    }
    std.debug.assert(t[8] == 0);
    var result: u256 = 0;
    for (0..4) |i| result |= @as(u256, t[i + 4]) << @intCast(64 * i);
    return if (result >= MODULUS) result - MODULUS else result;
}

test "BN254 REDC agrees with independent wide integer reduction at limb boundaries" {
    const radix: u256 = @intCast((@as(u512, 1) << 256) % MODULUS);
    const inverse: u256 = 20988524275117001072002809824448087578619730785600314334253784976379291040311;
    try std.testing.expectEqual(@as(u512, 1), @as(u512, radix) * inverse % MODULUS);
    const values = [_]u256{ 0, 1, MASK, MASK + 1, (@as(u256, 1) << 128) - 1, MODULUS - 2, MODULUS - 1 };
    for (values) |a| for (values) |b| {
        const reduced: u256 = @intCast(@as(u512, a) * b % MODULUS);
        const expected: u256 = @intCast(@as(u512, reduced) * inverse % MODULUS);
        try std.testing.expectEqual(expected, product(a, b));
    };
    var prng = std.Random.DefaultPrng.init(0x384256);
    const random = prng.random();
    for (0..128) |_| {
        const a = random.int(u256) % MODULUS;
        const b = random.int(u256) % MODULUS;
        const reduced: u256 = @intCast(@as(u512, a) * b % MODULUS);
        const expected: u256 = @intCast(@as(u512, reduced) * inverse % MODULUS);
        try std.testing.expectEqual(expected, product(a, b));
    }
}
