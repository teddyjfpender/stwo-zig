//! Table-free SHA-256 message-schedule equations for a future direct AIR.
//!
//! This module defines the 64-row local arithmetic and witness. The first
//! sixteen words are inputs and must be authenticated by a caller bus in a
//! joined proof. A future AIR must also enforce the t-2/7/15/16 row openings;
//! these host-side array indices do not themselves make a STARK proof.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const row_count: usize = 64;
pub const constraint_count: usize = 38;

/// Bit 0 is the least significant bit of a SHA word. Carries lie in 0..3.
pub fn Row(comptime F: type) type {
    return struct {
        word_bits: [32]F,
        carry_low_bits: [2]F,
        carry_high_bits: [2]F,
    };
}

fn constant(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    return if (F == M31) base else if (F == QM31) QM31.fromBase(base) else @compileError("SHA schedule requires M31 or QM31");
}

fn bit(comptime F: type, row: Row(F), index: usize) F {
    return row.word_bits[index];
}

fn xor2(comptime F: type, x: F, y: F) F {
    return x.add(y).sub(constant(F, 2).mul(x).mul(y));
}

fn xor3(comptime F: type, x: F, y: F, z: F) F {
    return xor2(F, xor2(F, x, y), z);
}

fn smallSigma0(comptime F: type, row: Row(F)) [32]F {
    var result: [32]F = undefined;
    for (&result, 0..) |*out, index| {
        out.* = xor3(
            F,
            bit(F, row, (index + 7) % 32),
            bit(F, row, (index + 18) % 32),
            if (index + 3 < 32) bit(F, row, index + 3) else constant(F, 0),
        );
    }
    return result;
}

fn smallSigma1(comptime F: type, row: Row(F)) [32]F {
    var result: [32]F = undefined;
    for (&result, 0..) |*out, index| {
        out.* = xor3(
            F,
            bit(F, row, (index + 17) % 32),
            bit(F, row, (index + 19) % 32),
            if (index + 10 < 32) bit(F, row, index + 10) else constant(F, 0),
        );
    }
    return result;
}

fn limb(comptime F: type, bits: [32]F, start: usize) F {
    var result = constant(F, 0);
    for (0..16) |index| {
        result = result.add(bits[start + index].mul(constant(F, @as(u32, 1) << @intCast(index))));
    }
    return result;
}

fn carry(comptime F: type, bits: [2]F) F {
    return bits[0].add(bits[1].mul(constant(F, 2)));
}

/// Constraints are field-generic: the same equations can be used for the
/// prover's M31 rows and verifier's QM31 openings. The first sixteen rows
/// constrain canonical bits and zero carries, but their word values are
/// deliberately caller-owned. Later rows constrain exact integer addition.
pub fn evaluate(comptime F: type, rows: *const [row_count]Row(F), t: usize) [constraint_count]F {
    std.debug.assert(t < row_count);
    const row = rows[t];
    var result: [constraint_count]F = undefined;
    const one = constant(F, 1);
    for (row.word_bits, 0..) |value, index|
        result[index] = value.mul(value.sub(one));
    if (t < 16) {
        result[32] = row.carry_low_bits[0];
        result[33] = row.carry_low_bits[1];
        result[34] = row.carry_high_bits[0];
        result[35] = row.carry_high_bits[1];
        result[36] = constant(F, 0);
        result[37] = constant(F, 0);
        return result;
    }
    for (row.carry_low_bits, 0..) |value, index|
        result[32 + index] = value.mul(value.sub(one));
    for (row.carry_high_bits, 0..) |value, index|
        result[34 + index] = value.mul(value.sub(one));

    const sigma0 = smallSigma0(F, rows[t - 15]);
    const sigma1 = smallSigma1(F, rows[t - 2]);
    const previous16 = rows[t - 16].word_bits;
    const previous7 = rows[t - 7].word_bits;
    const radix = constant(F, 1 << 16);
    result[36] = limb(F, previous16, 0)
        .add(limb(F, sigma0, 0))
        .add(limb(F, previous7, 0))
        .add(limb(F, sigma1, 0))
        .sub(limb(F, row.word_bits, 0))
        .sub(radix.mul(carry(F, row.carry_low_bits)));
    result[37] = limb(F, previous16, 16)
        .add(limb(F, sigma0, 16))
        .add(limb(F, previous7, 16))
        .add(limb(F, sigma1, 16))
        .add(carry(F, row.carry_low_bits))
        .sub(limb(F, row.word_bits, 16))
        .sub(radix.mul(carry(F, row.carry_high_bits)));
    return result;
}

fn sigma0Native(value: u32) u32 {
    return std.math.rotr(u32, value, 7) ^ std.math.rotr(u32, value, 18) ^ (value >> 3);
}
fn sigma1Native(value: u32) u32 {
    return std.math.rotr(u32, value, 17) ^ std.math.rotr(u32, value, 19) ^ (value >> 10);
}

/// Independent word-level reference used for witness tests only.
pub fn referenceWords(first: [16]u32) [row_count]u32 {
    var words: [row_count]u32 = undefined;
    @memcpy(words[0..16], &first);
    for (16..row_count) |t| {
        words[t] = words[t - 16] +% sigma0Native(words[t - 15]) +% words[t - 7] +% sigma1Native(words[t - 2]);
    }
    return words;
}

fn bitsOf(value: u32) [32]M31 {
    var bits: [32]M31 = undefined;
    for (&bits, 0..) |*slot, index| slot.* = M31.fromCanonical((value >> @intCast(index)) & 1);
    return bits;
}
fn bits2(value: u32) [2]M31 {
    std.debug.assert(value < 4);
    return .{ M31.fromCanonical(value & 1), M31.fromCanonical(value >> 1) };
}

pub fn witness(first: [16]u32) [row_count]Row(M31) {
    const words = referenceWords(first);
    var rows: [row_count]Row(M31) = undefined;
    for (&rows, 0..) |*row, t| {
        row.* = .{
            .word_bits = bitsOf(words[t]),
            .carry_low_bits = bits2(0),
            .carry_high_bits = bits2(0),
        };
        if (t < 16) continue;
        const inputs = [4]u32{ words[t - 16], sigma0Native(words[t - 15]), words[t - 7], sigma1Native(words[t - 2]) };
        var lo_sum: u32 = 0;
        var hi_sum: u32 = 0;
        for (inputs) |value| {
            lo_sum += value & 0xffff;
            hi_sum += value >> 16;
        }
        const lo_carry = lo_sum >> 16;
        const hi_carry = (hi_sum + lo_carry) >> 16;
        row.carry_low_bits = bits2(lo_carry);
        row.carry_high_bits = bits2(hi_carry);
    }
    return rows;
}

pub fn lift(rows: [row_count]Row(M31)) [row_count]Row(QM31) {
    var lifted: [row_count]Row(QM31) = undefined;
    for (rows, &lifted) |row, *target| {
        for (row.word_bits, &target.word_bits) |value, *slot| slot.* = QM31.fromBase(value);
        for (row.carry_low_bits, &target.carry_low_bits) |value, *slot| slot.* = QM31.fromBase(value);
        for (row.carry_high_bits, &target.carry_high_bits) |value, *slot| slot.* = QM31.fromBase(value);
    }
    return lifted;
}

fn valid(comptime F: type, rows: *const [row_count]Row(F)) bool {
    for (0..row_count) |t| for (evaluate(F, rows, t)) |constraint| {
        if (!constraint.isZero()) return false;
    };
    return true;
}

test "64-row direct SHA schedule constraints match word-level reference" {
    var random = std.Random.DefaultPrng.init(0x5348_4132_3536_5343);
    for (0..8) |_| {
        var first: [16]u32 = undefined;
        for (&first) |*word| word.* = random.random().int(u32);
        const words = referenceWords(first);
        const rows = witness(first);
        try std.testing.expect(valid(M31, &rows));
        const secure = lift(rows);
        try std.testing.expect(valid(QM31, &secure));
        for (rows, words) |row, word| {
            var rebuilt: u32 = 0;
            for (row.word_bits, 0..) |value, index| rebuilt |= value.toU32() << @intCast(index);
            try std.testing.expectEqual(word, rebuilt);
        }
    }
}

test "direct SHA schedule rejects bit, carry, and dependent input substitution" {
    const first: [16]u32 = .{ 0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24 };
    const words = referenceWords(first);
    try std.testing.expectEqualSlices(u32, &.{ 0x61626380, 0x000f0000, 0x7da86405, 0x600003c6 }, words[16..20]);
    const honest = witness(first);
    try std.testing.expect(valid(M31, &honest));
    var changed = honest;
    changed[20].word_bits[0] = changed[20].word_bits[0].add(M31.one());
    try std.testing.expect(!valid(M31, &changed));
    changed = honest;
    changed[17].carry_low_bits[0] = changed[17].carry_low_bits[0].add(M31.one());
    try std.testing.expect(!valid(M31, &changed));
    changed = honest;
    changed[0].word_bits[0] = changed[0].word_bits[0].add(M31.one());
    try std.testing.expect(!valid(M31, &changed));
    changed = honest;
    changed[0].carry_high_bits[1] = M31.one();
    try std.testing.expect(!valid(M31, &changed));
}
