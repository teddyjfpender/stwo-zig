//! Direct, table-free SHA-256 feed-forward equations for one compression.
//!
//! Each of eight rows adds the incoming chaining word to the terminal round
//! word modulo 2^32. Input half-words must be bound to Boolean-constrained
//! round state through a joint word bus; these local equations do not prove
//! that custody or a complete compression by themselves.
const std = @import("std");
const core = @import("stwo_core");
const sha = @import("s31_sha_provider").compression;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const row_count: usize = 8;
pub const constraint_count: usize = 36;

pub fn Row(comptime F: type) type {
    return struct {
        initial: [2]F,
        terminal: [2]F,
        output_bits: [32]F,
        carry_bits: [2]F,
    };
}

fn fixed(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    return if (F == M31) base else if (F == QM31) QM31.fromBase(base) else @compileError("SHA feed-forward requires M31 or QM31");
}

fn half(comptime F: type, bits: [32]F, start: usize) F {
    var result = fixed(F, 0);
    for (0..16) |i| result = result.add(bits[start + i].mul(fixed(F, @as(u32, 1) << @intCast(i))));
    return result;
}

/// Output and carries are canonical bits. With bus-bound 16-bit inputs, each
/// side of each addition is <= 131071, far below the M31 modulus.
pub fn evaluate(comptime F: type, row: Row(F)) [constraint_count]F {
    var out: [constraint_count]F = undefined;
    const one = fixed(F, 1);
    for (row.output_bits, 0..) |value, i| out[i] = value.mul(value.sub(one));
    for (row.carry_bits, 0..) |value, i| out[32 + i] = value.mul(value.sub(one));
    const radix = fixed(F, 1 << 16);
    out[34] = row.initial[0].add(row.terminal[0])
        .sub(half(F, row.output_bits, 0))
        .sub(radix.mul(row.carry_bits[0]));
    out[35] = row.initial[1].add(row.terminal[1]).add(row.carry_bits[0])
        .sub(half(F, row.output_bits, 16))
        .sub(radix.mul(row.carry_bits[1]));
    return out;
}

fn split(comptime F: type, value: u32) [2]F {
    return .{ fixed(F, value & 0xffff), fixed(F, value >> 16) };
}

pub fn witness(initial: sha.State, terminal: sha.State) [row_count]Row(M31) {
    var rows: [row_count]Row(M31) = undefined;
    for (&rows, initial, terminal) |*row, start, end| {
        const value = start +% end;
        const low_sum = (start & 0xffff) + (end & 0xffff);
        const high_sum = (start >> 16) + (end >> 16) + (low_sum >> 16);
        row.* = .{
            .initial = split(M31, start),
            .terminal = split(M31, end),
            .output_bits = undefined,
            .carry_bits = .{ M31.fromCanonical(low_sum >> 16), M31.fromCanonical(high_sum >> 16) },
        };
        for (&row.output_bits, 0..) |*bit, i| bit.* = M31.fromCanonical((value >> @intCast(i)) & 1);
    }
    return rows;
}

pub fn lift(rows: [row_count]Row(M31)) [row_count]Row(QM31) {
    var result: [row_count]Row(QM31) = undefined;
    for (rows, &result) |row, *target| {
        for (row.initial, &target.initial) |value, *slot| slot.* = QM31.fromBase(value);
        for (row.terminal, &target.terminal) |value, *slot| slot.* = QM31.fromBase(value);
        for (row.output_bits, &target.output_bits) |value, *slot| slot.* = QM31.fromBase(value);
        for (row.carry_bits, &target.carry_bits) |value, *slot| slot.* = QM31.fromBase(value);
    }
    return result;
}

fn valid(comptime F: type, rows: *const [row_count]Row(F)) bool {
    for (rows) |row| for (evaluate(F, row)) |constraint| {
        if (!constraint.isZero()) return false;
    };
    return true;
}

test "direct SHA feed-forward matches independent complete compression" {
    var random = std.Random.DefaultPrng.init(0x4645_4544_3332_3031);
    for (0..8) |_| {
        var block: [64]u8 = undefined;
        random.random().bytes(&block);
        const rounds = sha.witness(sha.initial_state, block);
        const rows = witness(sha.initial_state, rounds.states[64]);
        try std.testing.expect(valid(M31, &rows));
        const secure = lift(rows);
        try std.testing.expect(valid(QM31, &secure));
        const expected = sha.compress(sha.initial_state, block);
        for (rows, expected) |row, word| {
            var actual: u32 = 0;
            for (row.output_bits, 0..) |bit, i| actual |= bit.toU32() << @intCast(i);
            try std.testing.expectEqual(word, actual);
        }
    }
}

test "feed-forward rejects output bit, carry, and bound input changes" {
    const initial = sha.initial_state;
    const terminal: sha.State = @splat(0xffff_ffff);
    const honest = witness(initial, terminal);
    try std.testing.expect(valid(M31, &honest));
    var changed = honest;
    changed[0].output_bits[0] = changed[0].output_bits[0].add(M31.one());
    try std.testing.expect(!valid(M31, &changed));
    changed = honest;
    changed[0].carry_bits[0] = changed[0].carry_bits[0].add(M31.one());
    try std.testing.expect(!valid(M31, &changed));
    changed = honest;
    changed[0].initial[0] = changed[0].initial[0].add(M31.one());
    try std.testing.expect(!valid(M31, &changed));
}
