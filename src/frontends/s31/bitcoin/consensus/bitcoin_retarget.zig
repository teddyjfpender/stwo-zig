//! Exact Bitcoin mainnet first-retarget relation for height 2016.
//!
//! The caller must authenticate the previous block's timestamp and prove
//! that this is height 2016. The preceding 2015 headers must already have
//! used 0x1d00ffff. The standalone API checks claimed bits; the expected
//! bits API allows a fixed-topology fold to select the first retarget only
//! at the authenticated boundary step.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const relation = @import("../../language/relation.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const U32 = circuit.builder.wrappers.U32Wrapper(Var);

pub const genesis_time: u32 = 1231006505;
pub const target_timespan: u32 = 14 * 24 * 60 * 60;
pub const min_timespan: u32 = target_timespan / 4;
pub const max_timespan: u32 = target_timespan * 4;
pub const genesis_target: u256 = @as(u256, 0xffff) << 208;

fn hint(comptime V: type, value: u32) V {
    return circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(value)));
}

fn valueOf(comptime V: type, ctx: *circuit.builder.Context(V), wire: Var) u32 {
    return if (comptime V == QM31) ctx.get(wire).toM31Array()[0].toU32() else 0;
}

fn guessBit(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Var {
    const wire = try ctx.guessM31(hint(V, value));
    try ctx.eq(try ctx.mul(wire, try ctx.sub(wire, ctx.one())), ctx.zero());
    return wire;
}

fn guessBits(comptime V: type, ctx: *circuit.builder.Context(V), comptime count: usize, value: u32) !Var {
    var result = ctx.zero();
    for (0..count) |i| {
        const bit = try guessBit(V, ctx, (value >> @as(u5, @intCast(i))) & 1);
        const weight = try ctx.constant(QM31.fromBase(M31.fromCanonical(@as(u32, 1) << @as(u5, @intCast(i)))));
        result = try ctx.add(result, try ctx.mul(bit, weight));
    }
    return result;
}

fn guessByte(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Var {
    return guessBits(V, ctx, 8, value);
}

const Limbs = struct { low: Var, high: Var };
const Carry = struct { limbs: Limbs, word: Var };

fn splitU32(comptime V: type, ctx: *circuit.builder.Context(V), word: U32) !Limbs {
    const value: u32 = if (comptime V == QM31) circuit.builder.ivalue.unpackU32(QM31, ctx.get(word.get())) else 0;
    const low = try ctx.guessU16(hint(V, value & 0xffff));
    const high = try ctx.guessU16(hint(V, value >> 16));
    const i = try ctx.constant(QM31.fromU32Unchecked(0, 1, 0, 0));
    try ctx.eq(word.get(), try ctx.add(low, try ctx.mul(high, i)));
    return .{ .low = low, .high = high };
}

/// The result is the final borrow of `a - b` over two range-checked limbs.
/// Each subtraction equation has integer magnitude below 2^18 < M31.
fn lessThanLimbs(comptime V: type, ctx: *circuit.builder.Context(V), a: Limbs, b: Limbs) !Var {
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(65536)));
    var borrow = ctx.zero();
    for ([_]Var{ a.low, a.high }, [_]Var{ b.low, b.high }) |av, bv| {
        const avalue = valueOf(V, ctx, av);
        const bvalue = valueOf(V, ctx, bv);
        const incoming = valueOf(V, ctx, borrow);
        const next_value: u32 = @intFromBool(avalue < bvalue + incoming);
        const digit_value = (avalue + 65536 - bvalue - incoming) & 0xffff;
        const next = try guessBit(V, ctx, next_value);
        const digit = try ctx.guessU16(hint(V, digit_value));
        try ctx.eq(try ctx.add(av, try ctx.mul(next, base)), try ctx.add(try ctx.add(bv, borrow), digit));
        borrow = next;
    }
    return borrow;
}

fn constantLimbs(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Limbs {
    return .{
        .low = try ctx.constant(QM31.fromBase(M31.fromCanonical(value & 0xffff))),
        .high = try ctx.constant(QM31.fromBase(M31.fromCanonical(value >> 16))),
    };
}

/// A carry uses 16 low bits and seven high bits, then is proved at most
/// 4,838,400. The latter bound keeps every byte recurrence below M31.
fn guessCarry(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Carry {
    const low = try ctx.guessU16(hint(V, value & 0xffff));
    const high = try guessBits(V, ctx, 7, value >> 16);
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(65536)));
    const word = try ctx.add(low, try ctx.mul(high, base));
    const below_limit = try lessThanLimbs(V, ctx, .{ .low = low, .high = high }, try constantLimbs(V, ctx, max_timespan + 1));
    try ctx.eq(below_limit, ctx.one());
    return .{ .limbs = .{ .low = low, .high = high }, .word = word };
}

fn select(comptime V: type, ctx: *circuit.builder.Context(V), choose_right: Var, left: Var, right: Var) !Var {
    return ctx.add(left, try ctx.mul(choose_right, try ctx.sub(right, left)));
}

/// Core uses the previous block's time minus the first block's time, clamped
/// to [two weeks/4, two weeks*4]. The first block is mainnet genesis here.
/// `last_time` is an unsigned header `nTime`; subtraction itself is signed.
fn constrainedTimespan(comptime V: type, ctx: *circuit.builder.Context(V), last_time: U32) !Var {
    const last = try splitU32(V, ctx, last_time);
    const before_min = try lessThanLimbs(V, ctx, last, try constantLimbs(V, ctx, genesis_time + min_timespan));
    const after_max = try lessThanLimbs(V, ctx, try constantLimbs(V, ctx, genesis_time + max_timespan), last);
    const middle = try ctx.mul(try ctx.sub(ctx.one(), before_min), try ctx.sub(ctx.one(), after_max));
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(65536)));
    const last_base = try ctx.add(last.low, try ctx.mul(last.high, base));
    const elapsed = try ctx.sub(last_base, try ctx.constant(QM31.fromBase(M31.fromCanonical(genesis_time))));
    const minimum = try ctx.constant(QM31.fromBase(M31.fromCanonical(min_timespan)));
    const maximum = try ctx.constant(QM31.fromBase(M31.fromCanonical(max_timespan)));
    const expected = try ctx.add(try ctx.add(try ctx.mul(before_min, minimum), try ctx.mul(after_max, maximum)), try ctx.mul(middle, elapsed));
    const time_value: u32 = if (comptime V == QM31) circuit.builder.ivalue.unpackU32(QM31, ctx.get(last_time.get())) else 0;
    const difference: i64 = @as(i64, time_value) - genesis_time;
    const clamped: u32 = @intCast(std.math.clamp(difference, min_timespan, max_timespan));
    const timespan = try ctx.guessM31(hint(V, clamped));
    try ctx.eq(timespan, expected);
    return timespan;
}

pub fn hostFirstRetargetBits(last_time: u32) u32 {
    const difference: i64 = @as(i64, last_time) - genesis_time;
    const span: u32 = @intCast(std.math.clamp(difference, min_timespan, max_timespan));
    const product: u256 = genesis_target * @as(u256, span);
    const quotient = product / target_timespan;
    return compactFromTarget(@min(quotient, relation.mainnet_pow_limit));
}

fn compactFromTarget(target: u256) u32 {
    std.debug.assert(target != 0);
    const bits: u32 = 256 - @as(u32, @intCast(@clz(target)));
    var size: u32 = (bits + 7) / 8;
    var mantissa: u32 = if (size <= 3)
        @intCast(target << @as(u8, @intCast(8 * (3 - size))))
    else
        @intCast(target >> @as(u8, @intCast(8 * (size - 3))) & 0xffffff);
    if (mantissa & 0x800000 != 0) {
        mantissa >>= 8;
        size += 1;
    }
    return (size << 24) | mantissa;
}

/// Constrain the compact nBits of block height 2016 from the authenticated
/// block-2015 timestamp. The fixed old nBits is genesis `0x1d00ffff`.
/// Product and division use radix-256 carry equations whose maxima are below
/// M31, with range-checked bytes/carries and remainder < 1,209,600.
pub fn constrainFirstMainnetRetarget(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    authenticated_last_time: U32,
    claimed_bits: [2]Var,
) ![2]Var {
    const expected = try expectedFirstMainnetRetarget(V, ctx, authenticated_last_time);
    for (claimed_bits, expected) |claimed, want| try ctx.eq(claimed, want);
    return expected;
}

/// Return the exact compact bits without binding a caller's header. A fold
/// can gate the header equality by a constrained height selector while
/// retaining this arithmetic in every step's value-free circuit topology.
pub fn expectedFirstMainnetRetarget(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    authenticated_last_time: U32,
) ![2]Var {
    const span = try constrainedTimespan(V, ctx, authenticated_last_time);
    const span_value = valueOf(V, ctx, span);
    const product_value: u256 = genesis_target * @as(u256, span_value);
    const quotient_value: u256 = product_value / target_timespan;
    const remainder_value: u32 = @intCast(product_value % target_timespan);
    const radix = try ctx.constant(QM31.fromBase(M31.fromCanonical(256)));
    const denominator = try ctx.constant(QM31.fromBase(M31.fromCanonical(target_timespan)));

    var product_bytes: [32]Var = undefined;
    var quotient_bytes: [32]Var = undefined;
    for (0..32) |i| {
        const shift: u8 = @intCast(8 * i);
        product_bytes[i] = try guessByte(V, ctx, @intCast((product_value >> shift) & 0xff));
        quotient_bytes[i] = try guessByte(V, ctx, @intCast((quotient_value >> shift) & 0xff));
    }

    var product_carry = ctx.zero();
    var product_carry_value: u32 = 0;
    for (product_bytes, 0..) |digit, i| {
        const old_byte: u32 = if (i == 26 or i == 27) 255 else 0;
        const digit_value: u32 = @intCast((product_value >> @as(u8, @intCast(8 * i))) & 0xff);
        const numerator: u64 = @as(u64, old_byte) * span_value + product_carry_value;
        std.debug.assert(numerator >= digit_value and (numerator - digit_value) % 256 == 0);
        const next_value: u32 = @intCast((numerator - digit_value) / 256);
        const next = try guessCarry(V, ctx, next_value);
        const old = try ctx.constant(QM31.fromBase(M31.fromCanonical(old_byte)));
        try ctx.eq(try ctx.add(try ctx.mul(old, span), product_carry), try ctx.add(digit, try ctx.mul(radix, next.word)));
        product_carry = next.word;
        product_carry_value = next_value;
    }
    try ctx.eq(product_carry, ctx.zero());

    const remainder = try guessCarry(V, ctx, remainder_value);
    try ctx.eq(try lessThanLimbs(V, ctx, remainder.limbs, try constantLimbs(V, ctx, target_timespan)), ctx.one());
    var division_carry = remainder.word;
    var division_carry_value: u32 = remainder_value;
    for (quotient_bytes, product_bytes, 0..) |quotient_byte, product_byte, i| {
        const quotient_digit: u32 = @intCast((quotient_value >> @as(u8, @intCast(8 * i))) & 0xff);
        const product_digit: u32 = @intCast((product_value >> @as(u8, @intCast(8 * i))) & 0xff);
        const numerator: u64 = @as(u64, quotient_digit) * target_timespan + division_carry_value;
        std.debug.assert(numerator >= product_digit and (numerator - product_digit) % 256 == 0);
        const next_value: u32 = @intCast((numerator - product_digit) / 256);
        const next = try guessCarry(V, ctx, next_value);
        try ctx.eq(try ctx.add(try ctx.mul(quotient_byte, denominator), division_carry), try ctx.add(product_byte, try ctx.mul(radix, next.word)));
        division_carry = next.word;
        division_carry_value = next_value;
    }
    try ctx.eq(division_carry, ctx.zero());

    // powLimit is 2^224-1. Any nonzero byte above index 27 means the raw
    // quotient exceeds it; choose the exact cap before GetCompact.
    var upper_sum = ctx.zero();
    for (quotient_bytes[28..32]) |byte| upper_sum = try ctx.add(upper_sum, byte);
    const over_value: u32 = @intFromBool(quotient_value > relation.mainnet_pow_limit);
    const over = try guessBit(V, ctx, over_value);
    const not_over = try ctx.sub(ctx.one(), over);
    try ctx.eq(try ctx.mul(upper_sum, not_over), ctx.zero());
    _ = try ctx.inv(try ctx.add(upper_sum, not_over));
    var capped: [32]Var = undefined;
    for (quotient_bytes, &capped, 0..) |byte, *out, i| {
        const cap = try ctx.constant(QM31.fromBase(M31.fromCanonical(if (i < 28) 255 else 0)));
        out.* = try select(V, ctx, over, byte, cap);
    }
    const capped_value = @min(quotient_value, relation.mainnet_pow_limit);
    const top_byte: u32 = @intCast((capped_value >> 216) & 0xff);
    const high_bit = try guessBit(V, ctx, top_byte >> 7);
    const low_seven = try guessBits(V, ctx, 7, top_byte & 0x7f);
    const one_twenty_eight = try ctx.constant(QM31.fromBase(M31.fromCanonical(128)));
    try ctx.eq(capped[27], try ctx.add(low_seven, try ctx.mul(high_bit, one_twenty_eight)));
    // The clamped first-epoch target has byte 27 in [0x3f, 0xff], so Core's
    // GetCompact uses exponent 28, or 29 after the sign-bit shift.
    _ = try ctx.inv(capped[27]);
    const first = try select(V, ctx, high_bit, capped[25], capped[26]);
    const second = try select(V, ctx, high_bit, capped[26], capped[27]);
    const third = try select(V, ctx, high_bit, capped[27], ctx.zero());
    const exponent = try ctx.add(try ctx.constant(QM31.fromBase(M31.fromCanonical(28))), high_bit);
    const expected: [2]Var = .{
        try ctx.add(first, try ctx.mul(radix, second)),
        try ctx.add(third, try ctx.mul(radix, exponent)),
    };
    return expected;
}

test "first mainnet retarget host calculation agrees with pinned boundary vectors" {
    for ([_]struct { last: u32, bits: u32 }{
        .{ .last = 0, .bits = 0x1c3fffc0 },
        .{ .last = genesis_time + min_timespan - 1, .bits = 0x1c3fffc0 },
        .{ .last = genesis_time + min_timespan, .bits = 0x1c3fffc0 },
        .{ .last = genesis_time + min_timespan + 1, .bits = 0x1c3fffcd },
        .{ .last = genesis_time + 604809, .bits = 0x1c7ffffc },
        .{ .last = genesis_time + 604810, .bits = 0x1d008000 },
        .{ .last = genesis_time + target_timespan - 1, .bits = 0x1d00fffe },
        .{ .last = genesis_time + target_timespan, .bits = 0x1d00ffff },
        .{ .last = 0xffffffff, .bits = 0x1d00ffff },
    }) |case| try std.testing.expectEqual(case.bits, hostFirstRetargetBits(case.last));
}

test "first mainnet retarget circuit accepts exact compact bits and rejects adjacent claims" {
    for ([_]u32{ 0, genesis_time + min_timespan, genesis_time + min_timespan + 1, genesis_time + 604809, genesis_time + 604810, genesis_time + target_timespan - 1, genesis_time + target_timespan, genesis_time + max_timespan, 0xffffffff }) |last| {
        const expected_bits = hostFirstRetargetBits(last);
        for ([_]struct { bits: u32, valid: bool }{
            .{ .bits = expected_bits, .valid = true },
            .{ .bits = expected_bits ^ 1, .valid = false },
            .{ .bits = expected_bits ^ 0x01000000, .valid = false },
        }) |case| {
            var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 2);
            defer ctx.deinit();
            const last_wire = try circuit.builder.wrappers.guessU32(QM31, &ctx, circuit.builder.wrappers.u32Value(QM31, last));
            const claimed = [2]Var{
                try ctx.guessU16(hint(QM31, case.bits & 0xffff)),
                try ctx.guessU16(hint(QM31, case.bits >> 16)),
            };
            const want = try constrainFirstMainnetRetarget(QM31, &ctx, last_wire, claimed);
            try ctx.setOutputs(&want);
            try ctx.finalize(false);
            try std.testing.expectEqual(case.valid, try ctx.isCircuitValid());
        }
    }
}

test "first mainnet retarget value and witness-free circuits have one topology" {
    const last = genesis_time + 604810;
    const bits = hostFirstRetargetBits(last);
    var values = try circuit.builder.Context(QM31).init(std.testing.allocator, 2);
    defer values.deinit();
    const last_value = try circuit.builder.wrappers.guessU32(QM31, &values, circuit.builder.wrappers.u32Value(QM31, last));
    const claimed_value = [2]Var{
        try values.guessU16(hint(QM31, bits & 0xffff)),
        try values.guessU16(hint(QM31, bits >> 16)),
    };
    const result_value = try constrainFirstMainnetRetarget(QM31, &values, last_value, claimed_value);
    try values.setOutputs(&result_value);
    try values.finalize(false);
    try std.testing.expect(try values.isCircuitValid());

    const NoValue = circuit.builder.NoValue;
    var topology = try circuit.builder.Context(NoValue).init(std.testing.allocator, 2);
    defer topology.deinit();
    const empty_last = try circuit.builder.wrappers.guessU32(NoValue, &topology, circuit.builder.wrappers.u32Value(NoValue, 0));
    const empty_claimed = [2]Var{ try topology.guessU16(.{}), try topology.guessU16(.{}) };
    const empty_result = try constrainFirstMainnetRetarget(NoValue, &topology, empty_last, empty_claimed);
    try topology.setOutputs(&empty_result);
    try topology.finalize(false);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expectEqualDeep(values.circuit.add.items, topology.circuit.add.items);
    try std.testing.expectEqualDeep(values.circuit.mul.items, topology.circuit.mul.items);
    try std.testing.expectEqualDeep(values.circuit.eq.items, topology.circuit.eq.items);
    try std.testing.expectEqualDeep(values.circuit.m31_to_u32.items, topology.circuit.m31_to_u32.items);
    try std.testing.expectEqualDeep(values.circuit.output.items, topology.circuit.output.items);
}
