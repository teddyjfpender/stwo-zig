//! Exact integer bridge from typed M31 access fields to injective block-v2
//! address/global-clock byte tuples. Its residuals are designed for the
//! committed execution sidecar AIR; host evaluation alone is not authority.
const std = @import("std");
const core = @import("stwo_core");
const source = @import("block_execution_access_bridge_v2.zig");
const block_event = @import("../air/block/memory_event.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const bus = @import("block_memory_relation_v2.zig");
pub const COLUMN_COUNT: usize = 48;
pub const RESIDUAL_COUNT: usize = 55;

/// Only the public segment span may choose the affine clock offset. The
/// verifier recomputes this value and mixes the span into its proof statement.
pub fn baseClockFromPublicFrame(frame: block_event.Frame) !u64 {
    if (frame.global_first_cycle == 0 or frame.cycle_count == 0) return error.InvalidBlockAccessClock;
    return switch (frame.clock_frame) {
        .leaf_local => std.math.mul(u64, frame.global_first_cycle - 1, 4),
        .global_continuous => 0,
    };
}

pub const Witness = struct {
    word_index: [4]Q,
    byte_address: [4]Q,
    local_clock: [4]Q,
    global_clock: [8]Q,
    address_carry: [5]Q,
    clock_carry: [9]Q,
    word_high_bits: [6]Q,
    clock_high_bits: [3]Q,
    register_bits: [5]Q,

    pub fn zero() Witness {
        return .{
            .word_index = @splat(Q.zero()),
            .byte_address = @splat(Q.zero()),
            .local_clock = @splat(Q.zero()),
            .global_clock = @splat(Q.zero()),
            .address_carry = @splat(Q.zero()),
            .clock_carry = @splat(Q.zero()),
            .word_high_bits = @splat(Q.zero()),
            .clock_high_bits = @splat(Q.zero()),
            .register_bits = @splat(Q.zero()),
        };
    }

    /// Witness-only construction. The quotient must call `constraints` on
    /// these *committed* columns and the PCS-opened typed access pair.
    pub fn fromPair(pair: source.Pair(Q), base_clock: u64) !Witness {
        const access = try source.decodePair(pair);
        if (!access.active) return zero();
        const address: u32 = if (access.space == 1 and pair.address_unit == .word_index)
            try std.math.mul(u32, access.source_address, 4)
        else
            access.source_address;
        const global_clock = try std.math.add(u64, base_clock, access.local_clock);
        var result = zero();
        putBytes(&result.word_index, access.source_address);
        putBytes(&result.byte_address, address);
        putBytes(&result.local_clock, access.local_clock);
        putBytes(&result.global_clock, global_clock);
        for (0..6) |i| result.word_high_bits[i] = q((access.source_address >> @intCast(24 + i)) & 1);
        for (0..3) |i| result.clock_high_bits[i] = q((access.local_clock >> @intCast(24 + i)) & 1);
        for (0..5) |i| result.register_bits[i] = q((access.source_address >> @intCast(i)) & 1);
        const multiplier: u32 = if (access.space == 1 and pair.address_unit == .word_index) 4 else 1;
        for (0..4) |i| {
            const total = multiplier * byte(access.source_address, i) + result.address_carry[i].toM31Array()[0].toU32();
            result.address_carry[i + 1] = q(total >> 8);
        }
        for (0..8) |i| {
            const local = if (i < 4) byte(access.local_clock, i) else 0;
            const total = byte(base_clock, i) + local + result.clock_carry[i].toM31Array()[0].toU32();
            result.clock_carry[i + 1] = q(total >> 8);
        }
        return result;
    }

    pub fn columns(self: Witness) [COLUMN_COUNT]Q {
        var result: [COLUMN_COUNT]Q = undefined;
        var cursor: usize = 0;
        inline for (.{ self.word_index, self.byte_address, self.local_clock, self.global_clock, self.address_carry, self.clock_carry, self.word_high_bits, self.clock_high_bits, self.register_bits }) |part| {
            @memcpy(result[cursor..][0..part.len], &part);
            cursor += part.len;
        }
        std.debug.assert(cursor == COLUMN_COUNT);
        return result;
    }

    pub fn fromColumns(values: [COLUMN_COUNT]Q) Witness {
        var result = zero();
        var cursor: usize = 0;
        inline for (.{ &result.word_index, &result.byte_address, &result.local_clock, &result.global_clock, &result.address_carry, &result.clock_carry, &result.word_high_bits, &result.clock_high_bits, &result.register_bits }) |part| {
            @memcpy(part, values[cursor..][0..part.len]);
            cursor += part.len;
        }
        std.debug.assert(cursor == COLUMN_COUNT);
        return result;
    }
};

pub fn transitionAtPoint(pair: source.Pair(Q), witness: Witness) [bus.TRANSITION_ARITY]Q {
    var tuple: [bus.TRANSITION_ARITY]Q = undefined;
    tuple[0] = pair.space;
    @memcpy(tuple[1..5], &witness.byte_address);
    @memcpy(tuple[5..13], &witness.global_clock);
    @memcpy(tuple[13..17], &pair.before);
    @memcpy(tuple[17..21], &pair.after);
    return tuple;
}

pub const Residuals = struct {
    values: [64]Q = undefined,
    len: usize = 0,
    fn add(self: *Residuals, value: Q) void {
        std.debug.assert(self.len < self.values.len);
        self.values[self.len] = value;
        self.len += 1;
    }
    pub fn allZero(self: Residuals) bool {
        for (self.values[0..self.len]) |value| if (!value.isZero()) return false;
        return true;
    }
};

/// Polynomial identities over the same sampled typed access fields and
/// sidecar byte columns. Every byte column also requires an active-gated
/// universal range_check_8_8 request in the shared provider proof.
pub fn constraints(pair: source.Pair(Q), witness: Witness, base_clock: u64) Residuals {
    const shared = @import("block_execution_integer_algebra_v1.zig");
    const algebra = shared.Algebra(Q);
    const evaluated = algebra.constraints(pair, algebra.Witness.fromColumns(witness.columns()), shared.clockBytes(Q, base_clock));
    return .{ .values = evaluated.values, .len = evaluated.len };
}

fn putBytes(out: anytype, value: u64) void {
    for (out, 0..) |*dst, index| dst.* = q(byte(value, index));
}

fn byte(value: u64, index: usize) u32 {
    return @as(u8, @truncate(value >> @intCast(index * 8)));
}

fn q(value: u32) Q {
    return Q.fromBase(M.fromCanonical(value));
}

test "block-v2 integer bridge binds typed word index and full 64-bit clock" {
    var pair = source.Pair(Q){
        .active = Q.one(),
        .space = Q.one(),
        .source_address = q((1 << 30) - 1),
        .local_clock = q((1 << 27) - 1),
        .before = @splat(Q.zero()),
        .after = @splat(Q.zero()),
        .pair_residuals = @splat(Q.zero()),
        .access_ordinal = 2,
    };
    const base: u64 = (1 << 40) + 300;
    var witness = try Witness.fromPair(pair, base);
    try std.testing.expect(constraints(pair, witness, base).allZero());
    witness.byte_address[0] = witness.byte_address[0].add(Q.one());
    try std.testing.expect(!constraints(pair, witness, base).allZero());
    witness = try Witness.fromPair(pair, base);
    witness.global_clock[5] = witness.global_clock[5].add(Q.one());
    try std.testing.expect(!constraints(pair, witness, base).allZero());
    pair.space = Q.zero();
    pair.source_address = q(31);
    witness = try Witness.fromPair(pair, base);
    try std.testing.expect(constraints(pair, witness, base).allZero());
    const public_base = try baseClockFromPublicFrame(.{
        .clock_frame = .leaf_local,
        .global_first_cycle = (1 << 30) + 1,
        .cycle_count = 2,
    });
    try std.testing.expectEqual(@as(u64, 1) << 32, public_base);
    witness = try Witness.fromPair(pair, public_base);
    try std.testing.expect(constraints(pair, witness, public_base).allZero());
    try std.testing.expectEqual(RESIDUAL_COUNT, constraints(pair, witness, public_base).len);
}

test "typed load-store byte addresses are not multiplied and reject high or unaligned values" {
    var pair = source.Pair(Q){
        .active = Q.one(),
        .space = Q.one(),
        .source_address = q(0x0010_0000),
        .address_unit = .byte_address,
        .local_clock = q(7),
        .before = @splat(Q.zero()),
        .after = @splat(Q.zero()),
        .pair_residuals = @splat(Q.zero()),
        .access_ordinal = 3,
    };
    var witness = try Witness.fromPair(pair, 0);
    try std.testing.expect(constraints(pair, witness, 0).allZero());
    try std.testing.expectEqual(@as(u32, 0x10), witness.byte_address[2].toM31Array()[0].toU32());
    witness.byte_address[2] = Q.zero();
    try std.testing.expect(!constraints(pair, witness, 0).allZero());
    pair.source_address = q(0x0010_0002);
    try std.testing.expectError(error.InvalidTypedAccessValue, Witness.fromPair(pair, 0));
    pair.source_address = q(1 << 30);
    try std.testing.expectError(error.InvalidTypedAccessValue, Witness.fromPair(pair, 0));
    pair.address_unit = .word_index;
    try std.testing.expectError(error.InvalidTypedAccessValue, Witness.fromPair(pair, 0));
}
