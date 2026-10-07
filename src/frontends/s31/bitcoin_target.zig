//! Bitcoin mainnet compact target decoder for an 80-byte serialized header.
//! The compact field occupies bytes 72..75. Mainnet's actual powLimit is
//! 0x00000000ffffffff... (2^224-1); the genesis compact target is the
//! slightly smaller 0x00000000ffff0000....
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const std = @import("std");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;

fn hint(comptime V: type, value: u32) V {
    return circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(value)));
}

fn valueOf(comptime V: type, ctx: *circuit.builder.Context(V), wire: Var) u32 {
    return if (comptime V == QM31) ctx.get(wire).toM31Array()[0].v else 0;
}

fn bit(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Var {
    const wire = try ctx.newVar(hint(V, value));
    try ctx.mulInto(wire, wire, wire);
    return wire;
}

fn combine(comptime V: type, ctx: *circuit.builder.Context(V), bits: []const Var) !Var {
    const two = try ctx.constant(QM31.fromBase(M31.fromCanonical(2)));
    var result = bits[bits.len - 1];
    var at = bits.len - 1;
    while (at > 0) {
        at -= 1;
        result = try ctx.add(try ctx.mul(result, two), bits[at]);
    }
    return result;
}

/// Output is a 256-bit target as sixteen little-endian u16 limbs.
pub fn mainnetTarget(comptime V: type, ctx: *circuit.builder.Context(V), header: []const Var) ![16]Var {
    if (header.len != 40) return error.InvalidHeaderLength;
    var bytes: [4]Var = undefined;
    var host_bytes: [4]u32 = undefined;
    var sign: Var = undefined;
    for (0..2) |limb_index| {
        const input = header[36 + limb_index];
        const host_value = valueOf(V, ctx, input);
        var bits: [16]Var = undefined;
        for (&bits, 0..) |*wire, i| wire.* = try bit(V, ctx, (host_value >> @intCast(i)) & 1);
        try ctx.eq(try combine(V, ctx, &bits), input);
        for (0..2) |offset| {
            bytes[2 * limb_index + offset] = try combine(V, ctx, bits[offset * 8 ..][0..8]);
            host_bytes[2 * limb_index + offset] = (host_value >> @intCast(offset * 8)) & 0xff;
        }
        if (limb_index == 1) sign = bits[7];
    }
    try ctx.eq(sign, ctx.zero());

    var selectors: [32]Var = undefined;
    var selector_sum = ctx.zero();
    var exponent_sum = ctx.zero();
    for (&selectors, 1..) |*selector, exponent| {
        selector.* = try bit(V, ctx, @intFromBool(host_bytes[3] == exponent));
        selector_sum = try ctx.add(selector_sum, selector.*);
        const coefficient = try ctx.constant(QM31.fromBase(M31.fromCanonical(@intCast(exponent))));
        exponent_sum = try ctx.add(exponent_sum, try ctx.mul(selector.*, coefficient));
    }
    try ctx.eq(selector_sum, ctx.one());
    try ctx.eq(exponent_sum, bytes[3]);

    var target_bytes = [_]Var{ctx.zero()} ** 32;
    for (selectors, 1..) |selector, exponent| {
        for (0..3) |mantissa_index| {
            const position: i32 = @as(i32, @intCast(exponent)) - 3 + @as(i32, @intCast(mantissa_index));
            if (position < 0) continue;
            const at: usize = @intCast(position);
            target_bytes[at] = try ctx.add(target_bytes[at], try ctx.mul(selector, bytes[mantissa_index]));
        }
    }
    // Bitcoin Core's mainnet powLimit is 2^224-1: exactly the targets with
    // bytes 28..31 zero. This is larger than the genesis compact target.
    for (target_bytes[28..32]) |wire| try ctx.eq(wire, ctx.zero());
    var byte_sum = ctx.zero();
    for (target_bytes) |wire| byte_sum = try ctx.add(byte_sum, wire);
    _ = try ctx.inv(byte_sum); // A nonzero decoded target is mandatory.

    const scale = try ctx.constant(QM31.fromBase(M31.fromCanonical(256)));
    var target: [16]Var = undefined;
    for (&target, 0..) |*limb, i|
        limb.* = try ctx.add(target_bytes[2 * i], try ctx.mul(target_bytes[2 * i + 1], scale));
    return target;
}

test "compact target circuit matches independent integer decoding" {
    const relation = @import("relation.zig");
    for ([_]u32{ 0x0101_0000, 0x0200_0100, 0x0300_0001, 0x1d00_ffff, 0x1e00_0001 }) |compact| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        var header: [40]Var = undefined;
        for (&header, 0..) |*wire, index| {
            const limb: u32 = switch (index) {
                36 => compact & 0xffff,
                37 => compact >> 16,
                else => 0,
            };
            wire.* = (try circuit.builder.wrappers.guessU16(QM31, &ctx, .newUnsafe(hint(QM31, limb)))).get();
        }
        const output = try mainnetTarget(QM31, &ctx, &header);
        const target = try relation.mainnetTarget(compact);
        for (output, 0..) |wire, index| {
            const actual = ctx.get(wire).toM31Array()[0].v;
            const expected: u32 = @intCast((target >> @as(u8, @intCast(16 * index))) & 0xffff);
            try std.testing.expectEqual(expected, actual);
        }
        try ctx.setOutputs(&.{output[0]});
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
    for ([_]u32{ 0, 0x1d80_ffff, 0x2100_ffff, 0x0100_0001 }) |compact|
        try std.testing.expectError(error.InvalidCompactTarget, relation.mainnetTarget(compact));
    for ([_]u32{ 0x1d80_ffff, 0x1d01_ffff }) |compact| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 1);
        defer ctx.deinit();
        var header: [40]Var = undefined;
        for (&header, 0..) |*wire, index| {
            const limb: u32 = switch (index) {
                36 => compact & 0xffff,
                37 => compact >> 16,
                else => 0,
            };
            wire.* = (try circuit.builder.wrappers.guessU16(QM31, &ctx, .newUnsafe(hint(QM31, limb)))).get();
        }
        const output = try mainnetTarget(QM31, &ctx, &header);
        try ctx.setOutputs(&.{output[0]});
        try ctx.finalize(false);
        try std.testing.expect(!(try ctx.isCircuitValid()));
    }
}
