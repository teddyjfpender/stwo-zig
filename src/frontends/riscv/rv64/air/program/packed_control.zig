//! Injective24/24/16 ROM control words. Each limb is a SEPARATE relation lane;
//! no full-u64 reconstruction into M31 is sound. Canonicality comes from ROM.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const E = @import("../evaluation.zig");
const rom = @import("setup.zig");
const provider = @import("provider.zig");
const compact = @import("compact.zig");
pub const COUNT = 26;
pub const Tuple = [COUNT]Q;
pub const Word = [3]Q;
pub const field = struct {
    pub const valid = 0;
    pub const pc = 1;
    pub const opcode = 4;
    pub const rs1 = 5;
    pub const rs2 = 6;
    pub const rd = 7;
    pub const immediate = 8;
    pub const slots = 16;
    pub const increment = 20;
    pub const target = 23;
};
pub const Source = struct { start: usize, bytes: u8 = 1 };
pub const sources: [COUNT]Source = blk: {
    var result: [COUNT]Source = undefined;
    var i: usize = 0;
    result[i] = .{ .start = rom.field.valid };
    i += 1;
    for ([_]usize{rom.field.pc}) |start| for (0..3) |limb| {
        result[i] = .{ .start = start + 3 * limb, .bytes = if (limb == 2) 2 else 3 };
        i += 1;
    };
    for (rom.field.opcode..rom.field.increment) |start| {
        result[i] = .{ .start = start };
        i += 1;
    }
    for ([_]usize{ rom.field.increment, rom.field.target }) |start| for (0..3) |limb| {
        result[i] = .{ .start = start + 3 * limb, .bytes = if (limb == 2) 2 else 3 };
        i += 1;
    };
    if (i != COUNT) @compileError("packed control ROM width changed");
    break :blk result;
};
pub fn packBytes(bytes: [8]Q) Word {
    return packBytesFor(Q, bytes);
}
pub fn packBytesFor(comptime F: type, bytes: [8]F) [3]F {
    return .{ bytes[0].add(bytes[1].mul(E.qFor(F, 256))).add(bytes[2].mul(E.qFor(F, 65536))), bytes[3].add(bytes[4].mul(E.qFor(F, 256))).add(bytes[5].mul(E.qFor(F, 65536))), bytes[6].add(bytes[7].mul(E.qFor(F, 256))) };
}
pub fn pack(value: u64) Word {
    return packFor(Q, value);
}
pub fn packFor(comptime F: type, value: u64) [3]F {
    return .{ E.qFor(F, @intCast(value & 0xffffff)), E.qFor(F, @intCast((value >> 24) & 0xffffff)), E.qFor(F, @intCast(value >> 48)) };
}
pub fn packBase(value: u64) [3]M {
    return .{ M.fromCanonical(@intCast(value & 0xffffff)), M.fromCanonical(@intCast((value >> 24) & 0xffffff)), M.fromCanonical(@intCast(value >> 48)) };
}
pub fn pc(entry: *const Tuple) Word {
    return pcFor(Q, entry);
}
pub fn pcFor(comptime F: type, entry: *const [COUNT]F) [3]F {
    return entry[field.pc..][0..3].*;
}
pub fn increment(entry: *const Tuple) Word {
    return incrementFor(Q, entry);
}
pub fn incrementFor(comptime F: type, entry: *const [COUNT]F) [3]F {
    return entry[field.increment..][0..3].*;
}
pub fn target(entry: *const Tuple) Word {
    return targetFor(Q, entry);
}
pub fn targetFor(comptime F: type, entry: *const [COUNT]F) [3]F {
    return entry[field.target..][0..3].*;
}
pub fn fromRowBase(row: *const rom.Row) [COUNT]M {
    var result: [COUNT]M = undefined;
    for (&result, sources) |*value, source| {
        var combined = M.zero();
        var factor = M.one();
        for (0..source.bytes) |j| {
            combined = combined.add(row[source.start + j].mul(factor));
            factor = factor.mul(M.fromCanonical(256));
        }
        value.* = combined;
    }
    return result;
}
pub fn fromRow(row: *const rom.Row) Tuple {
    const base = fromRowBase(row);
    var result: Tuple = undefined;
    for (&result, base) |*value, source| value.* = Q.fromBase(source);
    return result;
}
/// Distributed coefficients let native full-byte ROM caches keep their exact
/// denominator oracle. Only26 independent secure coefficients are drawn.
pub fn draw(channel: *@import("../protocol.zig").Channel) provider.Challenges {
    channel.mixU32s(&.{ 0x52563634, 0x524f4d43, 2, COUNT });
    var result = provider.Challenges{ .offset = channel.drawSecureFelt(), .coefficients = @splat(Q.zero()) };
    for (sources) |source| {
        var coefficient = channel.drawSecureFelt();
        for (0..source.bytes) |j| {
            result.coefficients[source.start + j] = coefficient;
            coefficient = coefficient.mul(E.q(256));
        }
    }
    return result;
}
pub fn denominator(challenges: provider.Challenges, entry: *const Tuple) Q {
    return denominatorFor(Q, challenges, entry);
}
pub fn denominatorFor(comptime F: type, challenges: provider.Challenges, entry: *const [COUNT]F) E.SecureFor(F) {
    var result = E.splatFor(F, challenges.offset);
    for (entry, sources) |value, source| result = result.add(E.mulBaseFor(F, E.splatFor(F, challenges.coefficients[source.start]), value));
    return result;
}
pub fn executionDenominator(challenges: provider.Challenges, entry: *const Tuple) Q {
    return executionDenominatorFor(Q, challenges, entry);
}
pub fn executionDenominatorFor(comptime F: type, challenges: provider.Challenges, entry: *const [COUNT]F) E.SecureFor(F) {
    var result = E.splatFor(F, challenges.offset.add(challenges.coefficients[rom.field.valid]));
    for (entry[1..], sources[1..]) |value, source| result = result.add(E.mulBaseFor(F, E.splatFor(F, challenges.coefficients[source.start]), value));
    return result;
}
/// Non-control byte fields remain unchanged. PC/inc/target cannot be unpacked
/// as field polynomials and deliberately stay zero in the legacy logical view.
const zero_control_bytes: [8]Q = @splat(Q.zero());
pub fn inflateFixed(entry: *const Tuple, selectors: *const [E.L.fixed.OPCODES]Q) E.Fixed {
    return inflateFixedFor(Q, entry, selectors);
}
pub fn inflateFixedFor(comptime F: type, entry: *const [COUNT]F, selectors: *const [E.L.fixed.OPCODES]F) E.FixedFor(F) {
    const zeros: [8]F = @splat(F.zero());
    return compact.inflateDecodedFor(F, .{ .valid = entry[field.valid], .rs1 = entry[field.rs1], .rs2 = entry[field.rs2], .rd = entry[field.rd], .immediate = entry[field.immediate..][0..8], .slots = entry[field.slots..][0..4], .pc = &zeros, .increment = &zeros, .target = &zeros }, selectors);
}
pub fn evaluateSelectors(entry: *const Tuple, selectors: *const [E.L.fixed.OPCODES]Q, out: *E.Sink) void {
    return evaluateSelectorsFor(Q, entry, selectors, out);
}
pub fn evaluateSelectorsFor(comptime F: type, entry: *const [COUNT]F, selectors: *const [E.L.fixed.OPCODES]F, out: *E.SinkFor(F)) void {
    var sum = F.zero();
    var opcode = F.zero();
    for (selectors, 0..) |selector, i| {
        E.booleanFor(F, out, selector);
        sum = sum.add(selector);
        opcode = opcode.add(selector.mul(E.qFor(F, @intCast(i))));
    }
    out.emit(sum.sub(entry[field.valid]));
    out.emit(opcode.sub(entry[field.opcode]));
}
