const E = @import("evaluation.zig");
const Q = E.Q;
const L = E.L;
const O = E.O;
pub fn evaluate(v: E.View, out: *E.Sink) void {
    return evaluateGeneric(Q, v, out);
}
pub fn evaluateGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F)) void {
    const loads = [_]O{ .LB, .LBU, .LH, .LHU, .LW, .LWU, .LD };
    const stores = [_]O{ .SB, .SH, .SW, .SD };
    const load = v.sum(&loads);
    const store = v.sum(&stores);
    const memory = load.add(store);
    var offsets = F.zero();
    var offset_value = F.zero();
    for (0..8) |o| {
        const selector = v.m[L.offset_start + o];
        E.booleanFor(F, out, selector);
        offsets = offsets.add(selector);
        offset_value = offset_value.add(selector.mul(E.qFor(F, @intCast(o))));
    }
    out.emit(offsets.sub(memory));
    out.emit(memory.mul(offset_value.sub(v.bit(.address, 0)).sub(v.bit(.address, 1).mul(E.qFor(F, 2))).sub(v.bit(.address, 2).mul(E.qFor(F, 4)))));
    out.emit(load.mul(v.m[L.readable].sub(F.one())));
    out.emit(store.mul(v.m[L.writable].sub(F.one())));
    out.emit(F.one().sub(memory).mul(v.m[L.readable]));
    out.emit(F.one().sub(memory).mul(v.m[L.writable]));
    for (0..8) |i| out.emit(load.mul(v.byte(.memory_after, i).sub(v.byte(.memory_before, i))));
    const expected = ExpectedFor(F).prepare(v);
    for (load_specs) |spec| {
        const opcode = spec.opcode;
        const width = spec.width;
        for (0..8) |o| {
            if (o % width != 0 or o + width > 8) out.emit(v.op(opcode).mul(v.m[L.offset_start + o]));
        }
        for (0..8) |i| {
            const value = if (i < width) expected.low[spec.index][i] else if (spec.signed) expected.sign[spec.index] else F.zero();
            out.emit(v.op(opcode).mul(v.byte(.result, i).sub(value)));
        }
    }
    for (store_specs) |spec| {
        const opcode = spec.opcode;
        const width = spec.width;
        for (0..8) |o| if (o % width != 0 or o + width > 8) out.emit(v.op(opcode).mul(v.m[L.offset_start + o]));
        for (0..8) |i| {
            const value = expected.store(v, spec.index, i);
            out.emit(v.op(opcode).mul(v.byte(.memory_after, i).sub(value)));
        }
    }
}

const widths = [_]usize{ 1, 2, 4, 8 };
pub const LoadSpec = struct { opcode: O, width: usize, index: usize, signed: bool };
pub const load_specs = blk: {
    const opcodes = [_]O{ .LB, .LBU, .LH, .LHU, .LW, .LWU, .LD };
    var specs: [opcodes.len]LoadSpec = undefined;
    for (opcodes, &specs) |opcode, *spec| {
        const width = @import("../decode.zig").effects(opcode).memory_width;
        spec.* = .{ .opcode = opcode, .width = width, .index = @ctz(width), .signed = opcode == .LB or opcode == .LH or opcode == .LW };
    }
    break :blk specs;
};
pub const store_specs = blk: {
    const opcodes = [_]O{ .SB, .SH, .SW, .SD };
    var specs: [opcodes.len]LoadSpec = undefined;
    for (opcodes, &specs) |opcode, *spec| {
        const width = @import("../decode.zig").effects(opcode).memory_width;
        spec.* = .{ .opcode = opcode, .width = width, .index = @ctz(width), .signed = false };
    }
    break :blk specs;
};

/// Common subexpressions over all four access widths. Alignment selectors are
/// deliberately not assumed one-hot or aligned: these are polynomial identities
/// for arbitrary QM31 values, including verifier OODS samples.
fn ExpectedFor(comptime F: type) type {
    return struct {
        const Self = @This();
        low: [4][8]F = @splat(@splat(F.zero())),
        sign: [4]F = @splat(F.zero()),
        selector_sum: [4]F = @splat(F.zero()),
        fn prepare(v: E.ViewFor(F)) Self {
            var result = Self{};
            for (widths, 0..) |width, index| {
                for (0..9 - width) |offset| {
                    const selector = v.m[L.offset_start + offset];
                    result.selector_sum[index] = result.selector_sum[index].add(selector);
                    for (0..width) |byte| result.low[index][byte] = result.low[index][byte].add(selector.mul(v.byte(.memory_before, offset + byte)));
                    if (width < 8) result.sign[index] = result.sign[index].add(selector.mul(v.bit(.memory_before, (offset + width) * 8 - 1)));
                }
                result.sign[index] = result.sign[index].mul(E.qFor(F, 255));
            }
            return result;
        }
        fn store(self: *const Self, v: E.ViewFor(F), index: usize, byte: usize) F {
            const width = widths[index];
            if (width == 8) return v.m[L.offset_start].mul(v.byte(.b, byte));
            const before = v.byte(.memory_before, byte);
            var result = before.mul(self.selector_sum[index]);
            const begin = if (byte < width) 0 else byte - width + 1;
            const end = @min(byte, 8 - width) + 1;
            for (begin..end) |offset| result = result.add(v.m[L.offset_start + offset].mul(v.byte(.b, byte - offset).sub(before)));
            return result;
        }
    };
}
