const E = @import("evaluation.zig");
const Q = E.Q;
const L = E.L;
const O = E.O;
pub fn evaluate(v: E.View, out: *E.Sink) void {
    const loads = [_]O{ .LB, .LBU, .LH, .LHU, .LW, .LWU, .LD };
    const stores = [_]O{ .SB, .SH, .SW, .SD };
    const load = v.sum(&loads);
    const store = v.sum(&stores);
    const memory = load.add(store);
    var offsets = Q.zero();
    var offset_value = Q.zero();
    for (0..8) |o| {
        const selector = v.m[L.offset_start + o];
        E.boolean(out, selector);
        offsets = offsets.add(selector);
        offset_value = offset_value.add(selector.mul(E.q(@intCast(o))));
    }
    out.emit(offsets.sub(memory));
    out.emit(memory.mul(offset_value.sub(v.bit(.address, 0)).sub(v.bit(.address, 1).mul(E.q(2))).sub(v.bit(.address, 2).mul(E.q(4)))));
    out.emit(load.mul(v.m[L.readable].sub(Q.one())));
    out.emit(store.mul(v.m[L.writable].sub(Q.one())));
    out.emit(Q.one().sub(memory).mul(v.m[L.readable]));
    out.emit(Q.one().sub(memory).mul(v.m[L.writable]));
    for (0..8) |i| out.emit(load.mul(v.byte(.memory_after, i).sub(v.byte(.memory_before, i))));
    const expected = Expected.prepare(v);
    for (load_specs) |spec| {
        const opcode = spec.opcode;
        const width = spec.width;
        for (0..8) |o| {
            if (o % width != 0 or o + width > 8) out.emit(v.op(opcode).mul(v.m[L.offset_start + o]));
        }
        for (0..8) |i| {
            const value = if (i < width) expected.low[spec.index][i] else if (spec.signed) expected.sign[spec.index] else Q.zero();
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
const LoadSpec = struct { opcode: O, width: usize, index: usize, signed: bool };
const load_specs = blk: {
    const opcodes = [_]O{ .LB, .LBU, .LH, .LHU, .LW, .LWU, .LD };
    var specs: [opcodes.len]LoadSpec = undefined;
    for (opcodes, &specs) |opcode, *spec| {
        const width = @import("../decode.zig").effects(opcode).memory_width;
        spec.* = .{ .opcode = opcode, .width = width, .index = @ctz(width), .signed = opcode == .LB or opcode == .LH or opcode == .LW };
    }
    break :blk specs;
};
const store_specs = blk: {
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
const Expected = struct {
    low: [4][8]Q = @splat(@splat(Q.zero())),
    sign: [4]Q = @splat(Q.zero()),
    selector_sum: [4]Q = @splat(Q.zero()),
    fn prepare(v: E.View) Expected {
        var result = Expected{};
        for (widths, 0..) |width, index| {
            for (0..9 - width) |offset| {
                const selector = v.m[L.offset_start + offset];
                result.selector_sum[index] = result.selector_sum[index].add(selector);
                for (0..width) |byte| result.low[index][byte] = result.low[index][byte].add(selector.mul(v.byte(.memory_before, offset + byte)));
                if (width < 8) result.sign[index] = result.sign[index].add(selector.mul(v.bit(.memory_before, (offset + width) * 8 - 1)));
            }
            result.sign[index] = result.sign[index].mul(E.q(255));
        }
        return result;
    }
    fn store(self: *const Expected, v: E.View, index: usize, byte: usize) Q {
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
