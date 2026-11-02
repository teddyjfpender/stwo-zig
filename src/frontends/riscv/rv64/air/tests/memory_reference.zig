//! Retained pre-factoring memory polynomial, test and benchmark oracle only.
const E = @import("../evaluation.zig");
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
    for (loads) |opcode| {
        const width = @import("../../decode.zig").effects(opcode).memory_width;
        const signed = opcode == .LB or opcode == .LH or opcode == .LW;
        for (0..8) |o| {
            if (o % width != 0 or o + width > 8) out.emit(v.op(opcode).mul(v.m[L.offset_start + o]));
        }
        for (0..8) |i| {
            var expected = Q.zero();
            for (0..8) |o| {
                if (o + width > 8) continue;
                const value = if (i < width) v.byte(.memory_before, o + i) else if (signed) v.bit(.memory_before, (o + width) * 8 - 1).mul(E.q(255)) else Q.zero();
                expected = expected.add(v.m[L.offset_start + o].mul(value));
            }
            out.emit(v.op(opcode).mul(v.byte(.result, i).sub(expected)));
        }
    }
    for (stores) |opcode| {
        const width = @import("../../decode.zig").effects(opcode).memory_width;
        for (0..8) |o| if (o % width != 0 or o + width > 8) out.emit(v.op(opcode).mul(v.m[L.offset_start + o]));
        for (0..8) |i| {
            var expected = Q.zero();
            for (0..8) |o| {
                if (o + width > 8) continue;
                const value = if (i >= o and i - o < width) v.byte(.b, i - o) else v.byte(.memory_before, i);
                expected = expected.add(v.m[L.offset_start + o].mul(value));
            }
            out.emit(v.op(opcode).mul(v.byte(.memory_after, i).sub(expected)));
        }
    }
}
