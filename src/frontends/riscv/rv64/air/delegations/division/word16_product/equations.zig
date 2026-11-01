//! All integer normalization and policy equations. Product validity belongs to
//! the closed, typed MUL/MULHU support bus; local DIV residuals are insufficient.
const E = @import("../../../evaluation.zig");
const L = @import("layout.zig");
pub fn activeFor(comptime F: type, m: []const F) F {
    var active = F.zero();
    for (m[L.SELECTORS..L.COUNT]) |s| active = active.add(s);
    return active;
}
pub fn wordFor(comptime F: type, m: []const F) F {
    var word = F.zero();
    for (m[L.SELECTORS + 4 .. L.COUNT]) |s| word = word.add(s);
    return word;
}
pub fn remainderFor(comptime F: type, m: []const F) F {
    return m[L.SELECTORS + 2].add(m[L.SELECTORS + 3]).add(m[L.SELECTORS + 6]).add(m[L.SELECTORS + 7]);
}
pub fn tupleFor(comptime F: type, m: []const F, support: ?bool) [13]F {
    var out: [13]F = undefined;
    if (support) |high| {
        out[0] = E.qFor(F, @intFromEnum(if (high) @import("../../../../decode.zig").Opcode.MULHU else @import("../../../../decode.zig").Opcode.MUL));
        @memcpy(out[1..5], m[L.QUOTIENT..][0..4]);
        @memcpy(out[5..9], m[L.ABS_B..][0..4]);
        @memcpy(out[9..13], m[(if (high) L.PRODUCT_HIGH else L.PRODUCT_LOW)..][0..4]);
    } else {
        out[0] = F.zero();
        for (L.OPCODES, 0..) |op, i| out[0] = out[0].add(m[L.SELECTORS + i].mul(E.qFor(F, @intFromEnum(op))));
        @memcpy(out[1..13], m[L.A..][0..12]);
    }
    return out;
}
/// The two selected-top queries are quadratic, so they MUST use individual
/// strict inverses. The remaining29 range queries and3 FUNCTION queries are
/// affine and fit16 strict pairs. No packed-limb query replaces byte bounds.
pub fn rangeValuesFor(comptime F: type, m: []const F) [L.RANGE_QUERIES]F {
    var out: [L.RANGE_QUERIES]F = undefined;
    @memcpy(out[0..12], m[L.A..][0..12]);
    for ([_]usize{ L.ABS_A, L.REMAINDER, L.GAP, L.OUT }, 0..) |start, i| @memcpy(out[12 + 4 * i ..][0..4], m[start..][0..4]);
    const word = wordFor(F, m);
    for ([_]usize{ L.A, L.B }, 0..) |start, i| {
        const top = m[start + 3].add(word.mul(m[start + 1].sub(m[start + 3])));
        out[28 + i] = top.mul(E.qFor(F, 2)).sub(m[L.SIGN_A + i].mul(E.qFor(F, 65536)));
    }
    out[30] = m[L.OUT + 1].mul(E.qFor(F, 2)).sub(m[L.SIGN_OUT32].mul(E.qFor(F, 65536)));
    return out;
}
pub fn emitFor(comptime F: type, fixed: []const F, m: []const F, previous_count: F, count: F, out: *E.SinkFor(F)) void {
    const one = F.one();
    const radix = E.qFor(F, 65536);
    const active = activeFor(F, m);
    const word = wordFor(F, m);
    const rem = remainderFor(F, m);
    const signed = m[L.SELECTORS].add(m[L.SELECTORS + 2]).add(m[L.SELECTORS + 4]).add(m[L.SELECTORS + 6]);
    for (m[L.SELECTORS..L.COUNT]) |s| E.booleanFor(F, out, s);
    E.booleanFor(F, out, active);
    for (m[L.CARRY_A..L.SIGN_A]) |carry| E.booleanFor(F, out, carry);
    for (m[L.SIGN_A..L.DIVISOR_INVERSE]) |flag| E.booleanFor(F, out, flag);
    out.emit(m[L.COUNT].sub(one.sub(fixed[1]).mul(previous_count)).sub(active));
    out.emit(fixed[2].mul(m[L.COUNT].sub(count)));
    for (m[0..L.SELECTORS]) |v| out.emit(one.sub(active).mul(v));
    out.emit(m[L.NEG_A].sub(signed.mul(m[L.SIGN_A])));
    out.emit(m[L.NEG_B].sub(signed.mul(m[L.SIGN_B])));
    const nq = m[L.NEG_A].add(m[L.NEG_B]).sub(m[L.NEG_A].mul(m[L.NEG_B]).mul(E.qFor(F, 2)));
    out.emit(m[L.NEG_OUT].sub(nq.add(rem.mul(m[L.NEG_A].sub(nq)))));
    out.emit(m[L.ZERO_DIV].sub(m[L.ZERO].mul(one.sub(rem))));
    var sum_b = F.zero();
    for (m[L.ABS_B..][0..4]) |v| sum_b = sum_b.add(v);
    out.emit(sum_b.mul(m[L.DIVISOR_INVERSE]).sub(active.sub(m[L.ZERO])));
    out.emit(sum_b.mul(m[L.ZERO]));
    for (0..4) |i| {
        inline for (.{ .{ L.A, L.ABS_A, L.CARRY_A, L.NEG_A }, .{ L.B, L.ABS_B, L.CARRY_B, L.NEG_B } }) |which| {
            const effective = if (i < 2) m[which[0] + i] else one.sub(word).mul(m[which[0] + i]);
            const prior = if (i == 0) F.zero() else if (i == 2) one.sub(word).mul(m[which[2] + i - 1]) else m[which[2] + i - 1];
            out.emit(m[which[1] + i].sub(one.sub(m[which[3]].mul(E.qFor(F, 2))).mul(effective)).add(prior).sub(radix.mul(m[which[2] + i])));
            out.emit(one.sub(m[which[3]]).mul(m[which[2] + i]));
        }
        out.emit(m[L.PRODUCT_HIGH + i]);
        out.emit(m[L.ZERO].mul(m[L.QUOTIENT + i]));
        const prior_sum = if (i == 0) F.zero() else m[L.CARRY_SUM + i - 1];
        out.emit(m[L.PRODUCT_LOW + i].add(m[L.REMAINDER + i]).add(prior_sum).sub(m[L.ABS_A + i]).sub(radix.mul(m[L.CARRY_SUM + i])));
        const prior_gap = if (i == 0) one else m[L.BORROW_GAP + i - 1];
        out.emit(active.sub(m[L.ZERO]).mul(m[L.ABS_B + i].sub(m[L.REMAINDER + i]).sub(prior_gap).sub(m[L.GAP + i]).add(radix.mul(m[L.BORROW_GAP + i]))));
        out.emit(m[L.ZERO].mul(m[L.GAP + i]));
        out.emit(m[L.ZERO].mul(m[L.BORROW_GAP + i]));
        const chosen = m[L.QUOTIENT + i].add(rem.mul(m[L.REMAINDER + i].sub(m[L.QUOTIENT + i])));
        const prior_out = if (i == 0) F.zero() else if (i == 2) one.sub(word).mul(m[L.CARRY_OUT + i - 1]) else m[L.CARRY_OUT + i - 1];
        out.emit(m[L.OUT + i].sub(one.sub(m[L.NEG_OUT].mul(E.qFor(F, 2))).mul(chosen)).add(prior_out).sub(radix.mul(m[L.CARRY_OUT + i])));
        out.emit(one.sub(m[L.NEG_OUT]).mul(m[L.CARRY_OUT + i]));
        const base = if (i < 2) m[L.OUT + i] else m[L.OUT + i].add(word.mul(E.qFor(F, 65535).mul(m[L.SIGN_OUT32]).sub(m[L.OUT + i])));
        out.emit(m[L.C + i].sub(m[L.ZERO_DIV].mul(E.qFor(F, 65535))).sub(one.sub(m[L.ZERO_DIV]).mul(base)));
    }
    out.emit(m[L.CARRY_SUM + 3]);
    out.emit(active.sub(m[L.ZERO]).mul(m[L.BORROW_GAP + 3]));
}
