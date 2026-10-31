//! Byte-bounded 64x64 schoolbook arithmetic, signed high correction and W
//! sign-extension. One cyclic relation closes BYTE requests and typed MUL.
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
const Byte = @import("../../range/cpu.zig");
const Q = E.Q;
pub const Tuple = [L.TUPLE]Q;
pub const Values = [L.MAIN]Q;
pub const Interaction = [L.INTERACTION]Q;
pub const Challenges = struct {
    offset: Q,
    coefficients: [L.TUPLE]Q,
    pub fn draw(channel: *@import("../../protocol.zig").Channel) Challenges {
        channel.mixU32s(&.{ 0x4d554c31, L.TUPLE });
        var result: Challenges = undefined;
        result.offset = channel.drawSecureFelt();
        for (&result.coefficients) |*c| c.* = channel.drawSecureFelt();
        return result;
    }
    pub fn denominator(self: Challenges, entry: *const Tuple) Q {
        var result = self.offset;
        for (self.coefficients, entry) |c, value| result = result.add(c.mul(value));
        return result;
    }
};
pub fn active(main: *const Values) Q {
    var result = Q.zero();
    for (main[L.SELECTORS..L.COUNT]) |s| result = result.add(s);
    return result;
}
pub fn tuple(main: *const Values) Tuple {
    var result: Tuple = undefined;
    result[0] = Q.zero();
    for (L.OPCODES, 0..) |op, i| result[0] = result[0].add(main[L.SELECTORS + i].mul(E.q(@intFromEnum(op))));
    @memcpy(result[1..], main[0..24]);
    return result;
}
/// Every expression is affine in source columns. Doubled sign remainders
/// and scaled carry high bytes are BYTE requests too, with exact integer bounds.
pub fn byteValues(main: *const Values) [L.BYTE_QUERIES]Q {
    var values: [L.BYTE_QUERIES]Q = undefined;
    @memcpy(values[0..40], main[0..40]);
    for (0..15) |i| {
        values[40 + 3 * i] = main[L.CARRY_LOW + i];
        values[41 + 3 * i] = main[L.CARRY_HIGH + i];
        values[42 + 3 * i] = main[L.CARRY_HIGH + i].mul(E.q(32));
    }
    @memcpy(values[85..93], main[L.BORROW..][0..8]);
    values[93] = main[L.A + 7].sub(main[L.SIGN_A].mul(E.q(128))).mul(E.q(2));
    values[94] = main[L.B + 7].sub(main[L.SIGN_B].mul(E.q(128))).mul(E.q(2));
    values[95] = main[L.RESULT + 3].sub(main[L.SIGN_RESULT].mul(E.q(128))).mul(E.q(2));
    return values;
}
pub fn arithmetic(geometry: [3]Q, main: *const Values, previous_count: Q, count: u32, out: *E.Sink) void {
    const one = Q.one();
    const enabled = active(main);
    for (main[L.SELECTORS..L.COUNT]) |s| E.boolean(out, s);
    E.boolean(out, enabled);
    for (main[L.SIGN_A..L.SELECTORS]) |s| E.boolean(out, s);
    out.emit(main[L.COUNT].sub(one.sub(geometry[1]).mul(previous_count)).sub(enabled));
    out.emit(geometry[1].mul(main[L.COUNT].sub(enabled)));
    out.emit(geometry[2].mul(main[L.COUNT].sub(E.q(count))));
    for (main[0..L.SELECTORS]) |value| out.emit(one.sub(enabled).mul(value));
    for (0..16) |k| {
        var lhs = if (k == 0) Q.zero() else main[L.CARRY_LOW + k - 1].add(main[L.CARRY_HIGH + k - 1].mul(E.q(256)));
        for (0..8) |i| if (k >= i and k - i < 8) {
            lhs = lhs.add(main[L.A + i].mul(main[L.B + k - i]));
        };
        var rhs = main[L.PRODUCT + k];
        if (k != 15) rhs = rhs.add(main[L.CARRY_LOW + k].add(main[L.CARRY_HIGH + k].mul(E.q(256))).mul(E.q(256)));
        out.emit(lhs.sub(rhs));
    }
    const signed_both = main[L.SELECTORS + 1];
    const signed_first = signed_both.add(main[L.SELECTORS + 3]);
    const high = signed_first.add(main[L.SELECTORS + 2]);
    for (0..8) |i| {
        const borrow = main[L.BORROW + i];
        const prior = if (i == 0) Q.zero() else main[L.BORROW + i - 1];
        out.emit(one.sub(high).mul(borrow));
        out.emit(high.mul(main[L.PRODUCT + 8 + i].sub(main[L.RESULT + i]).sub(prior).add(borrow.mul(E.q(256))))
            .sub(signed_first.mul(main[L.SIGN_A]).mul(main[L.B + i]))
            .sub(signed_both.mul(main[L.SIGN_B]).mul(main[L.A + i])));
        out.emit(main[L.SELECTORS].mul(main[L.RESULT + i].sub(main[L.PRODUCT + i])));
        out.emit(main[L.SELECTORS + 4].mul(main[L.RESULT + i].sub(if (i < 4) main[L.PRODUCT + i] else main[L.SIGN_RESULT].mul(E.q(255)))));
    }
}
pub fn evaluate(geometry: [3]Q, main: *const Values, current: *const Interaction, previous: *const Interaction, previous_count: Q, count: u32, ch: Challenges, alpha: *const Byte.PreparedAlpha, claim: Q, out: *E.Sink) void {
    arithmetic(geometry, main, previous_count, count, out);
    const values = byteValues(main);
    var prior = Byte.secure(previous, L.INTERACTION - 4).sub(geometry[1].mul(claim));
    for (0..L.BYTE_QUERIES / 3) |group| {
        const prefix = Byte.secure(current, group * 4);
        const term = alpha.terms(values[group * 3 ..][0..3]);
        out.emit(prefix.sub(prior).mul(term.denominator).sub(term.numerator));
        prior = prefix;
    }
    const prefix = Byte.secure(current, L.INTERACTION - 4);
    out.emit(prefix.sub(prior).mul(ch.denominator(&tuple(main))).add(active(main)));
}
