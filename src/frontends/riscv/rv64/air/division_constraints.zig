const E = @import("evaluation.zig");
const Q = E.Q;
const L = E.L;
pub fn evaluate(v: E.View, out: *E.Sink) void {
    return evaluateGeneric(Q, v, out);
}
pub fn evaluateGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F)) void {
    const one = F.one();
    const full = v.sum(&.{ .DIV, .DIVU, .REM, .REMU });
    const word = v.sum(&.{ .DIVW, .DIVUW, .REMW, .REMUW });
    const div = full.add(word);
    const rem = v.sum(&.{ .REM, .REMU, .REMW, .REMUW });
    const quot = div.sub(rem);
    const signed_full = v.sum(&.{ .DIV, .REM });
    const signed_word = v.sum(&.{ .DIVW, .REMW });
    const zero = v.m[L.divisor_zero];
    const sa = v.m[L.sign_a];
    const sb = v.m[L.sign_b];
    out.emit(sa.sub(signed_full.mul(v.bit(.a, 63))).sub(signed_word.mul(v.bit(.a, 31))));
    out.emit(sb.sub(signed_full.mul(v.bit(.b, 63))).sub(signed_word.mul(v.bit(.b, 31))));
    out.emit(v.m[L.negate].sub(quot.mul(sa.add(sb).sub(sa.mul(sb).mul(E.qFor(F, 2))))).sub(rem.mul(sa)));
    out.emit(v.m[L.apply_negate].sub(v.m[L.negate].mul(one.sub(zero.mul(quot)))));
    var divisor_sum = F.zero();
    for (0..8) |i| divisor_sum = divisor_sum.add(v.byte(.abs_b, i));
    out.emit(zero.mul(divisor_sum));
    out.emit(divisor_sum.mul(v.m[L.divisor_inverse]).sub(div).add(zero));
    out.emit(zero.mul(v.m[L.divisor_inverse]));
    out.emit(one.sub(div).mul(zero));
    out.emit(one.sub(div).mul(v.m[L.divisor_inverse]));
    for (0..8) |i| {
        const enabled = full.add(if (i < 4) word else F.zero());
        const a = v.byte(.a, i);
        const b = v.byte(.b, i);
        const aa = v.byte(.abs_a, i);
        const bb = v.byte(.abs_b, i);
        const out_abs = v.byte(.out_abs, i);
        const raw = v.byte(.raw_result, i);
        const pa = if (i == 0) F.zero() else v.carry(.abs_a, i - 1);
        const pb = if (i == 0) F.zero() else v.carry(.abs_b, i - 1);
        const pn = if (i == 0) F.zero() else v.carry(.negate, i - 1);
        out.emit(enabled.mul(sa.mul(a.add(aa).add(pa).sub(v.carry(.abs_a, i).mul(E.qFor(F, 256)))).add(one.sub(sa).mul(aa.sub(a)))));
        out.emit(enabled.mul(sb.mul(b.add(bb).add(pb).sub(v.carry(.abs_b, i).mul(E.qFor(F, 256)))).add(one.sub(sb).mul(bb.sub(b)))));
        out.emit(one.sub(sa).mul(v.carry(.abs_a, i)));
        out.emit(one.sub(sb).mul(v.carry(.abs_b, i)));
        const negative = v.m[L.apply_negate];
        out.emit(enabled.mul(negative.mul(out_abs.add(raw).add(pn).sub(v.carry(.negate, i).mul(E.qFor(F, 256)))).add(one.sub(negative).mul(raw.sub(out_abs)))));
        out.emit(one.sub(negative).mul(v.carry(.negate, i)));
        out.emit(v.byte(.out_abs, i).sub(quot.mul(v.byte(.quotient, i))).sub(rem.mul(v.byte(.remainder, i))));
        out.emit(enabled.mul(v.byte(.result, i).sub(raw)));
        out.emit(enabled.mul(zero).mul(v.byte(.quotient, i).sub(E.qFor(F, 255))));
        if (i >= 4) {
            for ([_]L.Word{ .abs_a, .abs_b, .quotient, .remainder, .remainder_gap, .raw_result, .out_abs }) |w| out.emit(word.mul(v.byte(w, i)));
        }
        const rc = if (i == 0) one else v.carry(.remainder, i - 1);
        out.emit(enabled.mul(one.sub(zero)).mul(v.byte(.remainder, i).add(v.byte(.remainder_gap, i)).add(rc).sub(bb).sub(v.carry(.remainder, i).mul(E.qFor(F, 256)))));
        out.emit(zero.mul(v.byte(.remainder_gap, i)));
        out.emit(zero.mul(v.carry(.remainder, i)));
    }
    out.emit(full.mul(one.sub(zero)).mul(v.carry(.remainder, 7)));
    out.emit(word.mul(one.sub(zero)).mul(v.carry(.remainder, 3)));
    for (0..16) |i| {
        const carry = v.carry(if (i < 8) .div_sum_low else .div_sum_high, i % 8);
        const prior = if (i == 0) F.zero() else v.carry(if (i <= 8) .div_sum_low else .div_sum_high, (i - 1) % 8);
        const p = v.byte(if (i < 8) .product_low else .product_high, i % 8);
        const r = if (i < 8) v.byte(.remainder, i) else F.zero();
        const a = if (i < 8) v.byte(.abs_a, i) else F.zero();
        out.emit(div.mul(p.add(r).add(prior).sub(a).sub(carry.mul(E.qFor(F, 256)))));
    }
    out.emit(div.mul(v.carry(.div_sum_high, 7)));
}
