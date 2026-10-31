const E = @import("evaluation.zig");
const Q = E.Q;
const L = E.L;
const Inflation = @import("encoding.zig").Inflation;
pub fn evaluate(v: E.View, out: *E.Sink) void {
    return evaluateGeneric(Q, v, out);
}
pub fn evaluateGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F)) void {
    evaluateProfileGeneric(F, v, out, false);
}
pub fn evaluateProfile(v: E.View, out: *E.Sink, compact_carries: bool) void {
    return evaluateProfileGeneric(Q, v, out, compact_carries);
}
pub fn evaluateProfileGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F), compact_carries: bool) void {
    evaluateImplGeneric(F, v, out, compact_carries, null);
}
pub fn evaluateInflated(fixed: *const E.Fixed, prepared: Inflation.Result, out: *E.Sink, compact_carries: bool) void {
    return evaluateInflatedGeneric(Q, fixed, prepared, out, compact_carries);
}
pub fn evaluateInflatedGeneric(comptime F: type, fixed: *const E.FixedFor(F), prepared: Inflation.ResultFor(F), out: *E.SinkFor(F), compact_carries: bool) void {
    evaluateImplGeneric(F, .{ .f = fixed, .m = prepared.main }, out, compact_carries, prepared);
}
fn evaluateImplGeneric(comptime F: type, v: E.ViewFor(F), out: *E.SinkFor(F), compact_carries: bool, prepared: ?Inflation.ResultFor(F)) void {
    const mul = v.sum(&.{ .MUL, .MULH, .MULHSU, .MULHU, .MULW });
    const div = v.sum(&.{ .DIV, .DIVU, .REM, .REMU, .DIVW, .DIVUW, .REMW, .REMUW });
    const product = mul.add(div);
    for (0..8) |i| {
        out.emit(v.byte(.product_x, i).sub(mul.mul(v.byte(.a, i))).sub(div.mul(v.byte(.quotient, i))));
        out.emit(v.byte(.product_y, i).sub(mul.mul(v.byte(.b, i))).sub(div.mul(v.byte(.abs_b, i))));
    }
    for (0..16) |k| {
        const start = L.productCarry(k);
        if (compact_carries) {
            if (prepared) |result| @import("range/constraints.zig").productCarryRangeInflatedGeneric(F, v.f, result, out, k, product) else @import("range/constraints.zig").productCarryRangeGeneric(F, v, out, k, product);
        } else {
            var reconstructed = F.zero();
            for (0..11) |i| {
                const bit = v.m[start + 1 + i];
                E.booleanFor(F, out, bit);
                if (prepared == null) reconstructed = reconstructed.add(bit.mul(E.qFor(F, @as(u32, 1) << @as(u5, @intCast(i)))));
            }
            if (prepared != null) out.zeros(1) else out.emit(v.m[start].sub(reconstructed));
            out.emit(F.one().sub(product).mul(v.m[start]));
        }
        var sum = if (k == 0) F.zero() else v.m[L.productCarry(k - 1)];
        for (0..8) |i| if (k >= i and k - i < 8) {
            sum = sum.add(v.byte(.product_x, i).mul(v.byte(.product_y, k - i)));
        };
        const output = v.byte(if (k < 8) .product_low else .product_high, k % 8);
        out.emit(product.mul(sum.sub(output).sub(v.m[start].mul(E.qFor(F, 256)))));
    }
    out.emit(product.mul(v.m[L.productCarry(15)]));
    const sign_a = v.sum(&.{ .MULH, .MULHSU }).mul(v.bit(.a, 63));
    const sign_b = v.op(.MULH).mul(v.bit(.b, 63));
    for (0..8) |i| {
        const previous_a = if (i == 0) F.one() else v.carry(.high_a, i - 1);
        const previous_b = if (i == 0) F.one() else v.carry(.high_b, i - 1);
        out.emit(mul.mul(v.byte(.product_high, i).add(E.qFor(F, 255)).sub(sign_a.mul(v.byte(.b, i))).add(previous_a).sub(v.byte(.high_sub_a, i)).sub(v.carry(.high_a, i).mul(E.qFor(F, 256)))));
        out.emit(mul.mul(v.byte(.high_sub_a, i).add(E.qFor(F, 255)).sub(sign_b.mul(v.byte(.a, i))).add(previous_b).sub(v.byte(.high_sub_b, i)).sub(v.carry(.high_b, i).mul(E.qFor(F, 256)))));
        out.emit(v.op(.MUL).mul(v.byte(.result, i).sub(v.byte(.product_low, i))));
        out.emit(v.op(.MULHU).mul(v.byte(.result, i).sub(v.byte(.product_high, i))));
        out.emit(v.sum(&.{ .MULH, .MULHSU }).mul(v.byte(.result, i).sub(v.byte(.high_sub_b, i))));
        if (i < 4) out.emit(v.op(.MULW).mul(v.byte(.result, i).sub(v.byte(.product_low, i))));
    }
}
