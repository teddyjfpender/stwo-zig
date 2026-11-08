//! Quadratic DEEP authority for the wide-field path. No production selection.
const std = @import("std");
const C = @import("constraints.zig");
const circle = @import("circle.zig");
const M = @import("fields/m31.zig").M31;
const Q = @import("fields/qm31.zig").QM31;
const O = @import("fields/om31.zig").OM31;

fn at(comptime F: type, t: F) !circle.CirclePoint(F) {
    const inv = try F.one().add(t.square()).inv();
    return .{ .x = F.one().sub(t.square()).mul(inv), .y = t.add(t).mul(inv) };
}
fn conjugate(comptime F: type, p: circle.CirclePoint(F)) circle.CirclePoint(F) {
    return .{ .x = p.x.quadraticConjugate(), .y = p.y.quadraticConjugate() };
}
fn linear(comptime F: type, p: circle.CirclePoint(F)) F {
    return p.x.add(p.y.mulM31(M.fromCanonical(3))).add(F.fromBase(M.fromCanonical(5)));
}
fn domainLift(comptime F: type, p: circle.CirclePointM31) circle.CirclePoint(F) {
    return .{ .x = F.fromBase(p.x), .y = F.fromBase(p.y) };
}
fn exercise(comptime F: type, t: F) !void {
    const p = try at(F, t);
    try std.testing.expect(p.x.square().add(p.y.square()).eql(F.one()));
    const cp = conjugate(F, p);
    const f = linear(F, p);
    const alpha = F.one().add(t);
    const coeffs = try C.quadraticConjugateLineCoeffs(F, p, f, alpha);
    try std.testing.expect(coeffs.a.mul(p.y).add(coeffs.b).eql(coeffs.c.mul(f)));
    try std.testing.expect(coeffs.a.mul(cp.y).add(coeffs.b).eql(coeffs.c.mul(linear(F, cp))));
    const inner_inverse = try p.y.c1.inv();
    const expected = F{ .c0 = inner_inverse.neg(), .c1 = F.InnerField.zero() };
    var it = circle.Coset.halfOdds(6).iter();
    while (it.next()) |base| {
        const line = try C.quadraticConjugateLine(F, p, f, base);
        const den = C.quadraticLineDenominator(F, p, base);
        try std.testing.expect(!den.isZero());
        const lifted_den = F{ .c0 = den, .c1 = F.InnerField.zero() };
        const vanishing = C.pairVanishing(F, p, cp, domainLift(F, base));
        const generator = F{ .c0 = F.InnerField.zero(), .c1 = F.InnerField.one() };
        try std.testing.expect(vanishing.eql(generator.add(generator).neg().mul(lifted_den)));
        const quotient = try linear(F, domainLift(F, base)).sub(line).div(lifted_den);
        try std.testing.expect(quotient.eql(expected));
    }
}

test "wide DEEP: both quadratic towers interpolate and divide the same base polynomial" {
    try exercise(Q, Q.fromU32Unchecked(7, 11, 13, 17));
    try exercise(O, .{ .c0 = Q.fromU32Unchecked(7, 11, 13, 17), .c1 = Q.fromU32Unchecked(19, 23, 29, 31) });
    try exercise(O, .{ .c0 = Q.fromU32Unchecked(101, 103, 107, 109), .c1 = Q.fromU32Unchecked(113, 127, 131, 137) });
}

test "wide DEEP: fixed-subfield points reject a degenerate conjugate line" {
    const p = try at(O, O.fromInner(Q.fromU32Unchecked(7, 11, 13, 17)));
    try std.testing.expectError(error.DegenerateLine, C.quadraticConjugateLineCoeffs(O, p, O.one(), O.one()));
    try std.testing.expectError(error.DegenerateLine, C.quadraticConjugateLine(O, p, O.one(), circle.CirclePointM31.identity()));
}

test "wide DEEP: QM31 public wrappers preserve the established exact formulas" {
    const p = try at(Q, Q.fromU32Unchecked(7, 11, 13, 17));
    const f = Q.fromU32Unchecked(19, 23, 29, 31);
    const alpha = Q.fromU32Unchecked(37, 41, 43, 47);
    const a = f.complexConjugate().sub(f);
    const c = p.complexConjugate().y.sub(p.y);
    const b = f.mul(c).sub(a.mul(p.y));
    const got = try C.complexConjugateLineCoeffs(p, f, alpha);
    try std.testing.expect(got.a.eql(alpha.mul(a)));
    try std.testing.expect(got.b.eql(alpha.mul(b)));
    try std.testing.expect(got.c.eql(alpha.mul(c)));
    var it = circle.Coset.halfOdds(5).iter();
    while (it.next()) |base| {
        const old = f.add(try a.mul(p.y.neg().add(Q.fromBase(base.y))).div(c));
        try std.testing.expect((try C.complexConjugateLine(p, f, base)).eql(old));
    }
}
