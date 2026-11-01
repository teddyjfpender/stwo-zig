//! Native-pack execution of the core quadratic DEEP row law. This changes
//! arithmetic scheduling only: constants, denominator authority and scalar tail
//! are identical, and there is no allocation or extra retained plane.
const std = @import("std");
const core = @import("stwo_core");
const m = core.fields.m31;
const O = core.fields.om31.OM31;
const Q = core.fields.qm31.QM31;
const po = core.fields.packed_om31;
const pq = core.fields.packed_qm31;
const Authority = core.pcs.ForField(O).quotients;
pub fn finalize(constants: *const Authority.QuotientConstants, y: m.M31, numerators: []const O, inverses: []const Q) !O {
    if (constants.batch_linear_terms.len != numerators.len or inverses.len != numerators.len) return error.ShapeMismatch;
    var sum = po.splat(O.zero());
    var index: usize = 0;
    while (index + m.PACK_WIDTH <= numerators.len) : (index += m.PACK_WIDTH) {
        var a: [8]m.PackedM31 = undefined;
        var b: [8]m.PackedM31 = undefined;
        var inv: [4]m.PackedM31 = undefined;
        inline for (0..m.PACK_WIDTH) |lane| {
            const term = constants.batch_linear_terms[index + lane];
            const av = term.sum_a.toM31Array();
            const bv = term.sum_b.toM31Array();
            const iv = inverses[index + lane].toM31Array();
            inline for (0..8) |coordinate| {
                a[coordinate][lane] = av[coordinate].v;
                b[coordinate][lane] = bv[coordinate].v;
            }
            inline for (0..4) |coordinate| inv[coordinate][lane] = iv[coordinate].v;
        }
        const linear = po.fromCoordinates(a).mulBase(@as(m.PackedM31, @splat(y.v))).add(po.fromCoordinates(b));
        const numerator = po.loadNative(numerators[index..]).sub(linear);
        sum = sum.add(numerator.mulInner(pq.PackedQM31.fromCoordinates(inv)));
    }
    var result = O.zero();
    inline for (0..m.PACK_WIDTH) |lane| result = result.add(po.lane(sum, lane));
    for (constants.batch_linear_terms[index..], numerators[index..], inverses[index..]) |term, numerator, inverse| {
        result = result.add(numerator.sub(term.sum_a.mulM31(y).add(term.sum_b)).mulInner(inverse));
    }
    return result;
}
fn dense(seed: usize) O {
    var coordinates: [8]m.M31 = undefined;
    for (&coordinates, 0..) |*c, i| c.* = m.M31.fromCanonical(@intCast((seed + 13) * (i + 17) % 2147483647));
    return O.fromM31Array(coordinates);
}
test "coefficient storage packed wide DEEP finalization matches independent core authority" {
    const Term = std.meta.Child(@TypeOf(@as(Authority.QuotientConstants, undefined).batch_linear_terms));
    var terms: [65]Term = undefined;
    var numerators: [65]O = undefined;
    var inverses: [65]Q = undefined;
    for (&terms, &numerators, &inverses, 0..) |*term, *n, *inverse, i| {
        term.* = .{ .sum_a = dense(i + 7), .sum_b = dense(i + 91) };
        n.* = dense(i + 113);
        inverse.* = dense(i + 257).c0;
    }
    for ([_]usize{ 0, 1, 2, 3, 4, 5, 8, 13, 16, 31, 64, 65 }) |count| {
        const constants = Authority.QuotientConstants{ .line_coeffs = &.{}, .batch_linear_terms = terms[0..count] };
        for ([_]m.M31{ m.M31.zero(), m.M31.one(), m.M31.fromCanonical(2147483646) }) |y| {
            const expected = try Authority.finalizeRowQuotients(&constants, y, numerators[0..count], inverses[0..count]);
            const actual = try finalize(&constants, y, numerators[0..count], inverses[0..count]);
            try std.testing.expectEqual(expected, actual);
        }
    }
    const constants = Authority.QuotientConstants{ .line_coeffs = &.{}, .batch_linear_terms = &terms };
    try std.testing.expectError(error.ShapeMismatch, finalize(&constants, m.M31.one(), numerators[0..64], &inverses));
    try std.testing.expectError(error.ShapeMismatch, finalize(&constants, m.M31.one(), &numerators, inverses[0..64]));
}
