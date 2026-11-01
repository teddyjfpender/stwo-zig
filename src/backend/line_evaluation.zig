const std = @import("std");
const circle = @import("stwo_core").circle;
const fft = @import("stwo_core").fft;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const poly_line = @import("stwo_core").poly.line;
const core_utils = @import("stwo_core").utils;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const LineDomain = poly_line.LineDomain;
const LinePoly = poly_line.LinePoly;
const ResidentStorage = @import("resident_storage.zig").ResidentStorage;

/// Evaluations of a univariate polynomial on a line domain.
///
/// The values are expected in bit-reversed order, matching Stwo prover conventions.
pub const ForField = @import("line_evaluation_family.zig").ForField;
pub fn LineEvaluationFor(comptime S: type) type {
    return ForField(S).LineEvaluation;
}
pub const LineEvaluation = ForField(QM31).LineEvaluation;

test "prover line: init rejects invalid length" {
    const domain = try LineDomain.init(circle.Coset.halfOdds(2));
    const values = [_]QM31{ QM31.one(), QM31.one(), QM31.one() };
    try std.testing.expectError(
        LineEvaluation.Error.InvalidLength,
        LineEvaluation.initBorrowed(domain, values[0..]),
    );
}

test "prover line: interpolation roundtrip" {
    const allocator = std.testing.allocator;
    const coeffs_ordered = [_]QM31{
        QM31.fromBase(M31.fromCanonical(7)),
        QM31.fromBase(M31.fromCanonical(9)),
        QM31.fromBase(M31.fromCanonical(5)),
        QM31.fromBase(M31.fromCanonical(3)),
    };
    const domain = try LineDomain.init(circle.Coset.halfOdds(2));

    const eval_values = try allocator.alloc(QM31, coeffs_ordered.len);
    defer allocator.free(eval_values);

    var source_poly = LinePoly.fromOrderedCoefficients(try allocator.dupe(QM31, coeffs_ordered[0..]));
    defer source_poly.deinit(allocator);
    for (0..eval_values.len) |i| {
        const xq = QM31.fromBase(domain.at(i));
        eval_values[i] = try source_poly.evalAtPoint(allocator, xq);
    }
    core_utils.bitReverse(QM31, eval_values);

    var eval = try LineEvaluation.initOwned(domain, try allocator.dupe(QM31, eval_values));
    var poly = try eval.interpolate(allocator);
    defer poly.deinit(allocator);

    const recovered = poly.intoOrderedCoefficients();
    for (coeffs_ordered, 0..) |expected, i| {
        try std.testing.expect(recovered[i].eql(expected));
    }
}

test "prover line: polynomial evaluates back on domain" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 2;
    const domain = try LineDomain.init(circle.Coset.halfOdds(log_size));

    const values = try allocator.alloc(QM31, 1 << log_size);
    defer allocator.free(values);
    for (values, 0..) |*value, i| {
        value.* = QM31.fromBase(M31.fromCanonical(@intCast(i)));
    }
    const values_copy = try allocator.dupe(QM31, values);
    defer allocator.free(values_copy);

    var eval = try LineEvaluation.initOwned(domain, try allocator.dupe(QM31, values));
    var poly = try eval.interpolate(allocator);
    defer poly.deinit(allocator);

    var i: usize = 0;
    var it = domain.iter();
    while (it.next()) |x| : (i += 1) {
        const actual = try poly.evalAtPoint(allocator, QM31.fromBase(x));
        const expected = values_copy[core_utils.bitReverseIndex(i, log_size)];
        try std.testing.expect(actual.eql(expected));
    }
}
