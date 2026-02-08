const std = @import("std");
const circle = @import("../core/circle.zig");
const fft = @import("../core/fft.zig");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");
const poly_line = @import("../core/poly/line.zig");
const core_utils = @import("../core/utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const LineDomain = poly_line.LineDomain;
const LinePoly = poly_line.LinePoly;

/// Evaluations of a univariate polynomial on a line domain.
///
/// The values are expected in bit-reversed order, matching Stwo prover conventions.
pub const LineEvaluation = struct {
    values: []const QM31,
    domain_value: LineDomain,
    owns_values: bool = true,

    pub const Error = error{
        InvalidLength,
        DivisionByZero,
    };

    pub fn initOwned(line_domain: LineDomain, values: []QM31) Error!LineEvaluation {
        if (values.len != line_domain.size()) return Error.InvalidLength;
        return .{
            .values = values,
            .domain_value = line_domain,
            .owns_values = true,
        };
    }

    pub fn initBorrowed(line_domain: LineDomain, values: []const QM31) Error!LineEvaluation {
        if (values.len != line_domain.size()) return Error.InvalidLength;
        return .{
            .values = values,
            .domain_value = line_domain,
            .owns_values = false,
        };
    }

    pub fn deinit(self: *LineEvaluation, allocator: std.mem.Allocator) void {
        if (self.owns_values) allocator.free(self.values);
        self.* = undefined;
    }

    pub fn newZero(allocator: std.mem.Allocator, line_domain: LineDomain) !LineEvaluation {
        const values = try allocator.alloc(QM31, line_domain.size());
        @memset(values, QM31.zero());
        return .{
            .values = values,
            .domain_value = line_domain,
            .owns_values = true,
        };
    }

    pub fn len(self: LineEvaluation) usize {
        return self.values.len;
    }

    pub fn domain(self: LineEvaluation) LineDomain {
        return self.domain_value;
    }

    pub fn cloneOwned(self: LineEvaluation, allocator: std.mem.Allocator) !LineEvaluation {
        return .{
            .values = try allocator.dupe(QM31, self.values),
            .domain_value = self.domain_value,
            .owns_values = true,
        };
    }

    /// Interpolates this evaluation into a line polynomial.
    ///
    /// Consumes ownership of `values` when this evaluation owns them.
    pub fn interpolate(
        self: *LineEvaluation,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || Error)!LinePoly {
        const coeffs: []QM31 = if (self.owns_values)
            @constCast(self.values)
        else
            try allocator.dupe(QM31, self.values);

        core_utils.bitReverse(QM31, coeffs);
        try lineIfft(coeffs, self.domain_value);

        const len_m31 = M31.fromU64(coeffs.len);
        const len_inv = len_m31.inv() catch return Error.DivisionByZero;
        for (coeffs) |*v| v.* = v.mulM31(len_inv);

        if (self.owns_values) {
            self.values = &[_]QM31{};
            self.owns_values = false;
        }
        return LinePoly.initOwned(coeffs);
    }
};

/// In-place line-domain IFFT.
///
/// Preconditions:
/// - `values.len == domain.size()`
fn lineIfft(values: []QM31, domain: LineDomain) LineEvaluation.Error!void {
    if (values.len != domain.size()) return LineEvaluation.Error.InvalidLength;

    var current_domain = domain;
    while (current_domain.size() > 1) {
        const chunk_size = current_domain.size();
        const half = chunk_size / 2;
        var chunk_start: usize = 0;
        while (chunk_start < values.len) : (chunk_start += chunk_size) {
            const chunk = values[chunk_start .. chunk_start + chunk_size];
            var it = current_domain.iter();
            var i: usize = 0;
            while (i < half) : (i += 1) {
                const x = it.next().?;
                const inv_x = x.inv() catch return LineEvaluation.Error.DivisionByZero;
                fft.ibutterfly(QM31, &chunk[i], &chunk[half + i], inv_x);
            }
        }
        current_domain = current_domain.double();
    }
}

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
