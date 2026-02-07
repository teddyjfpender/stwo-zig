const std = @import("std");
const fraction = @import("../../core/fraction.zig");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const LookupUtilsError = error{
    ShapeMismatch,
    DivisionByZero,
};

/// Univariate polynomial in monomial basis with trailing zeros normalized away.
///
/// Inputs/outputs:
/// - input coefficients are interpreted as `[c0, c1, ..., ck]` for `c0 + c1*x + ... + ck*x^k`.
/// - all operations return normalized polynomials (`degree` matches last non-zero coefficient).
///
/// Invariants:
/// - `len <= coeffs.len`
/// - `coeffs[0..len]` contains all non-zero-leading terms.
///
/// Failure modes:
/// - allocation failures from polynomial constructors/ops.
/// - `interpolateLagrange` returns `ShapeMismatch` on length mismatch and
///   `DivisionByZero` for duplicated x-coordinates.
pub fn UnivariatePoly(comptime F: type) type {
    return struct {
        coeffs: []F,
        len: usize,
        owns_coeffs: bool = true,

        const Self = @This();

        pub fn initOwned(coeffs: []F) Self {
            return .{
                .len = trimmedLen(coeffs),
                .coeffs = coeffs,
                .owns_coeffs = true,
            };
        }

        pub fn initBorrowed(coeffs: []F) Self {
            return .{
                .len = trimmedLen(coeffs),
                .coeffs = coeffs,
                .owns_coeffs = false,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.owns_coeffs) allocator.free(self.coeffs);
            self.* = undefined;
        }

        pub fn cloneOwned(self: Self, allocator: std.mem.Allocator) !Self {
            return Self.initOwned(try allocator.dupe(F, self.coeffs[0..self.len]));
        }

        pub fn coeffsSlice(self: Self) []const F {
            return self.coeffs[0..self.len];
        }

        pub fn isZero(self: Self) bool {
            return self.len == 0;
        }

        pub fn degree(self: Self) usize {
            return if (self.len == 0) 0 else self.len - 1;
        }

        pub fn evalAtPoint(self: Self, point: F) F {
            return hornerEval(F, self.coeffs[0..self.len], point);
        }

        pub fn fromScalar(allocator: std.mem.Allocator, value: F) !Self {
            if (fieldIsZero(F, value)) {
                return Self.initOwned(try allocator.alloc(F, 0));
            }
            const out = try allocator.alloc(F, 1);
            out[0] = value;
            return Self.initOwned(out);
        }

        pub fn x(allocator: std.mem.Allocator) !Self {
            const out = try allocator.alloc(F, 2);
            out[0] = fieldZero(F);
            out[1] = fieldOne(F);
            return Self.initOwned(out);
        }

        pub fn add(self: Self, allocator: std.mem.Allocator, rhs: Self) !Self {
            const n = @max(self.len, rhs.len);
            const out = try allocator.alloc(F, n);
            for (0..n) |i| {
                const a = if (i < self.len) self.coeffs[i] else fieldZero(F);
                const b = if (i < rhs.len) rhs.coeffs[i] else fieldZero(F);
                out[i] = fieldAdd(F, a, b);
            }
            return Self.initOwned(out);
        }

        pub fn neg(self: Self, allocator: std.mem.Allocator) !Self {
            const out = try allocator.alloc(F, self.len);
            for (self.coeffs[0..self.len], 0..) |coeff, i| {
                out[i] = fieldNeg(F, coeff);
            }
            return Self.initOwned(out);
        }

        pub fn sub(self: Self, allocator: std.mem.Allocator, rhs: Self) !Self {
            var neg_rhs = try rhs.neg(allocator);
            defer neg_rhs.deinit(allocator);
            return self.add(allocator, neg_rhs);
        }

        pub fn mulScalar(self: Self, allocator: std.mem.Allocator, scalar: F) !Self {
            if (self.isZero() or fieldIsZero(F, scalar)) {
                return Self.initOwned(try allocator.alloc(F, 0));
            }
            const out = try allocator.alloc(F, self.len);
            for (self.coeffs[0..self.len], 0..) |coeff, i| {
                out[i] = fieldMul(F, coeff, scalar);
            }
            return Self.initOwned(out);
        }

        pub fn mulPoly(self: Self, allocator: std.mem.Allocator, rhs: Self) !Self {
            if (self.isZero() or rhs.isZero()) {
                return Self.initOwned(try allocator.alloc(F, 0));
            }

            const out_len = self.len + rhs.len - 1;
            const out = try allocator.alloc(F, out_len);
            @memset(out, fieldZero(F));

            for (self.coeffs[0..self.len], 0..) |coeff_a, i| {
                for (rhs.coeffs[0..rhs.len], 0..) |coeff_b, j| {
                    out[i + j] = fieldAdd(
                        F,
                        out[i + j],
                        fieldMul(F, coeff_a, coeff_b),
                    );
                }
            }
            return Self.initOwned(out);
        }

        pub fn interpolateLagrange(
            allocator: std.mem.Allocator,
            xs: []const F,
            ys: []const F,
        ) (std.mem.Allocator.Error || LookupUtilsError)!Self {
            if (xs.len != ys.len) return LookupUtilsError.ShapeMismatch;

            var coeffs = Self.initOwned(try allocator.alloc(F, 0));
            errdefer coeffs.deinit(allocator);

            for (xs, ys, 0..) |xi, yi, i| {
                var prod = yi;
                for (xs, 0..) |xj, j| {
                    if (i == j) continue;
                    prod = try fieldDiv(F, prod, fieldSub(F, xi, xj));
                }

                var term = try Self.fromScalar(allocator, prod);
                errdefer term.deinit(allocator);

                for (xs, 0..) |xj, j| {
                    if (i == j) continue;

                    const factor_coeffs = try allocator.alloc(F, 2);
                    factor_coeffs[0] = fieldNeg(F, xj);
                    factor_coeffs[1] = fieldOne(F);
                    var factor = Self.initOwned(factor_coeffs);
                    defer factor.deinit(allocator);

                    const next_term = try term.mulPoly(allocator, factor);
                    term.deinit(allocator);
                    term = next_term;
                }

                const next_coeffs = try coeffs.add(allocator, term);
                coeffs.deinit(allocator);
                term.deinit(allocator);
                coeffs = next_coeffs;
            }

            return coeffs;
        }

        fn trimmedLen(values: []const F) usize {
            var out = values.len;
            while (out > 0 and fieldIsZero(F, values[out - 1])) {
                out -= 1;
            }
            return out;
        }
    };
}

/// Horner evaluation of a univariate polynomial given monomial-basis coefficients.
pub fn hornerEval(comptime F: type, coeffs: []const F, x: F) F {
    var acc = fieldZero(F);
    var i = coeffs.len;
    while (i > 0) {
        i -= 1;
        acc = fieldAdd(F, fieldMul(F, acc, x), coeffs[i]);
    }
    return acc;
}

/// Returns `v_0 + alpha*v_1 + ... + alpha^(n-1)*v_{n-1}`.
pub fn randomLinearCombination(values: []const QM31, alpha: QM31) QM31 {
    return hornerEval(QM31, values, alpha);
}

/// Evaluates the boolean-hypercube Lagrange kernel.
pub fn eq(comptime F: type, x: []const F, y: []const F) LookupUtilsError!F {
    if (x.len != y.len) return LookupUtilsError.ShapeMismatch;

    var out = fieldOne(F);
    for (x, y) |xi, yi| {
        const same_branch = fieldMul(F, xi, yi);
        const neg_x = fieldSub(F, fieldOne(F), xi);
        const neg_y = fieldSub(F, fieldOne(F), yi);
        out = fieldMul(F, out, fieldAdd(F, same_branch, fieldMul(F, neg_x, neg_y)));
    }
    return out;
}

/// Computes `eq(0, assignment) * eval0 + eq(1, assignment) * eval1`.
pub fn foldMleEvals(comptime F: type, assignment: QM31, eval0: F, eval1: F) QM31 {
    if (F == QM31) {
        return assignment.mul(eval1.sub(eval0)).add(eval0);
    }
    if (F == M31) {
        return assignment.mul(QM31.fromBase(eval1.sub(eval0))).add(QM31.fromBase(eval0));
    }
    @compileError("foldMleEvals currently supports M31 and QM31");
}

/// Represents the reciprocal symbolic form `1/x` used in fraction algebra.
pub fn Reciprocal(comptime T: type) type {
    return struct {
        x: T,

        const Self = @This();

        pub fn new(x: T) Self {
            return .{ .x = x };
        }

        pub fn add(self: Self, rhs: Self) fraction.Fraction(T, T) {
            return .{
                .numerator = fieldAdd(T, self.x, rhs.x),
                .denominator = fieldMul(T, self.x, rhs.x),
            };
        }

        pub fn sub(self: Self, rhs: Self) fraction.Fraction(T, T) {
            return .{
                .numerator = fieldSub(T, rhs.x, self.x),
                .denominator = fieldMul(T, self.x, rhs.x),
            };
        }
    };
}

fn fieldZero(comptime F: type) F {
    return F.zero();
}

fn fieldOne(comptime F: type) F {
    return F.one();
}

fn fieldIsZero(comptime F: type, value: F) bool {
    return value.isZero();
}

fn fieldAdd(comptime F: type, a: F, b: F) F {
    return a.add(b);
}

fn fieldSub(comptime F: type, a: F, b: F) F {
    return a.sub(b);
}

fn fieldMul(comptime F: type, a: F, b: F) F {
    return a.mul(b);
}

fn fieldNeg(comptime F: type, value: F) F {
    return value.neg();
}

fn fieldDiv(comptime F: type, a: F, b: F) LookupUtilsError!F {
    if (@hasDecl(F, "div")) {
        return F.div(a, b) catch LookupUtilsError.DivisionByZero;
    }
    if (@hasDecl(F, "inv")) {
        const inv_b = b.inv() catch return LookupUtilsError.DivisionByZero;
        return a.mul(inv_b);
    }
    @compileError("field type must define `div` or `inv` for Lagrange interpolation");
}

test "lookups utils: lagrange interpolation" {
    const alloc = std.testing.allocator;
    const Poly = UnivariatePoly(M31);

    const xs = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(1),
        M31.fromCanonical(3),
        M31.fromCanonical(9),
    };
    const ys = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
    };

    var poly = try Poly.interpolateLagrange(alloc, xs[0..], ys[0..]);
    defer poly.deinit(alloc);

    for (xs, ys) |x, y| {
        try std.testing.expect(poly.evalAtPoint(x).eql(y));
    }
}

test "lookups utils: lagrange interpolation rejects mismatched sizes" {
    const Poly = UnivariatePoly(M31);
    const xs = [_]M31{M31.fromCanonical(1)};
    const ys = [_]M31{ M31.fromCanonical(2), M31.fromCanonical(3) };

    try std.testing.expectError(
        LookupUtilsError.ShapeMismatch,
        Poly.interpolateLagrange(std.testing.allocator, xs[0..], ys[0..]),
    );
}

test "lookups utils: lagrange interpolation rejects duplicate xs" {
    const Poly = UnivariatePoly(M31);
    const xs = [_]M31{ M31.fromCanonical(7), M31.fromCanonical(7) };
    const ys = [_]M31{ M31.fromCanonical(1), M31.fromCanonical(2) };

    try std.testing.expectError(
        LookupUtilsError.DivisionByZero,
        Poly.interpolateLagrange(std.testing.allocator, xs[0..], ys[0..]),
    );
}

test "lookups utils: polynomial arithmetic and normalization" {
    const alloc = std.testing.allocator;
    const Poly = UnivariatePoly(M31);

    var p = Poly.initOwned(try alloc.dupe(M31, &[_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.zero(),
        M31.zero(),
    }));
    defer p.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), p.coeffsSlice().len);
    try std.testing.expectEqual(@as(usize, 1), p.degree());

    var q = Poly.initOwned(try alloc.dupe(M31, &[_]M31{
        M31.fromCanonical(3),
        M31.fromCanonical(4),
    }));
    defer q.deinit(alloc);

    var sum = try p.add(alloc, q);
    defer sum.deinit(alloc);
    try std.testing.expect(sum.coeffsSlice()[0].eql(M31.fromCanonical(4)));
    try std.testing.expect(sum.coeffsSlice()[1].eql(M31.fromCanonical(6)));

    var product = try p.mulPoly(alloc, q);
    defer product.deinit(alloc);
    const coeffs = product.coeffsSlice();
    try std.testing.expectEqual(@as(usize, 3), coeffs.len);
    try std.testing.expect(coeffs[0].eql(M31.fromCanonical(3)));
    try std.testing.expect(coeffs[1].eql(M31.fromCanonical(10)));
    try std.testing.expect(coeffs[2].eql(M31.fromCanonical(8)));
}

test "lookups utils: horner and random linear combination" {
    const coeffs = [_]M31{
        M31.fromCanonical(9),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
    };
    const x = M31.fromCanonical(7);
    const eval = hornerEval(M31, coeffs[0..], x);
    const expected = coeffs[0].add(coeffs[1].mul(x)).add(coeffs[2].mul(x.square()));
    try std.testing.expect(eval.eql(expected));

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
    };
    const alpha = QM31.fromU32Unchecked(13, 14, 15, 16);
    const rlc = randomLinearCombination(values[0..], alpha);
    const expected_rlc = values[0]
        .add(values[1].mul(alpha))
        .add(values[2].mul(alpha.square()));
    try std.testing.expect(rlc.eql(expected_rlc));
}

test "lookups utils: eq kernel" {
    const zero = QM31.zero();
    const one = QM31.one();

    const a = [_]QM31{ one, zero, one };
    const b = [_]QM31{ one, zero, zero };

    try std.testing.expect((try eq(QM31, a[0..], a[0..])).eql(one));
    try std.testing.expect((try eq(QM31, a[0..], b[0..])).eql(zero));

    try std.testing.expectError(
        LookupUtilsError.ShapeMismatch,
        eq(QM31, a[0..2], b[0..]),
    );
}

test "lookups utils: fold mle evals" {
    const assignment = QM31.fromU32Unchecked(5, 0, 0, 0);
    const eval0 = M31.fromCanonical(3);
    const eval1 = M31.fromCanonical(11);

    const folded = foldMleEvals(M31, assignment, eval0, eval1);
    const expected = assignment
        .mul(QM31.fromBase(eval1.sub(eval0)))
        .add(QM31.fromBase(eval0));
    try std.testing.expect(folded.eql(expected));
}

test "lookups utils: reciprocal arithmetic" {
    const ReciprocalM31 = Reciprocal(M31);

    const a = ReciprocalM31.new(M31.fromCanonical(3));
    const b = ReciprocalM31.new(M31.fromCanonical(5));

    const add_res = a.add(b);
    try std.testing.expect(add_res.numerator.eql(M31.fromCanonical(8)));
    try std.testing.expect(add_res.denominator.eql(M31.fromCanonical(15)));

    const sub_res = a.sub(b);
    try std.testing.expect(sub_res.numerator.eql(M31.fromCanonical(2)));
    try std.testing.expect(sub_res.denominator.eql(M31.fromCanonical(15)));
}
