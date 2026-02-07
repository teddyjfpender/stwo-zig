const std = @import("std");
const fields = @import("fields/mod.zig");

const M31 = fields.m31.M31;
const CM31 = fields.cm31.CM31;
const QM31 = fields.qm31.QM31;

/// Projective fraction `numerator / denominator`.
pub fn Fraction(comptime N: type, comptime D: type) type {
    return struct {
        numerator: N,
        denominator: D,

        const Self = @This();

        pub inline fn new(numerator: N, denominator: D) Self {
            return .{
                .numerator = numerator,
                .denominator = denominator,
            };
        }

        pub fn add(self: Self, rhs: Self) Fraction(D, D) {
            const numerator = addDN(
                D,
                D,
                mulDN(D, N, rhs.denominator, self.numerator),
                mulDN(D, N, self.denominator, rhs.numerator),
            );
            const denominator = mulDD(D, self.denominator, rhs.denominator);
            return Fraction(D, D).new(numerator, denominator);
        }

        pub inline fn zero() Self {
            return .{
                .numerator = N.zero(),
                .denominator = D.one(),
            };
        }

        pub inline fn isZero(self: Self) bool {
            return self.numerator.isZero() and !self.denominator.isZero();
        }
    };
}

/// Sums fractions left-to-right; returns `zero` for an empty slice.
pub fn sumFractions(comptime N: type, comptime D: type, values: []const Fraction(N, D)) Fraction(N, D) {
    if (values.len == 0) return Fraction(N, D).zero();
    var acc = values[0];
    for (values[1..]) |v| {
        acc = acc.add(v);
    }
    return acc;
}

fn mulDD(comptime D: type, lhs: D, rhs: D) D {
    return lhs.mul(rhs);
}

fn addDN(comptime D: type, comptime N: type, lhs: D, rhs: N) D {
    if (D == N) return lhs.add(rhs);
    if (D == CM31 and N == M31) return lhs.addM31(rhs);
    if (D == QM31 and N == M31) return lhs.addM31(rhs);
    @compileError("unsupported D + N combination in Fraction");
}

fn mulDN(comptime D: type, comptime N: type, lhs: D, rhs: N) D {
    if (D == N) return lhs.mul(rhs);
    if (D == CM31 and N == M31) return lhs.mulM31(rhs);
    if (D == QM31 and N == M31) return lhs.mulM31(rhs);
    @compileError("unsupported D * N combination in Fraction");
}

test "fraction: m31 projective addition" {
    const F = Fraction(M31, M31);
    const a = F.new(M31.fromCanonical(1), M31.fromCanonical(2));
    const b = F.new(M31.fromCanonical(1), M31.fromCanonical(3));
    const sum = a.add(b);

    try std.testing.expect(sum.numerator.eql(M31.fromCanonical(5)));
    try std.testing.expect(sum.denominator.eql(M31.fromCanonical(6)));
}

test "fraction: m31 over qm31 denominator" {
    const F = Fraction(M31, QM31);
    const f0 = F.new(M31.fromCanonical(7), QM31.fromBase(M31.fromCanonical(11)));
    const f1 = F.new(M31.fromCanonical(13), QM31.fromBase(M31.fromCanonical(17)));

    const sum = f0.add(f1);
    const expected_num = QM31.fromBase(M31.fromCanonical(17))
        .mulM31(M31.fromCanonical(7))
        .addM31(M31.fromCanonical(11).mul(M31.fromCanonical(13)));
    const expected_den = QM31.fromBase(M31.fromCanonical(11)).mul(QM31.fromBase(M31.fromCanonical(17)));

    try std.testing.expect(sum.numerator.eql(expected_num));
    try std.testing.expect(sum.denominator.eql(expected_den));
}

test "fraction: zero and sum" {
    const F = Fraction(M31, M31);
    const z = F.zero();
    try std.testing.expect(z.isZero());

    const values = [_]F{
        F.new(M31.fromCanonical(1), M31.fromCanonical(2)),
        F.new(M31.fromCanonical(1), M31.fromCanonical(2)),
    };
    const total = sumFractions(M31, M31, values[0..]);
    try std.testing.expect(total.numerator.eql(M31.one()));
    try std.testing.expect(total.denominator.eql(M31.fromCanonical(4)));
}
