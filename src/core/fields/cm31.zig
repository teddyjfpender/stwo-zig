const std = @import("std");
const m31 = @import("m31.zig");

const M31 = m31.M31;

/// (2^31 - 1)^2.
pub const P2: u64 = 4_611_686_014_132_420_609;

/// Complex extension field over M31.
///
/// Representation:
/// - `a + bi`, where `a,b in M31`.
///
/// Invariants:
/// - `a` and `b` are always canonical M31 elements.
///
/// Failure modes:
/// - `inv` / `div` fail with `DivisionByZero` for the zero element.
/// - `tryIntoM31` fails with `NonBaseField` when the imaginary part is non-zero.
pub const CM31 = struct {
    a: M31,
    b: M31,

    pub const Error = error{
        DivisionByZero,
        NonBaseField,
    };

    pub inline fn zero() CM31 {
        return .{ .a = M31.zero(), .b = M31.zero() };
    }

    pub inline fn one() CM31 {
        return .{ .a = M31.one(), .b = M31.zero() };
    }

    pub inline fn fromU32Unchecked(a: u32, b: u32) CM31 {
        std.debug.assert(a < m31.Modulus);
        std.debug.assert(b < m31.Modulus);
        return .{
            .a = M31.fromCanonical(a),
            .b = M31.fromCanonical(b),
        };
    }

    pub inline fn fromM31(a: M31, b: M31) CM31 {
        return .{ .a = a, .b = b };
    }

    pub inline fn fromBase(x: M31) CM31 {
        return .{ .a = x, .b = M31.zero() };
    }

    pub inline fn isZero(self: CM31) bool {
        return self.a.isZero() and self.b.isZero();
    }

    pub inline fn eql(lhs: CM31, rhs: CM31) bool {
        return lhs.a.eql(rhs.a) and lhs.b.eql(rhs.b);
    }

    pub inline fn add(lhs: CM31, rhs: CM31) CM31 {
        return .{
            .a = lhs.a.add(rhs.a),
            .b = lhs.b.add(rhs.b),
        };
    }

    pub inline fn addM31(lhs: CM31, rhs: M31) CM31 {
        return .{
            .a = lhs.a.add(rhs),
            .b = lhs.b,
        };
    }

    pub inline fn sub(lhs: CM31, rhs: CM31) CM31 {
        return .{
            .a = lhs.a.sub(rhs.a),
            .b = lhs.b.sub(rhs.b),
        };
    }

    pub inline fn subM31(lhs: CM31, rhs: M31) CM31 {
        return .{
            .a = lhs.a.sub(rhs),
            .b = lhs.b,
        };
    }

    pub inline fn neg(self: CM31) CM31 {
        return .{
            .a = self.a.neg(),
            .b = self.b.neg(),
        };
    }

    pub inline fn mul(lhs: CM31, rhs: CM31) CM31 {
        // (a + bi) * (c + di) = (ac - bd) + (ad + bc)i.
        return .{
            .a = lhs.a.mul(rhs.a).sub(lhs.b.mul(rhs.b)),
            .b = lhs.a.mul(rhs.b).add(lhs.b.mul(rhs.a)),
        };
    }

    pub inline fn mulM31(lhs: CM31, rhs: M31) CM31 {
        return .{
            .a = lhs.a.mul(rhs),
            .b = lhs.b.mul(rhs),
        };
    }

    pub inline fn square(self: CM31) CM31 {
        return self.mul(self);
    }

    pub fn pow(self: CM31, exponent: u64) CM31 {
        var base = self;
        var e = exponent;
        var acc = CM31.one();
        while (e != 0) : (e >>= 1) {
            if ((e & 1) != 0) acc = acc.mul(base);
            base = base.square();
        }
        return acc;
    }

    pub fn inv(self: CM31) Error!CM31 {
        if (self.isZero()) return Error.DivisionByZero;
        const denom = self.a.square().add(self.b.square());
        const inv_denom = denom.inv() catch return Error.DivisionByZero;
        return .{
            .a = self.a.mul(inv_denom),
            .b = self.b.neg().mul(inv_denom),
        };
    }

    pub fn div(lhs: CM31, rhs: CM31) Error!CM31 {
        const inv_rhs = try rhs.inv();
        return lhs.mul(inv_rhs);
    }

    pub fn divM31(lhs: CM31, rhs: M31) Error!CM31 {
        const inv_rhs = rhs.inv() catch return Error.DivisionByZero;
        return lhs.mulM31(inv_rhs);
    }

    pub inline fn complexConjugate(self: CM31) CM31 {
        return .{
            .a = self.a,
            .b = self.b.neg(),
        };
    }

    pub fn tryIntoM31(self: CM31) Error!M31 {
        if (!self.b.isZero()) return Error.NonBaseField;
        return self.a;
    }

    pub fn format(
        self: CM31,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{} + {}i", .{ self.a, self.b });
    }
};

fn randElem(rng: std.Random) CM31 {
    while (true) {
        const a = rng.int(u32) & m31.Modulus;
        const b = rng.int(u32) & m31.Modulus;
        if (a != m31.Modulus and b != m31.Modulus) {
            return CM31.fromU32Unchecked(a, b);
        }
    }
}

test "cm31: inverse" {
    const x = CM31.fromU32Unchecked(1, 2);
    const inv_x = try x.inv();
    try std.testing.expect(x.mul(inv_x).eql(CM31.one()));

    try std.testing.expectError(CM31.Error.DivisionByZero, CM31.zero().inv());
}

test "cm31: basic ops parity sanity" {
    const p = m31.Modulus;
    const x = CM31.fromU32Unchecked(1, 2);
    const y = CM31.fromU32Unchecked(4, 5);
    const m = M31.fromCanonical(8);
    const x_mul_y = CM31.fromU32Unchecked(p - 6, 13);

    try std.testing.expect(x.add(y).eql(CM31.fromU32Unchecked(5, 7)));
    try std.testing.expect(y.addM31(m).eql(y.add(CM31.fromBase(m))));
    try std.testing.expect(x.mul(y).eql(x_mul_y));
    try std.testing.expect(y.mulM31(m).eql(y.mul(CM31.fromBase(m))));
    try std.testing.expect(x.neg().eql(CM31.fromU32Unchecked(p - 1, p - 2)));
    try std.testing.expect(x.sub(y).eql(CM31.fromU32Unchecked(p - 3, p - 3)));
    try std.testing.expect(y.subM31(m).eql(y.sub(CM31.fromBase(m))));
    try std.testing.expect((try x_mul_y.div(y)).eql(CM31.fromU32Unchecked(1, 2)));
    try std.testing.expect((try y.divM31(m)).eql(try y.div(CM31.fromBase(m))));
}

test "cm31: randomized field laws" {
    var prng = std.Random.DefaultPrng.init(0x9c0f_8411_06f4_8ea3);
    const rng = prng.random();

    var i: usize = 0;
    while (i < 5_000) : (i += 1) {
        const a = randElem(rng);
        const b = randElem(rng);
        const c = randElem(rng);

        try std.testing.expect(a.add(b).eql(b.add(a)));
        try std.testing.expect(a.mul(b).eql(b.mul(a)));
        try std.testing.expect(a.add(b).add(c).eql(a.add(b.add(c))));
        try std.testing.expect(a.mul(b).mul(c).eql(a.mul(b.mul(c))));
        try std.testing.expect(a.mul(b.add(c)).eql(a.mul(b).add(a.mul(c))));

        if (!a.isZero()) {
            const inv_a = try a.inv();
            try std.testing.expect(a.mul(inv_a).eql(CM31.one()));
        }
    }
}
