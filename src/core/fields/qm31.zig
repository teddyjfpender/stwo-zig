const std = @import("std");
const cm31_mod = @import("cm31.zig");
const m31_mod = @import("m31.zig");

const CM31 = cm31_mod.CM31;
const M31 = m31_mod.M31;

/// (2^31 - 1)^4.
pub const P4: u128 = 21_267_647_892_944_572_736_998_860_269_687_930_881;

/// Irreducible polynomial constant for the quadratic extension over CM31.
pub const R: CM31 = CM31.fromU32Unchecked(2, 1);

/// Number of base-field coefficients in QM31.
pub const SECURE_EXTENSION_DEGREE: usize = 4;

/// Quadratic extension field over CM31.
///
/// Representation:
/// - `(a + bi) + (c + di)u`, with `u^2 = 2 + i`.
///
/// Invariants:
/// - `c0` and `c1` are canonical CM31 values.
///
/// Failure modes:
/// - `inv` / `div` fail with `DivisionByZero` for the zero element.
/// - `tryIntoM31` fails with `NonBaseField` when not in the base field.
pub const QM31 = struct {
    c0: CM31,
    c1: CM31,

    pub const Error = error{
        DivisionByZero,
        NonBaseField,
    };

    pub inline fn zero() QM31 {
        return .{ .c0 = CM31.zero(), .c1 = CM31.zero() };
    }

    pub inline fn one() QM31 {
        return .{ .c0 = CM31.one(), .c1 = CM31.zero() };
    }

    pub inline fn fromU32Unchecked(a: u32, b: u32, c: u32, d: u32) QM31 {
        return .{
            .c0 = CM31.fromU32Unchecked(a, b),
            .c1 = CM31.fromU32Unchecked(c, d),
        };
    }

    pub inline fn fromM31(a: M31, b: M31, c: M31, d: M31) QM31 {
        return .{
            .c0 = CM31.fromM31(a, b),
            .c1 = CM31.fromM31(c, d),
        };
    }

    pub inline fn fromBase(x: M31) QM31 {
        return .{ .c0 = CM31.fromBase(x), .c1 = CM31.zero() };
    }

    pub inline fn fromM31Array(v: [SECURE_EXTENSION_DEGREE]M31) QM31 {
        return fromM31(v[0], v[1], v[2], v[3]);
    }

    pub inline fn toM31Array(self: QM31) [SECURE_EXTENSION_DEGREE]M31 {
        return .{ self.c0.a, self.c0.b, self.c1.a, self.c1.b };
    }

    /// Combines partial evaluations of base-field components into one QM31 value.
    pub fn fromPartialEvals(evals: [SECURE_EXTENSION_DEGREE]QM31) QM31 {
        var out = evals[0];
        out = out.add(evals[1].mul(QM31.fromU32Unchecked(0, 1, 0, 0)));
        out = out.add(evals[2].mul(QM31.fromU32Unchecked(0, 0, 1, 0)));
        out = out.add(evals[3].mul(QM31.fromU32Unchecked(0, 0, 0, 1)));
        return out;
    }

    pub inline fn mulCM31(self: QM31, rhs: CM31) QM31 {
        return .{
            .c0 = self.c0.mul(rhs),
            .c1 = self.c1.mul(rhs),
        };
    }

    pub inline fn isZero(self: QM31) bool {
        return self.c0.isZero() and self.c1.isZero();
    }

    pub inline fn eql(lhs: QM31, rhs: QM31) bool {
        return lhs.c0.eql(rhs.c0) and lhs.c1.eql(rhs.c1);
    }

    pub inline fn add(lhs: QM31, rhs: QM31) QM31 {
        return .{
            .c0 = lhs.c0.add(rhs.c0),
            .c1 = lhs.c1.add(rhs.c1),
        };
    }

    pub inline fn addM31(lhs: QM31, rhs: M31) QM31 {
        return .{
            .c0 = lhs.c0.addM31(rhs),
            .c1 = lhs.c1,
        };
    }

    pub inline fn sub(lhs: QM31, rhs: QM31) QM31 {
        return .{
            .c0 = lhs.c0.sub(rhs.c0),
            .c1 = lhs.c1.sub(rhs.c1),
        };
    }

    pub inline fn subM31(lhs: QM31, rhs: M31) QM31 {
        return .{
            .c0 = lhs.c0.subM31(rhs),
            .c1 = lhs.c1,
        };
    }

    pub inline fn neg(self: QM31) QM31 {
        return .{
            .c0 = self.c0.neg(),
            .c1 = self.c1.neg(),
        };
    }

    pub inline fn mul(lhs: QM31, rhs: QM31) QM31 {
        // Karatsuba over CM31:
        // (a + bu) * (c + du) = (ac + rbd) + ((a+b)(c+d)-ac-bd)u.
        const ac = lhs.c0.mul(rhs.c0);
        const bd = lhs.c1.mul(rhs.c1);
        const cross = lhs.c0.add(lhs.c1).mul(rhs.c0.add(rhs.c1)).sub(ac).sub(bd);
        return .{
            .c0 = ac.add(mulByR(bd)),
            .c1 = cross,
        };
    }

    pub inline fn mulM31(lhs: QM31, rhs: M31) QM31 {
        return .{
            .c0 = lhs.c0.mulM31(rhs),
            .c1 = lhs.c1.mulM31(rhs),
        };
    }

    pub inline fn square(self: QM31) QM31 {
        const a2 = self.c0.square();
        const b2 = self.c1.square();
        const ab = self.c0.mul(self.c1);
        return .{
            .c0 = a2.add(mulByR(b2)),
            .c1 = ab.add(ab),
        };
    }

    pub fn pow(self: QM31, exponent: u64) QM31 {
        var base = self;
        var e = exponent;
        var acc = QM31.one();
        while (e != 0) : (e >>= 1) {
            if ((e & 1) != 0) acc = acc.mul(base);
            base = base.square();
        }
        return acc;
    }

    pub fn inv(self: QM31) Error!QM31 {
        if (self.isZero()) return Error.DivisionByZero;

        // (a + bu)^-1 = (a - bu) / (a^2 - (2+i)b^2).
        const b2 = self.c1.square();
        const ib2 = mulByI(b2);
        const denom = self.c0.square().sub(b2.add(b2).add(ib2));
        if (denom.isZero()) return Error.DivisionByZero;
        const denom_inverse = denom.invUncheckedNonZero();
        return .{
            .c0 = self.c0.mul(denom_inverse),
            .c1 = self.c1.neg().mul(denom_inverse),
        };
    }

    pub fn div(lhs: QM31, rhs: QM31) Error!QM31 {
        const inv_rhs = try rhs.inv();
        return lhs.mul(inv_rhs);
    }

    pub fn divM31(lhs: QM31, rhs: M31) Error!QM31 {
        const inv_rhs = rhs.inv() catch return Error.DivisionByZero;
        return lhs.mulM31(inv_rhs);
    }

    pub inline fn complexConjugate(self: QM31) QM31 {
        return .{
            .c0 = self.c0,
            .c1 = self.c1.neg(),
        };
    }

    pub fn tryIntoM31(self: QM31) Error!M31 {
        if (!self.c1.isZero()) return Error.NonBaseField;
        return self.c0.tryIntoM31() catch return Error.NonBaseField;
    }

    pub fn format(
        self: QM31,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("({}) + ({})u", .{ self.c0, self.c1 });
    }
};

fn randM31(rng: std.Random) M31 {
    while (true) {
        const x = rng.int(u32) & m31_mod.Modulus;
        if (x != m31_mod.Modulus) return M31.fromCanonical(x);
    }
}

fn randElem(rng: std.Random) QM31 {
    return QM31.fromM31(randM31(rng), randM31(rng), randM31(rng), randM31(rng));
}

fn mulByR(value: CM31) CM31 {
    // (a + bi) * (2 + i) = (2a - b) + (a + 2b)i.
    const two_a = value.a.add(value.a);
    const two_b = value.b.add(value.b);
    return .{
        .a = two_a.sub(value.b),
        .b = value.a.add(two_b),
    };
}

fn mulByI(value: CM31) CM31 {
    return .{
        .a = value.b.neg(),
        .b = value.a,
    };
}

fn mulReference(lhs: QM31, rhs: QM31) QM31 {
    return .{
        .c0 = lhs.c0.mul(rhs.c0).add(R.mul(lhs.c1).mul(rhs.c1)),
        .c1 = lhs.c0.mul(rhs.c1).add(lhs.c1.mul(rhs.c0)),
    };
}

fn squareReference(value: QM31) QM31 {
    return mulReference(value, value);
}

test "qm31: mul and square match schoolbook reference" {
    var prng = std.Random.DefaultPrng.init(0x0b6e_c8a1_3158_44af);
    const rng = prng.random();

    var i: usize = 0;
    while (i < 3_000) : (i += 1) {
        const a = randElem(rng);
        const b = randElem(rng);
        try std.testing.expect(a.mul(b).eql(mulReference(a, b)));
        try std.testing.expect(a.square().eql(squareReference(a)));
    }
}

test "qm31: inverse" {
    const x = QM31.fromU32Unchecked(1, 2, 3, 4);
    const inv_x = try x.inv();
    try std.testing.expect(x.mul(inv_x).eql(QM31.one()));

    try std.testing.expectError(QM31.Error.DivisionByZero, QM31.zero().inv());
}

test "qm31: basic ops parity sanity" {
    const p = m31_mod.Modulus;
    const x = QM31.fromU32Unchecked(1, 2, 3, 4);
    const y = QM31.fromU32Unchecked(4, 5, 6, 7);
    const m = M31.fromCanonical(8);
    const x_mul_y = QM31.fromU32Unchecked(p - 71, 93, p - 16, 50);

    try std.testing.expect(x.add(y).eql(QM31.fromU32Unchecked(5, 7, 9, 11)));
    try std.testing.expect(y.addM31(m).eql(y.add(QM31.fromBase(m))));
    try std.testing.expect(x.mul(y).eql(x_mul_y));
    try std.testing.expect(y.mulM31(m).eql(y.mul(QM31.fromBase(m))));
    try std.testing.expect(x.neg().eql(QM31.fromU32Unchecked(p - 1, p - 2, p - 3, p - 4)));
    try std.testing.expect(x.sub(y).eql(QM31.fromU32Unchecked(p - 3, p - 3, p - 3, p - 3)));
    try std.testing.expect(y.subM31(m).eql(y.sub(QM31.fromBase(m))));
    try std.testing.expect((try x_mul_y.div(y)).eql(QM31.fromU32Unchecked(1, 2, 3, 4)));
    try std.testing.expect((try y.divM31(m)).eql(try y.div(QM31.fromBase(m))));
}

test "qm31: m31 array roundtrip" {
    const x = QM31.fromU32Unchecked(10, 20, 30, 40);
    const arr = x.toM31Array();
    const y = QM31.fromM31Array(arr);
    try std.testing.expect(x.eql(y));
}

test "qm31: randomized field laws" {
    var prng = std.Random.DefaultPrng.init(0x7cf5_6f15_72c0_021b);
    const rng = prng.random();

    var i: usize = 0;
    while (i < 2_000) : (i += 1) {
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
            try std.testing.expect(a.mul(inv_a).eql(QM31.one()));
        }
    }
}
