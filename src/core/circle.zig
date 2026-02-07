const std = @import("std");
const m31 = @import("fields/m31.zig");

const M31 = m31.M31;

/// A point on the unit circle: x^2 + y^2 = 1 over F_p.
///
/// Group law is complex multiplication.
pub const Point = struct {
    x: M31,
    y: M31,

    pub inline fn identity() Point {
        return .{ .x = M31.one(), .y = M31.zero() };
    }

    pub inline fn negOne() Point {
        return .{ .x = M31.fromCanonical(m31.Modulus - 1), .y = M31.zero() };
    }

    pub inline fn inv(self: Point) Point {
        // Inverse: conjugate on the circle.
        return .{ .x = self.x, .y = self.y.neg() };
    }

    pub inline fn isOnCircle(self: Point) bool {
        const lhs = self.x.square().add(self.y.square());
        return lhs.eql(M31.one());
    }

    /// Group multiplication (complex multiplication).
    pub inline fn mul(a: Point, b: Point) Point {
        const x = a.x.mul(b.x).sub(a.y.mul(b.y));
        const y = a.x.mul(b.y).add(a.y.mul(b.x));
        return .{ .x = x, .y = y };
    }

    pub inline fn square(self: Point) Point {
        return mul(self, self);
    }

    /// Exponentiation in the circle group.
    pub fn pow(self: Point, exponent: u64) Point {
        var base = self;
        var e = exponent;
        var acc = Point.identity();
        while (e != 0) : (e >>= 1) {
            if ((e & 1) != 0) acc = acc.mul(base);
            base = base.square();
        }
        return acc;
    }

    pub fn format(
        self: Point,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("({}, {})", .{ self.x, self.y });
    }
};

/// A generator of the circle group of order 2^31.
///
/// Derived from tangent parameterization t=2:
///   x = (1 - t^2) / (1 + t^2) = -3/5
///   y = (2t)       / (1 + t^2) =  4/5
///
/// Over p = 2^31 - 1, this point has order exactly 2^31.
pub const GENERATOR: Point = .{
    .x = M31.fromCanonical(1717986917),
    .y = M31.fromCanonical(1288490189),
};

fn randExp(rng: std.rand.Random) u64 {
    // Sample a 31-bit exponent in [0, 2^31-1].
    return @as(u64, rng.int(u32)) & ((@as(u64, 1) << 31) - 1);
}

test "circle: generator is on circle" {
    try std.testing.expect(GENERATOR.isOnCircle());
    try std.testing.expect(Point.identity().isOnCircle());
    try std.testing.expect(Point.negOne().isOnCircle());
}

test "circle: generator order checks" {
    const g = GENERATOR;
    const g_2_30 = g.pow(@as(u64, 1) << 30);
    const g_2_31 = g.pow(@as(u64, 1) << 31);

    try std.testing.expect(g_2_30.x.eql(M31.fromCanonical(m31.Modulus - 1)));
    try std.testing.expect(g_2_30.y.isZero());

    try std.testing.expect(g_2_31.x.eql(M31.one()));
    try std.testing.expect(g_2_31.y.isZero());
}

test "circle: group law consistency via cyclic generator" {
    var prng = std.rand.DefaultPrng.init(0x0bad_f00d_dead_beef);
    const rng = prng.random();

    const g = GENERATOR;
    const order_mask: u64 = (@as(u64, 1) << 31) - 1;

    var i: usize = 0;
    while (i < 5000) : (i += 1) {
        const a = randExp(rng);
        const b = randExp(rng);

        const lhs = g.pow(a).mul(g.pow(b));
        const rhs = g.pow((a + b) & order_mask);

        try std.testing.expect(lhs.x.eql(rhs.x));
        try std.testing.expect(lhs.y.eql(rhs.y));

        // inverse
        const p = g.pow(a);
        const inv_p = p.inv();
        const id = p.mul(inv_p);
        try std.testing.expect(id.x.eql(M31.one()));
        try std.testing.expect(id.y.isZero());
    }
}
