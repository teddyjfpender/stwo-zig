const std = @import("std");

/// The prime modulus p = 2^31 - 1.
pub const Modulus: u32 = 0x7fffffff;

/// An element of F_p where p = 2^31 - 1.
///
/// Representation invariant: `v` is always canonical in `[0, p-1]`.
pub const M31 = struct {
    v: u32,

    pub const Error = error{
        DivisionByZero,
        NonCanonical,
    };

    pub inline fn zero() M31 {
        return .{ .v = 0 };
    }

    pub inline fn one() M31 {
        return .{ .v = 1 };
    }

    /// Construct from a canonical representative in `[0, p-1]`.
    pub inline fn fromCanonical(x: u32) M31 {
        std.debug.assert(x < Modulus);
        return .{ .v = x };
    }

    /// Reduce an unsigned integer into F_p.
    pub inline fn fromU64(x: u64) M31 {
        return .{ .v = reduce64(x) };
    }

    pub inline fn isZero(self: M31) bool {
        return self.v == 0;
    }

    pub inline fn isOne(self: M31) bool {
        return self.v == 1;
    }

    pub inline fn eql(a: M31, b: M31) bool {
        return a.v == b.v;
    }

    pub inline fn add(a: M31, b: M31) M31 {
        var s: u32 = a.v + b.v;
        if (s >= Modulus) s -= Modulus;
        return .{ .v = s };
    }

    pub inline fn sub(a: M31, b: M31) M31 {
        if (a.v >= b.v) {
            return .{ .v = a.v - b.v };
        }
        return .{ .v = (a.v + Modulus) - b.v };
    }

    pub inline fn neg(a: M31) M31 {
        if (a.v == 0) return a;
        return .{ .v = Modulus - a.v };
    }

    pub inline fn mul(a: M31, b: M31) M31 {
        const prod: u64 = @as(u64, a.v) * @as(u64, b.v);
        return .{ .v = reduce64(prod) };
    }

    pub inline fn square(a: M31) M31 {
        return mul(a, a);
    }

    pub fn pow(a: M31, exponent: u64) M31 {
        var base = a;
        var e = exponent;
        var acc = M31.one();
        while (e != 0) : (e >>= 1) {
            if ((e & 1) != 0) acc = acc.mul(base);
            base = base.square();
        }
        return acc;
    }

    /// Multiplicative inverse.
    ///
    /// Errors if `self == 0`.
    pub fn inv(self: M31) Error!M31 {
        if (self.isZero()) return Error.DivisionByZero;
        // Fermat: a^(p-2)
        return self.pow(@as(u64, Modulus - 2));
    }

    pub fn div(a: M31, b: M31) Error!M31 {
        const inv_b = try b.inv();
        return a.mul(inv_b);
    }

    pub inline fn toU32(self: M31) u32 {
        return self.v;
    }

    pub fn toBytesLe(self: M31) [4]u8 {
        const x = self.v;
        return .{
            @intCast(x & 0xff),
            @intCast((x >> 8) & 0xff),
            @intCast((x >> 16) & 0xff),
            @intCast((x >> 24) & 0xff),
        };
    }

    pub fn fromBytesLe(bytes: [4]u8) Error!M31 {
        const x: u32 = (@as(u32, bytes[0])) |
            (@as(u32, bytes[1]) << 8) |
            (@as(u32, bytes[2]) << 16) |
            (@as(u32, bytes[3]) << 24);
        if (x >= Modulus) return Error.NonCanonical;
        return M31.fromCanonical(x);
    }

    /// Display helper for debugging.
    pub fn format(
        self: M31,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{}", .{self.v});
    }
};

/// Reduce a 64-bit integer modulo p = 2^31 - 1.
///
/// For x <= (p-1)^2 < 2^62, two Mersenne folds suffice.
fn reduce64(x: u64) u32 {
    const p: u64 = Modulus;
    var t: u64 = (x & p) + (x >> 31);
    t = (t & p) + (t >> 31);

    var r: u32 = @intCast(t);
    // t is in [0, p+1].
    if (r == Modulus) return 0;
    if (r > Modulus) return r - Modulus;
    return r;
}

fn randElem(rng: std.rand.Random) M31 {
    while (true) {
        const x = rng.int(u32) & Modulus;
        if (x != Modulus) return M31.fromCanonical(x);
    }
}

test "m31: canonical reduction" {
    const p = Modulus;
    try std.testing.expect(M31.fromU64(p).isZero());
    try std.testing.expectEqual(@as(u32, 1), M31.fromU64(p + 1).toU32());
    try std.testing.expect(M31.fromU64(@as(u64, 2) * p).isZero());
    try std.testing.expectEqual(@as(u32, 1), M31.fromU64(@as(u64, 2) * p + 1).toU32());
}

test "m31: basic identities" {
    const a = M31.fromCanonical(123456789);
    const b = M31.fromCanonical(987654321);

    try std.testing.expect(a.add(M31.zero()).eql(a));
    try std.testing.expect(a.mul(M31.one()).eql(a));
    try std.testing.expect(a.sub(a).isZero());
    try std.testing.expect(a.add(b).sub(b).eql(a));

    const minus_one = M31.fromCanonical(Modulus - 1);
    try std.testing.expect(minus_one.mul(minus_one).eql(M31.one()));
}

test "m31: inversion" {
    const a = M31.fromCanonical(7);
    const inv_a = try a.inv();
    try std.testing.expect(a.mul(inv_a).eql(M31.one()));

    try std.testing.expectError(M31.Error.DivisionByZero, M31.zero().inv());
}

test "m31: randomized ring laws" {
    var prng = std.rand.DefaultPrng.init(0x1234_5678_9abc_def0);
    const rng = prng.random();

    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        const a = randElem(rng);
        const b = randElem(rng);
        const c = randElem(rng);

        // Commutativity.
        try std.testing.expect(a.add(b).eql(b.add(a)));
        try std.testing.expect(a.mul(b).eql(b.mul(a)));

        // Associativity.
        try std.testing.expect(a.add(b).add(c).eql(a.add(b.add(c))));
        try std.testing.expect(a.mul(b).mul(c).eql(a.mul(b.mul(c))));

        // Distributivity.
        try std.testing.expect(a.mul(b.add(c)).eql(a.mul(b).add(a.mul(c))));

        // Inversion property for non-zero.
        if (!a.isZero()) {
            const inv_a = try a.inv();
            try std.testing.expect(a.mul(inv_a).eql(M31.one()));
        }
    }
}
