//! Additive degree-eight candidate, not a selected proof/security protocol.
//! OM31=QM31[v]/(v²-u), where u²=2+i. Norm_QM31/M31(u)=5 is a
//! nonsquare for p=2^31-1, so the new quadratic is irreducible.
const std = @import("std");
const m31 = @import("m31.zig");
const qm31 = @import("qm31.zig");
const M31 = m31.M31;
const Q = qm31.QM31;
pub const SECURE_EXTENSION_DEGREE = 8;
pub const ORDER: u256 = @as(u256, qm31.P4) * qm31.P4;
pub const NONRESIDUE = Q.fromU32Unchecked(0, 0, 1, 0);

/// Small shared arithmetic authority for native, packed and circuit pairs.
/// Ops owns only inner-field specializations (square, fixed-u multiply, scale,
/// inverse); this does not genericize a frontend or change any proof schema.
pub fn Quadratic(comptime F: type, comptime Ops: type) type {
    return struct {
        c0: F,
        c1: F,
        const Self = @This();
        pub fn zero() Self {
            return .{ .c0 = F.zero(), .c1 = F.zero() };
        }
        pub fn one() Self {
            return .{ .c0 = F.one(), .c1 = F.zero() };
        }
        pub fn basis() Self {
            return .{ .c0 = F.zero(), .c1 = F.one() };
        }
        pub fn fromBase(value: anytype) Self {
            return .{ .c0 = F.fromBase(value), .c1 = F.zero() };
        }
        pub fn fromInner(value: F) Self {
            return .{ .c0 = value, .c1 = F.zero() };
        }
        pub fn add(a: Self, b: Self) Self {
            return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
        }
        pub fn sub(a: Self, b: Self) Self {
            return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
        }
        pub fn neg(a: Self) Self {
            return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg() };
        }
        pub fn conjugate(a: Self) Self {
            return .{ .c0 = a.c0, .c1 = a.c1.neg() };
        }
        pub fn mul(a: Self, b: Self) Self {
            const ac = a.c0.mul(b.c0);
            const bd = a.c1.mul(b.c1);
            const cross = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(ac).sub(bd);
            return .{ .c0 = ac.add(Ops.mulByU(bd)), .c1 = cross };
        }
        pub fn square(a: Self) Self {
            const ab = a.c0.mul(a.c1);
            return .{ .c0 = Ops.square(a.c0).add(Ops.mulByU(Ops.square(a.c1))), .c1 = ab.add(ab) };
        }
        pub fn norm(a: Self) F {
            return Ops.square(a.c0).sub(Ops.mulByU(Ops.square(a.c1)));
        }
        pub fn mulInner(a: Self, b: F) Self {
            return .{ .c0 = a.c0.mul(b), .c1 = a.c1.mul(b) };
        }
        pub fn mulBase(a: Self, b: anytype) Self {
            return .{ .c0 = Ops.scale(a.c0, b), .c1 = Ops.scale(a.c1, b) };
        }
    };
}
pub const NativeOps = struct {
    pub fn mulByU(x: Q) Q {
        // (a+bu)u=(2+i)b+au: fixed-coordinate map, no general Q product.
        const b = x.c1;
        return .{ .c0 = .{ .a = b.a.add(b.a).sub(b.b), .b = b.a.add(b.b.add(b.b)) }, .c1 = x.c0 };
    }
    pub fn square(x: Q) Q {
        return x.square();
    }
    pub fn scale(x: Q, b: M31) Q {
        return x.mulM31(b);
    }
    pub fn inverse(x: Q) Q.Error!Q {
        return x.inv();
    }
};
pub const OM31 = struct {
    c0: Q,
    c1: Q,
    pub const InnerField = Q;
    const Self = @This();
    const A = Quadratic(Q, NativeOps);
    inline fn arithmetic(x: Self) A {
        return .{ .c0 = x.c0, .c1 = x.c1 };
    }
    inline fn wrap(x: A) Self {
        return .{ .c0 = x.c0, .c1 = x.c1 };
    }
    pub fn zero() Self {
        return wrap(A.zero());
    }
    pub fn one() Self {
        return wrap(A.one());
    }
    pub fn basis() Self {
        return wrap(A.basis());
    }
    pub fn fromBase(x: M31) Self {
        return wrap(A.fromBase(x));
    }
    pub fn fromInner(x: Q) Self {
        return wrap(A.fromInner(x));
    }
    pub fn add(x: Self, y: Self) Self {
        return wrap(arithmetic(x).add(arithmetic(y)));
    }
    pub fn sub(x: Self, y: Self) Self {
        return wrap(arithmetic(x).sub(arithmetic(y)));
    }
    pub fn mul(x: Self, y: Self) Self {
        return wrap(arithmetic(x).mul(arithmetic(y)));
    }
    pub fn square(x: Self) Self {
        return wrap(arithmetic(x).square());
    }
    pub fn neg(x: Self) Self {
        return wrap(arithmetic(x).neg());
    }
    pub fn conjugate(x: Self) Self {
        return wrap(arithmetic(x).conjugate());
    }
    /// Frobenius p^4, fixing QM31. This is not QM31's p^2 involution.
    pub fn quadraticConjugate(x: Self) Self {
        return x.conjugate();
    }
    pub fn norm(x: Self) Q {
        return arithmetic(x).norm();
    }
    pub fn mulInner(x: Self, y: Q) Self {
        return wrap(arithmetic(x).mulInner(y));
    }
    pub fn mulBase(x: Self, y: M31) Self {
        return wrap(arithmetic(x).mulBase(y));
    }
    pub fn mulM31(x: Self, y: M31) Self {
        return x.mulBase(y);
    }
    pub fn inv(a: Self) !Self {
        return a.conjugate().mulInner(try NativeOps.inverse(a.norm()));
    }
    pub fn div(a: Self, b: Self) !Self {
        return a.mul(try b.inv());
    }
    pub fn isZero(a: Self) bool {
        return a.c0.isZero() and a.c1.isZero();
    }
    pub fn eql(a: Self, b: Self) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }
    pub fn pow(a: Self, exponent: u256) Self {
        var power = a;
        var result = one();
        var e = exponent;
        while (e != 0) : (e >>= 1) {
            if (e & 1 != 0) result = result.mul(power);
            power = power.square();
        }
        return result;
    }
    pub fn fromM31Array(v: [8]M31) Self {
        return .{ .c0 = Q.fromM31Array(v[0..4].*), .c1 = Q.fromM31Array(v[4..8].*) };
    }
    pub fn toM31Array(a: Self) [8]M31 {
        return a.c0.toM31Array() ++ a.c1.toM31Array();
    }
    pub fn toBytesLe(a: Self) [32]u8 {
        var bytes: [32]u8 = undefined;
        for (a.toM31Array(), 0..) |v, i| std.mem.writeInt(u32, bytes[4 * i ..][0..4], v.v, .little);
        return bytes;
    }
    pub fn fromBytesLe(bytes: *const [32]u8) error{NonCanonicalField}!Self {
        var coordinates: [8]M31 = undefined;
        for (&coordinates, 0..) |*v, i| {
            const x = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
            if (x >= m31.Modulus) return error.NonCanonicalField;
            v.* = M31.fromCanonical(x);
        }
        return fromM31Array(coordinates);
    }
};

/// Bounded caller-owned, non-destructive norm batch. Scratch is exactly2n Q
/// values; the current optimized Q norm inverter is reused. All planes must
/// be disjoint. Zero/geometry failures occur before writing the output.
pub fn invertScaled(input: []const OM31, output: []OM31, scratch: []Q, scales: []const M31) !void {
    const n = try validateBatch(input, output, scratch, scales);
    const norms = scratch[0..n];
    const inverses = scratch[n..];
    for (input, norms) |x, *norm| norm.* = x.norm();
    try @import("qm31_norm_batch.zig").invertScaledOwned(norms, inverses, scales);
    for (input, inverses, output) |x, inverse, *out| out.* = x.conjugate().mulInner(inverse);
}
/// Same bounded API, with native-width SIMD norm and cofactor phases.
/// This remains opt-in until qualified measurements justify its use.
pub fn invertScaledPacked(input: []const OM31, output: []OM31, scratch: []Q, scales: []const M31) !void {
    const n = try validateBatch(input, output, scratch, scales);
    const packed_fields = @import("packed_om31.zig");
    const PackedQ = @import("packed_qm31.zig").PackedQM31;
    const width = m31.PACK_WIDTH;
    const norms = scratch[0..n];
    const inverses = scratch[n..];
    var first: usize = 0;
    while (first + width <= n) : (first += width) {
        const norm = packed_fields.loadNative(input[first..][0..width]).norm();
        inline for (0..width) |j| norms[first + j] = norm.lane(j);
    }
    for (input[first..], norms[first..]) |x, *norm| norm.* = x.norm();
    try @import("qm31_norm_batch.zig").invertScaledOwned(norms, inverses, scales);
    first = 0;
    while (first + width <= n) : (first += width) {
        const inverse = PackedQ.fromLanes(inverses[first..][0..width].*);
        const product = packed_fields.loadNative(input[first..][0..width]).conjugate().mulInner(inverse);
        packed_fields.storeNative(output[first..][0..width], product);
    }
    for (input[first..], inverses[first..], output[first..]) |x, inverse, *out| out.* = x.conjugate().mulInner(inverse);
}
fn validateBatch(input: []const OM31, output: []OM31, scratch: []Q, scales: []const M31) !usize {
    const n = input.len;
    if (output.len != n or scales.len != n or n > std.math.maxInt(usize) / 2 or scratch.len != 2 * n) return error.InvalidBatchGeometry;
    if (overlap(input, output) or overlap(input, scratch) or overlap(input, scales) or overlap(output, scratch) or overlap(output, scales) or overlap(scratch, scales)) return error.InvalidBatchGeometry;
    for (input) |x| if (x.isZero()) return error.DivisionByZero;
    return n;
}
fn overlap(a: anytype, b: anytype) bool {
    if (a.len == 0 or b.len == 0) return false;
    const x = @intFromPtr(a.ptr);
    const y = @intFromPtr(b.ptr);
    return x < y + b.len * @sizeOf(@TypeOf(b[0])) and y < x + a.len * @sizeOf(@TypeOf(a[0]));
}
