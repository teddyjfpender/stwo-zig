const std = @import("std");
const builtin = @import("builtin");

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

    /// Construct without checking canonicality, matching `CM31.fromU32Unchecked`
    /// and `QM31.fromU32Unchecked`.
    ///
    /// This exists for bulk readers that validate a whole run of borrowed
    /// words with one vector bound instead of one branch per element. A
    /// non-canonical value produces a deterministic wrong field element, never
    /// undefined behaviour, so the caller may defer its rejection to the end of
    /// the run as long as it discards the run's results.
    pub inline fn fromU32Unchecked(x: u32) M31 {
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

    pub inline fn complexConjugate(self: M31) M31 {
        return self;
    }

    pub inline fn mul(a: M31, b: M31) M31 {
        const prod: u64 = @as(u64, a.v) * @as(u64, b.v);
        return .{ .v = reduceProduct(prod) };
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
        return self.invUncheckedNonZero();
    }

    /// Multiplicative inverse for known non-zero elements.
    ///
    /// Preconditions:
    /// - `self != 0`.
    pub inline fn invUncheckedNonZero(self: M31) M31 {
        std.debug.assert(!self.isZero());
        return powPMinus2(self);
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
/// Two Mersenne folds reduce every `u64` input to at most `p + 3`. The
/// wrapping subtraction is then smaller exactly when canonicalization is
/// required, avoiding a compare/select chain on AArch64.
inline fn reduce64(x: u64) u32 {
    const p: u64 = Modulus;
    var t: u64 = (x & p) + (x >> 31);
    t = (t & p) + (t >> 31);

    const r: u32 = @intCast(t);
    return @min(r, r -% Modulus);
}

/// Reduce a product of two canonical M31 values. Unlike `reduce64`, the input
/// is strictly below p^2, so one Mersenne fold lands below 2p and a single
/// conditional subtraction canonicalizes it.
inline fn reduceProduct(x: u64) u32 {
    const p: u64 = Modulus;
    const folded = (x & p) + (x >> 31);
    const r: u32 = @intCast(folded);
    return if (r >= Modulus) r - Modulus else r;
}

// ---------------------------------------------------------------
// SIMD vectorized M31 operations (4-lane)
// ---------------------------------------------------------------

pub const VEC_WIDTH: usize = 4;
pub const Vec4u32 = @Vector(VEC_WIDTH, u32);
pub const Vec4u64 = @Vector(VEC_WIDTH, u64);
const P_VEC: Vec4u32 = @splat(Modulus);

/// Four-lane product reduction specialized for AArch64 AdvSIMD.
///
/// For canonical positive 31-bit inputs, SQDMULH computes exactly
/// `product >> 31`: its signed doubling cannot saturate below `(p - 1)^2`.
/// A regular lane-wise MUL supplies the low 31 bits. This expresses the
/// Mersenne fold in two full-width multiply instructions instead of widening
/// the low and high lane pairs separately.
inline fn mulVec4Aarch64(a: Vec4u32, b: Vec4u32) Vec4u32 {
    var low: Vec4u32 = undefined;
    var high: Vec4u32 = undefined;
    asm (
        \\mul %[low].4s, %[a].4s, %[b].4s
        \\sqdmulh %[high].4s, %[a].4s, %[b].4s
        : [low] "=&w" (low),
          [high] "=&w" (high),
        : [a] "w" (a),
          [b] "w" (b),
    );
    const folded = (low & P_VEC) +% high;
    return @min(folded, folded -% P_VEC);
}

/// Load four readable M31 values. Only M31's natural alignment is required;
/// alignment to the vector byte width is deliberately not a precondition.
pub inline fn loadVec4(ptr: [*]const M31) Vec4u32 {
    const raw: *const [VEC_WIDTH]u32 = @ptrCast(ptr);
    return raw.*;
}

/// Store four writable M31 values with the same natural-alignment contract as
/// `loadVec4`.
pub inline fn storeVec4(ptr: [*]M31, v: Vec4u32) void {
    const raw: *[VEC_WIDTH]u32 = @ptrCast(ptr);
    raw.* = v;
}

/// Vectorized M31 addition: (a + b) mod p, 4 lanes.
pub inline fn addVec4(a: Vec4u32, b: Vec4u32) Vec4u32 {
    const sum = a +% b;
    // Canonical inputs put `sum` below 2p.  In that range the wrapping
    // subtraction is larger when `sum < p` and smaller otherwise, so an
    // unsigned minimum performs the conditional reduction directly.  This
    // maps to one AdvSIMD UMIN instead of compare + mask + add on AArch64.
    if (comptime builtin.cpu.arch == .aarch64) {
        return @min(sum, sum -% P_VEC);
    }
    const geq_p = sum >= P_VEC;
    return @select(u32, geq_p, sum -% P_VEC, sum);
}

/// Vectorized M31 subtraction: (a - b) mod p, 4 lanes.
pub inline fn subVec4(a: Vec4u32, b: Vec4u32) Vec4u32 {
    if (comptime builtin.cpu.arch == .aarch64) {
        // Mirror of `addVec4`'s unsigned-minimum reduction. For canonical
        // `a, b`, the wrapping difference `d = a -% b` is either the true
        // difference in `[0, p)` -- in which case `d +% p` is in `[p, 2p)`,
        // does not wrap, and is larger -- or `a - b + 2^32`, which is at
        // least `2^32 - p + 1 > p`, in which case `d +% p` wraps to exactly
        // `a - b + p` in `[1, p)` and is smaller. The unsigned minimum
        // therefore selects the canonical difference in both cases, as one
        // SUB / ADD / UMIN triple instead of compare + mask + select.
        const d = a -% b;
        return @min(d, d +% P_VEC);
    }
    const lt = a < b;
    // If a < b, result = a + p - b; else result = a - b.
    return @select(u32, lt, (a +% P_VEC) -% b, a -% b);
}

/// Vectorized M31 multiplication: (a * b) mod p, 4 lanes.
/// Uses 64-bit intermediate products with Mersenne reduction.
pub inline fn mulVec4(a: Vec4u32, b: Vec4u32) Vec4u32 {
    if (comptime builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c) {
        return mulVec4Aarch64(a, b);
    }
    const a64: Vec4u64 = a;
    const b64: Vec4u64 = b;
    const prod = a64 * b64;
    return reduceProductVec4(prod);
}

/// Vector form of `reduceProduct`; every lane is a canonical product.
inline fn reduceProductVec4(x: Vec4u64) Vec4u32 {
    const p64: Vec4u64 = @splat(@as(u64, Modulus));
    const folded = (x & p64) + (x >> @splat(@as(u6, 31)));
    const r: Vec4u32 = @truncate(folded);
    if (comptime builtin.cpu.arch == .aarch64) {
        return @min(r, r -% P_VEC);
    }
    return @select(u32, r >= P_VEC, r -% P_VEC, r);
}

/// Vectorized Mersenne reduction: x mod (2^31 - 1), 4 lanes.
/// Two rounds of: t = (x & p) + (x >> 31).
inline fn reduceVec4(x: Vec4u64) Vec4u32 {
    const p64: Vec4u64 = @splat(@as(u64, Modulus));

    // Round 1
    var t = (x & p64) + (x >> @splat(@as(u6, 31)));
    // Round 2
    t = (t & p64) + (t >> @splat(@as(u6, 31)));

    const r: Vec4u32 = @truncate(t);
    // Conditional: if r == p -> 0, if r > p -> r - p, else r.
    const is_p = r == P_VEC;
    const gt_p = r > P_VEC;
    const adjusted = @select(u32, gt_p, r -% P_VEC, r);
    return @select(u32, is_p, @as(Vec4u32, @splat(0)), adjusted);
}

/// Vectorized butterfly over two disjoint four-element ranges. The operation
/// is in-place, handles no tail, and uses no caller or hidden heap scratch.
/// lhs[i] = lhs[i] + rhs[i]*twid, rhs[i] = lhs[i] - rhs[i]*twid.
pub inline fn butterflyVec4(lhs: [*]M31, rhs: [*]M31, twid: Vec4u32) void {
    std.debug.assert(disjointM31Ranges(lhs, rhs, VEC_WIDTH));
    const v0 = loadVec4(lhs);
    const v1 = loadVec4(rhs);
    const m = mulVec4(v1, twid);
    storeVec4(lhs, addVec4(v0, m));
    storeVec4(rhs, subVec4(v0, m));
}

/// Vectorized inverse butterfly over two disjoint four-element ranges. The
/// alignment, tail, and scratch contract matches `butterflyVec4`.
/// lhs[i] = lhs[i] + rhs[i], rhs[i] = (lhs[i] - rhs[i]) * itwid.
pub inline fn ibutterflyVec4(lhs: [*]M31, rhs: [*]M31, itwid: Vec4u32) void {
    std.debug.assert(disjointM31Ranges(lhs, rhs, VEC_WIDTH));
    const v0 = loadVec4(lhs);
    const v1 = loadVec4(rhs);
    storeVec4(lhs, addVec4(v0, v1));
    storeVec4(rhs, mulVec4(subVec4(v0, v1), itwid));
}

// ---------------------------------------------------------------
// SIMD vectorized M31 operations (hardware-native packed lanes)
// ---------------------------------------------------------------

/// Match the target's native SIMD width. A scalar lane keeps the same code path
/// available on targets where Zig does not recommend vectorization.
pub const PACK_WIDTH: usize = std.simd.suggestVectorLength(u32) orelse 1;
pub const PackedM31 = @Vector(PACK_WIDTH, u32);
pub const PackedU64 = @Vector(PACK_WIDTH, u64);
const P_PACKED: PackedM31 = @splat(Modulus);

pub const SimdMemoryContract = struct {
    pub const natural_alignment = @alignOf(M31);
    pub const fixed_width = VEC_WIDTH;
    pub const native_width = PACK_WIDTH;
    pub const caller_scratch_bytes = 0;
    pub const vector_byte_alignment_required = false;
    pub const butterfly_aliasing_supported = false;
};

/// Load exactly `PACK_WIDTH` readable values. The pointer must be naturally
/// aligned for M31 but may be unaligned to the packed vector's byte width.
pub inline fn loadPacked(ptr: [*]const M31) PackedM31 {
    const raw: *const [PACK_WIDTH]u32 = @ptrCast(ptr);
    return raw.*;
}

/// Store exactly `PACK_WIDTH` writable values under the `loadPacked` alignment
/// contract.
pub inline fn storePacked(ptr: [*]M31, v: PackedM31) void {
    const raw: *[PACK_WIDTH]u32 = @ptrCast(ptr);
    raw.* = v;
}

/// Packed M31 addition.
pub inline fn addPacked(a: PackedM31, b: PackedM31) PackedM31 {
    const sum = a +% b;
    if (comptime builtin.cpu.arch == .aarch64) {
        return @min(sum, sum -% P_PACKED);
    }
    return @select(u32, sum >= P_PACKED, sum -% P_PACKED, sum);
}

/// Packed M31 subtraction.
pub inline fn subPacked(a: PackedM31, b: PackedM31) PackedM31 {
    return @select(u32, a < b, (a +% P_PACKED) -% b, a -% b);
}

/// Packed M31 multiplication with Mersenne reduction.
pub inline fn mulPacked(a: PackedM31, b: PackedM31) PackedM31 {
    if (comptime builtin.cpu.arch == .aarch64 and
        builtin.zig_backend != .stage2_c and
        PACK_WIDTH == VEC_WIDTH)
    {
        return @bitCast(mulVec4Aarch64(@bitCast(a), @bitCast(b)));
    }
    const a64: PackedU64 = a;
    const b64: PackedU64 = b;
    const prod = a64 * b64;
    return reduceProductPacked(prod);
}

/// Four-term packed dot product with one final Mersenne reduction.
///
/// Canonical M31 inputs are at most 2^31 - 2, so four products sum to at
/// most 4 * (2^31 - 2)^2 = 2^64 - 2^35 + 16 and cannot overflow u64.
/// This is useful for column-major linear combinations where reducing every
/// product separately performs redundant work.
pub inline fn dot4Packed(
    values: [4]PackedM31,
    coefficients: [4]PackedM31,
) PackedM31 {
    const value0: PackedU64 = values[0];
    const value1: PackedU64 = values[1];
    const value2: PackedU64 = values[2];
    const value3: PackedU64 = values[3];
    const coefficient0: PackedU64 = coefficients[0];
    const coefficient1: PackedU64 = coefficients[1];
    const coefficient2: PackedU64 = coefficients[2];
    const coefficient3: PackedU64 = coefficients[3];
    return reducePacked(
        value0 * coefficient0 +
            value1 * coefficient1 +
            value2 * coefficient2 +
            value3 * coefficient3,
    );
}

/// Four-term scalar dot product with one final Mersenne reduction.
///
/// Four canonical products sum to less than `2^64`, so the accumulation is
/// exact in `u64`. This is the scalar-gather counterpart to `dot4Packed` for
/// reducers whose four terms come from independent borrowed columns.
pub inline fn dot4(values: [4]M31, coefficients: [4]M31) M31 {
    var sum: u64 = 0;
    inline for (0..4) |term| {
        sum += @as(u64, values[term].v) * @as(u64, coefficients[term].v);
    }
    return M31.fromU64(sum);
}

/// Native-width form of `reduceProduct`; every lane is a canonical product.
inline fn reduceProductPacked(x: PackedU64) PackedM31 {
    const p64: PackedU64 = @splat(@as(u64, Modulus));
    const folded = (x & p64) + (x >> @splat(@as(u6, 31)));
    const r: PackedM31 = @truncate(folded);
    if (comptime builtin.cpu.arch == .aarch64) {
        return @min(r, r -% P_PACKED);
    }
    return @select(u32, r >= P_PACKED, r -% P_PACKED, r);
}

/// Packed M31 negation.
pub inline fn negPacked(a: PackedM31) PackedM31 {
    const zero_vec: PackedM31 = @splat(0);
    const is_zero = a == zero_vec;
    return @select(u32, is_zero, zero_vec, P_PACKED -% a);
}

/// Packed Mersenne reduction: x mod (2^31 - 1).
/// Two rounds of: t = (x & p) + (x >> 31).
inline fn reducePacked(x: PackedU64) PackedM31 {
    const p64: PackedU64 = @splat(@as(u64, Modulus));
    var t = (x & p64) + (x >> @splat(@as(u6, 31)));
    t = (t & p64) + (t >> @splat(@as(u6, 31)));
    const r: PackedM31 = @truncate(t);
    return @select(u32, r >= P_PACKED, r -% P_PACKED, r);
}

/// Packed forward butterfly over two disjoint `PACK_WIDTH` ranges. The caller
/// owns the scalar tail; this operation allocates no scratch.
pub inline fn butterflyPacked(lhs: [*]M31, rhs: [*]M31, twid: PackedM31) void {
    std.debug.assert(disjointM31Ranges(lhs, rhs, PACK_WIDTH));
    const v0 = loadPacked(lhs);
    const v1 = loadPacked(rhs);
    const m = mulPacked(v1, twid);
    storePacked(lhs, addPacked(v0, m));
    storePacked(rhs, subPacked(v0, m));
}

/// Packed inverse butterfly with the same width, alias, and scratch contract
/// as `butterflyPacked`.
pub inline fn ibutterflyPacked(lhs: [*]M31, rhs: [*]M31, itwid: PackedM31) void {
    std.debug.assert(disjointM31Ranges(lhs, rhs, PACK_WIDTH));
    const v0 = loadPacked(lhs);
    const v1 = loadPacked(rhs);
    storePacked(lhs, addPacked(v0, v1));
    storePacked(rhs, mulPacked(subPacked(v0, v1), itwid));
}

/// Create a PackedM31 by splatting a scalar across all lanes.
pub inline fn splatPacked(x: M31) PackedM31 {
    return @splat(x.v);
}

/// Reports whether two M31 ranges are disjoint without dereferencing them.
/// False also covers byte-count or address overflow. Low-level SIMD butterfly
/// entry points require this predicate and assert it in checked builds.
pub fn disjointM31Ranges(lhs: [*]const M31, rhs: [*]const M31, width: usize) bool {
    const byte_len = std.math.mul(usize, width, @sizeOf(M31)) catch return false;
    const lhs_start = @intFromPtr(lhs);
    const rhs_start = @intFromPtr(rhs);
    const lhs_end = std.math.add(usize, lhs_start, byte_len) catch return false;
    const rhs_end = std.math.add(usize, rhs_start, byte_len) catch return false;
    return lhs_end <= rhs_start or rhs_end <= lhs_start;
}

/// Fixed-exponent inversion for `p = 2^31 - 1`, computing `a^(p-2)`.
/// Exponent bits: `111...1101` (31 bits).
fn powPMinus2(a: M31) M31 {
    var acc = a;
    inline for (0..30) |step| {
        acc = acc.square();
        const bit = 29 - step;
        if (bit >= 2 or bit == 0) {
            acc = acc.mul(a);
        }
    }
    return acc;
}

test "m31: bounded product reduction matches generic reduction" {
    const edge = [_]u32{ 0, 1, 2, Modulus / 2, Modulus - 2, Modulus - 1 };
    for (edge) |a| {
        for (edge) |b| {
            const product = @as(u64, a) * @as(u64, b);
            try std.testing.expectEqual(reduce64(product), reduceProduct(product));
        }
    }

    var prng = std.Random.DefaultPrng.init(0xd05e_31f0_1d5f_0a57);
    const random = prng.random();
    for (0..4096) |_| {
        const a = random.intRangeLessThan(u32, 0, Modulus);
        const b = random.intRangeLessThan(u32, 0, Modulus);
        const product = @as(u64, a) * @as(u64, b);
        try std.testing.expectEqual(reduce64(product), reduceProduct(product));
    }

    var lhs4: [VEC_WIDTH]u32 = undefined;
    var rhs4: [VEC_WIDTH]u32 = undefined;
    for (&lhs4, &rhs4) |*a, *b| {
        a.* = random.intRangeLessThan(u32, 0, Modulus);
        b.* = random.intRangeLessThan(u32, 0, Modulus);
    }
    const result4: [VEC_WIDTH]u32 = mulVec4(lhs4, rhs4);
    for (lhs4, rhs4, result4) |a, b, result| {
        try std.testing.expectEqual(reduceProduct(@as(u64, a) * b), result);
    }

    var lhs_packed: [PACK_WIDTH]u32 = undefined;
    var rhs_packed: [PACK_WIDTH]u32 = undefined;
    for (&lhs_packed, &rhs_packed) |*a, *b| {
        a.* = random.intRangeLessThan(u32, 0, Modulus);
        b.* = random.intRangeLessThan(u32, 0, Modulus);
    }
    const packed_result: [PACK_WIDTH]u32 = mulPacked(lhs_packed, rhs_packed);
    for (lhs_packed, rhs_packed, packed_result) |a, b, result| {
        try std.testing.expectEqual(reduceProduct(@as(u64, a) * b), result);
    }
}

test "m31: generic reduction canonicalizes the full u64 range" {
    const p: u64 = Modulus;
    const edge = [_]u64{
        0,
        1,
        p - 1,
        p,
        p + 1,
        p * p,
        4 * (p - 1) * (p - 1),
        std.math.maxInt(u64),
    };
    for (edge) |value| {
        try std.testing.expectEqual(@as(u32, @intCast(value % p)), reduce64(value));
    }

    var prng = std.Random.DefaultPrng.init(0x243f_6a88_85a3_08d3);
    const random = prng.random();
    for (0..4096) |_| {
        const value = random.int(u64);
        try std.testing.expectEqual(@as(u32, @intCast(value % p)), reduce64(value));
    }
}

test "m31: packed four-term dot product matches scalar accumulation" {
    var values: [4][PACK_WIDTH]u32 = undefined;
    var coefficients: [4][PACK_WIDTH]u32 = undefined;
    var packed_values: [4]PackedM31 = undefined;
    var packed_coefficients: [4]PackedM31 = undefined;
    var prng = std.Random.DefaultPrng.init(0x1f83_d9ab_fb41_bd6b);
    const random = prng.random();

    inline for (0..4) |term| {
        for (0..PACK_WIDTH) |lane| {
            values[term][lane] = random.intRangeLessThan(u32, 0, Modulus);
            coefficients[term][lane] = random.intRangeLessThan(u32, 0, Modulus);
        }
        packed_values[term] = values[term];
        packed_coefficients[term] = coefficients[term];
    }

    const actual: [PACK_WIDTH]u32 = dot4Packed(packed_values, packed_coefficients);
    for (0..PACK_WIDTH) |lane| {
        var scalar_values: [4]M31 = undefined;
        var scalar_coefficients: [4]M31 = undefined;
        var expected = M31.zero();
        inline for (0..4) |term| {
            scalar_values[term] = M31.fromCanonical(values[term][lane]);
            scalar_coefficients[term] = M31.fromCanonical(coefficients[term][lane]);
            expected = expected.add(
                scalar_values[term].mul(scalar_coefficients[term]),
            );
        }
        try std.testing.expectEqual(expected.v, actual[lane]);
        try std.testing.expectEqual(expected.v, dot4(scalar_values, scalar_coefficients).v);
    }
}

test "m31: packed reduction edge cases" {
    // Test reduce with x = 0: should give 0.
    {
        const zero_vec: PackedU64 = @splat(0);
        const result = reducePacked(zero_vec);
        const expected: PackedM31 = @splat(0);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // Test reduce with x = P: should give 0.
    {
        const p_vec: PackedU64 = @splat(@as(u64, Modulus));
        const result = reducePacked(p_vec);
        const expected: PackedM31 = @splat(0);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // Test reduce with x = 1: should give 1.
    {
        const one_vec: PackedU64 = @splat(1);
        const result = reducePacked(one_vec);
        const expected: PackedM31 = @splat(1);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // Test reduce with x = P-1: should give P-1.
    {
        const pm1_vec: PackedU64 = @splat(@as(u64, Modulus - 1));
        const result = reducePacked(pm1_vec);
        const expected: PackedM31 = @splat(Modulus - 1);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // Test reduce with x = P+1: should give 1.
    {
        const pp1_vec: PackedU64 = @splat(@as(u64, Modulus + 1));
        const result = reducePacked(pp1_vec);
        const expected: PackedM31 = @splat(1);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // Test reduce with x = P*P = (2^31-1)^2, the maximum product of two M31 values.
    // (P-1)^2 mod P should equal 1 (since P-1 = -1 mod P, and (-1)*(-1) = 1).
    // But P*P mod P = 0.
    {
        const p_sq: u64 = @as(u64, Modulus) * @as(u64, Modulus);
        const p_sq_vec: PackedU64 = @splat(p_sq);
        const result = reducePacked(p_sq_vec);
        const scalar_result = reduce64(p_sq);
        const expected: PackedM31 = @splat(scalar_result);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // Test reduce with x = (P-1)^2, the actual max product from mulPacked.
    {
        const pm1_sq: u64 = @as(u64, Modulus - 1) * @as(u64, Modulus - 1);
        const pm1_sq_vec: PackedU64 = @splat(pm1_sq);
        const result = reducePacked(pm1_sq_vec);
        const scalar_result = reduce64(pm1_sq);
        const expected: PackedM31 = @splat(scalar_result);
        try std.testing.expect(@reduce(.And, result == expected));
        // (P-1)^2 mod P = (-1)^2 mod P = 1.
        try std.testing.expectEqual(@as(u32, 1), scalar_result);
    }
    // Test reduce with x = 2^62 - 1 (largest value that fits comfortably in the reduction range).
    {
        const large: u64 = (@as(u64, 1) << 62) - 1;
        const large_vec: PackedU64 = @splat(large);
        const result = reducePacked(large_vec);
        const scalar_result = reduce64(large);
        const expected: PackedM31 = @splat(scalar_result);
        try std.testing.expect(@reduce(.And, result == expected));
    }
    // Test with heterogeneous lanes: each lane has a different edge case.
    {
        const cases = [_]u64{
            0,
            1,
            Modulus,
            Modulus - 1,
            Modulus + 1,
            @as(u64, Modulus) * @as(u64, Modulus),
            @as(u64, Modulus - 1) * @as(u64, Modulus - 1),
            (@as(u64, 1) << 62) - 1,
            2 * @as(u64, Modulus),
            2 * @as(u64, Modulus) + 1,
            3 * @as(u64, Modulus),
            @as(u64, 1) << 31,
            (@as(u64, 1) << 31) + 1,
            42,
            Modulus - 2,
            @as(u64, Modulus) * 3 + 7,
        };
        var input: [PACK_WIDTH]u64 = undefined;
        for (&input, 0..) |*value, i| value.* = cases[i % cases.len];
        const vec: PackedU64 = input;
        const result = reducePacked(vec);
        const result_arr: [PACK_WIDTH]u32 = result;
        for (0..PACK_WIDTH) |i| {
            try std.testing.expectEqual(reduce64(input[i]), result_arr[i]);
        }
    }
}
