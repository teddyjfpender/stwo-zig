//! Standalone scalar case from the frozen first FRI multiplication.
//! Run with `zig test <this-file> -ODebug` or `-OReleaseFast`.
//! These scalar bodies preserve main 4e260db96's Karatsuba arithmetic.
//! A passing case does not establish that the full-context failure is reduced.
const std = @import("std");
const p: u32 = 2147483647;

const M31 = struct {
    v: u32,
    inline fn add(a: M31, b: M31) M31 {
        var s: u32 = a.v + b.v;
        if (s >= p) s -= p;
        return .{ .v = s };
    }
    inline fn sub(a: M31, b: M31) M31 {
        if (a.v >= b.v) return .{ .v = a.v - b.v };
        return .{ .v = (a.v + p) - b.v };
    }
    inline fn mul(a: M31, b: M31) M31 {
        const product: u64 = @as(u64, a.v) * @as(u64, b.v);
        const folded = (product & @as(u64, p)) + (product >> 31);
        const r: u32 = @intCast(folded);
        return .{ .v = if (r >= p) r - p else r };
    }
};

const CM31 = struct {
    a: M31,
    b: M31,
    inline fn add(lhs: CM31, rhs: CM31) CM31 {
        return .{ .a = lhs.a.add(rhs.a), .b = lhs.b.add(rhs.b) };
    }
    inline fn sub(lhs: CM31, rhs: CM31) CM31 {
        return .{ .a = lhs.a.sub(rhs.a), .b = lhs.b.sub(rhs.b) };
    }
    inline fn square(self: CM31) CM31 {
        const ab = self.a.mul(self.b);
        return .{ .a = self.a.mul(self.a).sub(self.b.mul(self.b)), .b = ab.add(ab) };
    }
    inline fn mul(lhs: CM31, rhs: CM31) CM31 {
        const ac = lhs.a.mul(rhs.a);
        const bd = lhs.b.mul(rhs.b);
        const lhs_sum = lhs.a.add(lhs.b);
        const rhs_sum = rhs.a.add(rhs.b);
        const cross = lhs_sum.mul(rhs_sum);
        var imaginary = cross.sub(ac);
        imaginary = imaginary.sub(bd);
        return .{ .a = ac.sub(bd), .b = imaginary };
    }
};

const QM31 = struct {
    c0: CM31,
    c1: CM31,
    inline fn zero() QM31 {
        return field(&.{ 0, 0, 0, 0 });
    }
    inline fn isBase(self: QM31) bool {
        return self.c0.b.v == 0 and self.c1.a.v == 0 and self.c1.b.v == 0;
    }
    inline fn add(lhs: QM31, rhs: QM31) QM31 {
        return .{ .c0 = lhs.c0.add(rhs.c0), .c1 = lhs.c1.add(rhs.c1) };
    }
    inline fn sub(lhs: QM31, rhs: QM31) QM31 {
        return .{ .c0 = lhs.c0.sub(rhs.c0), .c1 = lhs.c1.sub(rhs.c1) };
    }
    inline fn mulM31(lhs: QM31, rhs: M31) QM31 {
        // Exact generic four-lane arithmetic used on the failing x86 target.
        const lanes: @Vector(4, u32) = .{ lhs.c0.a.v, lhs.c0.b.v, lhs.c1.a.v, lhs.c1.b.v };
        const wide: @Vector(4, u64) = lanes;
        const product = wide * @as(@Vector(4, u64), @splat(rhs.v));
        const folded = (product & @as(@Vector(4, u64), @splat(p))) + (product >> @as(@Vector(4, u6), @splat(31)));
        const reduced: @Vector(4, u32) = @truncate(folded);
        const modulus: @Vector(4, u32) = @splat(p);
        const value = @select(u32, reduced >= modulus, reduced -% modulus, reduced);
        return field(&.{ value[0], value[1], value[2], value[3] });
    }
    inline fn square(self: QM31) QM31 {
        if (self.isBase()) return field(&.{ self.c0.a.mul(self.c0.a).v, 0, 0, 0 });
        const a2 = self.c0.square();
        const b2 = self.c1.square();
        const ab = self.c0.mul(self.c1);
        const two_a = b2.a.add(b2.a);
        const two_b = b2.b.add(b2.b);
        const rbd = CM31{ .a = two_a.sub(b2.b), .b = b2.a.add(two_b) };
        return .{ .c0 = a2.add(rbd), .c1 = ab.add(ab) };
    }
    inline fn mul(lhs: QM31, rhs: QM31) QM31 {
        if (!@inComptime()) {
            if (rhs.isBase()) return lhs.mulM31(rhs.c0.a);
            if (lhs.isBase()) return rhs.mulM31(lhs.c0.a);
        }
        const ac = lhs.c0.mul(rhs.c0);
        const bd = lhs.c1.mul(rhs.c1);
        const lhs_sum = lhs.c0.add(lhs.c1);
        const rhs_sum = rhs.c0.add(rhs.c1);
        var cross = lhs_sum.mul(rhs_sum);
        cross = cross.sub(ac);
        cross = cross.sub(bd);
        const two_a = bd.a.add(bd.a);
        const two_b = bd.b.add(bd.b);
        const rbd = CM31{ .a = two_a.sub(bd.b), .b = bd.a.add(two_b) };
        return .{ .c0 = ac.add(rbd), .c1 = cross };
    }
};

fn field(words: *const [4]u32) QM31 {
    // Runtime checks stay active in ReleaseFast, excluding noncanonical inputs.
    for (words) |word| if (word >= p) @panic("noncanonical standalone operand");
    return .{ .c0 = .{ .a = .{ .v = words[0] }, .b = .{ .v = words[1] } }, .c1 = .{ .a = .{ .v = words[2] }, .b = .{ .v = words[3] } } };
}

export fn cm31_fri_product(lhs: *const [4]u32, rhs: *const [4]u32, out: *[2]u32) void {
    const value = field(lhs).c0.mul(field(rhs).c0);
    out.* = .{ value.a.v, value.b.v };
}

export fn qm31_fri_product(lhs: *const [4]u32, rhs: *const [4]u32, out: *[4]u32) void {
    const value = field(lhs).mul(field(rhs));
    out.* = .{ value.c0.a.v, value.c0.b.v, value.c1.a.v, value.c1.b.v };
}

test "cm31 FRI case: exact pinned complex and nested extension products" {
    var operands = [_][4]u32{
        .{ 5, 7, 11, 13 },
        .{ 1303640556, 459797465, 1763438021, 535549304 },
    };
    std.mem.doNotOptimizeAway(&operands);
    var complex: [2]u32 = undefined;
    var extension: [4]u32 = undefined;
    cm31_fri_product(&operands[0], &operands[1], &complex);
    qm31_fri_product(&operands[0], &operands[1], &extension);
    try std.testing.expectEqual([2]u32{ 1152136878, 687052982 }, complex);
    try std.testing.expectEqual([4]u32{ 1502722113, 2034726791, 546122166, 519690011 }, extension);
}

// Reduction control: canonical coset log-size 8, half-coset log-size 7.
// Inverse y coordinates are independently computed over Python integers from
// generator (2,1268011823), indices 2^22 + bitReverse7(i)*2^24. Their independent
// complete fold reproduces the existing frozen digest. This control can pass
// while the full owner still fails; it cannot qualify production proof output.
fn reducedFold(dst: []QM31, src: []const QM31, alpha: QM31, inverse: []const u32) void {
    const alpha_sq = alpha.square();
    var i: usize = 0;
    while (i < dst.len) : (i += 1) {
        var f0 = src[2 * i];
        var f1 = src[2 * i + 1];
        const tmp = f0;
        f0 = tmp.add(f1);
        f1 = tmp.sub(f1).mulM31(.{ .v = inverse[i] });
        const fp = alpha.mul(f1).add(f0);
        dst[i] = dst[i].mul(alpha_sq).add(fp);
    }
}

test "cm31 FRI case: standalone first-fold reduction control" {
    var input: [256]QM31 = undefined;
    for (&input, 0..) |*value, i| {
        const x: u32 = @intCast(i);
        value.* = field(&.{ x + 1, 2 * x + 3, 3 * x + 5, 7 * x + 11 });
    }
    var output = [_]QM31{QM31.zero()} ** 128;
    const inverse = [_]u32{ 843843091, 1303640556, 1276453308, 871030339, 320075643, 1827408004, 1405104315, 742379332, 2014780596, 132703051, 96249987, 2051233660, 1708758013, 438725634, 1226007467, 921476180, 1362637669, 784845978, 2008356521, 139127126, 518527480, 1628956167, 765748090, 1381735557, 1671026240, 476457407, 1855225973, 292257674, 762111838, 1385371809, 192067446, 1955416201, 976567520, 1170916127, 431526769, 1715956878, 455860229, 1691623418, 1761096071, 386387576, 980954310, 1166529337, 559070325, 1588413322, 139434816, 2008048831, 1708802609, 438681038, 1588347831, 559135816, 1168484868, 978998779, 851074894, 1296408753, 1325475375, 822008272, 1522373776, 625109871, 2030436951, 117046696, 1233383290, 914100357, 1282557466, 864926181, 1118504670, 1028978977, 361118641, 1786365006, 294988857, 1852494790, 939109562, 1208374085, 1828829860, 318653787, 834940976, 1312542671, 1726540070, 420943577, 1877378674, 270104973, 206760178, 1940723469, 1077012131, 1070471516, 643851562, 1503632085, 1521535931, 625947716, 1855259715, 292223932, 1772806030, 374677617, 1854196883, 293286764, 2120051002, 27432645, 874171709, 1273311938, 1170627406, 976856241, 262336869, 1885146778, 847318771, 1300164876, 1412963946, 734519701, 454241049, 1693242598, 2031635446, 115848201, 964577609, 1182906038, 1862684823, 284798824, 1258479978, 889003669, 3240883, 2144242764, 1820602501, 326881146, 989324474, 1158159173, 1654199645, 493284002, 1283150231, 864333416, 503514665, 1643968982 };
    reducedFold(&output, &input, field(&.{ 5, 7, 11, 13 }), &inverse);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("STWO_CIRCUIT_VALUES_V1\x00");
    hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u64, output.len)));
    for (&output) |*value| {
        for ([_]u32{ value.c0.a.v, value.c0.b.v, value.c1.a.v, value.c1.b.v }) |word|
            hasher.update(&std.mem.toBytes(std.mem.nativeToLittle(u32, word)));
    }
    try std.testing.expectEqualStrings(
        "012d32936102268b54bb331e44297762696434e0f64e8794086ec51d373d44ec",
        &std.fmt.bytesToHex(hasher.finalResult(), .lower),
    );
}
