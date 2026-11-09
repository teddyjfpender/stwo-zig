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
    inline fn mul(lhs: QM31, rhs: QM31) QM31 {
        // The frozen operands are both non-base, so production takes this path.
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
