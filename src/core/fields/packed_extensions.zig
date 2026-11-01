//! Shared four-row packed CM31/QM31 arithmetic and AoS transposition.
const std = @import("std");
const m31 = @import("m31.zig");
const cm31 = @import("cm31.zig");
const qm31 = @import("qm31.zig");

pub const PackedCM31x4 = struct {
    a: m31.Vec4u32,
    b: m31.Vec4u32,
};

pub inline fn loadPackedCM31x4(ptr: [*]const cm31.CM31) PackedCM31x4 {
    comptime {
        std.debug.assert(@sizeOf(cm31.CM31) == 2 * @sizeOf(u32));
        std.debug.assert(@offsetOf(cm31.CM31, "a") == 0);
        std.debug.assert(@offsetOf(cm31.CM31, "b") == @sizeOf(u32));
    }
    const raw: *const [8]u32 = @ptrCast(ptr);
    const lo: m31.Vec4u32 = raw[0..4].*;
    const hi: m31.Vec4u32 = raw[4..8].*;
    return .{
        .a = @shuffle(u32, lo, hi, @Vector(4, i32){ 0, 2, -1, -3 }),
        .b = @shuffle(u32, lo, hi, @Vector(4, i32){ 1, 3, -2, -4 }),
    };
}

pub inline fn storePackedCM31x4(ptr: [*]cm31.CM31, value: PackedCM31x4) void {
    const lo = @shuffle(u32, value.a, value.b, @Vector(4, i32){ 0, -1, 1, -2 });
    const hi = @shuffle(u32, value.a, value.b, @Vector(4, i32){ 2, -3, 3, -4 });
    const raw: *[8]u32 = @ptrCast(ptr);
    raw[0..4].* = lo;
    raw[4..8].* = hi;
}

pub inline fn mulPackedCM31x4(lhs: PackedCM31x4, rhs: PackedCM31x4) PackedCM31x4 {
    const ac = m31.mulVec4(lhs.a, rhs.a);
    const bd = m31.mulVec4(lhs.b, rhs.b);
    const cross = m31.mulVec4(
        m31.addVec4(lhs.a, lhs.b),
        m31.addVec4(rhs.a, rhs.b),
    );
    return .{
        .a = m31.subVec4(ac, bd),
        .b = m31.subVec4(m31.subVec4(cross, ac), bd),
    };
}

pub const PackedQM31x4 = struct {
    c0a: m31.Vec4u32,
    c0b: m31.Vec4u32,
    c1a: m31.Vec4u32,
    c1b: m31.Vec4u32,
};

pub inline fn loadPackedQM31x4(ptr: [*]const qm31.QM31) PackedQM31x4 {
    comptime std.debug.assert(@sizeOf(qm31.QM31) == 4 * @sizeOf(u32));
    const raw: *const [16]u32 = @ptrCast(ptr);
    const row0: m31.Vec4u32 = raw[0..4].*;
    const row1: m31.Vec4u32 = raw[4..8].*;
    const row2: m31.Vec4u32 = raw[8..12].*;
    const row3: m31.Vec4u32 = raw[12..16].*;
    const low01 = @shuffle(u32, row0, row1, @Vector(4, i32){ 0, 1, -1, -2 });
    const high01 = @shuffle(u32, row0, row1, @Vector(4, i32){ 2, 3, -3, -4 });
    const low23 = @shuffle(u32, row2, row3, @Vector(4, i32){ 0, 1, -1, -2 });
    const high23 = @shuffle(u32, row2, row3, @Vector(4, i32){ 2, 3, -3, -4 });
    return .{
        .c0a = @shuffle(u32, low01, low23, @Vector(4, i32){ 0, 2, -1, -3 }),
        .c0b = @shuffle(u32, low01, low23, @Vector(4, i32){ 1, 3, -2, -4 }),
        .c1a = @shuffle(u32, high01, high23, @Vector(4, i32){ 0, 2, -1, -3 }),
        .c1b = @shuffle(u32, high01, high23, @Vector(4, i32){ 1, 3, -2, -4 }),
    };
}

pub inline fn storePackedQM31x4(ptr: [*]qm31.QM31, value: PackedQM31x4) void {
    const low01 = @shuffle(u32, value.c0a, value.c0b, @Vector(4, i32){ 0, 1, -1, -2 });
    const high01 = @shuffle(u32, value.c0a, value.c0b, @Vector(4, i32){ 2, 3, -3, -4 });
    const low23 = @shuffle(u32, value.c1a, value.c1b, @Vector(4, i32){ 0, 1, -1, -2 });
    const high23 = @shuffle(u32, value.c1a, value.c1b, @Vector(4, i32){ 2, 3, -3, -4 });
    const raw: *[16]u32 = @ptrCast(ptr);
    raw[0..4].* = @shuffle(u32, low01, low23, @Vector(4, i32){ 0, 2, -1, -3 });
    raw[4..8].* = @shuffle(u32, low01, low23, @Vector(4, i32){ 1, 3, -2, -4 });
    raw[8..12].* = @shuffle(u32, high01, high23, @Vector(4, i32){ 0, 2, -1, -3 });
    raw[12..16].* = @shuffle(u32, high01, high23, @Vector(4, i32){ 1, 3, -2, -4 });
}

pub inline fn mulPackedQM31x4(lhs: PackedQM31x4, rhs: PackedQM31x4) PackedQM31x4 {
    const lhs_c0 = PackedCM31x4{ .a = lhs.c0a, .b = lhs.c0b };
    const lhs_c1 = PackedCM31x4{ .a = lhs.c1a, .b = lhs.c1b };
    const rhs_c0 = PackedCM31x4{ .a = rhs.c0a, .b = rhs.c0b };
    const rhs_c1 = PackedCM31x4{ .a = rhs.c1a, .b = rhs.c1b };
    const ac = mulPackedCM31x4(lhs_c0, rhs_c0);
    const bd = mulPackedCM31x4(lhs_c1, rhs_c1);
    const cross = mulPackedCM31x4(
        .{
            .a = m31.addVec4(lhs.c0a, lhs.c1a),
            .b = m31.addVec4(lhs.c0b, lhs.c1b),
        },
        .{
            .a = m31.addVec4(rhs.c0a, rhs.c1a),
            .b = m31.addVec4(rhs.c0b, rhs.c1b),
        },
    );
    const cross_minus_products = PackedCM31x4{
        .a = m31.subVec4(m31.subVec4(cross.a, ac.a), bd.a),
        .b = m31.subVec4(m31.subVec4(cross.b, ac.b), bd.b),
    };
    const rbd = PackedCM31x4{
        .a = m31.subVec4(m31.addVec4(bd.a, bd.a), bd.b),
        .b = m31.addVec4(bd.a, m31.addVec4(bd.b, bd.b)),
    };
    return .{
        .c0a = m31.addVec4(ac.a, rbd.a),
        .c0b = m31.addVec4(ac.b, rbd.b),
        .c1a = cross_minus_products.a,
        .c1b = cross_minus_products.b,
    };
}

pub inline fn addPackedQM31x4(lhs: PackedQM31x4, rhs: PackedQM31x4) PackedQM31x4 {
    return .{
        .c0a = m31.addVec4(lhs.c0a, rhs.c0a),
        .c0b = m31.addVec4(lhs.c0b, rhs.c0b),
        .c1a = m31.addVec4(lhs.c1a, rhs.c1a),
        .c1b = m31.addVec4(lhs.c1b, rhs.c1b),
    };
}

pub inline fn subPackedQM31x4(lhs: PackedQM31x4, rhs: PackedQM31x4) PackedQM31x4 {
    return .{
        .c0a = m31.subVec4(lhs.c0a, rhs.c0a),
        .c0b = m31.subVec4(lhs.c0b, rhs.c0b),
        .c1a = m31.subVec4(lhs.c1a, rhs.c1a),
        .c1b = m31.subVec4(lhs.c1b, rhs.c1b),
    };
}

pub inline fn splatPackedQM31x4(value: qm31.QM31) PackedQM31x4 {
    const limbs = value.toM31Array();
    return .{
        .c0a = @splat(limbs[0].v),
        .c0b = @splat(limbs[1].v),
        .c1a = @splat(limbs[2].v),
        .c1b = @splat(limbs[3].v),
    };
}

pub inline fn zeroPackedQM31x4() PackedQM31x4 {
    return .{ .c0a = @splat(0), .c0b = @splat(0), .c1a = @splat(0), .c1b = @splat(0) };
}

/// Loads eight consecutive AoS values `ptr[0..8]` and returns the four even
/// (`ptr[0], ptr[2], ptr[4], ptr[6]`) and four odd elements as packed lanes.
pub inline fn loadEvenOddPackedQM31x4(ptr: [*]const qm31.QM31) [2]PackedQM31x4 {
    const lo = loadPackedQM31x4(ptr);
    const hi = loadPackedQM31x4(ptr + 4);
    const even = @Vector(4, i32){ 0, 2, -1, -3 };
    const odd = @Vector(4, i32){ 1, 3, -2, -4 };
    return .{
        .{
            .c0a = @shuffle(u32, lo.c0a, hi.c0a, even),
            .c0b = @shuffle(u32, lo.c0b, hi.c0b, even),
            .c1a = @shuffle(u32, lo.c1a, hi.c1a, even),
            .c1b = @shuffle(u32, lo.c1b, hi.c1b, even),
        },
        .{
            .c0a = @shuffle(u32, lo.c0a, hi.c0a, odd),
            .c0b = @shuffle(u32, lo.c0b, hi.c0b, odd),
            .c1a = @shuffle(u32, lo.c1a, hi.c1a, odd),
            .c1b = @shuffle(u32, lo.c1b, hi.c1b, odd),
        },
    };
}

/// Exact field sum of the four lanes (field addition is associative, so the
/// result equals any sequential scalar accumulation of the same terms).
pub inline fn sumLanesPackedQM31x4(value: PackedQM31x4) qm31.QM31 {
    var out: [4]qm31.QM31 = undefined;
    storePackedQM31x4(&out, value);
    return out[0].add(out[1]).add(out[2]).add(out[3]);
}

test "packed QM31x4 helpers agree with scalar arithmetic" {
    var values: [8]qm31.QM31 = undefined;
    for (&values, 0..) |*v, i| {
        const x: u32 = @intCast(97 * i + 13);
        v.* = qm31.QM31.fromU32Unchecked(x, m31.Modulus - 1 - x, x * 3, 7 + x);
    }
    const pair = loadEvenOddPackedQM31x4(&values);
    const k = qm31.QM31.fromU32Unchecked(5, m31.Modulus - 2, 9, 1);
    const sum = addPackedQM31x4(pair[0], pair[1]);
    const diff = subPackedQM31x4(pair[0], mulPackedQM31x4(pair[1], splatPackedQM31x4(k)));
    var got_sum: [4]qm31.QM31 = undefined;
    var got_diff: [4]qm31.QM31 = undefined;
    storePackedQM31x4(&got_sum, sum);
    storePackedQM31x4(&got_diff, diff);
    var total = qm31.QM31.zero();
    for (0..4) |i| {
        try std.testing.expect(got_sum[i].eql(values[2 * i].add(values[2 * i + 1])));
        try std.testing.expect(got_diff[i].eql(values[2 * i].sub(values[2 * i + 1].mul(k))));
        total = total.add(got_sum[i]);
    }
    try std.testing.expect(sumLanesPackedQM31x4(sum).eql(total));
    try std.testing.expect(sumLanesPackedQM31x4(zeroPackedQM31x4()).isZero());
}
