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
