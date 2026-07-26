//! Backend-neutral Stark-curve arithmetic over Cairo's canonical felt encoding.

const std = @import("std");
const felt252 = @import("felt252.zig");

pub const beta: u256 =
    0x06f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89;

pub const Error = felt252.Error || error{
    PointAtInfinity,
};

pub const AffinePoint = struct {
    x: u256,
    y: u256,
};

const ProjectivePoint = struct {
    x: u256,
    y: u256,
    z: u256,
};

pub fn addAffine(lhs: AffinePoint, rhs: AffinePoint) Error!AffinePoint {
    if (lhs.x == rhs.x) {
        if (lhs.y != rhs.y) return error.PointAtInfinity;
        return doubleAffine(lhs);
    }
    const slope = try felt252.div(
        felt252.sub(rhs.y, lhs.y),
        felt252.sub(rhs.x, lhs.x),
    );
    const x = felt252.sub(
        felt252.sub(felt252.mul(slope, slope), lhs.x),
        rhs.x,
    );
    return .{
        .x = x,
        .y = felt252.sub(felt252.mul(slope, felt252.sub(lhs.x, x)), lhs.y),
    };
}

pub fn doubleAffine(point: AffinePoint) Error!AffinePoint {
    var projective = fromAffine(point);
    try doubleProjective(&projective);
    return toAffine(projective);
}

pub fn tableCombination(
    low_point: AffinePoint,
    low_scalar: u256,
    high_point: ?AffinePoint,
    high_scalar: u32,
    offset: AffinePoint,
) Error!AffinePoint {
    var result = try scalarMul(low_point, low_scalar);
    if (high_point) |point| {
        if (high_scalar != 0) {
            const high = try scalarMul(point, high_scalar);
            const high_affine = try toAffine(high);
            try addMixed(&result, high_affine);
        }
    }
    if (isInfinity(result)) return offset;
    try addMixed(&result, offset);
    return toAffine(result);
}

pub fn isOnCurve(point: AffinePoint) bool {
    const x_squared = felt252.mul(point.x, point.x);
    return felt252.mul(point.y, point.y) ==
        felt252.add(felt252.add(felt252.mul(x_squared, point.x), point.x), beta);
}

fn scalarMul(point: AffinePoint, scalar: u256) Error!ProjectivePoint {
    var result = infinity();
    if (scalar == 0) return result;
    const bit_length: usize = 256 - @clz(scalar);
    var bit = bit_length;
    while (bit != 0) {
        bit -= 1;
        if (!isInfinity(result)) try doubleProjective(&result);
        if ((scalar >> @intCast(bit)) & 1 != 0) try addMixed(&result, point);
    }
    return result;
}

fn fromAffine(point: AffinePoint) ProjectivePoint {
    return .{ .x = point.x, .y = point.y, .z = 1 };
}

fn infinity() ProjectivePoint {
    return .{ .x = 0, .y = 1, .z = 0 };
}

fn isInfinity(point: ProjectivePoint) bool {
    return point.z == 0;
}

fn toAffine(point: ProjectivePoint) Error!AffinePoint {
    if (isInfinity(point)) return error.PointAtInfinity;
    const inverse_z = try felt252.div(1, point.z);
    return .{
        .x = felt252.mul(point.x, inverse_z),
        .y = felt252.mul(point.y, inverse_z),
    };
}

fn addMixed(point: *ProjectivePoint, affine: AffinePoint) Error!void {
    if (isInfinity(point.*)) {
        point.* = fromAffine(affine);
        return;
    }
    const u = felt252.sub(felt252.mul(affine.y, point.z), point.y);
    const v = felt252.sub(felt252.mul(affine.x, point.z), point.x);
    if (v == 0) {
        if (u == 0) {
            try doubleProjective(point);
            return;
        }
        point.* = infinity();
        return;
    }
    const uu = felt252.mul(u, u);
    const vv = felt252.mul(v, v);
    const vvv = felt252.mul(v, vv);
    const r = felt252.mul(vv, point.x);
    const a = felt252.sub(
        felt252.sub(felt252.mul(uu, point.z), vvv),
        felt252.add(r, r),
    );
    point.* = .{
        .x = felt252.mul(v, a),
        .y = felt252.sub(
            felt252.mul(u, felt252.sub(r, a)),
            felt252.mul(vvv, point.y),
        ),
        .z = felt252.mul(vvv, point.z),
    };
}

fn doubleProjective(point: *ProjectivePoint) Error!void {
    if (isInfinity(point.*)) return;
    if (point.y == 0) {
        point.* = infinity();
        return;
    }
    const xx = felt252.mul(point.x, point.x);
    const zz = felt252.mul(point.z, point.z);
    const w = felt252.add(felt252.add(felt252.add(xx, xx), xx), zz);
    const yz = felt252.mul(point.y, point.z);
    const s = felt252.add(yz, yz);
    const ss = felt252.mul(s, s);
    const sss = felt252.mul(s, ss);
    const r = felt252.mul(point.y, s);
    const rr = felt252.mul(r, r);
    const b = felt252.sub(
        felt252.sub(felt252.mul(felt252.add(point.x, r), felt252.add(point.x, r)), xx),
        rr,
    );
    const h = felt252.sub(felt252.mul(w, w), felt252.add(b, b));
    point.* = .{
        .x = felt252.mul(h, s),
        .y = felt252.sub(
            felt252.mul(w, felt252.sub(b, h)),
            felt252.add(rr, rr),
        ),
        .z = sss,
    };
}

test "Stark curve projective doubling agrees with affine addition" {
    const point = AffinePoint{
        .x = 0x0234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b,
        .y = 0x03b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615,
    };
    try std.testing.expect(isOnCurve(point));
    try std.testing.expectEqual(try addAffine(point, point), try doubleAffine(point));
}
