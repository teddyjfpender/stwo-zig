//! Native-width secure-field arithmetic over independent row lanes.
//!
//! `QM31` already uses four AdvSIMD lanes for one secure value. This type turns
//! the axes inside out: each coordinate is a native vector whose lanes are
//! independent secure values. It is the representation wanted by column-major
//! polynomial and lookup kernels that evaluate several rows together.

const std = @import("std");
const m31 = @import("m31.zig");
const qm31 = @import("qm31.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
pub const PackedM31 = m31.PackedM31;

pub const PackedCM31 = struct {
    a: PackedM31,
    b: PackedM31,

    pub inline fn add(lhs: PackedCM31, rhs: PackedCM31) PackedCM31 {
        return .{
            .a = m31.addPacked(lhs.a, rhs.a),
            .b = m31.addPacked(lhs.b, rhs.b),
        };
    }

    pub inline fn sub(lhs: PackedCM31, rhs: PackedCM31) PackedCM31 {
        return .{
            .a = m31.subPacked(lhs.a, rhs.a),
            .b = m31.subPacked(lhs.b, rhs.b),
        };
    }

    pub inline fn mul(lhs: PackedCM31, rhs: PackedCM31) PackedCM31 {
        const ac = m31.mulPacked(lhs.a, rhs.a);
        const bd = m31.mulPacked(lhs.b, rhs.b);
        const cross = m31.mulPacked(
            m31.addPacked(lhs.a, lhs.b),
            m31.addPacked(rhs.a, rhs.b),
        );
        return .{
            .a = m31.subPacked(ac, bd),
            .b = m31.subPacked(m31.subPacked(cross, ac), bd),
        };
    }

    pub inline fn mulByR(value: PackedCM31) PackedCM31 {
        // (a + bi) * (2 + i) = (2a - b) + (a + 2b)i.
        return .{
            .a = m31.subPacked(m31.addPacked(value.a, value.a), value.b),
            .b = m31.addPacked(value.a, m31.addPacked(value.b, value.b)),
        };
    }
};

pub const PackedQM31 = struct {
    c0: PackedCM31,
    c1: PackedCM31,

    pub inline fn zero() PackedQM31 {
        const zeros: PackedM31 = @splat(0);
        return .{
            .c0 = .{ .a = zeros, .b = zeros },
            .c1 = .{ .a = zeros, .b = zeros },
        };
    }

    pub inline fn one() PackedQM31 {
        return fromBase(@splat(1));
    }

    pub inline fn fromBase(value: PackedM31) PackedQM31 {
        const zeros: PackedM31 = @splat(0);
        return .{
            .c0 = .{ .a = value, .b = zeros },
            .c1 = .{ .a = zeros, .b = zeros },
        };
    }

    pub inline fn splat(value: QM31) PackedQM31 {
        const limbs = value.toM31Array();
        return .{
            .c0 = .{
                .a = m31.splatPacked(limbs[0]),
                .b = m31.splatPacked(limbs[1]),
            },
            .c1 = .{
                .a = m31.splatPacked(limbs[2]),
                .b = m31.splatPacked(limbs[3]),
            },
        };
    }

    pub inline fn fromLanes(values: [m31.PACK_WIDTH]QM31) PackedQM31 {
        var lane_coordinates: [qm31.SECURE_EXTENSION_DEGREE]PackedM31 = undefined;
        inline for (0..m31.PACK_WIDTH) |row_lane| {
            const limbs = values[row_lane].toM31Array();
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                lane_coordinates[coordinate][row_lane] = limbs[coordinate].v;
            }
        }
        return fromCoordinates(lane_coordinates);
    }

    pub inline fn fromCoordinates(
        values: [qm31.SECURE_EXTENSION_DEGREE]PackedM31,
    ) PackedQM31 {
        return .{
            .c0 = .{ .a = values[0], .b = values[1] },
            .c1 = .{ .a = values[2], .b = values[3] },
        };
    }

    pub inline fn add(lhs: PackedQM31, rhs: PackedQM31) PackedQM31 {
        return .{ .c0 = lhs.c0.add(rhs.c0), .c1 = lhs.c1.add(rhs.c1) };
    }

    pub inline fn sub(lhs: PackedQM31, rhs: PackedQM31) PackedQM31 {
        return .{ .c0 = lhs.c0.sub(rhs.c0), .c1 = lhs.c1.sub(rhs.c1) };
    }

    pub inline fn mul(lhs: PackedQM31, rhs: PackedQM31) PackedQM31 {
        const ac = lhs.c0.mul(rhs.c0);
        const bd = lhs.c1.mul(rhs.c1);
        const cross = lhs.c0.add(lhs.c1).mul(rhs.c0.add(rhs.c1)).sub(ac).sub(bd);
        return .{ .c0 = ac.add(bd.mulByR()), .c1 = cross };
    }

    pub inline fn mulBase(self: PackedQM31, value: PackedM31) PackedQM31 {
        return .{
            .c0 = .{
                .a = m31.mulPacked(self.c0.a, value),
                .b = m31.mulPacked(self.c0.b, value),
            },
            .c1 = .{
                .a = m31.mulPacked(self.c1.a, value),
                .b = m31.mulPacked(self.c1.b, value),
            },
        };
    }

    pub inline fn coordinates(self: PackedQM31) [qm31.SECURE_EXTENSION_DEGREE]PackedM31 {
        return .{ self.c0.a, self.c0.b, self.c1.a, self.c1.b };
    }

    pub inline fn lane(self: PackedQM31, index: usize) QM31 {
        return QM31.fromU32Unchecked(
            self.c0.a[index],
            self.c0.b[index],
            self.c1.a[index],
            self.c1.b[index],
        );
    }
};

test "packed QM31 preserves independent scalar lanes" {
    var lhs: [m31.PACK_WIDTH]QM31 = undefined;
    var rhs: [m31.PACK_WIDTH]QM31 = undefined;
    inline for (0..m31.PACK_WIDTH) |lane| {
        const value: u32 = @intCast(7 * lane + 1);
        lhs[lane] = QM31.fromU32Unchecked(value, value + 1, value + 2, value + 3);
        rhs[lane] = QM31.fromU32Unchecked(value + 4, value + 5, value + 6, value + 7);
    }
    const product = PackedQM31.fromLanes(lhs).mul(PackedQM31.fromLanes(rhs));
    inline for (0..m31.PACK_WIDTH) |lane| {
        try std.testing.expect(product.lane(lane).eql(lhs[lane].mul(rhs[lane])));
    }
}
