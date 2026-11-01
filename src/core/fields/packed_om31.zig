//! Additive native-width and grouped16-row OM31 arithmetic; existing column-major M31 domains unchanged.
const m31 = @import("m31.zig");
const packed_fields = @import("packed_qm31.zig");
const om31 = @import("om31.zig");
const P = packed_fields.PackedQM31;
pub const Ops = struct {
    pub fn mulByU(x: P) P {
        return .{ .c0 = x.c1.mulByR(), .c1 = x.c0 };
    }
    pub fn square(x: P) P {
        return x.mul(x);
    }
    pub fn scale(x: P, b: m31.PackedM31) P {
        return x.mulBase(b);
    }
};
/// Arithmetic-only packed API: no hidden scalar inverse or serialization.
pub const PackedOM31 = om31.Quadratic(P, Ops);
pub fn splat(x: om31.OM31) PackedOM31 {
    return .{ .c0 = P.splat(x.c0), .c1 = P.splat(x.c1) };
}
pub fn fromCoordinates(c: [8]m31.PackedM31) PackedOM31 {
    return .{ .c0 = P.fromCoordinates(c[0..4].*), .c1 = P.fromCoordinates(c[4..8].*) };
}
pub fn coordinates(x: PackedOM31) [8]m31.PackedM31 {
    return x.c0.coordinates() ++ x.c1.coordinates();
}
pub fn lane(x: PackedOM31, i: usize) om31.OM31 {
    return .{ .c0 = x.c0.lane(i), .c1 = x.c1.lane(i) };
}

pub const GROUP_ROWS = 16;
comptime {
    if (m31.PACK_WIDTH > GROUP_ROWS or GROUP_ROWS % m31.PACK_WIDTH != 0) @compileError("unsupported native SIMD grouping");
}
pub const GROUP_PACKS = GROUP_ROWS / m31.PACK_WIDTH;
/// Exactly16 column-major rows using the target's native vectors (four groups
/// of four rows on AArch64). No claim of a hardware16-lane instruction.
pub const PackedOM31x16 = struct {
    groups: [GROUP_PACKS]PackedOM31,
    pub fn splat(x: om31.OM31) @This() {
        return .{ .groups = @splat(@import("packed_om31.zig").splat(x)) };
    }
    pub fn fromCoordinates(input: *const [8][GROUP_ROWS]m31.M31) @This() {
        var out: @This() = undefined;
        inline for (0..GROUP_PACKS) |g| {
            var c: [8]m31.PackedM31 = undefined;
            inline for (0..8) |j| c[j] = m31.loadPacked(input[j][g * m31.PACK_WIDTH ..].ptr);
            out.groups[g] = @import("packed_om31.zig").fromCoordinates(c);
        }
        return out;
    }
    pub fn mul(a: @This(), b: @This()) @This() {
        var out: @This() = undefined;
        inline for (0..GROUP_PACKS) |g| out.groups[g] = a.groups[g].mul(b.groups[g]);
        return out;
    }
    pub fn mulBase(a: @This(), b: *const [GROUP_ROWS]m31.M31) @This() {
        var out: @This() = undefined;
        inline for (0..GROUP_PACKS) |g| out.groups[g] = a.groups[g].mulBase(m31.loadPacked(b[g * m31.PACK_WIDTH ..].ptr));
        return out;
    }
    pub fn add(a: @This(), b: @This()) @This() {
        var out: @This() = undefined;
        inline for (0..GROUP_PACKS) |g| out.groups[g] = a.groups[g].add(b.groups[g]);
        return out;
    }
    pub fn lane(a: @This(), index: usize) om31.OM31 {
        return @import("packed_om31.zig").lane(a.groups[index / m31.PACK_WIDTH], index % m31.PACK_WIDTH);
    }
};
