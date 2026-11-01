const std = @import("std");
const E = @import("../../../evaluation.zig");
const R = @import("../../../memory/closed_ram/mod.zig");
const Owner = @import("../../../memory/load_store_v2/types.zig");
const S = @import("../../../providers/scalar_range.zig");
const P = @import("../program.zig");
const L = @import("layout.zig");
pub const Q = E.Q;
pub const Call = struct { pointer: u64, epoch: u16, tick: u24, before: [24]u64, after: [24]u64, predecessors: [24]R.types.State };
pub const Challenges = struct { ram: R.types.RamChallenges, owner: Owner.OwnerChallenges, wire: @import("../equations.zig").Wire, range16: S.Challenges, range8: S.Challenges };
pub const Claims = struct {
    ram: Q,
    owner: Q,
    wire: Q,
    range16: Q,
    range8: Q,
    pub fn zero() @This() {
        return .{ .ram = Q.zero(), .owner = Q.zero(), .wire = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero() };
    }
    pub fn values(self: @This()) [5]Q {
        return .{ self.ram, self.owner, self.wire, self.range16, self.range8 };
    }
};
/// Wire35 packet bridges. ADD/DOUBLE keep the secp program kinds 1/2; the
/// SHA-256 compression packet (admitted by `ethereum_services_v3`) is kind 3:
/// three 32-byte coordinates (state, message halves), only the state written.
/// The arith256_mod packet (v3) is kind 4: five coordinates a, b, c, m, r,
/// only the trailing r written (its before-value is still a Wire35 input).
/// Curve/field packets (v3, kinds 5..11 = curves.Op ordinals): inline
/// 32-byte coordinates, the leading `curves.writtenCoords` written in place.
pub const Kind = enum(u8) { add = 1, double = 2, sha256 = 3, arith256_mod = 4, bn254_g1_add = 5, bn254_g1_double = 6, bn254_fp2_mul = 7, bls12_381_fp2_mul = 8, arith384_mont = 9, bls12_381_g1_add = 10, bls12_381_g1_double = 11 };
pub const Curves = @import("../../../../ethereum_services/curves.zig");
pub fn curveOp(kind: Kind) ?Curves.Op {
    return if (@intFromEnum(kind) >= 5) @enumFromInt(@intFromEnum(kind)) else null;
}
pub fn curveKind(op: Curves.Op) Kind {
    return @enumFromInt(@intFromEnum(op));
}
pub fn kindOf(kind: P.Kind) Kind {
    return @enumFromInt(@intFromEnum(kind));
}
fn program(kind: Kind) *const P.Program {
    return P.get(@enumFromInt(@intFromEnum(kind)));
}
pub fn tag(kind: Kind) u32 {
    return switch (kind) {
        .add => 0x20011,
        .double => 0x20012,
        .sha256 => 0x30010,
        .arith256_mod => 0x30021,
        else => @intCast(Curves.tag(curveOp(kind).?)),
    };
}
pub fn coordinates(kind: Kind) usize {
    return switch (kind) {
        .sha256 => 3,
        .arith256_mod => 5,
        .add, .double => program(kind).inputs,
        else => Curves.coords(curveOp(kind).?),
    };
}
/// Number of coordinates that the service overwrites (ADD/DOUBLE: X, Y, Z).
pub fn written(kind: Kind) usize {
    return switch (kind) {
        .sha256, .arith256_mod => 1,
        .add, .double => 3,
        else => Curves.writtenCoords(curveOp(kind).?),
    };
}
/// Whether coordinate `coord` is overwritten: the leading `written` ones,
/// except arith256_mod whose single output r is the last coordinate.
pub fn isWritten(kind: Kind, coord: usize) bool {
    return if (kind == .arith256_mod) coord == 4 else coord < written(kind);
}
/// Wire35 ID of the after-value of written coordinate `coord`.
pub fn outputWire(kind: Kind, coord: usize) u32 {
    return switch (kind) {
        .sha256 => 3,
        .arith256_mod => 5,
        .add, .double => program(kind).outputs[coord],
        // Curve/field truths produce written coordinate c as wire coords + c.
        else => @intCast(coordinates(kind) + coord),
    };
}
pub fn validateGeometry(kind: Kind, calls: usize, first_id: u32, log: u32) !usize {
    const n = try @import("../../../memory/load_store_v2/source.zig").sizeForLog(log);
    if (calls > (n - 1) / coordinates(kind) or first_id == 0 or first_id >= @import("stwo_core").fields.m31.Modulus or calls > @import("stwo_core").fields.m31.Modulus - first_id) return error.InvalidWord16SecpGeometry;
    if (L.U16.len * @as(u64, n) >= @import("stwo_core").fields.m31.Modulus or L.U8.len * @as(u64, n) >= @import("stwo_core").fields.m31.Modulus) return error.Word16SecpMassBound;
    return n;
}
