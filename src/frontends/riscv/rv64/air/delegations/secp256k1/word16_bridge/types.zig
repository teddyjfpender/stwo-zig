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
pub fn tag(kind: P.Kind) u32 {
    return if (kind == .add) 0x20011 else 0x20012;
}
pub fn coordinates(kind: P.Kind) usize {
    return P.get(kind).inputs;
}
pub fn validateGeometry(kind: P.Kind, calls: usize, first_id: u32, log: u32) !usize {
    const n = try @import("../../../memory/load_store_v2/source.zig").sizeForLog(log);
    if (calls > (n - 1) / coordinates(kind) or first_id == 0 or first_id >= @import("stwo_core").fields.m31.Modulus or calls > @import("stwo_core").fields.m31.Modulus - first_id) return error.InvalidWord16SecpGeometry;
    if (L.U16.len * @as(u64, n) >= @import("stwo_core").fields.m31.Modulus or L.U8.len * @as(u64, n) >= @import("stwo_core").fields.m31.Modulus) return error.Word16SecpMassBound;
    return n;
}
