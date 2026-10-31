const E = @import("../../../evaluation.zig");
const R = @import("../../../memory/closed_ram/mod.zig");
const Owner = @import("../../../memory/load_store_v2/types.zig");
const K = @import("../equations.zig");
const Scalar = @import("../../../providers/scalar_range.zig");
pub const Q = E.Q;
pub const State = R.types.State;
pub const Call = struct { pointer: u64, epoch: u16, tick: u24, before: [25]u64, after: [25]u64, predecessors: [25]State };
pub const Challenges = struct { ram: R.types.RamChallenges, owner: Owner.OwnerChallenges, io: K.Io, range16: Scalar.Challenges, range8: Scalar.Challenges };
pub const Claims = struct {
    ram: Q,
    owner: Q,
    io: Q,
    range16: Q,
    range8: Q,
    pub fn zero() @This() {
        return .{ .ram = Q.zero(), .owner = Q.zero(), .io = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero() };
    }
    pub fn values(self: @This()) [5]Q {
        return .{ self.ram, self.owner, self.io, self.range16, self.range8 };
    }
};
pub fn validateGeometry(calls: usize, first_id: u32, log: u32) !usize {
    const n = try @import("../../../memory/load_store_v2/source.zig").sizeForLog(log);
    if (calls > (n - 1) / 25 or first_id == 0 or first_id >= @import("stwo_core").fields.m31.Modulus or calls > @import("stwo_core").fields.m31.Modulus - first_id) return error.InvalidWord16KeccakGeometry;
    if (22 * @as(u64, n) >= @import("stwo_core").fields.m31.Modulus or 19 * @as(u64, n) >= @import("stwo_core").fields.m31.Modulus) return error.Word16KeccakMassBound;
    return n;
}
