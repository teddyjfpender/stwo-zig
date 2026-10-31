//! Stateful owner bus shared by the full CPU, LS and typed ECALL adapters.
//! Challenge drawing belongs to the coordinator after ALL stage-one roots.
const E = @import("../../evaluation.zig");
const decode = @import("../../../decode.zig");
const Legacy = @import("../load_store_v1/types.zig");
const R = @import("../closed_ram/types.zig");
const Range = @import("../../providers/scalar_range.zig");
pub const Q = E.Q;
pub const M = @import("stwo_core").fields.m31.M31;
pub const OWNER_ARITY = 19;
pub const owner = struct {
    pub const opcode = 0;
    pub const a = 1;
    pub const immediate = 5;
    pub const b = 9;
    pub const c = 13;
    pub const epoch = 17;
    pub const tick = 18;
};
pub fn OwnerChallengesFor(comptime C: type) type {
    return struct {
        offset: C,
        coefficients: [OWNER_ARITY]C,
        pub fn denominatorFor(self: @This(), comptime F: type, tuple: [OWNER_ARITY]F) E.SecureFor(F) {
            return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
        }
    };
}
pub const OwnerChallenges = OwnerChallengesFor(Q);
pub fn isLoadStore(opcode: decode.Opcode) bool {
    return switch (opcode) {
        .LB, .LH, .LW, .LD, .LBU, .LHU, .LWU, .SB, .SH, .SW, .SD => true,
        else => false,
    };
}
pub const Challenges = struct { ram: R.RamChallenges, owner: OwnerChallenges, range16: Range.Challenges, range8: Range.Challenges, selection: Legacy.SelectionChallenges };
pub const Claims = Legacy.Claims;
/// The checked v1 relation emits +1/D. Projecting to -D makes its SAME
/// inverse/prefix equations emit -1/D for the CPU-owned nineteen-coordinate bus.
/// m3 is repurposed from diagnostic owner ID to the exact scalar after-tick.
pub fn project(ch: Challenges) Legacy.Challenges {
    var old = Legacy.OwnerChallenges{ .offset = ch.owner.offset.neg(), .coefficients = @splat(Q.zero()) };
    old.coefficients[0] = ch.owner.coefficients[owner.tick].neg();
    old.coefficients[1] = ch.owner.coefficients[owner.opcode].neg();
    for (0..16) |i| old.coefficients[2 + i] = ch.owner.coefficients[1 + i].neg();
    old.coefficients[18] = ch.owner.coefficients[owner.epoch].neg();
    return .{ .ram = ch.ram, .owner = old, .range16 = ch.range16, .range8 = ch.range8, .selection = ch.selection };
}
