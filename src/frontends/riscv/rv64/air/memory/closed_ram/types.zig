const std = @import("std");
const E = @import("../../evaluation.zig");
const Scalar = @import("../../providers/scalar_range.zig");
pub const Q = E.Q;
pub const State = struct { value: u64, epoch: u16 = 0, tick: u24 = 0, rights: u2 };
pub const Cell = struct { address: u64, state: State };
pub const Operation = struct { id: u16, address: u64, epoch: u16, tick: u24, value: u64, write: bool };
pub const Row = [28]@import("stwo_core").fields.m31.M31;
pub const PublicRows = [32][14]@import("stwo_core").fields.m31.M31;
pub const RamChallenges = struct {
    offset: Q,
    coefficients: [14]Q,
    pub fn denominatorFor(self: @This(), comptime F: type, tuple: [14]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
    }
};
pub const OwnerChallenges = struct {
    offset: Q,
    coefficients: [13]Q,
    pub fn denominatorFor(self: @This(), comptime F: type, tuple: [13]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
    }
};
pub const Challenges = struct { ram: RamChallenges, owner: OwnerChallenges, range16: Scalar.Challenges, range8: Scalar.Challenges };
pub const Claims = struct {
    ram: Q,
    owner: Q,
    range16: Q,
    range8: Q,
    pub fn zero() @This() {
        return .{ .ram = Q.zero(), .owner = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero() };
    }
    pub fn values(self: @This()) [4]Q {
        return .{ self.ram, self.owner, self.range16, self.range8 };
    }
};
pub fn identity() [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rv64.closed-ram.epoch16-tick16+8.rw2.tuple14.v1:space,addr4,epoch,tlo,thi,value4,R,W;owner13-unit;public-complete-image-no-zero-fallback", &result, .{});
    return result;
}
pub fn word(comptime F: type, v: u64) [4]F {
    var out: [4]F = undefined;
    for (&out, 0..) |*x, i| x.* = E.qFor(F, @as(u16, @truncate(v >> @as(u6, @intCast(16 * i)))));
    return out;
}
