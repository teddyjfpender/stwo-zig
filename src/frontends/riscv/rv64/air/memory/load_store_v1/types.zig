const std = @import("std");
const E = @import("../../evaluation.zig");
const R = @import("../closed_ram/types.zig");
const S = @import("../../providers/scalar_range.zig");
pub const Q = E.Q;
pub const M = @import("stwo_core").fields.m31.M31;
pub const OwnerRows = [64][22]M;
pub const OwnerChallenges = struct {
    offset: Q,
    coefficients: [21]Q,
    pub fn denominatorFor(self: @This(), comptime F: type, tuple: [21]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
    }
};
pub const SelectionChallenges = struct {
    offset: Q,
    coefficients: [5]Q,
    pub fn denominatorFor(self: @This(), comptime F: type, tuple: [5]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
    }
};
pub const Challenges = struct { ram: R.RamChallenges, owner: OwnerChallenges, range16: S.Challenges, range8: S.Challenges, selection: SelectionChallenges };
pub const Claims = struct {
    ram: Q,
    owner: Q,
    range16: Q,
    range8: Q,
    selection: Q,
    pub fn zero() @This() {
        return .{ .ram = Q.zero(), .owner = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero(), .selection = Q.zero() };
    }
    pub fn values(self: @This()) [5]Q {
        return .{ self.ram, self.owner, self.range16, self.range8, self.selection };
    }
};
pub fn identity() [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rv64.closed-load-store.word16.v1:base+imm-wrap64,B-store,C-load;natural-alignment-no-crossword;RAM-epoch16-tick24-multiple4-rw2;owner21;selection-pair16-facts17:input16,parity,byte,byte7,input15", &result, .{});
    return result;
}
