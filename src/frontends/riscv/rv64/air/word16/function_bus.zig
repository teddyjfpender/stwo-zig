//! Shared pure-function lookup arithmetic. This module deliberately cannot
//! draw challenges: the integration manifest owns drawing after ALL ordered
//! actual PCS stage-one roots, roles, geometries and masses are sealed.
const std = @import("std");
const E = @import("../evaluation.zig");
const core = @import("stwo_core");
pub const PAYLOAD = 13;
pub const INTERACTION = 8;
pub const CONSTRAINTS = 3;
pub const Challenges = struct {
    offset: E.Q,
    coefficients: [PAYLOAD]E.Q,
    pub fn denominatorFor(self: @This(), comptime F: type, tuple: [PAYLOAD]F) E.SecureFor(F) {
        return E.denominatorFor(F, self.offset, &self.coefficients, &tuple, true);
    }
};
pub const FunctionChallenges = Challenges;

/// Includes every positive physical query sharing a relation, not merely the
/// largest bin. A characteristic-sized invalid multiset could otherwise vanish.
pub fn admitPositiveMass(masses: []const u64) !u64 {
    var total: u64 = 0;
    for (masses) |mass| {
        total = std.math.add(u64, total, mass) catch return error.Word16MassExceeded;
        if (total >= core.fields.m31.Modulus) return error.Word16MassExceeded;
    }
    return total;
}

/// A cyclic prefix starts at -claim and ends at zero. The explicit inverse
/// rejects poles even at zero multiplicity. Emission order is protocol data.
pub fn emitFor(comptime F: type, tuple: [PAYLOAD]F, weight: F, first: F, last: F, inverse: E.SecureFor(F), sum: E.SecureFor(F), previous: E.SecureFor(F), claim: E.Q, ch: Challenges, sink: anytype) void {
    const S = E.SecureFor(F);
    sink.emit(inverse.mul(ch.denominatorFor(F, tuple)).sub(S.one()));
    sink.emit(sum.sub(previous).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(E.mulBaseFor(F, inverse, weight)));
    sink.emit(E.mulBaseFor(F, sum, last));
}
