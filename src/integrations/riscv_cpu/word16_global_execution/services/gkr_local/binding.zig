//! Authenticated terminal projection authority. MAIN masks at the random row
//! point enter the SAME fraction emitter as metadata gathering. This module is
//! algebra only: the accepting PCS must authenticate all masks and constrain
//! Eq and the cyclic prefix before accepting a terminal marginal.
const std = @import("std");
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const R = @import("fractions.zig");
pub fn ProjectionFor(comptime F: type) type {
    return struct {
        challenges: *const @import("challenges.zig").For(E.ConstFor(F)),
        lane_weights: []const E.SecureFor(F),
        terms: usize,
        used: usize = 0,
        numerator: E.SecureFor(F) = .zero(),
        denominator: E.SecureFor(F) = .zero(),
        pub fn emit(self: *@This(), relation: R.Relation, tuple: anytype, weight: F) void {
            std.debug.assert(self.used < self.terms and self.terms <= self.lane_weights.len);
            const eq = self.lane_weights[self.used];
            self.numerator = self.numerator.add(E.mulBaseFor(F, eq, weight));
            self.denominator = self.denominator.add(eq.mul(self.challenges.denominatorFor(F, relation, tuple)));
            self.used += 1;
        }
        pub fn finish(self: *@This()) !void {
            if (self.used != self.terms or self.terms == 0 or !std.math.isPowerOfTwo(self.lane_weights.len)) return error.LocalGkrProjectionShape;
            // Padded query lanes are exactly N=0,D=1, not omitted poles or
            // inactive fractions. Their denominator marginal is nonzero.
            for (self.lane_weights[self.terms..]) |eq| self.denominator = self.denominator.add(eq);
        }
        pub fn combine(self: *const @This(), eta: E.SecureFor(F)) E.SecureFor(F) {
            return self.numerator.add(eta.mul(self.denominator));
        }
    };
}
/// eta must be drawn after BOTH immutable terminal marginals are fixed. Each
/// instance receives its own prefix and target; cross-instance cancellation
/// cannot stand in for authentication of an individual input MLE.
pub fn prefixResidualFor(comptime F: type, current: F, previous: F, eq: F, projection: F, target_per_row: F) F {
    return current.sub(previous).sub(eq.mul(projection)).add(target_per_row);
}
/// The physical role wrapper derives these succinct Eq-polynomial auxiliaries
/// from its checked instance suffix and its OWN folded PCS evaluation point.
/// They are not producer-declared proof inputs.
pub fn AuxFor(comptime S: type) type {
    return struct { first: S, second: S, carry: S, eq0: S, eq1: S };
}
pub fn MaskFor(comptime S: type) type {
    return struct { eq: S, eq_next2: S, prefix: S, prefix_previous: S };
}
pub const CONSTRAINTS = 3;
pub const INTERACTION_COLUMNS = 2 * E.extensionDegree(@import("stwo_core").fields.om31.OM31);
/// Original MAIN arithmetic and these constraints share ONE physical role MAIN
/// span. q is the authenticated Eq recurrence's succinct carry polynomial.
pub fn emitFor(comptime F: type, masks: MaskFor(E.SecureFor(F)), aux: AuxFor(E.SecureFor(F)), projection: E.SecureFor(F), target_per_row: E.SecureFor(F), sink: *E.SinkFor(F)) void {
    sink.emit(masks.eq.sub(aux.eq0).mul(aux.first).add(masks.eq.sub(aux.eq1).mul(aux.second)));
    sink.emit(masks.eq.sub(masks.eq_next2.mul(aux.carry)));
    sink.emit(masks.prefix.sub(masks.prefix_previous).sub(masks.eq.mul(projection)).add(target_per_row));
}
