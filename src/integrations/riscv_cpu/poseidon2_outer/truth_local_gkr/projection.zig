//! Original truth tuple expressions evaluated at authenticated MAIN masks.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const TF = @import("../../word16_global_execution/services/gkr_local/truth_fractions.zig");
const B = @import("../../word16_global_execution/services/gkr_local/binding.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/truth_frame.zig");
pub fn ProjectionFor(comptime F: type) type {
    return struct {
        challenges: *const TF.ChallengesFor(E.ConstFor(F)),
        weights: []const E.SecureFor(F),
        terms: usize,
        used: usize = 0,
        numerator: E.SecureFor(F) = .zero(),
        denominator: E.SecureFor(F) = .zero(),
        pub fn emit(self: *@This(), relation: TF.Relation, tuple: anytype, weight: F) void {
            std.debug.assert(self.used < self.terms and self.terms <= self.weights.len);
            const eq = self.weights[self.used];
            self.numerator = self.numerator.add(E.mulBaseFor(F, eq, weight));
            self.denominator = self.denominator.add(eq.mul(self.challenges.denominatorFor(F, relation, tuple)));
            self.used += 1;
        }
        pub fn finish(self: *@This()) !void {
            if (self.used != self.terms or self.terms == 0 or !std.math.isPowerOfTwo(self.weights.len)) return error.LocalGkrProjectionShape;
            for (self.weights[self.terms..]) |eq| self.denominator = self.denominator.add(eq);
        }
        pub fn combine(self: *const @This(), eta: E.SecureFor(F)) E.SecureFor(F) {
            return self.numerator.add(eta.mul(self.denominator));
        }
    };
}
/// The common classic row authority calls finish at exactly the old local
/// accumulator position. Global KIO/Wire equations follow unchanged.
pub fn BindingSinkFor(comptime F: type) type {
    return struct {
        projection: ProjectionFor(F),
        masks: B.MaskFor(E.SecureFor(F)),
        aux: B.AuxFor(E.SecureFor(F)),
        eta: E.SecureFor(F),
        target: E.SecureFor(F),
        out: *E.SinkFor(F),
        pub fn emit(self: *@This(), relation: TF.Relation, tuple: anytype, weight: F) void {
            self.projection.emit(relation, tuple, weight);
        }
        pub fn finish(self: *@This(), instance: Frame.Instance, _: []const F, _: F, _: F, _: E.ConstFor(F)) !void {
            if (instance.queries != self.projection.terms) return error.LocalGkrProjectionShape;
            try self.projection.finish();
            B.emitFor(F, self.masks, self.aux, self.projection.combine(self.eta), self.target, self.out);
        }
    };
}
