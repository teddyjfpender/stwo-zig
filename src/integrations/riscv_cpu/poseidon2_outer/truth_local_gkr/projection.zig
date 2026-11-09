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
        weights: []const E.ConstFor(F),
        terms: usize,
        used: usize = 0,
        numerator: E.SecureFor(F) = .zero(),
        denominator: E.SecureFor(F) = .zero(),
        pub fn emit(self: *@This(), relation: TF.Relation, tuple: anytype, weight: F) void {
            std.debug.assert(self.used < self.terms and self.terms <= self.weights.len);
            const eq = E.splatFor(F, self.weights[self.used]);
            self.numerator = self.numerator.add(E.mulBaseFor(F, eq, weight));
            self.denominator = self.denominator.add(eq.mul(self.challenges.denominatorFor(F, relation, tuple)));
            self.used += 1;
        }
        pub fn finish(self: *@This()) !void {
            if (self.used != self.terms or self.terms == 0 or !std.math.isPowerOfTwo(self.weights.len)) return error.LocalGkrProjectionShape;
            for (self.weights[self.terms..]) |eq| self.denominator = self.denominator.add(E.splatFor(F, eq));
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
/// Multilinear lane weights in O(lanes), sharing products between siblings.
/// Each split needs one secure multiplication; the sibling is parent-product.
/// This avoids O(lanes*log(lanes)) circuit arithmetic for the1920-query chip.
pub fn laneWeightsFor(comptime F: type, a: std.mem.Allocator, point: []const F) ![]F {
    if (point.len > 11) return error.InvalidTruthGkrQueries;
    const out = try a.alloc(F, @as(usize, 1) << @intCast(point.len));
    out[0] = F.one();
    var len: usize = 1;
    var k = point.len;
    while (k > 0) {
        k -= 1;
        for (0..len) |i| {
            const parent = out[i];
            const right = parent.mul(point[k]);
            out[i] = parent.sub(right);
            out[len + i] = right;
        }
        len *= 2;
    }
    return out;
}
test "OP truth local GKR shared lane weights equal direct Boolean basis" {
    const core = @import("stwo_core");
    const O = core.fields.om31.OM31;
    var point: [11]O = undefined;
    for (&point, 0..) |*v, i| v.* = O.fromBase(core.fields.m31.M31.fromCanonical(@intCast(13 + 17 * i)));
    for ([_]usize{ 0, 1, 5, 11 }) |bits| {
        const weights = try laneWeightsFor(O, std.testing.allocator, point[0..bits]);
        defer std.testing.allocator.free(weights);
        var sum = O.zero();
        for (weights, 0..) |actual, lane| {
            var expected = O.one();
            for (point[0..bits], 0..) |r, bit| expected = expected.mul(if ((lane >> @intCast(bits - 1 - bit)) & 1 == 1) r else O.one().sub(r));
            try std.testing.expect(actual.eql(expected));
            sum = sum.add(actual);
        }
        try std.testing.expect(sum.eql(O.one()));
    }
}
