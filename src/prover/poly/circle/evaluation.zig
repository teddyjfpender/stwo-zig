const std = @import("std");
const circle = @import("../../../core/circle.zig");
const constraints = @import("../../../core/constraints.zig");
const fields = @import("../../../core/fields/mod.zig");
const m31 = @import("../../../core/fields/m31.zig");
const qm31 = @import("../../../core/fields/qm31.zig");
const canonic = @import("../../../core/poly/circle/canonic.zig");
const domain_mod = @import("../../../core/poly/circle/domain.zig");
const utils = @import("../../../core/utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointM31 = circle.CirclePointM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CanonicCoset = canonic.CanonicCoset;
const CircleDomain = domain_mod.CircleDomain;

pub const EvaluationError = error{
    ShapeMismatch,
    PointOnDomain,
};

/// Evaluation of a base-field column over a circle domain in bit-reversed order.
///
/// Invariants:
/// - `values.len == domain.size()`.
/// - `values[i]` corresponds to `domain.at(bit_reverse(i))`.
pub const CircleEvaluation = struct {
    domain: CircleDomain,
    values: []const M31,

    pub fn init(domain: CircleDomain, values: []const M31) EvaluationError!CircleEvaluation {
        if (domain.size() != values.len) return EvaluationError.ShapeMismatch;
        return .{
            .domain = domain,
            .values = values,
        };
    }

    /// Computes barycentric weights for a sampled point outside the canonic coset.
    ///
    /// Failure modes:
    /// - `PointOnDomain` when `point` lies on the domain.
    pub fn barycentricWeights(
        allocator: std.mem.Allocator,
        coset: CanonicCoset,
        point: CirclePointQM31,
    ) (std.mem.Allocator.Error || EvaluationError)![]QM31 {
        const domain = coset.circleDomain();
        const n = domain.size();

        const denominators = try allocator.alloc(QM31, n);
        defer allocator.free(denominators);

        const minus_two = QM31.fromBase(M31.fromCanonical(2)).neg();
        const generated_coset = circle.Coset.new(
            circle.CirclePointIndex.generator(),
            domain.logSize(),
        );

        for (0..n) |i| {
            const domain_point = pointM31IntoQM31(
                domain.at(utils.bitReverseIndex(i, domain.logSize())),
            );
            const si_i = minus_two.mul(domain_point.y).mul(
                constraints.cosetVanishingDerivative(QM31, generated_coset, domain_point),
            );
            const vi_p = constraints.pointVanishing(QM31, domain_point, point) catch {
                return EvaluationError.PointOnDomain;
            };
            denominators[i] = si_i.mul(vi_p);
        }

        const denominator_inv = fields.batchInverse(QM31, allocator, denominators) catch {
            return EvaluationError.PointOnDomain;
        };
        defer allocator.free(denominator_inv);

        const vn_p = constraints.cosetVanishing(
            QM31,
            CanonicCoset.new(domain.logSize()).coset(),
            point,
        );

        const out = try allocator.alloc(QM31, n);
        for (out, denominator_inv) |*weight, inv| {
            weight.* = vn_p.mul(inv);
        }
        return out;
    }

    pub fn barycentricEvalAtPointWithWeights(
        self: CircleEvaluation,
        weights: []const QM31,
    ) EvaluationError!QM31 {
        if (self.values.len != weights.len) return EvaluationError.ShapeMismatch;

        var acc = QM31.zero();
        for (self.values, weights) |value, weight| {
            acc = acc.add(QM31.fromBase(value).mul(weight));
        }
        return acc;
    }

    pub fn barycentricEvalAtPoint(
        self: CircleEvaluation,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
    ) (std.mem.Allocator.Error || EvaluationError)!QM31 {
        const weights = try barycentricWeights(
            allocator,
            CanonicCoset.new(self.domain.logSize()),
            point,
        );
        defer allocator.free(weights);
        return self.barycentricEvalAtPointWithWeights(weights);
    }

    pub fn evalAtPoint(
        self: CircleEvaluation,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
    ) (std.mem.Allocator.Error || EvaluationError)!QM31 {
        return self.barycentricEvalAtPoint(allocator, point);
    }
};

fn pointM31IntoQM31(point: CirclePointM31) CirclePointQM31 {
    return .{
        .x = QM31.fromBase(point.x),
        .y = QM31.fromBase(point.y),
    };
}

test "prover poly circle evaluation: barycentric evaluates constant column" {
    const alloc = std.testing.allocator;
    const domain = CanonicCoset.new(5).circleDomain();
    const values = try alloc.alloc(M31, domain.size());
    defer alloc.free(values);
    @memset(values, M31.fromCanonical(77));

    const evaluation = try CircleEvaluation.init(domain, values);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(17);
    const got = try evaluation.evalAtPoint(alloc, point);
    try std.testing.expect(got.eql(QM31.fromBase(M31.fromCanonical(77))));
}

test "prover poly circle evaluation: barycentric evaluates x-coordinate column" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 6;
    const domain = CanonicCoset.new(log_size).circleDomain();

    const values = try alloc.alloc(M31, domain.size());
    defer alloc.free(values);
    for (values, 0..) |*value, i| {
        const point = domain.at(utils.bitReverseIndex(i, log_size));
        value.* = point.x;
    }

    const evaluation = try CircleEvaluation.init(domain, values);
    const sampled = circle.SECURE_FIELD_CIRCLE_GEN.mul(1234567);
    const got = try evaluation.evalAtPoint(alloc, sampled);
    try std.testing.expect(got.eql(sampled.x));
}

test "prover poly circle evaluation: rejects point on domain" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 4;
    const domain = CanonicCoset.new(log_size).circleDomain();
    const values = try alloc.alloc(M31, domain.size());
    defer alloc.free(values);
    @memset(values, M31.one());

    const evaluation = try CircleEvaluation.init(domain, values);
    const domain_point = pointM31IntoQM31(domain.at(utils.bitReverseIndex(0, log_size)));
    try std.testing.expectError(
        EvaluationError.PointOnDomain,
        evaluation.evalAtPoint(alloc, domain_point),
    );
}
