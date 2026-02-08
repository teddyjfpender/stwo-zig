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

pub const BarycentricContext = struct {
    log_size: u32,
    coset: CanonicCoset,
    vanishing_shift: CirclePointQM31,
    domain_points: []CirclePointQM31,
    si_values: []QM31,

    pub fn init(allocator: std.mem.Allocator, log_size: u32) !BarycentricContext {
        const coset = CanonicCoset.new(log_size);
        const domain = coset.circleDomain();
        const coset_m31 = coset.coset();
        const n = domain.size();

        const domain_points = try allocator.alloc(CirclePointQM31, n);
        errdefer allocator.free(domain_points);
        const si_values = try allocator.alloc(QM31, n);
        errdefer allocator.free(si_values);

        const minus_two = QM31.fromBase(M31.fromCanonical(2)).neg();
        const generated_coset = circle.Coset.new(
            circle.CirclePointIndex.generator(),
            log_size,
        );
        for (0..n) |i| {
            const point = pointM31IntoQM31(domain.at(utils.bitReverseIndex(i, log_size)));
            domain_points[i] = point;
            si_values[i] = minus_two.mul(point.y).mul(
                constraints.cosetVanishingDerivative(QM31, generated_coset, point),
            );
        }

        return .{
            .log_size = log_size,
            .coset = coset,
            .vanishing_shift = pointM31IntoQM31(coset_m31.initial).neg().add(pointM31IntoQM31(coset_m31.half_step)),
            .domain_points = domain_points,
            .si_values = si_values,
        };
    }

    pub fn deinit(self: *BarycentricContext, allocator: std.mem.Allocator) void {
        allocator.free(self.domain_points);
        allocator.free(self.si_values);
        self.* = undefined;
    }

    pub fn computeWeights(
        self: *const BarycentricContext,
        allocator: std.mem.Allocator,
        workspace: *BarycentricWorkspace,
        point: CirclePointQM31,
    ) (std.mem.Allocator.Error || EvaluationError)![]const QM31 {
        const n = self.domain_points.len;
        if (self.si_values.len != n) return EvaluationError.ShapeMismatch;

        try workspace.ensureCapacity(allocator, n);
        const denominators = workspace.denominators[0..n];
        const weights = workspace.weights[0..n];
        const factors = workspace.factors[0..n];

        for (self.domain_points, self.si_values, 0..) |domain_point, si_i, i| {
            const h = point.sub(domain_point);
            const one_plus_x = QM31.one().add(h.x);
            if (one_plus_x.isZero()) {
                return EvaluationError.PointOnDomain;
            }

            // Equivalent to `si_i * pointVanishing(domain_point, point)` without
            // per-element inversion: denominator is `si_i * h.y`, and we apply
            // `1 + h.x` as a post-factor after the shared batch inverse.
            denominators[i] = si_i.mul(h.y);
            factors[i] = one_plus_x;
        }

        try batchInverseInto(denominators, weights);

        const vn_p = self.cosetVanishingAtPoint(point);
        for (weights, factors) |*weight, factor| {
            weight.* = vn_p.mul(weight.*).mul(factor);
        }
        return weights;
    }

    fn cosetVanishingAtPoint(self: *const BarycentricContext, point: CirclePointQM31) QM31 {
        var x = point.add(self.vanishing_shift).x;
        var i: u32 = 1;
        while (i < self.log_size) : (i += 1) {
            x = circle.CirclePoint(QM31).doubleX(x);
        }
        return x;
    }
};

pub const BarycentricWorkspace = struct {
    denominators: []QM31,
    weights: []QM31,
    factors: []QM31,

    pub fn init() BarycentricWorkspace {
        return .{
            .denominators = &[_]QM31{},
            .weights = &[_]QM31{},
            .factors = &[_]QM31{},
        };
    }

    pub fn deinit(self: *BarycentricWorkspace, allocator: std.mem.Allocator) void {
        if (self.denominators.len != 0) allocator.free(self.denominators);
        if (self.weights.len != 0) allocator.free(self.weights);
        if (self.factors.len != 0) allocator.free(self.factors);
        self.* = undefined;
    }

    pub fn ensureCapacity(
        self: *BarycentricWorkspace,
        allocator: std.mem.Allocator,
        len: usize,
    ) std.mem.Allocator.Error!void {
        if (self.denominators.len < len) {
            if (self.denominators.len != 0) allocator.free(self.denominators);
            self.denominators = try allocator.alloc(QM31, len);
        }
        if (self.weights.len < len) {
            if (self.weights.len != 0) allocator.free(self.weights);
            self.weights = try allocator.alloc(QM31, len);
        }
        if (self.factors.len < len) {
            if (self.factors.len != 0) allocator.free(self.factors);
            self.factors = try allocator.alloc(QM31, len);
        }
    }
};

fn batchInverseInto(values: []const QM31, out: []QM31) EvaluationError!void {
    if (values.len != out.len) return EvaluationError.ShapeMismatch;
    if (values.len == 0) return;

    out[0] = QM31.one();
    var i: usize = 1;
    while (i < values.len) : (i += 1) {
        out[i] = out[i - 1].mul(values[i - 1]);
    }

    var inv = out[values.len - 1].mul(values[values.len - 1]).inv() catch {
        return EvaluationError.PointOnDomain;
    };

    var j: usize = values.len;
    while (j > 1) {
        j -= 1;
        out[j] = inv.mul(out[j]);
        inv = inv.mul(values[j]);
    }
    out[0] = inv;
}

fn barycentricWeightsReference(
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
        return barycentricWeightsReference(
            allocator,
            CanonicCoset.new(coset.logSize()),
            point,
        );
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
        var context = try BarycentricContext.init(allocator, self.domain.logSize());
        defer context.deinit(allocator);

        var workspace = BarycentricWorkspace.init();
        defer workspace.deinit(allocator);

        return self.barycentricEvalAtPointWithContext(allocator, &context, &workspace, point);
    }

    pub fn barycentricEvalAtPointWithContext(
        self: CircleEvaluation,
        allocator: std.mem.Allocator,
        context: *const BarycentricContext,
        workspace: *BarycentricWorkspace,
        point: CirclePointQM31,
    ) (std.mem.Allocator.Error || EvaluationError)!QM31 {
        if (context.log_size != self.domain.logSize()) return EvaluationError.ShapeMismatch;
        const weights = try context.computeWeights(allocator, workspace, point);
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

test "prover poly circle evaluation: context fast path matches reference weights" {
    const alloc = std.testing.allocator;
    const log_sizes = [_]u32{ 2, 3, 4, 5, 6 };

    var prng = std.Random.DefaultPrng.init(0x5EED_BA5E_F00D_1234);
    const random = prng.random();

    for (log_sizes) |log_size| {
        var context = try BarycentricContext.init(alloc, log_size);
        defer context.deinit(alloc);

        var workspace = BarycentricWorkspace.init();
        defer workspace.deinit(alloc);

        var sample_idx: usize = 0;
        while (sample_idx < 12) : (sample_idx += 1) {
            const sampled = circle.SECURE_FIELD_CIRCLE_GEN.mul(@as(u64, random.int(u32)) + 13);
            const reference_weights = barycentricWeightsReference(
                alloc,
                CanonicCoset.new(log_size),
                sampled,
            ) catch |err| switch (err) {
                EvaluationError.PointOnDomain => continue,
                else => return err,
            };
            defer alloc.free(reference_weights);

            const fast_weights = try context.computeWeights(alloc, &workspace, sampled);
            try std.testing.expectEqual(reference_weights.len, fast_weights.len);
            for (reference_weights, fast_weights) |reference_weight, fast_weight| {
                try std.testing.expect(reference_weight.eql(fast_weight));
            }
        }
    }
}

test "prover poly circle evaluation: context fast eval matches reference eval" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 5;
    const domain = CanonicCoset.new(log_size).circleDomain();

    const values = try alloc.alloc(M31, domain.size());
    defer alloc.free(values);
    for (values, 0..) |*value, i| {
        const domain_point = domain.at(utils.bitReverseIndex(i, log_size));
        value.* = domain_point.x.add(M31.fromCanonical(@intCast((i % 7) + 1)));
    }

    const evaluation = try CircleEvaluation.init(domain, values);
    var context = try BarycentricContext.init(alloc, log_size);
    defer context.deinit(alloc);

    var workspace = BarycentricWorkspace.init();
    defer workspace.deinit(alloc);

    const sampled = circle.SECURE_FIELD_CIRCLE_GEN.mul(987654321);
    const fast = try evaluation.barycentricEvalAtPointWithContext(
        alloc,
        &context,
        &workspace,
        sampled,
    );
    const reference = try evaluation.barycentricEvalAtPoint(alloc, sampled);
    try std.testing.expect(fast.eql(reference));
}

test "prover poly circle evaluation: context rejects log-size mismatch" {
    const alloc = std.testing.allocator;
    const domain = CanonicCoset.new(4).circleDomain();
    const values = try alloc.alloc(M31, domain.size());
    defer alloc.free(values);
    @memset(values, M31.fromCanonical(3));

    const evaluation = try CircleEvaluation.init(domain, values);
    var context = try BarycentricContext.init(alloc, 5);
    defer context.deinit(alloc);

    var workspace = BarycentricWorkspace.init();
    defer workspace.deinit(alloc);

    const sampled = circle.SECURE_FIELD_CIRCLE_GEN.mul(111);
    try std.testing.expectError(
        EvaluationError.ShapeMismatch,
        evaluation.barycentricEvalAtPointWithContext(
            alloc,
            &context,
            &workspace,
            sampled,
        ),
    );
}
