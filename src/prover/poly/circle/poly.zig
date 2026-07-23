const std = @import("std");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const domain_mod = @import("stwo_core").poly.circle.domain;
const line_mod = @import("stwo_core").poly.line;
const poly_utils = @import("stwo_core").poly.utils;
const eval_mod = @import("evaluation.zig");
const point_evaluation = @import("point_evaluation.zig");
const transforms = @import("transforms.zig");
const twiddles_mod = @import("../twiddles.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CircleDomain = domain_mod.CircleDomain;
const M31TwiddleTree = twiddles_mod.TwiddleTree([]const M31);

pub const PolyError = transforms.PolyError;

/// Host polynomial coefficients in the circle-FFT basis.
///
/// Invariants:
/// - `coeffs.len` is a non-zero power of two.
pub const CircleCoefficients = struct {
    coeffs: []const M31,
    log_size: u32,
    owns_coeffs: bool,

    pub fn initBorrowed(coeffs: []const M31) PolyError!CircleCoefficients {
        if (coeffs.len == 0 or !std.math.isPowerOfTwo(coeffs.len)) {
            return PolyError.InvalidLength;
        }
        return .{
            .coeffs = coeffs,
            .log_size = @intCast(std.math.log2_int(usize, coeffs.len)),
            .owns_coeffs = false,
        };
    }

    pub fn initOwned(coeffs: []M31) PolyError!CircleCoefficients {
        var out = try initBorrowed(coeffs);
        out.owns_coeffs = true;
        return out;
    }

    pub fn deinit(self: *CircleCoefficients, allocator: std.mem.Allocator) void {
        if (self.owns_coeffs) allocator.free(@constCast(self.coeffs));
        self.* = undefined;
    }

    pub fn logSize(self: CircleCoefficients) u32 {
        return self.log_size;
    }

    pub fn coefficients(self: CircleCoefficients) []const M31 {
        return self.coeffs;
    }

    /// Evaluates the polynomial at one secure-field point.
    pub fn evalAtPoint(self: CircleCoefficients, point: CirclePointQM31) QM31 {
        if (self.log_size == 0) return QM31.fromBase(self.coeffs[0]);

        var factors: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
        return self.evalAtPointWithFactors(
            fillEvalFactorsForPoint(point, self.log_size, &factors),
        );
    }

    pub fn evalAtPointWithFactors(
        self: CircleCoefficients,
        factors: []const QM31,
    ) QM31 {
        std.debug.assert(factors.len == self.log_size);
        if (self.log_size == 0) return QM31.fromBase(self.coeffs[0]);
        return point_evaluation.evalAtPointIterative(
            self.coeffs,
            factors,
            self.log_size,
        );
    }

    pub fn evalAtPointsFolded(
        self: CircleCoefficients,
        points: []const CirclePointQM31,
        fold_count: u32,
        out: []QM31,
    ) void {
        std.debug.assert(points.len == out.len);
        var flat_factors: [32 * circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
        if (points.len <= 32) {
            fillEvalFactorsForPointsFolded(
                points,
                fold_count,
                self.log_size,
                flat_factors[0 .. points.len * self.log_size],
            );
            self.evalAtPointsWithFlatFactors(
                flat_factors[0 .. points.len * self.log_size],
                out,
            );
            return;
        }

        const chunk_points: usize = 32;
        var at: usize = 0;
        while (at < points.len) {
            const chunk_len = @min(chunk_points, points.len - at);
            fillEvalFactorsForPointsFolded(
                points[at .. at + chunk_len],
                fold_count,
                self.log_size,
                flat_factors[0 .. chunk_len * self.log_size],
            );
            self.evalAtPointsWithFlatFactors(
                flat_factors[0 .. chunk_len * self.log_size],
                out[at .. at + chunk_len],
            );
            at += chunk_len;
        }
    }

    pub fn evalAtPointsWithFlatFactors(
        self: CircleCoefficients,
        flat_factors: []const QM31,
        out: []QM31,
    ) void {
        std.debug.assert(self.log_size == 0 or flat_factors.len == out.len * self.log_size);
        if (self.log_size == 0) {
            const constant = QM31.fromBase(self.coeffs[0]);
            @memset(out, constant);
            return;
        }

        var factor_at: usize = 0;
        for (out) |*value| {
            value.* = point_evaluation.evalAtPointIterative(
                self.coeffs,
                flat_factors[factor_at .. factor_at + self.log_size],
                self.log_size,
            );
            factor_at += self.log_size;
        }
    }

    pub fn evalManyAtPointsWithFlatFactors(
        polys: []const CircleCoefficients,
        flat_factors: []const QM31,
        out_batch: []const []QM31,
        basis_scratch: []QM31,
    ) void {
        std.debug.assert(polys.len == out_batch.len);
        if (polys.len == 0) return;

        const log_size = polys[0].log_size;
        if (log_size == 0) {
            for (polys, out_batch) |poly, out| {
                const constant = QM31.fromBase(poly.coeffs[0]);
                @memset(out, constant);
            }
            return;
        }

        const point_count = out_batch[0].len;
        std.debug.assert(flat_factors.len == point_count * log_size);
        const basis_len = @as(usize, 1) << @intCast(log_size);
        std.debug.assert(basis_scratch.len >= point_count * basis_len);
        for (polys, out_batch) |poly, out| {
            std.debug.assert(poly.log_size == log_size);
            std.debug.assert(out.len == point_count);
        }

        var factor_at: usize = 0;
        var basis_at: usize = 0;
        for (0..point_count) |_| {
            point_evaluation.fillSubsetProductBasis(
                flat_factors[factor_at .. factor_at + log_size],
                basis_scratch[basis_at .. basis_at + basis_len],
            );
            factor_at += log_size;
            basis_at += basis_len;
        }
        evalManyAtPointsWithSubsetProductBases(
            polys,
            basis_scratch[0 .. point_count * basis_len],
            out_batch,
        );
    }

    pub fn evalManyAtPointsWithSubsetProductBases(
        polys: []const CircleCoefficients,
        point_bases: []const QM31,
        out_batch: []const []QM31,
    ) void {
        std.debug.assert(polys.len == out_batch.len);
        if (polys.len == 0) return;

        const log_size = polys[0].log_size;
        const basis_len = @as(usize, 1) << @intCast(log_size);
        const point_count = out_batch[0].len;
        std.debug.assert(point_bases.len == point_count * basis_len);

        var basis_at: usize = 0;
        for (0..point_count) |point_idx| {
            const basis = point_bases[basis_at .. basis_at + basis_len];
            var poly_idx: usize = 0;
            if (comptime m31.PACK_WIDTH > 1) {
                while (poly_idx + m31.PACK_WIDTH <= polys.len) : (poly_idx += m31.PACK_WIDTH) {
                    var coefficient_batches: [m31.PACK_WIDTH][]const M31 = undefined;
                    for (0..m31.PACK_WIDTH) |lane| {
                        coefficient_batches[lane] = polys[poly_idx + lane].coeffs;
                    }
                    const values = point_evaluation.evalBatchWithSubsetProductBasis(
                        coefficient_batches,
                        basis,
                    );
                    for (values, 0..) |value, lane| {
                        out_batch[poly_idx + lane][point_idx] = value;
                    }
                }
            }
            for (polys[poly_idx..], out_batch[poly_idx..]) |poly, out| {
                out[point_idx] = point_evaluation.evalWithSubsetProductBasis(
                    poly.coeffs,
                    basis,
                );
            }
            basis_at += basis_len;
        }
    }

    pub fn extend(
        self: CircleCoefficients,
        allocator: std.mem.Allocator,
        log_size: u32,
    ) (std.mem.Allocator.Error || PolyError)!CircleCoefficients {
        if (log_size < self.log_size) return PolyError.InvalidLogSize;
        const new_len = checkedPow2(log_size) catch return PolyError.InvalidLogSize;
        const out = try allocator.alloc(M31, new_len);
        @memset(out, M31.zero());
        @memcpy(out[0..self.coeffs.len], self.coeffs);
        return CircleCoefficients.initOwned(out);
    }

    pub fn evaluate(
        self: CircleCoefficients,
        allocator: std.mem.Allocator,
        domain: CircleDomain,
    ) (std.mem.Allocator.Error || PolyError || eval_mod.EvaluationError)!eval_mod.CircleEvaluation {
        var twiddle_tree_owned = twiddles_mod.precomputeM31(allocator, domain.half_coset) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.SingularTwiddle => return PolyError.SingularSystem,
        };
        defer twiddles_mod.deinitM31(allocator, &twiddle_tree_owned);
        return self.evaluateWithTwiddles(
            allocator,
            domain,
            .{
                .root_coset = twiddle_tree_owned.root_coset,
                .twiddles = twiddle_tree_owned.twiddles,
                .itwiddles = twiddle_tree_owned.itwiddles,
            },
        );
    }

    pub fn evaluateWithTwiddles(
        self: CircleCoefficients,
        allocator: std.mem.Allocator,
        domain: CircleDomain,
        twiddle_tree: M31TwiddleTree,
    ) (std.mem.Allocator.Error || PolyError || eval_mod.EvaluationError)!eval_mod.CircleEvaluation {
        if (domain.logSize() < self.log_size) return PolyError.InvalidLogSize;
        if (!domain.half_coset.isDoublingOf(twiddle_tree.root_coset)) return PolyError.InvalidLogSize;
        const values = try allocator.alloc(M31, domain.size());
        errdefer allocator.free(values);
        @memcpy(values[0..self.coeffs.len], self.coeffs);
        if (self.coeffs.len * 4 == values.len) {
            transforms.evaluateFourfoldExtensionBufferWithTwiddles(
                values,
                domain,
                twiddle_tree,
            );
        } else if (self.coeffs.len * 2 == values.len) {
            transforms.evaluateExtensionBufferWithTwiddles(values, domain, twiddle_tree);
        } else {
            if (self.coeffs.len < values.len) @memset(values[self.coeffs.len..], M31.zero());
            transforms.evaluateBufferWithTwiddles(values, domain, twiddle_tree);
        }
        return eval_mod.CircleEvaluation.init(domain, values);
    }

    pub const SplitPair = struct {
        left: CircleCoefficients,
        right: CircleCoefficients,

        pub fn deinit(self: *SplitPair, allocator: std.mem.Allocator) void {
            self.left.deinit(allocator);
            self.right.deinit(allocator);
            self.* = undefined;
        }
    };

    /// Splits the coefficient vector in the middle.
    ///
    /// Returns `(left, right)` such that:
    /// `p(z) = left(z) + pi^{L-2}(z.x) * right(z)`, where `L = log2(coeffs.len)`.
    pub fn splitAtMid(
        self: CircleCoefficients,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || PolyError)!SplitPair {
        if (self.log_size == 0) return PolyError.InvalidLogSize;
        const mid = self.coeffs.len / 2;
        const left = try allocator.dupe(M31, self.coeffs[0..mid]);
        errdefer allocator.free(left);
        const right = try allocator.dupe(M31, self.coeffs[mid..]);
        errdefer allocator.free(right);

        return .{
            .left = try CircleCoefficients.initOwned(left),
            .right = try CircleCoefficients.initOwned(right),
        };
    }
};

/// Compatibility type function for callers parameterized by a prover backend.
/// Coefficients currently borrow host slices, so their representation is
/// backend-independent.
pub fn CircleCoefficientsGeneric(comptime B: type) type {
    _ = B;
    return CircleCoefficients;
}

test "prover poly circle poly: generic type preserves host representation" {
    try std.testing.expect(CircleCoefficientsGeneric(struct {}) == CircleCoefficients);
}

/// Interpolates circle coefficients from bit-reversed domain evaluations.
///
/// This is a deterministic reference implementation (Gaussian elimination).
pub fn interpolateFromEvaluation(
    allocator: std.mem.Allocator,
    evaluation: eval_mod.CircleEvaluation,
) (std.mem.Allocator.Error || PolyError)!CircleCoefficients {
    var twiddle_tree_owned = twiddles_mod.precomputeM31(allocator, evaluation.domain.half_coset) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.SingularTwiddle => return PolyError.SingularSystem,
    };
    defer twiddles_mod.deinitM31(allocator, &twiddle_tree_owned);
    return interpolateFromEvaluationWithTwiddles(
        allocator,
        evaluation,
        .{
            .root_coset = twiddle_tree_owned.root_coset,
            .twiddles = twiddle_tree_owned.twiddles,
            .itwiddles = twiddle_tree_owned.itwiddles,
        },
    );
}

pub fn interpolateFromEvaluationWithTwiddles(
    allocator: std.mem.Allocator,
    evaluation: eval_mod.CircleEvaluation,
    twiddle_tree: M31TwiddleTree,
) (std.mem.Allocator.Error || PolyError)!CircleCoefficients {
    const n = evaluation.values.len;
    if (n == 0 or !std.math.isPowerOfTwo(n)) return PolyError.InvalidLength;
    if (evaluation.domain.size() != n) return PolyError.InvalidLength;
    if (!evaluation.domain.half_coset.isDoublingOf(twiddle_tree.root_coset)) return PolyError.InvalidLogSize;
    const coeffs = try allocator.dupe(M31, evaluation.values);
    errdefer allocator.free(coeffs);
    try transforms.interpolateIntoBufferWithTwiddles(
        coeffs,
        evaluation.domain,
        twiddle_tree,
    );
    return CircleCoefficients.initOwned(coeffs);
}

/// Consumes owned bit-reversed evaluation values and turns them into owned coefficients in place.
///
/// Ownership:
/// - `owned_values` is consumed on success and becomes the returned coefficient storage.
/// - On error, the caller retains ownership of `owned_values`.
pub fn interpolateOwnedValuesWithTwiddles(
    domain: CircleDomain,
    owned_values: []M31,
    twiddle_tree: M31TwiddleTree,
) PolyError!CircleCoefficients {
    const n = owned_values.len;
    if (n == 0 or !std.math.isPowerOfTwo(n)) return PolyError.InvalidLength;
    if (domain.size() != n) return PolyError.InvalidLength;
    if (!domain.half_coset.isDoublingOf(twiddle_tree.root_coset)) return PolyError.InvalidLogSize;
    try transforms.interpolateIntoBufferWithTwiddles(
        owned_values,
        domain,
        twiddle_tree,
    );
    return CircleCoefficients.initOwned(owned_values);
}

pub fn interpolateOwnedValuesBatchWithTwiddles(
    domain: CircleDomain,
    owned_values_batch: []const []M31,
    twiddle_tree: M31TwiddleTree,
) PolyError!void {
    if (owned_values_batch.len == 0) return;
    for (owned_values_batch) |owned_values| {
        const n = owned_values.len;
        if (n == 0 or !std.math.isPowerOfTwo(n)) return PolyError.InvalidLength;
        if (domain.size() != n) return PolyError.InvalidLength;
    }
    if (!domain.half_coset.isDoublingOf(twiddle_tree.root_coset)) return PolyError.InvalidLogSize;
    try interpolateBuffersWithTwiddles(
        owned_values_batch,
        domain,
        twiddle_tree,
    );
}

pub fn evaluateManyWithTwiddles(
    allocator: std.mem.Allocator,
    polys: []const CircleCoefficients,
    domain: CircleDomain,
    twiddle_tree: M31TwiddleTree,
) (std.mem.Allocator.Error || PolyError || eval_mod.EvaluationError)![][]M31 {
    const out = try allocator.alloc([]M31, polys.len);
    errdefer allocator.free(out);

    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |values| allocator.free(values);
    }

    var all_extension = polys.len > 0;
    for (polys, 0..) |poly, i| {
        if (domain.logSize() < poly.log_size) return PolyError.InvalidLogSize;
        const values = try allocator.alloc(M31, domain.size());
        @memcpy(values[0..poly.coeffs.len], poly.coeffs);
        if (poly.coeffs.len * 2 != values.len) {
            all_extension = false;
            if (poly.coeffs.len < values.len) @memset(values[poly.coeffs.len..], M31.zero());
        }
        out[i] = values;
        initialized += 1;
    }

    if (all_extension) {
        try transforms.evaluateExtensionBuffersWithTwiddles(out, domain, twiddle_tree);
    } else {
        for (out, polys) |values, poly| {
            if (poly.coeffs.len * 2 == values.len) @memset(values[poly.coeffs.len..], M31.zero());
        }
        try evaluateBuffersWithTwiddles(out, domain, twiddle_tree);
    }
    return out;
}

pub const interpolateBuffersWithTwiddles = transforms.interpolateBuffersWithTwiddles;

pub const evaluateBuffersWithTwiddles = transforms.evaluateBuffersWithTwiddles;

pub const evaluateExtensionBuffersWithTwiddles = transforms.evaluateExtensionBuffersWithTwiddles;

pub const evaluateFourfoldExtensionBuffersWithTwiddles =
    transforms.evaluateFourfoldExtensionBuffersWithTwiddles;

fn checkedPow2(log_size: u32) PolyError!usize {
    if (log_size >= @bitSizeOf(usize)) return PolyError.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn pointM31IntoQM31(point: circle.CirclePointM31) CirclePointQM31 {
    return .{
        .x = QM31.fromBase(point.x),
        .y = QM31.fromBase(point.y),
    };
}

const repeatedDoubleOnCircleQM31 = point_evaluation.repeatedDoubleOnCircleQM31;

pub const fillEvalFactorsForPoint = point_evaluation.fillEvalFactorsForPoint;
pub const fillEvalFactorsForPointsFolded = point_evaluation.fillEvalFactorsForPointsFolded;

test "prover poly circle poly: eval at point for constant polynomial" {
    const coeffs = [_]M31{M31.fromCanonical(23)};
    const poly = try CircleCoefficients.initBorrowed(coeffs[0..]);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(11);
    try std.testing.expect(poly.evalAtPoint(point).eql(QM31.fromBase(M31.fromCanonical(23))));
}

test "prover poly circle poly: split-at-mid identity" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 5;

    const coeffs = try alloc.alloc(M31, @as(usize, 1) << @intCast(log_size));
    defer alloc.free(coeffs);
    for (coeffs, 0..) |*coeff, i| {
        const canonical: u32 = @intCast((i * 17 + 5) % m31.Modulus);
        coeff.* = M31.fromCanonical(canonical);
    }

    const poly = try CircleCoefficients.initBorrowed(coeffs);
    var split = try poly.splitAtMid(alloc);
    defer split.deinit(alloc);

    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(21903);
    const lhs = split.left.evalAtPoint(point).add(
        point.repeatedDouble(log_size - 2).x.mul(split.right.evalAtPoint(point)),
    );
    const rhs = poly.evalAtPoint(point);
    try std.testing.expect(lhs.eql(rhs));
}

test "prover poly circle poly: eval at points folded batch matches scalar oracle" {
    const alloc = std.testing.allocator;
    const log_sizes = [_]u32{ 2, 3, 4, 5, 6, 7 };

    var prng = std.Random.DefaultPrng.init(0x194a_2f73_8cdd_4a61);
    const random = prng.random();

    for (log_sizes) |log_size| {
        const n = @as(usize, 1) << @intCast(log_size);
        const coeffs = try alloc.alloc(M31, n);
        defer alloc.free(coeffs);
        for (coeffs) |*coeff| {
            coeff.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
        }

        const poly = try CircleCoefficients.initBorrowed(coeffs);
        const points_len: usize = 32;
        const points = try alloc.alloc(CirclePointQM31, points_len);
        defer alloc.free(points);
        const out = try alloc.alloc(QM31, points_len);
        defer alloc.free(out);
        for (points) |*point| {
            point.* = circle.SECURE_FIELD_CIRCLE_GEN.mul(@as(u64, random.int(u32)) + 41);
        }

        const max_fold = @min(log_size, @as(u32, 4));
        var fold_count: u32 = 0;
        while (fold_count <= max_fold) : (fold_count += 1) {
            poly.evalAtPointsFolded(points, fold_count, out);
            for (points, out) |point, batch_value| {
                const folded_point = if (fold_count == 0) point else repeatedDoubleOnCircleQM31(point, fold_count);
                const scalar = poly.evalAtPoint(folded_point);
                try std.testing.expect(batch_value.eql(scalar));
            }
        }
    }
}

test "prover poly circle poly: precomputed folded factors match scalar oracle" {
    const alloc = std.testing.allocator;
    const log_sizes = [_]u32{ 1, 3, 5, 7 };
    const point_counts = [_]usize{ 1, 5, 9 };

    var prng = std.Random.DefaultPrng.init(0x92a3_197d_4c5b_6ef1);
    const random = prng.random();

    for (log_sizes) |log_size| {
        const coeffs = try alloc.alloc(M31, @as(usize, 1) << @intCast(log_size));
        defer alloc.free(coeffs);
        for (coeffs) |*coeff| {
            coeff.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
        }
        const poly = try CircleCoefficients.initBorrowed(coeffs);

        for (point_counts) |point_count| {
            const points = try alloc.alloc(CirclePointQM31, point_count);
            defer alloc.free(points);
            for (points) |*point| {
                point.* = circle.SECURE_FIELD_CIRCLE_GEN.mul(@as(u64, random.int(u32)) + 73);
            }

            const expected = try alloc.alloc(QM31, point_count);
            defer alloc.free(expected);
            const actual = try alloc.alloc(QM31, point_count);
            defer alloc.free(actual);
            const factors = try alloc.alloc(QM31, point_count * log_size);
            defer alloc.free(factors);

            const max_fold = @min(log_size, @as(u32, 3));
            var fold_count: u32 = 0;
            while (fold_count <= max_fold) : (fold_count += 1) {
                poly.evalAtPointsFolded(points, fold_count, expected);
                fillEvalFactorsForPointsFolded(points, fold_count, log_size, factors);
                poly.evalAtPointsWithFlatFactors(factors, actual);
                for (expected, actual) |lhs, rhs| {
                    try std.testing.expect(lhs.eql(rhs));
                }
            }
        }
    }
}

test "prover poly circle poly: batched point evaluation matches scalar helper" {
    const alloc = std.testing.allocator;
    // Cross the log-8 boundary where subset-product construction switches to
    // its packed high-block path.
    const log_size: u32 = 10;
    const poly_count: usize = m31.PACK_WIDTH + 1;
    const point_count: usize = 7;

    var prng = std.Random.DefaultPrng.init(0xd1a5_4e7b_11c2_39af);
    const random = prng.random();

    const polys = try alloc.alloc(CircleCoefficients, poly_count);
    defer alloc.free(polys);
    const scalar_out = try alloc.alloc([]QM31, poly_count);
    defer alloc.free(scalar_out);
    const batch_out = try alloc.alloc([]QM31, poly_count);
    defer alloc.free(batch_out);

    for (0..poly_count) |poly_idx| {
        const coeffs = try alloc.alloc(M31, @as(usize, 1) << @intCast(log_size));
        for (coeffs) |*coeff| {
            coeff.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
        }
        polys[poly_idx] = try CircleCoefficients.initOwned(coeffs);
        scalar_out[poly_idx] = try alloc.alloc(QM31, point_count);
        batch_out[poly_idx] = try alloc.alloc(QM31, point_count);
    }
    defer {
        for (polys) |*poly| poly.deinit(alloc);
        for (scalar_out) |values| alloc.free(values);
        for (batch_out) |values| alloc.free(values);
    }

    const points = try alloc.alloc(CirclePointQM31, point_count);
    defer alloc.free(points);
    for (points) |*point| {
        point.* = circle.SECURE_FIELD_CIRCLE_GEN.mul(@as(u64, random.int(u32)) + 101);
    }

    const factors = try alloc.alloc(QM31, point_count * log_size);
    defer alloc.free(factors);
    fillEvalFactorsForPointsFolded(points, 0, log_size, factors);

    for (polys, scalar_out) |poly, out| {
        poly.evalAtPointsWithFlatFactors(factors, out);
    }
    const basis = try alloc.alloc(QM31, point_count * (@as(usize, 1) << @intCast(log_size)));
    defer alloc.free(basis);
    CircleCoefficients.evalManyAtPointsWithFlatFactors(polys, factors, batch_out, basis);

    for (scalar_out, batch_out) |expected, actual| {
        for (expected, actual) |lhs, rhs| {
            try std.testing.expect(lhs.eql(rhs));
        }
    }
}

test "prover poly circle poly: evaluate on domain returns base values" {
    const alloc = std.testing.allocator;
    const coeffs = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(0),
        M31.fromCanonical(0),
        M31.fromCanonical(0),
    };
    const poly = try CircleCoefficients.initBorrowed(coeffs[0..]);
    const domain = @import("stwo_core").poly.circle.canonic.CanonicCoset.new(3).circleDomain();

    const evaluation = try poly.evaluate(alloc, domain);
    defer alloc.free(@constCast(evaluation.values));

    for (evaluation.values) |value| {
        try std.testing.expect(value.eql(M31.fromCanonical(1)));
    }
}

test "prover poly circle poly: interpolation roundtrip" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 4;
    const n = @as(usize, 1) << @intCast(log_size);

    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    for (coeffs, 0..) |*coeff, i| {
        const canonical: u32 = @intCast((i * 19 + 3) % m31.Modulus);
        coeff.* = M31.fromCanonical(canonical);
    }

    const poly = try CircleCoefficients.initBorrowed(coeffs);
    const domain = @import("stwo_core").poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
    const evaluation = try poly.evaluate(alloc, domain);
    defer alloc.free(@constCast(evaluation.values));

    var interpolated = try interpolateFromEvaluation(alloc, evaluation);
    defer interpolated.deinit(alloc);
    try std.testing.expectEqualSlices(M31, poly.coefficients(), interpolated.coefficients());
}

test "prover poly circle poly: evaluate with twiddles matches evaluate" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 5;
    const domain_log_size: u32 = 7;
    const n = @as(usize, 1) << @intCast(log_size);

    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    for (coeffs, 0..) |*coeff, i| {
        const canonical: u32 = @intCast((i * 23 + 11) % m31.Modulus);
        coeff.* = M31.fromCanonical(canonical);
    }

    const poly = try CircleCoefficients.initBorrowed(coeffs);
    const domain = @import("stwo_core").poly.circle.canonic.CanonicCoset.new(domain_log_size).circleDomain();

    const eval_direct = try poly.evaluate(alloc, domain);
    defer alloc.free(@constCast(eval_direct.values));

    var twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer twiddles_mod.deinitM31(alloc, &twiddle_tree);
    const eval_with_twiddles = try poly.evaluateWithTwiddles(
        alloc,
        domain,
        .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        },
    );
    defer alloc.free(@constCast(eval_with_twiddles.values));

    try std.testing.expectEqualSlices(M31, eval_direct.values, eval_with_twiddles.values);
}

test "prover poly circle poly: fourfold extension skips two degenerate layers exactly" {
    const alloc = std.testing.allocator;
    const coeff_log_size: u32 = 6;
    const domain_log_size: u32 = coeff_log_size + 2;
    const coeff_len = @as(usize, 1) << @intCast(coeff_log_size);
    const domain_len = @as(usize, 1) << @intCast(domain_log_size);
    const sentinel = M31.fromCanonical(0x5a5a);

    const baseline = try alloc.alloc(M31, domain_len);
    defer alloc.free(baseline);
    const candidate = try alloc.alloc(M31, domain_len);
    defer alloc.free(candidate);
    for (0..coeff_len) |index| {
        const value = M31.fromCanonical(@intCast((index * 31 + 17) % m31.Modulus));
        baseline[index] = value;
        candidate[index] = value;
    }
    @memset(baseline[coeff_len..], M31.zero());
    @memset(candidate[coeff_len..], sentinel);

    const domain = canonic.CanonicCoset.new(domain_log_size).circleDomain();
    var twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer twiddles_mod.deinitM31(alloc, &twiddle_tree);
    const twiddles: M31TwiddleTree = .{
        .root_coset = twiddle_tree.root_coset,
        .twiddles = twiddle_tree.twiddles,
        .itwiddles = twiddle_tree.itwiddles,
    };

    transforms.evaluateBufferWithTwiddles(baseline, domain, twiddles);
    transforms.evaluateFourfoldExtensionBufferWithTwiddles(candidate, domain, twiddles);
    try std.testing.expectEqualSlices(M31, baseline, candidate);
}

test "prover poly circle poly: interpolate with twiddles matches interpolate" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 6;
    const n = @as(usize, 1) << @intCast(log_size);

    const values = try alloc.alloc(M31, n);
    defer alloc.free(values);
    for (values, 0..) |*value, i| {
        const canonical: u32 = @intCast((i * 7 + 29) % m31.Modulus);
        value.* = M31.fromCanonical(canonical);
    }

    const domain = @import("stwo_core").poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
    const evaluation = try eval_mod.CircleEvaluation.init(domain, values);

    var interpolated_direct = try interpolateFromEvaluation(alloc, evaluation);
    defer interpolated_direct.deinit(alloc);

    var twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer twiddles_mod.deinitM31(alloc, &twiddle_tree);
    var interpolated_with_twiddles = try interpolateFromEvaluationWithTwiddles(
        alloc,
        evaluation,
        .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        },
    );
    defer interpolated_with_twiddles.deinit(alloc);

    try std.testing.expectEqualSlices(
        M31,
        interpolated_direct.coefficients(),
        interpolated_with_twiddles.coefficients(),
    );
}
