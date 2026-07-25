const std = @import("std");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const domain_mod = @import("stwo_core").poly.circle.domain;
const poly = @import("poly.zig");
const eval_mod = @import("evaluation.zig");
const secure_column = @import("../../secure_column.zig");
const twiddles_mod = @import("../twiddles.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CircleDomain = domain_mod.CircleDomain;
const CircleCoefficients = poly.CircleCoefficients;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

pub const SecurePolyError = error{
    ShapeMismatch,
};

pub const SecureCirclePoly = struct {
    polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients,

    pub fn init(
        polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients,
    ) (SecurePolyError || poly.PolyError)!SecureCirclePoly {
        const log_size = polys[0].logSize();
        for (polys[1..]) |coord| {
            if (coord.logSize() != log_size) return SecurePolyError.ShapeMismatch;
        }
        return .{ .polys = polys };
    }

    pub fn deinit(self: *SecureCirclePoly, allocator: std.mem.Allocator) void {
        for (&self.polys) |*coord| {
            coord.deinit(allocator);
        }
        self.* = undefined;
    }

    pub fn evalColumnsAtPoint(
        self: SecureCirclePoly,
        point: CirclePointQM31,
    ) [qm31.SECURE_EXTENSION_DEGREE]QM31 {
        return .{
            self.polys[0].evalAtPoint(point),
            self.polys[1].evalAtPoint(point),
            self.polys[2].evalAtPoint(point),
            self.polys[3].evalAtPoint(point),
        };
    }

    pub fn evalAtPoint(self: SecureCirclePoly, point: CirclePointQM31) QM31 {
        return QM31.fromPartialEvals(self.evalColumnsAtPoint(point));
    }

    pub fn logSize(self: SecureCirclePoly) u32 {
        return self.polys[0].logSize();
    }

    pub fn intoCoordinatePolys(self: SecureCirclePoly) [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients {
        return self.polys;
    }

    pub const SplitPair = struct {
        left: SecureCirclePoly,
        right: SecureCirclePoly,

        pub fn deinit(self: *SplitPair, allocator: std.mem.Allocator) void {
            self.left.deinit(allocator);
            self.right.deinit(allocator);
            self.* = undefined;
        }
    };

    pub const SplitChunks = struct {
        chunks: []SecureCirclePoly,

        pub fn deinit(self: *SplitChunks, allocator: std.mem.Allocator) void {
            for (self.chunks) |*chunk| chunk.deinit(allocator);
            allocator.free(self.chunks);
            self.* = undefined;
        }
    };

    /// Splits each coordinate coefficient vector into `2^depth` contiguous
    /// chunks. Chunk order is the recursive left-to-right split order used by
    /// the composition OODS reconstruction.
    pub fn splitIntoChunks(
        self: SecureCirclePoly,
        allocator: std.mem.Allocator,
        depth: u32,
    ) (std.mem.Allocator.Error || SecurePolyError || poly.PolyError)!SplitChunks {
        if (depth == 0 or depth >= self.logSize()) {
            return SecurePolyError.ShapeMismatch;
        }
        if (depth >= @bitSizeOf(usize)) return SecurePolyError.ShapeMismatch;
        const chunk_count = @as(usize, 1) << @intCast(depth);
        const coefficient_count = self.polys[0].coefficients().len;
        const chunk_len = coefficient_count / chunk_count;
        if (chunk_len == 0) return SecurePolyError.ShapeMismatch;

        const chunks = try allocator.alloc(SecureCirclePoly, chunk_count);
        var initialized: usize = 0;
        errdefer {
            for (chunks[0..initialized]) |*chunk| chunk.deinit(allocator);
            allocator.free(chunks);
        }

        for (chunks, 0..) |*chunk, chunk_index| {
            var coordinates: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
            var coordinate_count: usize = 0;
            errdefer {
                for (coordinates[0..coordinate_count]) |*coordinate| {
                    coordinate.deinit(allocator);
                }
            }
            const start = chunk_index * chunk_len;
            for (&coordinates, self.polys) |*coordinate, source| {
                coordinate.* = try CircleCoefficients.initOwned(
                    try allocator.dupe(
                        M31,
                        source.coefficients()[start .. start + chunk_len],
                    ),
                );
                coordinate_count += 1;
            }
            chunk.* = try SecureCirclePoly.init(coordinates);
            initialized += 1;
        }
        return .{ .chunks = chunks };
    }

    pub fn splitAtMid(
        self: SecureCirclePoly,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || SecurePolyError || poly.PolyError)!SplitPair {
        var left_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
        var right_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
        var initialized: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < initialized) : (i += 1) {
                left_polys[i].deinit(allocator);
                right_polys[i].deinit(allocator);
            }
        }

        for (self.polys, 0..) |coord, i| {
            const split = try coord.splitAtMid(allocator);
            left_polys[i] = split.left;
            right_polys[i] = split.right;
            initialized += 1;
        }

        return .{
            .left = try SecureCirclePoly.init(left_polys),
            .right = try SecureCirclePoly.init(right_polys),
        };
    }
};

pub fn interpolateFromEvaluation(
    allocator: std.mem.Allocator,
    domain: CircleDomain,
    values: *const SecureColumnByCoords,
) !SecureCirclePoly {
    var twiddle_tree_owned = try twiddles_mod.precomputeM31(allocator, domain.half_coset);
    defer twiddles_mod.deinitM31(allocator, &twiddle_tree_owned);
    return interpolateFromEvaluationWithTwiddles(
        allocator,
        domain,
        values,
        .{
            .root_coset = twiddle_tree_owned.root_coset,
            .twiddles = twiddle_tree_owned.twiddles,
            .itwiddles = twiddle_tree_owned.itwiddles,
        },
    );
}

/// Interpolates and splits an evaluation, with a direct path for constant
/// secure-field columns. A constant polynomial has only coefficient zero in
/// the left half and an all-zero right half.
pub fn interpolateAndSplitFromEvaluation(
    allocator: std.mem.Allocator,
    domain: CircleDomain,
    values: *SecureColumnByCoords,
) !SecureCirclePoly.SplitPair {
    var twiddle_tree_owned = try twiddles_mod.precomputeM31(allocator, domain.half_coset);
    defer twiddles_mod.deinitM31(allocator, &twiddle_tree_owned);
    return interpolateAndSplitFromEvaluationWithTwiddles(
        allocator,
        domain,
        values,
        .{
            .root_coset = twiddle_tree_owned.root_coset,
            .twiddles = twiddle_tree_owned.twiddles,
            .itwiddles = twiddle_tree_owned.itwiddles,
        },
    );
}

pub fn interpolateAndSplitFromEvaluationWithTwiddles(
    allocator: std.mem.Allocator,
    domain: CircleDomain,
    values: *SecureColumnByCoords,
    twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
) !SecureCirclePoly.SplitPair {
    return interpolateAndSplitFromEvaluationWithTwiddlesForBackend(
        void,
        allocator,
        domain,
        values,
        twiddle_tree,
    );
}

/// Backend-scoped secure interpolation. An accelerator is selected from the
/// proof's backend type instead of process-global mutable state.
pub fn interpolateAndSplitFromEvaluationWithTwiddlesForBackend(
    comptime B: type,
    allocator: std.mem.Allocator,
    domain: CircleDomain,
    values: *SecureColumnByCoords,
    twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
) !SecureCirclePoly.SplitPair {
    if (domain.size() != values.len() or values.len() < 2) return SecurePolyError.ShapeMismatch;

    if (comptime B != void and @hasDecl(B, "interpolateSecureComposition")) {
        if (try B.interpolateSecureComposition(
            allocator,
            values,
            domain,
            twiddle_tree,
        )) {
            if (values.representation == .coefficients)
                return splitCoefficientColumnsBorrowed(values);
            return splitCoefficientColumns(allocator, values);
        }
    }

    if (!evaluationIsConstant(values)) {
        var polynomial = try interpolateFromEvaluationWithTwiddles(
            allocator,
            domain,
            values,
            twiddle_tree,
        );
        defer polynomial.deinit(allocator);
        return polynomial.splitAtMid(allocator);
    }

    const half_len = values.len() / 2;
    var left_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var right_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized: usize = 0;
    errdefer {
        for (0..initialized) |coordinate| {
            left_polys[coordinate].deinit(allocator);
            right_polys[coordinate].deinit(allocator);
        }
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        const left = try allocator.alloc(M31, half_len);
        errdefer allocator.free(left);
        @memset(left, M31.zero());
        left[0] = values.columns[coordinate][0];
        const right = try allocator.alloc(M31, half_len);
        errdefer allocator.free(right);
        @memset(right, M31.zero());
        left_polys[coordinate] = try CircleCoefficients.initOwned(left);
        right_polys[coordinate] = try CircleCoefficients.initOwned(right);
        initialized += 1;
    }

    return .{
        .left = try SecureCirclePoly.init(left_polys),
        .right = try SecureCirclePoly.init(right_polys),
    };
}

fn splitCoefficientColumnsBorrowed(
    values: *const SecureColumnByCoords,
) !SecureCirclePoly.SplitPair {
    if (values.representation != .coefficients) return SecurePolyError.ShapeMismatch;
    const half_len = values.len() / 2;
    var left_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var right_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    for (values.columns, 0..) |column, coordinate| {
        left_polys[coordinate] = try CircleCoefficients.initBorrowed(column[0..half_len]);
        right_polys[coordinate] = try CircleCoefficients.initBorrowed(column[half_len..]);
    }
    return .{
        .left = try SecureCirclePoly.init(left_polys),
        .right = try SecureCirclePoly.init(right_polys),
    };
}

fn evaluationIsConstant(values: *const SecureColumnByCoords) bool {
    for (values.columns) |column| {
        const first = column[0];
        for (column[1..]) |value| {
            if (!value.eql(first)) return false;
        }
    }
    return true;
}

fn splitCoefficientColumns(
    allocator: std.mem.Allocator,
    values: *const SecureColumnByCoords,
) !SecureCirclePoly.SplitPair {
    var left_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var right_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized: usize = 0;
    errdefer {
        for (0..initialized) |coordinate| {
            left_polys[coordinate].deinit(allocator);
            right_polys[coordinate].deinit(allocator);
        }
    }

    for (values.columns, 0..) |column, coordinate| {
        const polynomial = try CircleCoefficients.initBorrowed(column);
        const split = try polynomial.splitAtMid(allocator);
        left_polys[coordinate] = split.left;
        right_polys[coordinate] = split.right;
        initialized += 1;
    }

    return .{
        .left = try SecureCirclePoly.init(left_polys),
        .right = try SecureCirclePoly.init(right_polys),
    };
}

pub fn interpolateFromEvaluationWithTwiddles(
    allocator: std.mem.Allocator,
    domain: CircleDomain,
    values: *const SecureColumnByCoords,
    twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
) !SecureCirclePoly {
    if (domain.size() != values.len()) return SecurePolyError.ShapeMismatch;

    var coordinate_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized) : (i += 1) coordinate_polys[i].deinit(allocator);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
        const evaluation = try eval_mod.CircleEvaluation.init(domain, values.columns[i]);
        coordinate_polys[i] = try poly.interpolateFromEvaluationWithTwiddles(
            allocator,
            evaluation,
            twiddle_tree,
        );
        initialized += 1;
    }

    return SecureCirclePoly.init(coordinate_polys);
}

test "prover poly circle secure poly: split-at-mid identity" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 6;
    const n = @as(usize, 1) << @intCast(log_size);

    var coordinate_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized) : (i += 1) coordinate_polys[i].deinit(alloc);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        const coeffs = try alloc.alloc(M31, n);
        for (coeffs, 0..) |*coeff, i| {
            const canonical: u32 = @intCast((i * 13 + coord * 11 + 7) % m31.Modulus);
            coeff.* = M31.fromCanonical(canonical);
        }
        coordinate_polys[coord] = try CircleCoefficients.initOwned(coeffs);
        initialized += 1;
    }

    var secure_poly = try SecureCirclePoly.init(coordinate_polys);
    initialized = 0;
    defer secure_poly.deinit(alloc);

    var split = try secure_poly.splitAtMid(alloc);
    defer split.deinit(alloc);

    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(123456789);
    const lhs = split.left.evalAtPoint(point).add(
        point.repeatedDouble(log_size - 2).x.mul(split.right.evalAtPoint(point)),
    );
    const rhs = secure_poly.evalAtPoint(point);
    try std.testing.expect(lhs.eql(rhs));
}

test "prover poly circle secure poly: recursive chunk reconstruction matches full evaluation" {
    const alloc = std.testing.allocator;
    const proof_mod = @import("stwo_core").proof;
    const log_size: u32 = 6;
    const n = @as(usize, 1) << @intCast(log_size);

    var coordinate_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized: usize = 0;
    errdefer {
        for (coordinate_polys[0..initialized]) |*coordinate| coordinate.deinit(alloc);
    }
    for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        const coefficients = try alloc.alloc(M31, n);
        for (coefficients, 0..) |*coefficient, index| {
            coefficient.* = M31.fromCanonical(
                @intCast((index * 977 + coordinate * 131 + 19) % m31.Modulus),
            );
        }
        coordinate_polys[coordinate] = try CircleCoefficients.initOwned(coefficients);
        initialized += 1;
    }

    var polynomial = try SecureCirclePoly.init(coordinate_polys);
    initialized = 0;
    defer polynomial.deinit(alloc);

    const points = [_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(1),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(123456789),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(987654321),
    };
    for (1..5) |depth_usize| {
        const depth: u32 = @intCast(depth_usize);
        var chunks = try polynomial.splitIntoChunks(alloc, depth);
        defer chunks.deinit(alloc);
        var chunk_evals: [16]QM31 = undefined;

        for (points) |point| {
            for (chunks.chunks, 0..) |chunk, chunk_index| {
                chunk_evals[chunk_index] = chunk.evalAtPoint(point);
            }
            const reconstructed = proof_mod.reconstructCompositionChunkEvals(
                chunk_evals[0..chunks.chunks.len],
                point,
                log_size,
                depth,
            ) orelse return error.InvalidReconstruction;
            try std.testing.expect(reconstructed.eql(polynomial.evalAtPoint(point)));
        }
    }
}

fn checkSplitIntoChunksAllocationFailures(allocator: std.mem.Allocator) !void {
    const log_size: u32 = 4;
    const n = @as(usize, 1) << @intCast(log_size);
    var coordinate_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized: usize = 0;
    errdefer {
        for (coordinate_polys[0..initialized]) |*coordinate| coordinate.deinit(allocator);
    }
    for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        const coefficients = try allocator.alloc(M31, n);
        for (coefficients, 0..) |*coefficient, index| {
            coefficient.* = M31.fromCanonical(@intCast(index + coordinate + 1));
        }
        coordinate_polys[coordinate] = try CircleCoefficients.initOwned(coefficients);
        initialized += 1;
    }

    var polynomial = try SecureCirclePoly.init(coordinate_polys);
    initialized = 0;
    defer polynomial.deinit(allocator);
    var chunks = try polynomial.splitIntoChunks(allocator, 2);
    defer chunks.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), chunks.chunks.len);
}

test "prover poly circle secure poly: depth-two split cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkSplitIntoChunksAllocationFailures,
        .{},
    );
}

test "prover poly circle secure poly: rejects mixed coordinate log sizes" {
    const coeffs0 = [_]M31{ M31.one(), M31.zero(), M31.zero(), M31.zero() };
    const coeffs1 = [_]M31{ M31.one(), M31.zero() };

    const p0 = try CircleCoefficients.initBorrowed(coeffs0[0..]);
    const p1 = try CircleCoefficients.initBorrowed(coeffs1[0..]);
    try std.testing.expectError(
        SecurePolyError.ShapeMismatch,
        SecureCirclePoly.init(.{ p0, p0, p0, p1 }),
    );
}

test "prover poly circle secure poly: interpolate from evaluation roundtrip" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 4;
    const domain = @import("stwo_core").poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
    const n = domain.size();

    var coordinate_polys: [qm31.SECURE_EXTENSION_DEGREE]CircleCoefficients = undefined;
    var initialized_polys: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized_polys) : (i += 1) coordinate_polys[i].deinit(alloc);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        const coeffs = try alloc.alloc(M31, n);
        for (coeffs, 0..) |*coeff, i| {
            const canonical: u32 = @intCast((i * 7 + coord * 5 + 1) % m31.Modulus);
            coeff.* = M31.fromCanonical(canonical);
        }
        coordinate_polys[coord] = try CircleCoefficients.initOwned(coeffs);
        initialized_polys += 1;
    }

    var secure_poly = try SecureCirclePoly.init(coordinate_polys);
    initialized_polys = 0;
    defer secure_poly.deinit(alloc);

    var eval_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    var initialized_eval_cols: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < initialized_eval_cols) : (i += 1) alloc.free(eval_columns[i]);
    }

    for (secure_poly.polys, 0..) |coord_poly, i| {
        const eval = try coord_poly.evaluate(alloc, domain);
        eval_columns[i] = @constCast(eval.values);
        initialized_eval_cols += 1;
    }

    var secure_eval = try SecureColumnByCoords.initOwned(eval_columns);
    defer secure_eval.deinit(alloc);

    var interpolated = try interpolateFromEvaluation(alloc, domain, &secure_eval);
    defer interpolated.deinit(alloc);

    for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
        try std.testing.expectEqualSlices(
            M31,
            secure_poly.polys[i].coefficients(),
            interpolated.polys[i].coefficients(),
        );
    }
}

test "prover poly circle secure poly: interpolate with twiddles matches interpolate" {
    const alloc = std.testing.allocator;
    const log_size: u32 = 5;
    const domain = @import("stwo_core").poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
    const n = domain.size();

    var eval_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        const values = try alloc.alloc(M31, n);
        for (values, 0..) |*value, i| {
            const canonical: u32 = @intCast((i * 13 + coord * 17 + 3) % m31.Modulus);
            value.* = M31.fromCanonical(canonical);
        }
        eval_columns[coord] = values;
    }

    var secure_eval = try SecureColumnByCoords.initOwned(eval_columns);
    defer secure_eval.deinit(alloc);

    var interpolated = try interpolateFromEvaluation(alloc, domain, &secure_eval);
    defer interpolated.deinit(alloc);

    var twiddle_tree = try twiddles_mod.precomputeM31(alloc, domain.half_coset);
    defer twiddles_mod.deinitM31(alloc, &twiddle_tree);
    var interpolated_with_twiddles = try interpolateFromEvaluationWithTwiddles(
        alloc,
        domain,
        &secure_eval,
        .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        },
    );
    defer interpolated_with_twiddles.deinit(alloc);

    for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
        try std.testing.expectEqualSlices(
            M31,
            interpolated.polys[i].coefficients(),
            interpolated_with_twiddles.polys[i].coefficients(),
        );
    }
}

test "prover poly circle secure poly: interpolate and split reuses exact twiddles" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 5;
    const domain = @import("stwo_core").poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();

    var columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        const values = try allocator.alloc(M31, domain.size());
        for (values, 0..) |*value, index| {
            value.* = M31.fromCanonical(@intCast(index * 11 + coordinate * 7 + 1));
        }
        columns[coordinate] = values;
        initialized += 1;
    }
    var evaluation = try SecureColumnByCoords.initOwned(columns);
    initialized = 0;
    defer evaluation.deinit(allocator);

    var expected = try interpolateAndSplitFromEvaluation(allocator, domain, &evaluation);
    defer expected.deinit(allocator);
    var twiddle_tree = try twiddles_mod.precomputeM31(allocator, domain.half_coset);
    defer twiddles_mod.deinitM31(allocator, &twiddle_tree);
    var actual = try interpolateAndSplitFromEvaluationWithTwiddles(
        allocator,
        domain,
        &evaluation,
        .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        },
    );
    defer actual.deinit(allocator);

    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        try std.testing.expectEqualSlices(
            M31,
            expected.left.polys[coordinate].coefficients(),
            actual.left.polys[coordinate].coefficients(),
        );
        try std.testing.expectEqualSlices(
            M31,
            expected.right.polys[coordinate].coefficients(),
            actual.right.polys[coordinate].coefficients(),
        );
    }
}
