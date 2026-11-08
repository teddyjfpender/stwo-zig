const std = @import("std");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const domain_mod = @import("stwo_core").poly.circle.domain;
const poly = @import("poly.zig");
const eval_mod = @import("evaluation.zig");
const secure_column = @import("../../secure_column.zig");
const twiddles_mod = @import("../twiddles.zig");
const work_profile = @import("stwo_prover_api").work_profile;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CircleDomain = domain_mod.CircleDomain;
const CircleCoefficients = poly.CircleCoefficients;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const WorkRecorder = work_profile.Recorder(true);

pub const ForField = @import("secure_poly_family.zig").ForField;
const Default = ForField(QM31);
pub const SecurePolyError = Default.SecurePolyError;
pub const SecureCirclePoly = Default.SecureCirclePoly;
pub const interpolateFromEvaluation = Default.interpolateFromEvaluation;
pub const interpolateAndSplitFromEvaluation = Default.interpolateAndSplitFromEvaluation;
pub const interpolateAndSplitFromEvaluationWithTwiddles = Default.interpolateAndSplitFromEvaluationWithTwiddles;
pub const interpolateAndSplitFromEvaluationWithTwiddlesForBackend = Default.interpolateAndSplitFromEvaluationWithTwiddlesForBackend;
pub const interpolateAndSplitFromEvaluationWithTwiddlesForBackendAndWorkRecorder = Default.interpolateAndSplitFromEvaluationWithTwiddlesForBackendAndWorkRecorder;
const validateSecureExecution = Default.validateSecureExecution;
const recordSecureInterpolation = Default.recordSecureInterpolation;

test "secure interpolation work: four one-column batches own four inversions" {
    var recorder = WorkRecorder{};
    try recorder.expectProducer(.secure_composition_interpolation_fft);
    try recordSecureInterpolation(&recorder, .{
        .log_size = 3,
        .column_count = 4,
        .batch_count = 4,
    });

    try std.testing.expectEqual(@as(u64, 96), recorder.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 80), recorder.counters.field_multiplications);
    try std.testing.expectEqual(@as(u64, 4), recorder.counters.field_inversions);
    try std.testing.expectEqual(@as(u64, 48), recorder.counters.fft_butterflies);
    try std.testing.expect(!recorder.incomplete);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.secure_composition_interpolation_fft)],
    );
}

test "secure interpolation work: CPU and Metal receipts preserve lane parity" {
    const cpu = work_profile.M31InterpolationExecution{
        .log_size = 19,
        .column_count = 4,
        .batch_count = 4,
    };
    const metal = work_profile.M31InterpolationExecution{
        .log_size = 19,
        .column_count = 4,
        .batch_count = 1,
    };
    const cpu_work = try cpu.exactWork();
    const metal_work = try metal.exactWork();
    try std.testing.expectEqual(cpu_work.field_additions, metal_work.field_additions);
    try std.testing.expectEqual(cpu_work.fft_butterflies, metal_work.fft_butterflies);
    try std.testing.expectEqual(@as(u64, 4), cpu_work.field_inversions);
    try std.testing.expectEqual(@as(u64, 1), metal_work.field_inversions);
    try std.testing.expectEqualDeep(
        try cpu.perColumnBatchProjection(),
        try metal.perColumnBatchProjection(),
    );
    try std.testing.expectError(
        error.InvalidCounterGroup,
        validateSecureExecution(.{
            .log_size = 18,
            .column_count = 4,
            .batch_count = 1,
        }, 19),
    );
}

test "secure interpolation work: already-coefficient path is exact zero" {
    var recorder = WorkRecorder{};
    try recorder.expectProducer(.secure_composition_interpolation_fft);
    try recordSecureInterpolation(&recorder, null);

    try std.testing.expect(!recorder.incomplete);
    try std.testing.expect(recorder.counters.isZero());
    try std.testing.expectEqual(
        @as(u8, 0x0f),
        recorder.source_mask.bits & 0x0f,
    );
}

pub const interpolateFromEvaluationWithTwiddles = Default.interpolateFromEvaluationWithTwiddles;

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
