//! Differential and arithmetic tests for CPU RISC-V composition.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition = @import("riscv_composition.zig");

const constraints = core.constraints;
const m31 = core.fields.m31;
const qm31 = core.fields.qm31;
const packed_qm31 = core.fields.packed_qm31;
const canonic = core.poly.circle.canonic;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const PackedM31 = m31.PackedM31;
const PackedQM31 = packed_qm31.PackedQM31;
const Component = prover.air.component_prover.ComponentProver;
const BaseProgram = prover.air.component_prover.OwnedBasePolynomialProgram;
const LookupProgram = prover.air.component_prover.OwnedLookupPolynomialProgram;
const Poly = prover.air.component_prover.Poly;
const Trace = prover.air.component_prover.Trace;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;

const evaluate = composition.evaluate;
const telemetrySnapshot = composition.telemetrySnapshot;

fn denominatorScalars(eval_log_size: u32) ![2]M31 {
    if (eval_log_size == 0) return error.InvalidCompositionLogSize;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const trace_coset = canonic.CanonicCoset.new(eval_log_size - 1).coset();
    var result: [2]M31 = undefined;
    for (&result, 0..) |*inverse, index| {
        inverse.* = try constraints.cosetVanishing(
            M31,
            trace_coset,
            eval_domain.at(core.utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    return result;
}

test "cpu RISC-V composition: packed secure arithmetic matches scalar QM31" {
    const Helpers = struct {
        fn pack(values: [m31.PACK_WIDTH]QM31) PackedQM31 {
            var coordinates: [qm31.SECURE_EXTENSION_DEGREE]PackedM31 = .{
                @splat(0), @splat(0), @splat(0), @splat(0),
            };
            for (values, 0..) |value, lane| {
                const scalar = value.toM31Array();
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    coordinates[coordinate][lane] = scalar[coordinate].v;
                }
            }
            return .{
                .c0 = .{ .a = coordinates[0], .b = coordinates[1] },
                .c1 = .{ .a = coordinates[2], .b = coordinates[3] },
            };
        }

        fn expectEqual(expected: [m31.PACK_WIDTH]QM31, actual: PackedQM31) !void {
            const coordinates = actual.coordinates();
            for (expected, 0..) |value, lane| {
                const unpacked = QM31.fromM31(
                    M31.fromCanonical(coordinates[0][lane]),
                    M31.fromCanonical(coordinates[1][lane]),
                    M31.fromCanonical(coordinates[2][lane]),
                    M31.fromCanonical(coordinates[3][lane]),
                );
                try std.testing.expect(value.eql(unpacked));
            }
        }
    };

    var lhs: [m31.PACK_WIDTH]QM31 = undefined;
    var rhs: [m31.PACK_WIDTH]QM31 = undefined;
    var products: [m31.PACK_WIDTH]QM31 = undefined;
    var base_products: [m31.PACK_WIDTH]QM31 = undefined;
    const base = M31.fromCanonical(17);
    for (0..m31.PACK_WIDTH) |lane| {
        const value: u32 = @intCast(lane + 1);
        lhs[lane] = QM31.fromU32Unchecked(value, value + 2, value + 4, value + 6);
        rhs[lane] = QM31.fromU32Unchecked(value + 8, value + 10, value + 12, value + 14);
        products[lane] = lhs[lane].mul(rhs[lane]);
        base_products[lane] = lhs[lane].mulM31(base);
    }
    try Helpers.expectEqual(products, Helpers.pack(lhs).mul(Helpers.pack(rhs)));
    try Helpers.expectEqual(
        base_products,
        Helpers.pack(lhs).mulBase(m31.splatPacked(base)),
    );
}

const DifferentialPair = struct {
    trace_log_size: u32,
    relation_z: QM31,
    relation_alpha: QM31,
    claim: QM31,

    fn cast(ctx: *const anyopaque) *const DifferentialPair {
        return @ptrCast(@alignCast(ctx));
    }

    fn semanticComponent(self: *const DifferentialPair) Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = oneConstraint,
                .maxConstraintLogDegreeBound = evalLogSize,
                .traceLogDegreeBounds = unusedTraceBounds,
                .maskPoints = unusedMaskPoints,
                .preprocessedColumnIndices = noPreprocessedIndices,
                .evaluateConstraintQuotientsAtPoint = unusedPointEvaluation,
                .evaluateConstraintQuotientsOnDomain = evaluateSemanticReference,
            },
            .backend_composition_capability = .{
                .base_polynomial_v1 = .{
                    .program_id = 0x1001,
                    .trace_log_size = self.trace_log_size,
                    .selector_tree_index = 0,
                    .selector_column = 1,
                    .main_tree_index = 1,
                    .first_main_column = 0,
                    .main_column_count = 2,
                    .export_program = exportSemanticProgram,
                },
            },
        };
    }

    fn lookupComponent(self: *const DifferentialPair, mismatched_offset: bool) Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = oneConstraint,
                .maxConstraintLogDegreeBound = evalLogSize,
                .traceLogDegreeBounds = unusedTraceBounds,
                .maskPoints = unusedMaskPoints,
                .preprocessedColumnIndices = noPreprocessedIndices,
                .evaluateConstraintQuotientsAtPoint = unusedPointEvaluation,
                .evaluateConstraintQuotientsOnDomain = evaluateLookupReference,
            },
            .backend_composition_capability = .{
                .lookup_polynomial_v1 = .{
                    .program_id = 0x2001,
                    .trace_log_size = self.trace_log_size,
                    .selector_tree_index = 0,
                    .selector_column = 0,
                    .main_tree_index = 1,
                    .first_main_column = if (mismatched_offset) 1 else 0,
                    .main_column_count = 2,
                    .interaction_tree_index = 2,
                    .first_interaction_column = 0,
                    .interaction_column_count = 4,
                    .export_program = exportLookupProgram,
                    .export_parameters = exportLookupParameters,
                },
            },
        };
    }

    fn oneConstraint(_: *const anyopaque) usize {
        return 1;
    }

    fn evalLogSize(ctx: *const anyopaque) u32 {
        return cast(ctx).trace_log_size + 1;
    }

    fn unusedTraceBounds(
        _: *const anyopaque,
        _: std.mem.Allocator,
    ) !core.air.components.TraceLogDegreeBounds {
        return error.UnusedDifferentialHook;
    }

    fn unusedMaskPoints(
        _: *const anyopaque,
        _: std.mem.Allocator,
        _: core.circle.CirclePointQM31,
        _: u32,
    ) !core.air.components.MaskPoints {
        return error.UnusedDifferentialHook;
    }

    fn noPreprocessedIndices(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.alloc(usize, 0);
    }

    fn unusedPointEvaluation(
        _: *const anyopaque,
        _: core.circle.CirclePointQM31,
        _: *const core.air.components.MaskValues,
        _: *core.air.accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {}

    fn exportSemanticProgram(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !BaseProgram {
        const nodes = try allocator.dupe(prover.air.component_prover.BasePolynomialNode, &.{
            .{ .op = .column, .value = 0 },
            .{ .op = .column, .value = 1 },
            .{ .op = .mul, .lhs = 0, .rhs = 1 },
            .{ .op = .column, .value = 2 },
            .{ .op = .sub, .lhs = 2, .rhs = 3 },
        });
        errdefer allocator.free(nodes);
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .roots = try allocator.dupe(u32, &.{4}),
            .column_count = 3,
        };
    }

    fn exportLookupProgram(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !LookupProgram {
        const nodes = try allocator.dupe(prover.air.component_prover.BasePolynomialNode, &.{
            .{ .op = .column, .value = 0 },
            .{ .op = .column, .value = 1 },
        });
        errdefer allocator.free(nodes);
        const entries = try allocator.alloc(prover.air.component_prover.LookupPolynomialEntry, 1);
        errdefer allocator.free(entries);
        var roots: [prover.air.component_prover.MAX_LOOKUP_POLYNOMIAL_ARITY]u32 = undefined;
        roots[0] = 0;
        entries[0] = .{ .numerator = 1, .values = roots, .arity = 1 };
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .entries = entries,
            .column_count = 2,
            .batch_size = 1,
        };
    }

    fn exportLookupParameters(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]QM31 {
        const self = cast(ctx);
        return allocator.dupe(QM31, &.{ self.relation_z, self.relation_alpha, self.claim });
    }

    fn evaluateSemanticReference(
        ctx: *const anyopaque,
        trace: *const Trace,
        accumulator: *Accumulator,
    ) !void {
        const self = cast(ctx);
        const eval_log_size = self.trace_log_size + 1;
        const row_count = @as(usize, 1) << @intCast(eval_log_size);
        const main = trace.polys.items[1];
        const is_active = trace.polys.items[0][1].values;
        const denominators = try denominatorScalars(eval_log_size);
        var columns = try accumulator.columns(
            accumulator.allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        defer accumulator.allocator.free(columns);
        for (0..row_count) |row| {
            const constraint = main[0].values[row].mul(main[1].values[row])
                .sub(is_active[row]);
            columns[0].accumulate(
                row,
                columns[0].random_coeff_powers[0].mulM31(constraint)
                    .mulM31(denominators[@intFromBool(row >= row_count / 2)]),
            );
        }
    }

    fn evaluateLookupReference(
        ctx: *const anyopaque,
        trace: *const Trace,
        accumulator: *Accumulator,
    ) !void {
        const self = cast(ctx);
        const eval_log_size = self.trace_log_size + 1;
        const row_count = @as(usize, 1) << @intCast(eval_log_size);
        const main = trace.polys.items[1];
        const is_first = trace.polys.items[0][0].values;
        const interaction = trace.polys.items[2];
        const denominators = try denominatorScalars(eval_log_size);
        var columns = try accumulator.columns(
            accumulator.allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        defer accumulator.allocator.free(columns);
        for (0..row_count) |row| {
            const previous_row = core.utils.previousBitReversedCircleDomainIndex(
                row,
                self.trace_log_size,
                eval_log_size,
            );
            const current = secureAt(interaction, row);
            const previous = secureAt(interaction, previous_row);
            const relation_denominator = self.relation_alpha.mulM31(main[0].values[row])
                .sub(self.relation_z);
            const delta = current.sub(previous).add(self.claim.mulM31(is_first[row]));
            const constraint = delta.mul(relation_denominator)
                .sub(QM31.fromBase(main[1].values[row]));
            columns[0].accumulate(
                row,
                columns[0].random_coeff_powers[0].mul(constraint)
                    .mulM31(denominators[@intFromBool(row >= row_count / 2)]),
            );
        }
    }

    fn secureAt(columns: []const Poly, row: usize) QM31 {
        return QM31.fromM31(
            columns[0].values[row],
            columns[1].values[row],
            columns[2].values[row],
            columns[3].values[row],
        );
    }
};

test "cpu RISC-V composition: exported adjacent pair matches generic and records admission" {
    const allocator = std.testing.allocator;
    const eval_log_size: u32 = @intCast(std.math.log2_int(usize, m31.PACK_WIDTH) + 1);
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    const mock = DifferentialPair{
        .trace_log_size = eval_log_size - 1,
        .relation_z = QM31.fromU32Unchecked(3, 5, 7, 11),
        .relation_alpha = QM31.fromU32Unchecked(13, 17, 19, 23),
        .claim = QM31.fromU32Unchecked(29, 31, 37, 41),
    };

    const is_first = try allocator.alloc(M31, row_count);
    defer allocator.free(is_first);
    const is_active = try allocator.alloc(M31, row_count);
    defer allocator.free(is_active);
    const main_0 = try allocator.alloc(M31, row_count);
    defer allocator.free(main_0);
    const main_1 = try allocator.alloc(M31, row_count);
    defer allocator.free(main_1);
    var interaction_values: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    for (&interaction_values) |*values| values.* = try allocator.alloc(M31, row_count);
    defer for (interaction_values) |values| allocator.free(values);

    for (0..row_count) |row| {
        is_first[row] = M31.fromCanonical(@intFromBool(row == 0));
        is_active[row] = M31.one();
        main_0[row] = M31.fromCanonical(@intCast(2 * row + 3));
        main_1[row] = M31.fromCanonical(@intCast(5 * row + 7));
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            interaction_values[coordinate][row] = M31.fromCanonical(
                @intCast((coordinate + 2) * (row + 1) + 43),
            );
        }
    }

    const preprocessed = try allocator.dupe(Poly, &.{
        .{ .log_size = eval_log_size, .values = is_first },
        .{ .log_size = eval_log_size, .values = is_active },
    });
    defer allocator.free(preprocessed);
    const main = try allocator.dupe(Poly, &.{
        .{ .log_size = eval_log_size, .values = main_0 },
        .{ .log_size = eval_log_size, .values = main_1 },
    });
    defer allocator.free(main);
    const interaction = try allocator.alloc(Poly, qm31.SECURE_EXTENSION_DEGREE);
    defer allocator.free(interaction);
    for (interaction, interaction_values) |*poly, values| {
        poly.* = .{ .log_size = eval_log_size, .values = values };
    }
    const tree_items = try allocator.dupe([]const Poly, &.{
        preprocessed,
        main,
        interaction,
    });
    var trace = Trace{ .polys = core.pcs.TreeVec([]const Poly).initOwned(tree_items) };
    defer trace.polys.deinit(allocator);

    const components = [_]Component{
        mock.semanticComponent(),
        mock.lookupComponent(false),
    };
    const component_provers = prover.air.component_prover.ComponentProvers{
        .components = components[0..],
        .n_preprocessed_columns = preprocessed.len,
    };
    const random_coeff = QM31.fromU32Unchecked(47, 53, 59, 61);
    var reference = try component_provers.computeCompositionEvaluation(
        allocator,
        random_coeff,
        &trace,
    );
    defer reference.deinit(allocator);

    const admitted_before = telemetrySnapshot();
    var accelerated = (try evaluate(
        allocator,
        components[0..],
        random_coeff,
        &trace,
    )).?;
    defer accelerated.deinit(allocator);
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        for (reference.columns[coordinate], accelerated.columns[coordinate]) |expected, actual| {
            try std.testing.expect(expected.eql(actual));
        }
    }
    const admitted = telemetrySnapshot().delta(admitted_before);
    try std.testing.expectEqual(@as(u64, 1), admitted.attempts);
    try std.testing.expectEqual(@as(u64, 1), admitted.admissions);
    try std.testing.expectEqual(@as(u64, 0), admitted.declines);
    try std.testing.expectEqual(@as(u64, 1), admitted.eligible_pairs);
    try std.testing.expectEqual(@as(u64, 0), admitted.fallback_components);
    try std.testing.expectEqual(@as(u64, 1), admitted.distinct_buckets);
    try std.testing.expectEqual(@as(u64, 1), admitted.row_tiles);
    try std.testing.expect(admitted.max_scratch_bytes_per_worker != 0);

    const mismatched = [_]Component{
        mock.semanticComponent(),
        mock.lookupComponent(true),
    };
    const declined_before = telemetrySnapshot();
    try std.testing.expect(try evaluate(
        allocator,
        mismatched[0..],
        random_coeff,
        &trace,
    ) == null);
    const declined = telemetrySnapshot().delta(declined_before);
    try std.testing.expectEqual(@as(u64, 1), declined.attempts);
    try std.testing.expectEqual(@as(u64, 0), declined.admissions);
    try std.testing.expectEqual(@as(u64, 1), declined.declines);

    var fallback_semantic = mock.semanticComponent();
    fallback_semantic.backend_composition_capability = null;
    const mixed = [_]Component{
        fallback_semantic,
        mock.semanticComponent(),
        mock.lookupComponent(false),
    };
    const mixed_provers = prover.air.component_prover.ComponentProvers{
        .components = mixed[0..],
        .n_preprocessed_columns = preprocessed.len,
    };
    var mixed_reference = try mixed_provers.computeCompositionEvaluation(
        allocator,
        random_coeff,
        &trace,
    );
    defer mixed_reference.deinit(allocator);

    const mixed_before = telemetrySnapshot();
    var mixed_accelerated = (try evaluate(
        allocator,
        mixed[0..],
        random_coeff,
        &trace,
    )).?;
    defer mixed_accelerated.deinit(allocator);
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        for (mixed_reference.columns[coordinate], mixed_accelerated.columns[coordinate]) |expected, actual| {
            try std.testing.expect(expected.eql(actual));
        }
    }
    const mixed_snapshot = telemetrySnapshot().delta(mixed_before);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.attempts);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.admissions);
    try std.testing.expectEqual(@as(u64, 0), mixed_snapshot.declines);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.eligible_pairs);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.fallback_components);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.distinct_buckets);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.row_tiles);
}
