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
const ColumnAccumulator = prover.air.accumulation.ColumnAccumulator;
const PreparedDomainEvaluation = prover.air.prepared_domain.PreparedDomainEvaluation;
const TaskContext = prover.task_graph.TaskContext;

const evaluate = composition.evaluate;
const evaluateWithExecution = composition.evaluateWithExecution;
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
    legacy_semantic_calls: ?*std.atomic.Value(usize) = null,
    prepared_semantic_calls: ?*std.atomic.Value(usize) = null,
    prepared_semantic_runs: ?*std.atomic.Value(usize) = null,

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
            .prepare_domain_evaluator = prepareSemanticDomain,
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
        if (self.legacy_semantic_calls) |calls| _ = calls.fetchAdd(1, .monotonic);
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

    const PreparedSemanticState = struct {
        allocator: std.mem.Allocator,
        owner: *const DifferentialPair,
        main_0: []const M31,
        main_1: []const M31,
        is_active: []const M31,
        denominators: [2]M31,
        column_accumulators: []ColumnAccumulator,

        const vtable = prover.air.prepared_domain.VTable{
            .run = runErased,
            .deinit = deinitErased,
        };

        fn runErased(context: *anyopaque, task_context: *TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.owner.prepared_semantic_runs) |runs| {
                _ = runs.fetchAdd(1, .monotonic);
            }
            const column = &self.column_accumulators[0];
            for (self.main_0, self.main_1, self.is_active, 0..) |lhs, rhs, active, row| {
                if (task_context.isCancelled()) return;
                const constraint = lhs.mul(rhs).sub(active);
                column.accumulate(
                    row,
                    column.random_coeff_powers[0].mulM31(constraint)
                        .mulM31(self.denominators[@intFromBool(row >= self.main_0.len / 2)]),
                );
            }
        }

        fn deinitErased(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const allocator = self.allocator;
            allocator.free(self.column_accumulators);
            allocator.destroy(self);
        }
    };

    fn prepareSemanticDomain(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace: *const Trace,
        accumulator: *Accumulator,
    ) !PreparedDomainEvaluation {
        const self = cast(ctx);
        if (self.prepared_semantic_calls) |calls| _ = calls.fetchAdd(1, .monotonic);
        const eval_log_size = self.trace_log_size + 1;
        const row_count = @as(usize, 1) << @intCast(eval_log_size);
        if (trace.polys.items.len < 2 or trace.polys.items[0].len < 2 or
            trace.polys.items[1].len < 2)
        {
            return error.InvalidProofShape;
        }
        const main = trace.polys.items[1];
        const is_active = trace.polys.items[0][1].values;
        if (main[0].values.len != row_count or main[1].values.len != row_count or
            is_active.len != row_count)
        {
            return error.InvalidProofShape;
        }

        const denominators = try denominatorScalars(eval_log_size);
        const state = try allocator.create(PreparedSemanticState);
        errdefer allocator.destroy(state);
        const columns = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        errdefer allocator.free(columns);
        state.* = .{
            .allocator = allocator,
            .owner = self,
            .main_0 = main[0].values,
            .main_1 = main[1].values,
            .is_active = is_active,
            .denominators = denominators,
            .column_accumulators = columns,
        };
        return .{
            .context = state,
            .vtable = &PreparedSemanticState.vtable,
            .resources = .{
                .final_output_bytes = row_count * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31),
                .shared_resident_bytes = @sizeOf(PreparedSemanticState) + @sizeOf(ColumnAccumulator),
                .worker_stack_bytes = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
            },
        };
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
    // Four 4,096-row accelerator tiles exercise the same canonical plan with
    // one, two, and four execution lanes below.
    const eval_log_size: u32 = 14;
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    var legacy_semantic_calls: std.atomic.Value(usize) = .init(0);
    var prepared_semantic_calls: std.atomic.Value(usize) = .init(0);
    var prepared_semantic_runs: std.atomic.Value(usize) = .init(0);
    const mock = DifferentialPair{
        .trace_log_size = eval_log_size - 1,
        .relation_z = QM31.fromU32Unchecked(3, 5, 7, 11),
        .relation_alpha = QM31.fromU32Unchecked(13, 17, 19, 23),
        .claim = QM31.fromU32Unchecked(29, 31, 37, 41),
        .legacy_semantic_calls = &legacy_semantic_calls,
        .prepared_semantic_calls = &prepared_semantic_calls,
        .prepared_semantic_runs = &prepared_semantic_runs,
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
    try std.testing.expectEqual(@as(u64, 4), admitted.row_tiles);
    try std.testing.expectEqual(@as(u64, 1), admitted.execution_lanes);
    try std.testing.expectEqual(@as(u64, 1), admitted.structured_executions);
    try std.testing.expectEqual(@as(u64, 1), admitted.max_graph_peak_active);
    try std.testing.expect(admitted.max_scratch_bytes_per_worker != 0);
    try std.testing.expectEqual(@as(usize, 1), legacy_semantic_calls.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), prepared_semantic_calls.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), prepared_semantic_runs.load(.monotonic));

    for ([_]usize{ 2, 4 }) |worker_count| {
        var pool: prover.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{
            .worker_count = worker_count,
            .stack_size = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        });
        defer pool.deinit();
        const explicit_before = telemetrySnapshot();
        var explicit = (try evaluateWithExecution(
            allocator,
            components[0..],
            random_coeff,
            &trace,
            .{
                .worker_budget = try prover.work_pool.WorkerBudget.init(worker_count),
                .pool = &pool,
            },
        )).?;
        defer explicit.deinit(allocator);
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            for (reference.columns[coordinate], explicit.columns[coordinate]) |expected, actual| {
                try std.testing.expect(expected.eql(actual));
            }
        }
        const explicit_snapshot = telemetrySnapshot().delta(explicit_before);
        try std.testing.expectEqual(@as(u64, 4), explicit_snapshot.row_tiles);
        try std.testing.expectEqual(@as(u64, @intCast(worker_count)), explicit_snapshot.execution_lanes);
        try std.testing.expectEqual(@as(u64, 0), explicit_snapshot.pool_lease_declines);
        try std.testing.expect(explicit_snapshot.max_graph_peak_active >= worker_count);
    }

    const finite_budget_before = telemetrySnapshot();
    var finite_failing = std.testing.FailingAllocator.init(allocator, .{});
    finite_failing.fail_index = finite_failing.alloc_index;
    finite_failing.resize_fail_index = finite_failing.resize_index;
    try std.testing.expectError(
        error.FiniteCompositionByteBudgetUnsupported,
        evaluateWithExecution(
            finite_failing.allocator(),
            components[0..],
            random_coeff,
            &trace,
            .{ .byte_budget = 1 },
        ),
    );
    try std.testing.expect(!finite_failing.has_induced_failure);
    const finite_budget_snapshot = telemetrySnapshot().delta(finite_budget_before);
    try std.testing.expectEqual(@as(u64, 1), finite_budget_snapshot.finite_budget_rejections);

    // Strict callers observe lease contention before any task starts. The
    // compatibility wrapper may reuse the already-prepared graph serially,
    // and must report that it did not honor the requested parallel lease.
    var contention_pool: prover.work_pool.WorkPool = undefined;
    try contention_pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    });
    defer contention_pool.deinit();
    var competing_lease = try contention_pool.acquire(
        try prover.work_pool.WorkerBudget.init(2),
    );
    defer competing_lease.deinit();
    try std.testing.expectError(
        error.WorkerBudgetUnavailable,
        evaluateWithExecution(
            allocator,
            components[0..],
            random_coeff,
            &trace,
            .{
                .worker_budget = try prover.work_pool.WorkerBudget.init(2),
                .pool = &contention_pool,
            },
        ),
    );
    const contention_before = telemetrySnapshot();
    var contention_fallback = (try evaluateWithExecution(
        allocator,
        components[0..],
        random_coeff,
        &trace,
        .{
            .worker_budget = try prover.work_pool.WorkerBudget.init(2),
            .pool = &contention_pool,
            .serial_on_contention = true,
        },
    )).?;
    defer contention_fallback.deinit(allocator);
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        try std.testing.expectEqualSlices(
            M31,
            reference.columns[coordinate],
            contention_fallback.columns[coordinate],
        );
    }
    const contention_snapshot = telemetrySnapshot().delta(contention_before);
    try std.testing.expectEqual(@as(u64, 1), contention_snapshot.pool_lease_declines);

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
    try std.testing.expectError(
        error.FiniteCompositionByteBudgetUnsupported,
        evaluateWithExecution(
            allocator,
            mismatched[0..],
            random_coeff,
            &trace,
            .{ .byte_budget = 1 },
        ),
    );

    var legacy_fallback = mock.semanticComponent();
    legacy_fallback.backend_composition_capability = null;
    legacy_fallback.prepare_domain_evaluator = null;
    const strict_mixed = [_]Component{
        legacy_fallback,
        mock.semanticComponent(),
        mock.lookupComponent(false),
    };
    const strict_before = telemetrySnapshot();
    const legacy_before_strict = legacy_semantic_calls.load(.monotonic);
    try std.testing.expectError(
        error.UnpreparedCompositionFallback,
        evaluateWithExecution(
            allocator,
            strict_mixed[0..],
            random_coeff,
            &trace,
            .{},
        ),
    );
    const strict_snapshot = telemetrySnapshot().delta(strict_before);
    try std.testing.expectEqual(
        @as(u64, 1),
        strict_snapshot.unprepared_fallback_rejections,
    );
    try std.testing.expectEqual(
        legacy_before_strict,
        legacy_semantic_calls.load(.monotonic),
    );

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
    const legacy_calls_before_acceleration = legacy_semantic_calls.load(.monotonic);

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
    try std.testing.expectEqual(@as(u64, 4), mixed_snapshot.row_tiles);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.execution_lanes);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.structured_executions);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.prepared_fallback_components);
    try std.testing.expectEqual(@as(u64, 0), mixed_snapshot.coordinator_fallback_components);
    try std.testing.expectEqual(
        legacy_calls_before_acceleration,
        legacy_semantic_calls.load(.monotonic),
    );
    try std.testing.expectEqual(@as(usize, 1), prepared_semantic_calls.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 1), prepared_semantic_runs.load(.monotonic));

    for ([_]usize{ 2, 4 }) |worker_count| {
        var pool: prover.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{
            .worker_count = worker_count,
            .stack_size = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        });
        defer pool.deinit();
        var parallel_mixed = (try evaluateWithExecution(
            allocator,
            mixed[0..],
            random_coeff,
            &trace,
            .{
                .worker_budget = try prover.work_pool.WorkerBudget.init(worker_count),
                .pool = &pool,
            },
        )).?;
        defer parallel_mixed.deinit(allocator);
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            try std.testing.expectEqualSlices(
                M31,
                mixed_reference.columns[coordinate],
                parallel_mixed.columns[coordinate],
            );
        }
    }
}
