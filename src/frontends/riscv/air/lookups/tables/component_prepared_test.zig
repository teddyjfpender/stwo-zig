//! Focused contract tests for coordinator-prepared fixed-table evaluation.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const pcs = @import("stwo_core").pcs;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const work_pool = @import("stwo_prover_engine").work_pool;
const logup = @import("../../logup.zig");
const relations_mod = @import("../../relation_challenges.zig");
const component_mod = @import("component.zig");
const interaction = @import("interaction.zig");
const schema = @import("schema.zig");

const ConstructionMetadata = component_mod.ConstructionMetadata;
const LookupTableComponent = component_mod.LookupTableComponent;

fn secureTuple(tuple: schema.Tuple) [schema.MAX_ARITY]QM31 {
    var result = [_]QM31{QM31.zero()} ** schema.MAX_ARITY;
    for (tuple.slice(), result[0..tuple.len]) |value, *dst| dst.* = QM31.fromBase(value);
    return result;
}

test "lookup table component: construction metadata pins all schemas" {
    const expected_logs = [_]u32{ 18, 20, 19, 20, 16, 15 };
    const expected_arities = [_]usize{ 4, 1, 2, 3, 2, 2 };
    for (0..schema.KIND_COUNT) |index| {
        const kind: schema.Kind = @enumFromInt(index);
        const metadata = ConstructionMetadata.forKind(kind);
        try std.testing.expectEqual(expected_logs[index], metadata.log_size);
        try std.testing.expectEqual(expected_arities[index], metadata.tuple_columns);
        try std.testing.expectEqual(1 + expected_arities[index], metadata.preprocessed_columns);
        try std.testing.expectEqual(@as(usize, 1), metadata.main_columns);
        try std.testing.expectEqual(@as(usize, 4), metadata.interaction_columns);
        try std.testing.expectEqual(@as(usize, 4), metadata.previous_masks);
        try std.testing.expectEqual(@as(usize, 1), metadata.constraints);
    }
}

test "lookup table component: verifier construction exposes exact masks and columns" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const component = try LookupTableComponent.initVerifier(
        .range_check_8_8_4,
        3,
        &.{ 7, 8, 9 },
        11,
        13,
        &relations,
        QM31.zero(),
    );
    const verifier = component.asVerifierComponent();
    try std.testing.expectEqual(@as(usize, 1), verifier.nConstraints());
    try std.testing.expectEqual(@as(u32, 21), verifier.maxConstraintLogDegreeBound());
    const indices = try verifier.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 3, 7, 8, 9 }, indices);
    var bounds = try verifier.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(@as(usize, 4), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 1), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, 4), bounds.items[2].len);
    var masks = try verifier.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        verifier.maxConstraintLogDegreeBound(),
    );
    defer masks.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 4), masks.items[0].len);
    try std.testing.expectEqual(@as(usize, 1), masks.items[1].len);
    for (masks.items[2]) |column| try std.testing.expectEqual(@as(usize, 2), column.len);
}

test "lookup table component: singleton identity rejects all placement mutations" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const kind: schema.Kind = .range_check_8_8;
    const tuple0 = try schema.tupleAt(kind, 1);
    const tuple1 = try schema.tupleAt(kind, 258);
    const signed_multiplicity = M31.one().neg();
    const pairs = [_]logup.RowPair{
        try interaction.rowPair(kind, tuple0, signed_multiplicity, &relations),
        try interaction.rowPair(kind, tuple1, signed_multiplicity, &relations),
    };
    var cumulative = try logup.cumulativeColumn(allocator, &pairs);
    defer cumulative.deinit(allocator);
    const component = try LookupTableComponent.initVerifier(
        kind,
        0,
        &.{ 1, 2 },
        0,
        0,
        &relations,
        cumulative.claimed,
    );
    const secure0 = secureTuple(tuple0);
    const secure1 = secureTuple(tuple1);
    const multiplicity = QM31.fromBase(signed_multiplicity);
    try std.testing.expect((try component.evaluateRow(
        secure0[0..tuple0.len],
        multiplicity,
        cumulative.sums[0],
        cumulative.sums[1],
        QM31.one(),
    )).isZero());
    try std.testing.expect((try component.evaluateRow(
        secure1[0..tuple1.len],
        multiplicity,
        cumulative.sums[1],
        cumulative.sums[0],
        QM31.zero(),
    )).isZero());
    var bad_tuple = secure0;
    bad_tuple[0] = bad_tuple[0].add(QM31.one());
    try std.testing.expect(!(try component.evaluateRow(
        bad_tuple[0..tuple0.len],
        multiplicity,
        cumulative.sums[0],
        cumulative.sums[1],
        QM31.one(),
    )).isZero());
    try std.testing.expect(!(try component.evaluateRow(
        secure0[0..tuple0.len],
        multiplicity.add(QM31.one()),
        cumulative.sums[0],
        cumulative.sums[1],
        QM31.one(),
    )).isZero());
    var bad_claim = component;
    bad_claim.claim = bad_claim.claim.add(QM31.one());
    try std.testing.expect(!(try bad_claim.evaluateRow(
        secure0[0..tuple0.len],
        multiplicity,
        cumulative.sums[0],
        cumulative.sums[1],
        QM31.one(),
    )).isZero());
    try std.testing.expect(!(try component.evaluateRow(
        secure1[0..tuple1.len],
        multiplicity,
        cumulative.sums[1],
        cumulative.sums[1],
        QM31.zero(),
    )).isZero());
}

test "lookup table component: OODS adapter enforces predecessor ordering" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const kind: schema.Kind = .range_check_8_8;
    const table_tuple = try schema.tupleAt(kind, 258);
    const signed_multiplicity = M31.one().neg();
    const pairs = [_]logup.RowPair{
        try interaction.rowPair(kind, table_tuple, signed_multiplicity, &relations),
    };
    var cumulative = try logup.cumulativeColumn(allocator, &pairs);
    defer cumulative.deinit(allocator);
    const component = try LookupTableComponent.initVerifier(
        kind,
        0,
        &.{ 1, 2 },
        0,
        0,
        &relations,
        cumulative.claimed,
    );
    var first_values = [_]QM31{QM31.one()};
    var tuple0_values = [_]QM31{QM31.fromBase(table_tuple.values[0])};
    var tuple1_values = [_]QM31{QM31.fromBase(table_tuple.values[1])};
    var preprocessed = [_][]QM31{ &first_values, &tuple0_values, &tuple1_values };
    var multiplicity_values = [_]QM31{QM31.fromBase(signed_multiplicity)};
    var main = [_][]QM31{&multiplicity_values};
    const current = cumulative.sums[0].toM31Array();
    var coordinate0 = [_]QM31{ QM31.fromBase(current[0]), QM31.fromBase(current[0]) };
    var coordinate1 = [_]QM31{ QM31.fromBase(current[1]), QM31.fromBase(current[1]) };
    var coordinate2 = [_]QM31{ QM31.fromBase(current[2]), QM31.fromBase(current[2]) };
    var coordinate3 = [_]QM31{ QM31.fromBase(current[3]), QM31.fromBase(current[3]) };
    var secure = [_][]QM31{ &coordinate0, &coordinate1, &coordinate2, &coordinate3 };
    var trees = [_][][]QM31{ &preprocessed, &main, &secure };
    const mask = core_air_components.MaskValues.initOwned(&trees);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var honest = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &honest,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(honest.finalize().isZero());
    coordinate0[1] = coordinate0[1].add(QM31.one());
    var reordered = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &reordered,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!reordered.finalize().isZero());
}

test "lookup table component: constructors fail closed on ambiguous bindings" {
    const relations = relations_mod.Relations.dummy();
    try std.testing.expectError(
        error.InvalidTraceShape,
        LookupTableComponent.initVerifier(.range_check_8_8, 0, &.{1}, 0, 0, &relations, QM31.zero()),
    );
    try std.testing.expectError(
        error.InvalidTraceShape,
        LookupTableComponent.initVerifier(.range_check_8_8, 0, &.{ 1, 1 }, 0, 0, &relations, QM31.zero()),
    );
    try std.testing.expectError(
        error.InvalidTraceShape,
        LookupTableComponent.initVerifier(.range_check_8_8, 0, &.{ 0, 1 }, 0, 0, &relations, QM31.zero()),
    );
}

test "lookup table component: prover construction uses committed shift masks" {
    const relations = relations_mod.Relations.dummy();
    const component = try LookupTableComponent.initProver(
        .range_check_m31,
        0,
        &.{ 1, 2 },
        3,
        4,
        &relations,
        QM31.zero(),
    );
    const prover = component.asProverComponent();
    try std.testing.expectEqual(@as(usize, 1), prover.nConstraints());
    try std.testing.expectEqual(@as(u32, 16), prover.maxConstraintLogDegreeBound());
    try std.testing.expect(prover.prepare_domain_evaluator != null);
    try std.testing.expect(prover.domain_parallel_evaluator == null);
    try std.testing.expect(!prover.pool_exclusive_domain);
}

const TableFixture = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    preprocessed: [1 + schema.MAX_ARITY]prover_component.Poly,
    main: [1]prover_component.Poly,
    secure: [interaction.N_COLUMNS]prover_component.Poly,
    trees: [3][]const prover_component.Poly,
    trace_data: prover_component.Trace,
    eval_log_size: u32,
    eval_size: usize,
    n_tuple: usize,

    fn init(self: *@This(), allocator: std.mem.Allocator, kind: schema.Kind) !void {
        const eval_log_size = schema.logSize(kind) + 1;
        const eval_size = @as(usize, 1) << @intCast(eval_log_size);
        const n_tuple = schema.arity(kind);
        const source_count = 2 + n_tuple + interaction.N_COLUMNS;
        self.* = undefined;
        self.allocator = allocator;
        self.storage = try allocator.alloc(M31, source_count * eval_size);
        self.eval_log_size = eval_log_size;
        self.eval_size = eval_size;
        self.n_tuple = n_tuple;
        var source: usize = 0;
        for (self.preprocessed[0 .. 1 + n_tuple]) |*destination| {
            destination.* = self.poly(source);
            source += 1;
        }
        self.main[0] = self.poly(source);
        source += 1;
        for (&self.secure) |*destination| {
            destination.* = self.poly(source);
            source += 1;
        }
        self.trees = .{
            self.preprocessed[0 .. 1 + n_tuple],
            self.main[0..],
            self.secure[0..],
        };
        self.trace_data = .{
            .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&self.trees),
        };
    }

    fn poly(self: *@This(), source: usize) prover_component.Poly {
        const start = source * self.eval_size;
        const values = self.storage[start .. start + self.eval_size];
        for (values, 0..) |*value, row| {
            value.* = M31.fromU64((@as(u64, source) + 1) * 65_537 + row * 257 + 1);
        }
        return .{ .log_size = self.eval_log_size, .values = values };
    }

    fn deinit(self: *@This()) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

fn legacyEvaluateTableDomain(
    component: *const LookupTableComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !void {
    const allocator = accumulator.allocator;
    const log_size = schema.logSize(component.kind);
    const eval_log_size = log_size + 1;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const eval_size = eval_domain.size();
    const n_tuple = schema.arity(component.kind);
    const evaluations = try allocator.alloc([]const M31, 2 + n_tuple + interaction.N_COLUMNS);
    defer allocator.free(evaluations);
    const pp = trace_data.polys.items[0];
    const main = trace_data.polys.items[1];
    const secure = trace_data.polys.items[2];
    var source: usize = 0;
    evaluations[source] = pp[component.is_first_col_idx].values;
    source += 1;
    for (component.tuple_col_indices[0..n_tuple]) |index| {
        evaluations[source] = pp[index].values;
        source += 1;
    }
    evaluations[source] = main[component.main_col_offset].values;
    source += 1;
    for (secure[component.interaction_col_offset..][0..interaction.N_COLUMNS]) |poly| {
        evaluations[source] = poly.values;
        source += 1;
    }
    var denominator_inv: [2]M31 = undefined;
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (&denominator_inv, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(index),
        ).inv();
    }
    const accumulators = try accumulator.columns(
        allocator,
        &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
    );
    defer allocator.free(accumulators);
    const column_accumulator = &accumulators[0];
    const direct_store = column_accumulator.next_fresh_index == 0;
    const main_index = 1 + n_tuple;
    const interaction_start = main_index + 1;
    for (0..eval_size) |row| {
        const previous_row = utils.previousBitReversedCircleDomainIndex(
            row,
            log_size,
            eval_log_size,
        );
        var tuple: [schema.MAX_ARITY]QM31 = undefined;
        for (tuple[0..n_tuple], evaluations[1..][0..n_tuple]) |*value, column| {
            value.* = QM31.fromBase(column[row]);
        }
        const constraint = try component.evaluateRow(
            tuple[0..n_tuple],
            QM31.fromBase(evaluations[main_index][row]),
            secureAt(evaluations[interaction_start..][0..interaction.N_COLUMNS], row),
            secureAt(evaluations[interaction_start..][0..interaction.N_COLUMNS], previous_row),
            QM31.fromBase(evaluations[0][row]),
        );
        const contribution = column_accumulator.random_coeff_powers[0]
            .mul(constraint)
            .mulM31(denominator_inv[row >> @intCast(log_size)]);
        const output = column_accumulator.col;
        if (direct_store) output.set(row, contribution) else output.set(row, output.at(row).add(contribution));
    }
    column_accumulator.next_fresh_index = if (direct_store) eval_size else null;
}

fn serialTaskContext(
    user_context: *anyopaque,
    cancellation: *const prover_task_graph.CancellationToken,
) prover_task_graph.TaskContext {
    return .{
        .user_context = user_context,
        .cancellation = cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
}

const PreparedThreadInvocation = struct {
    prepared: *prepared_domain.PreparedDomainEvaluation,
    cancellation: *const prover_task_graph.CancellationToken,
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        var context = serialTaskContext(self.prepared.context, self.cancellation);
        self.prepared.run(&context) catch |failure| {
            self.failure = failure;
        };
    }
};

fn runPreparedOnReviewedStack(
    prepared: *prepared_domain.PreparedDomainEvaluation,
    cancellation: *const prover_task_graph.CancellationToken,
) !void {
    var invocation = PreparedThreadInvocation{
        .prepared = prepared,
        .cancellation = cancellation,
    };
    const thread = try std.Thread.spawn(
        .{ .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES },
        PreparedThreadInvocation.run,
        .{&invocation},
    );
    thread.join();
    if (invocation.failure) |failure| return failure;
}

fn runPreparedWithWorkers(
    prepared: *prepared_domain.PreparedDomainEvaluation,
    worker_count: usize,
) !prover_task_graph.ExecutionReport {
    const Runner = struct {
        prepared: *prepared_domain.PreparedDomainEvaluation,

        fn run(context: *prover_task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            try self.prepared.run(context);
        }
    };

    var runner = Runner{ .prepared = prepared };
    var graph = try prover_task_graph.ComponentTaskGraph.init(std.testing.allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .name = "lookup-table-prepared-domain",
        .func = Runner.run,
        .context = &runner,
        .class = prepared.task_class,
        .resources = prepared.resources,
        .work_estimate = 1,
    });

    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = worker_count,
        .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    });
    defer pool.deinit();
    try std.testing.expectEqual(
        @as(usize, 128 * 1024),
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    );
    try std.testing.expectEqual(prepared_domain.ROW_EVALUATOR_STACK_BYTES, pool.stackSize());
    return graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(worker_count),
        .pool = &pool,
    });
}

fn prepareTableDomainForFailure(
    allocator: std.mem.Allocator,
    component: *const LookupTableComponent,
    trace_data: *const prover_component.Trace,
) !void {
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        component.maxConstraintLogDegreeBound(),
        component.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        allocator,
        trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();
}

fn expectParallelRangeFailureCancellation() !void {
    const allocator = std.testing.allocator;
    var fixture: TableFixture = undefined;
    try fixture.init(allocator, .range_check_20);
    defer fixture.deinit();
    const relations = relations_mod.Relations.dummy();
    var component = try LookupTableComponent.initProver(
        .range_check_20,
        0,
        &.{1},
        0,
        0,
        &relations,
        QM31.zero(),
    );
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        fixture.eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        allocator,
        &fixture.trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();

    // Preparation captures one tuple column. Switching to a two-tuple schema
    // makes every started range fail with InvalidTraceShape at its first row.
    // Range zero must still run even if a helper publishes its failure first.
    component.kind = .range_check_8_8;
    const telemetry_before = component_mod.preparedParallelTelemetrySnapshot();
    try std.testing.expectError(
        error.InvalidTraceShape,
        runPreparedWithWorkers(&prepared, 4),
    );
    const telemetry = component_mod.PreparedParallelTelemetrySnapshot.delta(
        component_mod.preparedParallelTelemetrySnapshot(),
        telemetry_before,
    );
    try std.testing.expectEqual(@as(u64, 3), telemetry.child_submissions);
    try std.testing.expectEqual(@as(u64, 3), telemetry.child_completions);
    try std.testing.expect(telemetry.range_failures >= 1);
    try std.testing.expect(telemetry.local_cancellation_requests >= 1);
    try std.testing.expect(
        telemetry.local_cancellation_requests <= telemetry.range_failures,
    );
}

fn expectByteEquivalent(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(expected.len(), actual.len());
    inline for (0..4) |coordinate| {
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(expected.columns[coordinate]),
            std.mem.sliceAsBytes(actual.columns[coordinate]),
        );
    }
}

test "lookup table prepared domain: legacy bytes allocation freedom stack and cancellation" {
    const allocator = std.testing.allocator;
    const kind: schema.Kind = .range_check_m31;
    var fixture: TableFixture = undefined;
    try fixture.init(allocator, kind);
    defer fixture.deinit();
    const relations = relations_mod.Relations.dummy();
    const component = try LookupTableComponent.initProver(
        kind,
        0,
        &.{ 1, 2 },
        0,
        0,
        &relations,
        QM31.zero(),
    );
    const random_coeff = QM31.fromU32Unchecked(5, 1, 0, 0);
    var legacy_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        fixture.eval_log_size,
        component.nConstraints(),
    );
    defer legacy_accumulator.deinit();
    try legacyEvaluateTableDomain(&component, &fixture.trace_data, &legacy_accumulator);
    var legacy = try legacy_accumulator.finalize();
    defer legacy.deinit(allocator);
    var saw_nonzero = false;
    for (0..legacy.len()) |row| saw_nonzero = saw_nonzero or !legacy.at(row).isZero();
    try std.testing.expect(saw_nonzero);

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const prepared_allocator = failing.allocator();
    var prepared_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        prepared_allocator,
        random_coeff,
        fixture.eval_log_size,
        component.nConstraints(),
    );
    defer prepared_accumulator.deinit();
    var prepared = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        prepared_allocator,
        &fixture.trace_data,
        &prepared_accumulator,
    )).?;
    defer prepared.deinit();
    try std.testing.expectEqual(prover_task_graph.TaskClass.pool_exclusive, prepared.task_class);
    try std.testing.expectEqual(
        fixture.eval_size * @sizeOf(QM31),
        prepared.resources.final_output_bytes,
    );
    try std.testing.expect(prepared.resources.shared_resident_bytes > 0);
    try std.testing.expectEqual(@as(usize, 0), prepared.resources.exclusive_scratch_bytes);
    try std.testing.expectEqual(@as(usize, 0), prepared.resources.device_resident_bytes);
    try std.testing.expectEqual(
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        prepared.resources.worker_stack_bytes,
    );
    const allocation_count = failing.alloc_index;
    const resize_count = failing.resize_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = resize_count;
    var cancellation = prover_task_graph.CancellationToken{};
    const serial_telemetry_before = component_mod.preparedParallelTelemetrySnapshot();
    try runPreparedOnReviewedStack(&prepared, &cancellation);
    const serial_telemetry = component_mod.PreparedParallelTelemetrySnapshot.delta(
        component_mod.preparedParallelTelemetrySnapshot(),
        serial_telemetry_before,
    );
    try std.testing.expectEqual(@as(u64, 0), serial_telemetry.child_submissions);
    try std.testing.expectEqual(@as(u64, 0), serial_telemetry.child_completions);
    try std.testing.expectEqual(@as(u64, 0), serial_telemetry.range_failures);
    try std.testing.expectEqual(@as(u64, 0), serial_telemetry.local_cancellation_requests);
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(resize_count, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    failing.resize_fail_index = std.math.maxInt(usize);
    var actual = try prepared_accumulator.finalize();
    defer actual.deinit(prepared_allocator);
    try expectByteEquivalent(legacy, actual);

    for ([_]usize{ 2, 4 }) |worker_count| {
        var parallel_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
            allocator,
            random_coeff,
            fixture.eval_log_size,
            component.nConstraints(),
        );
        defer parallel_accumulator.deinit();
        var parallel = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
            allocator,
            &fixture.trace_data,
            &parallel_accumulator,
        )).?;
        defer parallel.deinit();
        const telemetry_before = component_mod.preparedParallelTelemetrySnapshot();
        const report = try runPreparedWithWorkers(&parallel, worker_count);
        const telemetry = component_mod.PreparedParallelTelemetrySnapshot.delta(
            component_mod.preparedParallelTelemetrySnapshot(),
            telemetry_before,
        );
        const expected_children = worker_count - 1;
        try std.testing.expectEqual(worker_count, report.configured_workers);
        try std.testing.expectEqual(@as(usize, 1), report.succeeded_tasks);
        try std.testing.expectEqual(@as(usize, 0), report.failed_tasks);
        try std.testing.expectEqual(
            @as(u64, @intCast(expected_children)),
            telemetry.child_submissions,
        );
        try std.testing.expectEqual(
            @as(u64, @intCast(expected_children)),
            telemetry.child_completions,
        );
        try std.testing.expectEqual(@as(u64, 0), telemetry.range_failures);
        try std.testing.expectEqual(@as(u64, 0), telemetry.local_cancellation_requests);
        var parallel_result = try parallel_accumulator.finalize();
        defer parallel_result.deinit(allocator);
        try expectByteEquivalent(legacy, parallel_result);
    }

    try std.testing.checkAllAllocationFailures(
        allocator,
        prepareTableDomainForFailure,
        .{ &component, &fixture.trace_data },
    );
    var cancelled_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        fixture.eval_log_size,
        component.nConstraints(),
    );
    defer cancelled_accumulator.deinit();
    var cancelled = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        allocator,
        &fixture.trace_data,
        &cancelled_accumulator,
    )).?;
    defer cancelled.deinit();
    var cancelled_token = prover_task_graph.CancellationToken{};
    _ = cancelled_token.request();
    try runPreparedOnReviewedStack(&cancelled, &cancelled_token);
    var cancelled_result = try cancelled_accumulator.finalize();
    defer cancelled_result.deinit(allocator);
    for (0..cancelled_result.len()) |row| {
        try std.testing.expect(cancelled_result.at(row).isZero());
    }
    try expectParallelRangeFailureCancellation();
}

fn expectPrepareError(
    expected: anyerror,
    component: *const LookupTableComponent,
    trace_data: *const prover_component.Trace,
    accumulator_log_size: u32,
) !void {
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        std.testing.allocator,
        QM31.one(),
        accumulator_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    try std.testing.expectError(
        expected,
        component.asProverComponent().prepareConstraintQuotientsOnDomain(
            std.testing.allocator,
            trace_data,
            &accumulator,
        ),
    );
}

test "lookup table prepared domain: adversarial committed shapes fail closed" {
    const allocator = std.testing.allocator;
    const kind: schema.Kind = .range_check_m31;
    var fixture: TableFixture = undefined;
    try fixture.init(allocator, kind);
    defer fixture.deinit();
    const relations = relations_mod.Relations.dummy();
    const component = try LookupTableComponent.initProver(
        kind,
        0,
        &.{ 1, 2 },
        0,
        0,
        &relations,
        QM31.zero(),
    );
    var short_trees = [_][]const prover_component.Poly{
        fixture.trees[0],
        fixture.trees[1],
    };
    const short_trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&short_trees),
    };
    try expectPrepareError(
        error.InvalidProofShape,
        &component,
        &short_trace,
        fixture.eval_log_size,
    );
    var overflowing_offset = component;
    overflowing_offset.interaction_col_offset = std.math.maxInt(usize);
    try expectPrepareError(
        error.InvalidProofShape,
        &overflowing_offset,
        &fixture.trace_data,
        fixture.eval_log_size,
    );
    overflowing_offset = component;
    overflowing_offset.main_col_offset = std.math.maxInt(usize);
    try expectPrepareError(
        error.InvalidProofShape,
        &overflowing_offset,
        &fixture.trace_data,
        fixture.eval_log_size,
    );
    {
        const saved = fixture.preprocessed[1];
        defer fixture.preprocessed[1] = saved;
        fixture.preprocessed[1] = .{
            .log_size = fixture.eval_log_size - 1,
            .values = saved.values[0 .. fixture.eval_size / 2],
        };
        try expectPrepareError(
            error.InvalidProofShape,
            &component,
            &fixture.trace_data,
            fixture.eval_log_size,
        );
    }
    {
        const saved = fixture.secure[0];
        defer fixture.secure[0] = saved;
        fixture.secure[0].values = saved.values[0 .. saved.values.len - 1];
        try expectPrepareError(
            error.InvalidColumnLength,
            &component,
            &fixture.trace_data,
            fixture.eval_log_size,
        );
    }
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}
