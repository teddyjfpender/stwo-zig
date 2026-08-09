//! Parallel execution contracts for coordinator-prepared opcode lookup evaluation.

const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const work_pool = @import("stwo_prover_engine").work_pool;
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");
const component_mod = @import("opcode_component.zig");
const entry = @import("entry.zig");
const opcode_entries = @import("opcode_entries.zig");
const support = @import("opcode_component_prepared_test_support.zig");

const OpcodeLookupComponent = component_mod.OpcodeLookupComponent;
const OpcodeFixture = support.OpcodeFixture;

fn legacyEvaluateOpcodeDomain(
    component: *const OpcodeLookupComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !void {
    const allocator = accumulator.allocator;
    const eval_log_size = component.log_size + 1;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const eval_size = eval_domain.size();
    const n_main = trace.nColumnsForFamily(component.family);
    const n_interaction = opcode_entries.interactionColumnCount(component.family);
    const preprocessed = trace_data.polys.items[0];
    const main = trace_data.polys.items[1];
    const secure = trace_data.polys.items[2];
    const evaluations = try allocator.alloc([]const M31, 1 + n_main + n_interaction);
    defer allocator.free(evaluations);
    var source: usize = 0;
    evaluations[source] = preprocessed[component.is_first_col_idx].values;
    source += 1;
    for (main[component.main_col_offset..][0..n_main]) |poly| {
        evaluations[source] = poly.values;
        source += 1;
    }
    for (secure[component.interaction_col_offset..][0..n_interaction]) |poly| {
        evaluations[source] = poly.values;
        source += 1;
    }
    const denominator_inv = try allocator.alloc(M31, 2);
    defer allocator.free(denominator_inv);
    const coset = canonic.CanonicCoset.new(component.log_size).coset();
    for (denominator_inv, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    const accumulators = try accumulator.columns(
        allocator,
        &.{.{ .log_size = eval_log_size, .n_cols = component.nConstraints() }},
    );
    defer allocator.free(accumulators);
    const column_accumulator = &accumulators[0];
    const direct_store = column_accumulator.next_fresh_index == 0;
    const interaction_start = 1 + n_main;
    const batch_count = component.nConstraints();
    const powers = column_accumulator.random_coeff_powers;
    for (0..eval_size) |row| {
        const previous_row = utils.previousBitReversedCircleDomainIndex(
            row,
            component.log_size,
            eval_log_size,
        );
        var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
        for (sampled[0..n_main], evaluations[1..][0..n_main]) |*value, column| {
            value.* = QM31.fromBase(column[row]);
        }
        var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        for (0..batch_count) |batch| {
            current[batch] = secureAt(evaluations[interaction_start + 4 * batch ..][0..4], row);
            previous[batch] = secureAt(
                evaluations[interaction_start + 4 * batch ..][0..4],
                previous_row,
            );
        }
        const constraints = try component.evaluateRow(
            sampled[0..n_main],
            current[0..batch_count],
            previous[0..batch_count],
            QM31.fromBase(evaluations[0][row]),
        );
        var folded = QM31.zero();
        for (constraints.values[0..constraints.len], 0..) |constraint, index| {
            folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
        }
        const contribution = folded.mulM31(
            denominator_inv[row >> @intCast(component.log_size)],
        );
        const output = column_accumulator.col;
        if (direct_store) {
            output.set(row, contribution);
        } else {
            output.set(row, output.at(row).add(contribution));
        }
    }
    column_accumulator.next_fresh_index = if (direct_store) eval_size else null;
}

const PreparedThreadInvocation = struct {
    prepared: *prepared_domain.PreparedDomainEvaluation,
    cancellation: *const prover_task_graph.CancellationToken,
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        var context = prover_task_graph.TaskContext{
            .user_context = self.prepared.context,
            .cancellation = self.cancellation,
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
        .name = "opcode-prepared-domain",
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
    try std.testing.expectEqual(@as(usize, 128 * 1024), pool.stackSize());
    return graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(worker_count),
        .pool = &pool,
    });
}

fn prepareOpcodeDomainForFailure(
    allocator: std.mem.Allocator,
    component: *const OpcodeLookupComponent,
    trace_data: *const prover_component.Trace,
) !void {
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        component.maxConstraintLogDegreeBound(),
        component.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = try prepareOpcodeDomain(allocator, component, trace_data, &accumulator);
    defer prepared.deinit();
}

fn prepareOpcodeDomain(
    allocator: std.mem.Allocator,
    component: *const OpcodeLookupComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !prepared_domain.PreparedDomainEvaluation {
    return (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        allocator,
        trace_data,
        accumulator,
    )).?;
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

test "opcode prepared domain: sharded legacy bytes allocation freedom and cancellation" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 13;
    var fixture: OpcodeFixture = undefined;
    try fixture.init(allocator, family, log_size);
    defer fixture.deinit();
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const component = try OpcodeLookupComponent.initProver(
        family,
        log_size,
        0,
        0,
        0,
        &relations,
        claims[0..opcode_entries.batchCount(family)],
    );
    const random_coeff = QM31.fromU32Unchecked(3, 1, 0, 0);
    var legacy_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        fixture.eval_log_size,
        2 * component.nConstraints(),
    );
    defer legacy_accumulator.deinit();
    try legacyEvaluateOpcodeDomain(&component, &fixture.trace_data, &legacy_accumulator);
    try legacyEvaluateOpcodeDomain(&component, &fixture.trace_data, &legacy_accumulator);
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
        2 * component.nConstraints(),
    );
    defer prepared_accumulator.deinit();
    var prepared = try prepareOpcodeDomain(
        prepared_allocator,
        &component,
        &fixture.trace_data,
        &prepared_accumulator,
    );
    defer prepared.deinit();
    var additive = try prepareOpcodeDomain(
        prepared_allocator,
        &component,
        &fixture.trace_data,
        &prepared_accumulator,
    );
    defer additive.deinit();
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
    const serial_before = component_mod.preparedParallelTelemetrySnapshot();
    try runPreparedOnReviewedStack(&prepared, &cancellation);
    try runPreparedOnReviewedStack(&additive, &cancellation);
    const serial = component_mod.PreparedParallelTelemetrySnapshot.delta(
        component_mod.preparedParallelTelemetrySnapshot(),
        serial_before,
    );
    try std.testing.expectEqual(@as(u64, 0), serial.child_submissions);
    try std.testing.expectEqual(@as(u64, 0), serial.child_completions);
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
            2 * component.nConstraints(),
        );
        defer parallel_accumulator.deinit();
        var fresh = try prepareOpcodeDomain(
            allocator,
            &component,
            &fixture.trace_data,
            &parallel_accumulator,
        );
        defer fresh.deinit();
        var add = try prepareOpcodeDomain(
            allocator,
            &component,
            &fixture.trace_data,
            &parallel_accumulator,
        );
        defer add.deinit();
        for ([_]*prepared_domain.PreparedDomainEvaluation{ &fresh, &add }) |pass| {
            const before = component_mod.preparedParallelTelemetrySnapshot();
            const report = try runPreparedWithWorkers(pass, worker_count);
            const telemetry = component_mod.PreparedParallelTelemetrySnapshot.delta(
                component_mod.preparedParallelTelemetrySnapshot(),
                before,
            );
            try std.testing.expectEqual(@as(usize, 1), report.succeeded_tasks);
            try std.testing.expectEqual(
                @as(u64, @intCast(worker_count - 1)),
                telemetry.child_submissions,
            );
            try std.testing.expectEqual(telemetry.child_submissions, telemetry.child_completions);
            try std.testing.expectEqual(@as(u64, 0), telemetry.range_failures);
        }
        var parallel = try parallel_accumulator.finalize();
        defer parallel.deinit(allocator);
        try expectByteEquivalent(legacy, parallel);
    }

    try std.testing.checkAllAllocationFailures(
        allocator,
        prepareOpcodeDomainForFailure,
        .{ &component, &fixture.trace_data },
    );

    var cancelled_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        fixture.eval_log_size,
        component.nConstraints(),
    );
    defer cancelled_accumulator.deinit();
    var cancelled = try prepareOpcodeDomain(
        allocator,
        &component,
        &fixture.trace_data,
        &cancelled_accumulator,
    );
    defer cancelled.deinit();
    var cancelled_token = prover_task_graph.CancellationToken{};
    _ = cancelled_token.request();
    try runPreparedOnReviewedStack(&cancelled, &cancelled_token);
    var cancelled_result = try cancelled_accumulator.finalize();
    defer cancelled_result.deinit(allocator);
    for (0..cancelled_result.len()) |row| {
        try std.testing.expect(cancelled_result.at(row).isZero());
    }

    var failure_component = component;
    var failure_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        fixture.eval_log_size,
        component.nConstraints(),
    );
    defer failure_accumulator.deinit();
    var failure_prepared = try prepareOpcodeDomain(
        allocator,
        &failure_component,
        &fixture.trace_data,
        &failure_accumulator,
    );
    defer failure_prepared.deinit();
    failure_component.family = .shifts_imm;
    const failure_before = component_mod.preparedParallelTelemetrySnapshot();
    try std.testing.expectError(error.InvalidTraceShape, runPreparedWithWorkers(&failure_prepared, 4));
    const failure = component_mod.PreparedParallelTelemetrySnapshot.delta(
        component_mod.preparedParallelTelemetrySnapshot(),
        failure_before,
    );
    try std.testing.expectEqual(@as(u64, 3), failure.child_submissions);
    try std.testing.expectEqual(@as(u64, 3), failure.child_completions);
    try std.testing.expect(failure.range_failures >= 1);
    try std.testing.expect(failure.local_cancellation_requests >= 1);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}
