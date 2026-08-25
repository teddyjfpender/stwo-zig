const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs = @import("stwo_core").pcs;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const component_mod = @import("component.zig");
const memory_interaction = @import("memory_commitment/interaction.zig");
const prepared_evaluation = @import("prepared_evaluation_owner.zig");
const relation_challenges = @import("relation_challenges.zig");

const RiscVTraceComponent = component_mod.RiscVTraceComponent;

test "component: coset vanishing is block-constant over the extended quotient domain" {
    inline for ([_][2]u32{ .{ 1, 3 }, .{ 2, 4 }, .{ 2, 5 }, .{ 1, 5 }, .{ 3, 6 } }) |sizes| {
        const log_size = sizes[0];
        const eval_log_size = sizes[1];
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const trace_coset = canonic.CanonicCoset.new(log_size).coset();
        for (0..eval_domain.size()) |position| {
            const at_position = core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(utils.bitReverseIndex(position, eval_log_size)),
            );
            const block = position >> @intCast(log_size);
            const by_block = core_constraints.cosetVanishing(
                M31,
                trace_coset,
                eval_domain.at(utils.bitReverseIndex(block, eval_log_size - log_size)),
            );
            try std.testing.expect(at_position.eql(by_block));
        }
    }
}

fn testMemoryComponent(relations: *const relation_challenges.Relations) RiscVTraceComponent {
    return .{
        .desc = .{
            .family = .base_alu_imm,
            .log_size = 4,
            .n_rows = 16,
            .n_columns = 8,
        },
        .initial_pc = 0,
        .total_steps = 0,
        .is_first_col_idx = 0,
        .is_active_col_idx = 1,
        .main_col_offset = 0,
        .kind = .memory,
        .relations = relations,
    };
}

fn testLeafTaskContext(
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
        .worker_budget = prover_work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
}

const PreparedPoolInvocation = struct {
    prepared: *prepared_domain.PreparedDomainEvaluation,
    cancellation: *const prover_task_graph.CancellationToken,
    coordinator_thread: std.Thread.Id,
    ran_on_helper: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        if (std.Thread.getCurrentId() == self.coordinator_thread) {
            self.failure = error.PreparedDomainDidNotUseHelper;
            return;
        }
        self.ran_on_helper.store(true, .release);
        var task_context = testLeafTaskContext(
            self.prepared.context,
            self.cancellation,
        );
        self.prepared.run(&task_context) catch |failure| {
            self.failure = failure;
        };
    }
};

fn runPreparedOnReviewedStack(
    prepared: *prepared_domain.PreparedDomainEvaluation,
    cancellation: *const prover_task_graph.CancellationToken,
) !void {
    var pool: prover_work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = prepared.resources.worker_stack_bytes,
    });
    defer pool.deinit();
    try std.testing.expectEqual(
        prepared.resources.worker_stack_bytes,
        pool.stackSize(),
    );

    var lease = try pool.acquire(try prover_work_pool.WorkerBudget.init(2));
    defer lease.deinit();
    var invocation = PreparedPoolInvocation{
        .prepared = prepared,
        .cancellation = cancellation,
        .coordinator_thread = std.Thread.getCurrentId(),
    };
    var wait_group = std.Thread.WaitGroup{};
    try lease.spawnWg(&wait_group, PreparedPoolInvocation.run, .{&invocation});
    wait_group.wait();
    lease.completeWave();
    if (invocation.failure) |failure| return failure;
    try std.testing.expect(invocation.ran_on_helper.load(.acquire));
}

fn testTrace(
    trees: *[3][]const prover_component.Poly,
) prover_component.Trace {
    return .{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(trees),
    };
}

fn evaluateMemoryReference(
    component: *const RiscVTraceComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !void {
    const allocator = accumulator.allocator;
    const log_size = component.desc.log_size;
    const eval_log_size = log_size + 1;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const eval_size = eval_domain.size();
    const source_count = 2 + 8 + memory_interaction.N_COLUMNS;
    const evaluations = try allocator.alloc([]const M31, source_count);
    defer allocator.free(evaluations);

    const pp = trace_data.polys.items[0];
    const main = trace_data.polys.items[1];
    const interaction = trace_data.polys.items[2];
    var source_index: usize = 0;
    const first = pp[component.is_first_col_idx];
    try first.validate();
    try std.testing.expectEqual(eval_log_size, first.log_size);
    evaluations[source_index] = first.values;
    source_index += 1;
    const active = pp[component.is_active_col_idx];
    try active.validate();
    try std.testing.expectEqual(eval_log_size, active.log_size);
    evaluations[source_index] = active.values;
    source_index += 1;
    for (main[component.main_col_offset..][0..8]) |poly| {
        try poly.validate();
        try std.testing.expectEqual(eval_log_size, poly.log_size);
        evaluations[source_index] = poly.values;
        source_index += 1;
    }
    for (interaction[component.interaction_col_offset..][0..memory_interaction.N_COLUMNS]) |poly| {
        try poly.validate();
        try std.testing.expectEqual(eval_log_size, poly.log_size);
        evaluations[source_index] = poly.values;
        source_index += 1;
    }
    try std.testing.expectEqual(source_count, source_index);

    const extension_bits: u5 = @intCast(eval_log_size - log_size);
    const trace_coset = canonic.CanonicCoset.new(log_size).coset();
    const denominator_inv = try allocator.alloc(M31, @as(usize, 1) << extension_bits);
    defer allocator.free(denominator_inv);
    for (denominator_inv, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            trace_coset,
            eval_domain.at(utils.bitReverseIndex(index, extension_bits)),
        ).inv();
    }

    const accumulators = try accumulator.columns(
        allocator,
        &.{.{ .log_size = eval_log_size, .n_cols = component.nConstraints() }},
    );
    defer allocator.free(accumulators);
    const column_accumulator = &accumulators[0];
    const powers = column_accumulator.random_coeff_powers;
    const denominator_shift: std.math.Log2Int(usize) = @intCast(log_size);
    for (0..eval_size) |row| {
        const previous_row = utils.previousBitReversedCircleDomainIndex(
            row,
            log_size,
            eval_log_size,
        );
        const is_first = QM31.fromBase(evaluations[0][row]);
        const is_active = QM31.fromBase(evaluations[1][row]);
        const main_start: usize = 2;
        const interaction_start = main_start + 8;
        var sampled: [8]QM31 = undefined;
        for (&sampled, 0..) |*value, column| {
            value.* = QM31.fromBase(evaluations[main_start + column][row]);
        }
        var sums: [memory_interaction.N_SUMS]QM31 = undefined;
        var previous: [memory_interaction.N_SUMS]QM31 = undefined;
        for (0..memory_interaction.N_SUMS) |index| {
            const offset = interaction_start + index * 4;
            sums[index] = secureAtReference(evaluations[offset..][0..4], row);
            previous[index] = secureAtReference(
                evaluations[offset..][0..4],
                previous_row,
            );
        }
        const constraints = memory_interaction.evaluate(
            sampled,
            is_active,
            is_first,
            sums,
            previous,
            component.memory_claims,
            component.relations,
        );
        var folded = QM31.zero();
        for (constraints, 0..) |constraint, index| {
            folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
        }
        column_accumulator.accumulate(
            row,
            folded.mulM31(denominator_inv[row >> denominator_shift]),
        );
    }
}

fn secureAtReference(coordinates: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(
        coordinates[0][row],
        coordinates[1][row],
        coordinates[2][row],
        coordinates[3][row],
    );
}

fn expectSecureColumnsEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(expected.len(), actual.len());
    for (0..expected.len()) |row| {
        try std.testing.expect(expected.at(row).eql(actual.at(row)));
    }
}

fn exercisePreparedMemoryComponent(allocator: std.mem.Allocator) !void {
    const eval_log_size: u32 = 5;
    const eval_size = @as(usize, 1) << @intCast(eval_log_size);
    const relations = relation_challenges.Relations.dummy();
    const component = testMemoryComponent(&relations);
    var values = [_]M31{M31.zero()} ** eval_size;
    const poly = prover_component.Poly{
        .log_size = eval_log_size,
        .values = &values,
    };
    var preprocessed = [_]prover_component.Poly{poly} ** 2;
    var main = [_]prover_component.Poly{poly} ** 8;
    var interaction = [_]prover_component.Poly{poly} ** memory_interaction.N_COLUMNS;
    var trees = [_][]const prover_component.Poly{ &preprocessed, &main, &interaction };
    const trace_data = testTrace(&trees);
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        allocator,
        &trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();
    var cancellation = prover_task_graph.CancellationToken{};
    var task_context = testLeafTaskContext(prepared.context, &cancellation);
    try prepared.run(&task_context);
}

test "component: prepared memory evaluator rolls back every allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exercisePreparedMemoryComponent,
        .{},
    );
}

const PreparedStateLayout = struct {
    allocator: std.mem.Allocator,
    component: *const RiscVTraceComponent,
    evaluations: [][]const M31,
    // Retained even on the zero-copy V1 path so candidate PCS domains can own
    // reconstructed quotient-domain views without changing task state shape.
    evaluation_owner: prepared_evaluation.Owner,
    denominator_inv: []M31,
    accumulators: []prover_air_accumulation.ColumnAccumulator,
    eval_log_size: u32,
    eval_size: usize,
    opcode_main_sources: usize,
};

test "component: prepared memory domain ownership is explicit and fail closed" {
    var equal_domain_values = [_]M31{M31.zero()} ** 32;
    const equal_domain = prover_component.Poly{
        .log_size = 5,
        .values = &equal_domain_values,
    };
    try std.testing.expect(!try prepared_evaluation.needsOwned(equal_domain, 4, 5));
    try std.testing.expectEqual(
        @as(usize, 0),
        try prepared_evaluation.residentBytes(0, equal_domain_values.len),
    );

    var wider_values = [_]M31{M31.zero()} ** 64;
    const unbacked_wider_domain = prover_component.Poly{
        .log_size = 6,
        .values = &wider_values,
    };
    try std.testing.expectError(
        error.InvalidProofShape,
        prepared_evaluation.needsOwned(unbacked_wider_domain, 4, 5),
    );
}

test "component: prepared memory evaluator is exact and allocation-free" {
    const allocator = std.testing.allocator;
    const eval_log_size: u32 = 5;
    const eval_size = @as(usize, 1) << @intCast(eval_log_size);
    const source_count = 2 + 8 + memory_interaction.N_COLUMNS;
    const relations = relation_challenges.Relations.dummy();
    const component = testMemoryComponent(&relations);
    const random_coeff = QM31.fromU32Unchecked(3, 1, 4, 1);
    var zero_values = [_]M31{M31.zero()} ** eval_size;
    var active_values = [_]M31{M31.one()} ** eval_size;
    const zero_poly = prover_component.Poly{
        .log_size = eval_log_size,
        .values = &zero_values,
    };
    const active_poly = prover_component.Poly{
        .log_size = eval_log_size,
        .values = &active_values,
    };
    var preprocessed = [_]prover_component.Poly{zero_poly} ** 2;
    preprocessed[1] = active_poly;
    var main_values: [8][eval_size]M31 = undefined;
    var main: [8]prover_component.Poly = undefined;
    for (&main_values, &main, 0..) |*values, *poly, column| {
        for (values, 0..) |*value, row| {
            value.* = M31.fromU64(17 + column * 37 + row * 13);
        }
        poly.* = .{ .log_size = eval_log_size, .values = values };
    }
    var interaction_values: [memory_interaction.N_COLUMNS][eval_size]M31 = undefined;
    var interaction: [memory_interaction.N_COLUMNS]prover_component.Poly = undefined;
    for (&interaction_values, &interaction, 0..) |*values, *poly, column| {
        for (values, 0..) |*value, row| {
            value.* = M31.fromU64(101 + column * 43 + row * 29);
        }
        poly.* = .{ .log_size = eval_log_size, .values = values };
    }
    var trees = [_][]const prover_component.Poly{ &preprocessed, &main, &interaction };
    const trace_data = testTrace(&trees);

    var reference_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        eval_log_size,
        component.nConstraints(),
    );
    defer reference_accumulator.deinit();
    try evaluateMemoryReference(&component, &trace_data, &reference_accumulator);
    var reference_result = try reference_accumulator.finalize();
    defer reference_result.deinit(allocator);
    var saw_nonzero = false;
    for (0..reference_result.len()) |row| {
        saw_nonzero = saw_nonzero or !reference_result.at(row).isZero();
    }
    try std.testing.expect(saw_nonzero);

    var wrapper_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        eval_log_size,
        component.nConstraints(),
    );
    defer wrapper_accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace_data, &wrapper_accumulator);
    var wrapper_result = try wrapper_accumulator.finalize();
    defer wrapper_result.deinit(allocator);
    try expectSecureColumnsEqual(&reference_result, &wrapper_result);

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const prepared_allocator = failing.allocator();
    var prepared_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        prepared_allocator,
        random_coeff,
        eval_log_size,
        component.nConstraints(),
    );
    defer prepared_accumulator.deinit();
    const prover = component.asProverComponent();
    try std.testing.expect(prover.prepare_domain_evaluator != null);
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(
        prepared_allocator,
        &trace_data,
        &prepared_accumulator,
    )).?;
    defer prepared.deinit();
    const expected_resident_bytes = @sizeOf(PreparedStateLayout) +
        source_count * @sizeOf([]const M31) +
        2 * @sizeOf(M31) +
        try prepared_evaluation.residentBytes(0, eval_size) +
        @sizeOf(prover_air_accumulation.ColumnAccumulator);
    try std.testing.expectEqual(
        eval_size * @sizeOf(QM31),
        prepared.resources.final_output_bytes,
    );
    try std.testing.expectEqual(
        expected_resident_bytes,
        prepared.resources.shared_resident_bytes,
    );
    try std.testing.expectEqual(@as(usize, 0), prepared.resources.exclusive_scratch_bytes);
    try std.testing.expectEqual(@as(usize, 0), prepared.resources.device_resident_bytes);
    try std.testing.expectEqual(
        component_mod.memory_prepared_row_stack_bytes,
        prepared.resources.worker_stack_bytes,
    );
    try prepared.validate();

    const allocation_count = failing.alloc_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = failing.resize_index;
    var cancellation = prover_task_graph.CancellationToken{};
    try runPreparedOnReviewedStack(&prepared, &cancellation);
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    failing.resize_fail_index = std.math.maxInt(usize);

    var prepared_result = try prepared_accumulator.finalize();
    defer prepared_result.deinit(prepared_allocator);
    try expectSecureColumnsEqual(&reference_result, &prepared_result);

    var cancelled_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        eval_log_size,
        component.nConstraints(),
    );
    defer cancelled_accumulator.deinit();
    var cancelled = (try prover.prepareConstraintQuotientsOnDomain(
        allocator,
        &trace_data,
        &cancelled_accumulator,
    )).?;
    defer cancelled.deinit();
    var cancelled_token = prover_task_graph.CancellationToken{};
    _ = cancelled_token.request();
    var cancelled_context = testLeafTaskContext(cancelled.context, &cancelled_token);
    try cancelled.run(&cancelled_context);
    var cancelled_result = try cancelled_accumulator.finalize();
    defer cancelled_result.deinit(allocator);
    for (0..cancelled_result.len()) |row| {
        try std.testing.expect(cancelled_result.at(row).isZero());
    }
}

test "component: prepared evaluator rejects malformed geometry before running" {
    const allocator = std.testing.allocator;
    const relations = relation_challenges.Relations.dummy();
    var component = testMemoryComponent(&relations);
    var values = [_]M31{M31.zero()} ** 32;
    const poly = prover_component.Poly{ .log_size = 5, .values = &values };
    var preprocessed = [_]prover_component.Poly{poly} ** 2;
    var main = [_]prover_component.Poly{poly} ** 8;
    var interaction = [_]prover_component.Poly{poly} ** memory_interaction.N_COLUMNS;
    var trees = [_][]const prover_component.Poly{ &preprocessed, &main, &interaction };
    const trace_data = testTrace(&trees);
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        5,
        component.nConstraints(),
    );
    defer accumulator.deinit();

    component.desc.n_columns = 7;
    try std.testing.expectError(
        error.InvalidProofShape,
        component.asProverComponent().prepareConstraintQuotientsOnDomain(
            allocator,
            &trace_data,
            &accumulator,
        ),
    );
    component.desc.n_columns = 8;
    component.main_col_offset = std.math.maxInt(usize);
    try std.testing.expectError(
        error.InvalidProofShape,
        component.asProverComponent().prepareConstraintQuotientsOnDomain(
            allocator,
            &trace_data,
            &accumulator,
        ),
    );
    component.main_col_offset = 0;
    component.desc.log_size = 0;
    try std.testing.expectError(
        error.InvalidProofShape,
        component.asProverComponent().prepareConstraintQuotientsOnDomain(
            allocator,
            &trace_data,
            &accumulator,
        ),
    );
    component.desc.log_size = 30;
    try std.testing.expectError(
        error.InvalidProofShape,
        component.asProverComponent().prepareConstraintQuotientsOnDomain(
            allocator,
            &trace_data,
            &accumulator,
        ),
    );
}
