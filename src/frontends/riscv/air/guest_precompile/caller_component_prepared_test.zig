//! Prepared-domain ownership, resource, and hot-loop evidence for the caller adapter.

const std = @import("std");
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs = @import("stwo_core").pcs;
const prover_engine = @import("stwo_prover_engine");
const prover_air_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prepared_domain = prover_engine.air.prepared_domain;
const prover_poly = prover_engine.poly.circle.poly;
const prover_task_graph = prover_engine.task_graph;
const prover_work_pool = prover_engine.work_pool;
const components = @import("component_registry.zig");
const relations_mod = @import("relation_challenges.zig");
const statement_mod = @import("statement.zig");
const support = @import("main_trace_test_support.zig");
const subject = @import("caller_component.zig");

fn callerAuthority(
    descriptor: components.Descriptor,
) !components.CallerConstruction {
    return switch (try components.Registry.forProfile(.rv32im_zkvm_poseidon2_v1)
        .verifierConstruction(descriptor)) {
        .caller => |authority| authority,
        .provider => error.TestExpectedCallerAuthority,
    };
}

fn initComponent(
    extension: *const statement_mod.ExtensionStatement,
    relations: *const relations_mod.Poseidon2V1Relations,
    claim: subject.Claim,
    placement: subject.ColumnPlacement,
) !subject.CallerComponent {
    return subject.CallerComponent.initProver(
        try callerAuthority(extension.components[0]),
        claim,
        placement,
        relations,
    );
}

fn canonicalClaim(
    extension: *const statement_mod.ExtensionStatement,
    batch_sums: [subject.batch_count]QM31,
) !subject.Claim {
    return subject.Claim.canonical(
        try callerAuthority(extension.components[0]),
        batch_sums,
    );
}

fn expectSomeNonZero(values: anytype) !void {
    for (values) |value| if (!value.isZero()) return;
    return error.TestExpectedSomeNonZero;
}

fn zeroDomainTrace(
    values: []const M31,
    eval_log_size: u32,
    preprocessed: *[subject.preprocessed_column_count]prover_component.Poly,
    main: *[subject.main_column_count]prover_component.Poly,
    interaction_columns: *[subject.interaction_column_count]prover_component.Poly,
    trees: *[3][]const prover_component.Poly,
) prover_component.Trace {
    const zero_poly = prover_component.Poly{
        .log_size = eval_log_size,
        .values = values,
    };
    preprocessed.* = .{zero_poly} ** subject.preprocessed_column_count;
    main.* = .{zero_poly} ** subject.main_column_count;
    interaction_columns.* = .{zero_poly} ** subject.interaction_column_count;
    trees.* = .{ preprocessed, main, interaction_columns };
    return .{ .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(trees) };
}

fn runPreparedOnBoundedHelper(
    prepared: *prepared_domain.PreparedDomainEvaluation,
) !void {
    const Runner = struct {
        prepared: *prepared_domain.PreparedDomainEvaluation,
        coordinator_thread: std.Thread.Id,
        ran_on_helper: std.atomic.Value(bool) = .init(false),

        fn run(context: *prover_task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            if (std.Thread.getCurrentId() == self.coordinator_thread) {
                return error.PreparedDomainDidNotUseHelper;
            }
            self.ran_on_helper.store(true, .release);
            try self.prepared.run(context);
        }
    };
    const Coordinator = struct {
        fn run(_: *prover_task_graph.TaskContext) !void {}
    };

    var runner = Runner{
        .prepared = prepared,
        .coordinator_thread = std.Thread.getCurrentId(),
    };
    var coordinator_byte: u8 = 0;
    var graph = try prover_task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        2,
    );
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .name = "caller-stack-probe-coordinator",
        .func = Coordinator.run,
        .context = &coordinator_byte,
        .work_estimate = 2,
    });
    _ = try graph.addTask(.{
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 1,
            .shard_or_chunk_index = 0,
        },
        .name = "caller-stack-probe-prepared",
        .func = Runner.run,
        .context = &runner,
        .resources = prepared.resources,
        .work_estimate = 1,
    });

    var pool: prover_work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    });
    defer pool.deinit();
    _ = try graph.execute(.{
        .worker_budget = try prover_work_pool.WorkerBudget.init(2),
        .pool = &pool,
    });
    try std.testing.expect(runner.ran_on_helper.load(.acquire));
}

fn prepareZeroDomain(
    allocator: std.mem.Allocator,
    component: *const subject.CallerComponent,
    trace_data: *const prover_component.Trace,
    eval_log_size: u32,
) !void {
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        subject.constraint_count,
    );
    defer accumulator.deinit();
    var prepared = (try component.asProverComponent()
        .prepareConstraintQuotientsOnDomain(
        allocator,
        trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();
}

test "caller component extends base coefficients before its allocation-free row loop" {
    const allocator = std.testing.allocator;
    const trace_log_size: u32 = components.minimum_log_size;
    const eval_log_size = trace_log_size + 1;
    const trace_size: usize = 1 << trace_log_size;
    const eval_size: usize = 1 << eval_log_size;
    var zero_coefficients = [_]M31{M31.zero()} ** trace_size;
    const coefficients = try prover_poly.CircleCoefficients.initBorrowed(
        &zero_coefficients,
    );
    const base_poly = prover_component.Poly{
        .log_size = trace_log_size,
        .values = &zero_coefficients,
        .coefficients = coefficients,
    };
    var preprocessed = [_]prover_component.Poly{base_poly} **
        subject.preprocessed_column_count;
    var main = [_]prover_component.Poly{base_poly} ** subject.main_column_count;
    var interaction_columns = [_]prover_component.Poly{base_poly} **
        subject.interaction_column_count;
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction_columns,
    };
    const trace_data = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };

    var core = support.coreFixture(0);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 0);
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    const component = try initComponent(
        &extension,
        &relations,
        try canonicalClaim(&extension, .{QM31.zero()} ** subject.batch_count),
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
    );
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        subject.constraint_count,
    );
    defer accumulator.deinit();
    var prepared = (try component.asProverComponent()
        .prepareConstraintQuotientsOnDomain(
        allocator,
        &trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();

    const source_count = subject.preprocessed_column_count +
        subject.main_column_count + subject.interaction_column_count;
    const extended_value_bytes = source_count * eval_size * @sizeOf(M31);
    try std.testing.expect(
        prepared.resources.shared_resident_bytes > extended_value_bytes,
    );
    try runPreparedOnBoundedHelper(&prepared);
    var result = try accumulator.finalize();
    defer result.deinit(allocator);
    for (0..result.len()) |row| try std.testing.expect(result.at(row).isZero());

    preprocessed[0].coefficients = null;
    var malformed = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        subject.constraint_count,
    );
    defer malformed.deinit();
    try std.testing.expectError(
        error.InvalidProofShape,
        component.asProverComponent().prepareConstraintQuotientsOnDomain(
            allocator,
            &trace_data,
            &malformed,
        ),
    );
}

test "caller component prepared row loop is allocation-free on the bounded stack" {
    const allocator = std.testing.allocator;
    const eval_log_size: u32 = 5;
    const eval_size: usize = 1 << eval_log_size;
    const zero_values = try allocator.alloc(M31, eval_size);
    defer allocator.free(zero_values);
    @memset(zero_values, M31.zero());
    var preprocessed: [subject.preprocessed_column_count]prover_component.Poly = undefined;
    var main: [subject.main_column_count]prover_component.Poly = undefined;
    var interaction_columns: [subject.interaction_column_count]prover_component.Poly = undefined;
    var trees: [3][]const prover_component.Poly = undefined;
    const trace_data = zeroDomainTrace(
        zero_values,
        eval_log_size,
        &preprocessed,
        &main,
        &interaction_columns,
        &trees,
    );
    var core = support.coreFixture(0);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 0);
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    const component = try initComponent(
        &extension,
        &relations,
        try canonicalClaim(&extension, .{QM31.zero()} ** subject.batch_count),
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
    );

    var zero_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        subject.constraint_count,
    );
    defer zero_accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(
        &trace_data,
        &zero_accumulator,
    );
    var zero_result = try zero_accumulator.finalize();
    defer zero_result.deinit(allocator);
    for (0..zero_result.len()) |row| try std.testing.expect(zero_result.at(row).isZero());

    const active_values = try allocator.alloc(M31, eval_size);
    defer allocator.free(active_values);
    @memset(active_values, M31.one());
    preprocessed[1] = .{ .log_size = eval_log_size, .values = active_values };
    var expected_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        subject.constraint_count,
    );
    defer expected_accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(
        &trace_data,
        &expected_accumulator,
    );
    var expected = try expected_accumulator.finalize();
    defer expected.deinit(allocator);
    try expectSomeNonZero((struct {
        fn collect(result: @TypeOf(expected)) [eval_size]QM31 {
            var values: [eval_size]QM31 = undefined;
            for (&values, 0..) |*value, row| value.* = result.at(row);
            return values;
        }
    }).collect(expected));

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const prepared_allocator = failing.allocator();
    var prepared_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        prepared_allocator,
        QM31.one(),
        eval_log_size,
        subject.constraint_count,
    );
    defer prepared_accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(
        prepared_allocator,
        &trace_data,
        &prepared_accumulator,
    )).?;
    defer prepared.deinit();
    try std.testing.expectEqual(eval_size * @sizeOf(QM31), prepared.resources.final_output_bytes);
    try std.testing.expect(prepared.resources.shared_resident_bytes > 0);
    try std.testing.expectEqual(
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        prepared.resources.worker_stack_bytes,
    );

    const allocation_count = failing.alloc_index;
    failing.fail_index = allocation_count;
    try runPreparedOnBoundedHelper(&prepared);
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    var actual = try prepared_accumulator.finalize();
    defer actual.deinit(prepared_allocator);
    for (0..actual.len()) |row| {
        try std.testing.expect(actual.at(row).eql(expected.at(row)));
    }

    var short_trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
    };
    const short_trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&short_trees),
    };
    var malformed = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        subject.constraint_count,
    );
    defer malformed.deinit();
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsOnDomain(&short_trace, &malformed),
    );

    try std.testing.checkAllAllocationFailures(
        allocator,
        prepareZeroDomain,
        .{ &component, &trace_data, eval_log_size },
    );
}

fn allocateMetadata(
    allocator: std.mem.Allocator,
    component: *const subject.CallerComponent,
) !void {
    var bounds = try component.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    var masks = try component.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound() + 2,
    );
    defer masks.deinitDeep(allocator);
    const indices = try component.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
}

test "caller component metadata allocation failures roll back completely" {
    var core = support.coreFixture(1);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    const component = try initComponent(
        &extension,
        &relations,
        try canonicalClaim(&extension, .{QM31.zero()} ** subject.batch_count),
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateMetadata,
        .{&component},
    );
}
