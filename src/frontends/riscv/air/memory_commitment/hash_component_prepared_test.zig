//! Focused ownership and execution tests for prepared hash AIR domains.
const std = @import("std");
const circle = @import("stwo_core").circle;
const core_constraints = @import("stwo_core").constraints;
const M31 = @import("stwo_core").fields.m31.M31;
const qm31 = @import("stwo_core").fields.qm31;
const QM31 = qm31.QM31;
const pcs = @import("stwo_core").pcs;
const canonic = @import("stwo_core").poly.circle.canonic;
const core_utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const hash_component = @import("hash_component.zig");
const merkle_node = @import("merkle_node.zig");
const poseidon2_air = @import("poseidon2_air.zig");
const relations_mod = @import("../relation_challenges.zig");
const HashComponent = hash_component.HashComponent;
const Kind = hash_component.Kind;
const LOG_SIZE: u32 = 4;
const EVAL_LOG_SIZE: u32 = LOG_SIZE + 1;
const IS_FIRST_INDEX: usize = 1;
const IS_ACTIVE_INDEX: usize = 3;
const MAIN_OFFSET: usize = 2;
const INTERACTION_OFFSET: usize = 3;
const HELPER_STACK_BYTES = prepared_domain.ROW_EVALUATOR_STACK_BYTES;
const SourceMode = enum { borrowed_lde, owned_extension };
const DomainFixture = struct {
    allocator: std.mem.Allocator,
    values: []M31,
    preprocessed: []prover_component.Poly,
    main: []prover_component.Poly,
    interaction: []prover_component.Poly,
    trees: [][]const prover_component.Poly,

    fn init(
        allocator: std.mem.Allocator,
        component_value: *const HashComponent,
        mode: SourceMode,
    ) !DomainFixture {
        const value_log_size = switch (mode) {
            .borrowed_lde => EVAL_LOG_SIZE,
            .owned_extension => LOG_SIZE,
        };
        const value_count = @as(usize, 1) << @intCast(value_log_size);
        const values = try allocator.alloc(M31, value_count);
        errdefer allocator.free(values);
        for (values, 0..) |*value, index| {
            value.* = M31.fromU64((index * 17 + 5) % 97);
        }
        const coefficients = switch (mode) {
            .borrowed_lde => null,
            .owned_extension => try prover_poly.CircleCoefficients.initBorrowed(values),
        };
        const poly = prover_component.Poly{
            .log_size = value_log_size,
            .values = values,
            .coefficients = coefficients,
        };
        const preprocessed_count = @max(
            component_value.is_first_col_idx,
            component_value.is_active_col_idx,
        ) + 1;
        const preprocessed = try allocator.alloc(prover_component.Poly, preprocessed_count);
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, poly);
        const main = try allocator.alloc(
            prover_component.Poly,
            component_value.main_col_offset + hash_component.nMainColumns(component_value.kind),
        );
        errdefer allocator.free(main);
        @memset(main, poly);
        const interaction = try allocator.alloc(
            prover_component.Poly,
            component_value.interaction_col_offset +
                hash_component.nInteractionColumns(component_value.kind),
        );
        errdefer allocator.free(interaction);
        @memset(interaction, poly);
        const trees = try allocator.alloc([]const prover_component.Poly, 3);
        errdefer allocator.free(trees);
        trees[0] = preprocessed;
        trees[1] = main;
        trees[2] = interaction;
        return .{
            .allocator = allocator,
            .values = values,
            .preprocessed = preprocessed,
            .main = main,
            .interaction = interaction,
            .trees = trees,
        };
    }

    fn trace(self: *const DomainFixture) prover_component.Trace {
        return .{
            .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(self.trees),
        };
    }

    fn deinit(self: *DomainFixture) void {
        const allocator = self.allocator;
        allocator.free(self.trees);
        allocator.free(self.interaction);
        allocator.free(self.main);
        allocator.free(self.preprocessed);
        allocator.free(self.values);
        self.* = undefined;
    }
};
fn component(kind: Kind, relations: *const relations_mod.Relations) HashComponent {
    return .{
        .kind = kind,
        .log_size = LOG_SIZE,
        .n_rows = 1,
        .is_first_col_idx = IS_FIRST_INDEX,
        .is_active_col_idx = IS_ACTIVE_INDEX,
        .main_col_offset = MAIN_OFFSET,
        .interaction_col_offset = INTERACTION_OFFSET,
        .relations = relations,
    };
}

fn sourceCount(kind: Kind) usize {
    return 2 + hash_component.nMainColumns(kind) + hash_component.nInteractionColumns(kind);
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

fn prepare(
    allocator: std.mem.Allocator,
    component_value: *const HashComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !prepared_domain.PreparedDomainEvaluation {
    return (try component_value.asProverComponent().prepareConstraintQuotientsOnDomain(
        allocator,
        trace_data,
        accumulator,
    )).?;
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
    var graph = try prover_task_graph.ComponentTaskGraph.init(std.testing.allocator, 2);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .name = "hash-stack-probe-coordinator",
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
        .name = "hash-stack-probe-prepared",
        .func = Runner.run,
        .context = &runner,
        .resources = prepared.resources,
        .work_estimate = 1,
    });

    var pool: prover_work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = HELPER_STACK_BYTES,
    });
    defer pool.deinit();
    try std.testing.expectEqual(
        @as(usize, 128 * 1024),
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    );
    try std.testing.expectEqual(
        HELPER_STACK_BYTES,
        pool.stackSize(),
    );
    _ = try graph.execute(.{
        .worker_budget = try prover_work_pool.WorkerBudget.init(2),
        .pool = &pool,
    });
    try std.testing.expect(runner.ran_on_helper.load(.acquire));
}

fn expectSameColumn(lhs: anytype, rhs: anytype) !void {
    try std.testing.expectEqual(lhs.len(), rhs.len());
    for (0..lhs.len()) |row| try std.testing.expect(lhs.at(row).eql(rhs.at(row)));
}

fn referenceValues(poly: prover_component.Poly, eval_log_size: u32) ![]const M31 {
    try poly.validate();
    if (poly.log_size != eval_log_size) return error.InvalidProofShape;
    return poly.values;
}

fn referenceSecure(
    evaluations: []const []const M31,
    offset: usize,
    row: usize,
) QM31 {
    return QM31.fromM31(
        evaluations[offset][row],
        evaluations[offset + 1][row],
        evaluations[offset + 2][row],
        evaluations[offset + 3][row],
    );
}

fn referenceMain(
    comptime count: usize,
    evaluations: []const []const M31,
    offset: usize,
    row: usize,
) [count]QM31 {
    var result: [count]QM31 = undefined;
    for (&result, evaluations[offset..][0..count]) |*value, column| {
        value.* = QM31.fromBase(column[row]);
    }
    return result;
}

fn referenceInteractions(
    comptime count: usize,
    evaluations: []const []const M31,
    offset: usize,
    row: usize,
    previous_row: usize,
    sums: *[count]QM31,
    previous: *[count]QM31,
) void {
    for (0..count) |index| {
        sums[index] = referenceSecure(evaluations, offset + 4 * index, row);
        previous[index] = referenceSecure(evaluations, offset + 4 * index, previous_row);
    }
}

fn referenceFold(powers: []const QM31, constraints: []const QM31) QM31 {
    var result = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        result = result.add(powers[powers.len - 1 - index].mul(constraint));
    }
    return result;
}

/// Independent reconstruction of the pre-prepared domain traversal.
fn evaluateReferenceDomain(
    allocator: std.mem.Allocator,
    component_value: *const HashComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !void {
    if (trace_data.polys.items.len < 3) return error.InvalidProofShape;
    const eval_log_size = component_value.log_size + 1;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const eval_size = eval_domain.size();
    const n_main = hash_component.nMainColumns(component_value.kind);
    const n_interaction = hash_component.nInteractionColumns(component_value.kind);
    const evaluations = try allocator.alloc([]const M31, sourceCount(component_value.kind));
    defer allocator.free(evaluations);
    const preprocessed = trace_data.polys.items[0];
    const main = trace_data.polys.items[1];
    const interaction = trace_data.polys.items[2];
    if (preprocessed.len <= @max(
        component_value.is_first_col_idx,
        component_value.is_active_col_idx,
    ) or
        main.len < component_value.main_col_offset + n_main or
        interaction.len < component_value.interaction_col_offset + n_interaction)
    {
        return error.InvalidProofShape;
    }
    evaluations[0] = try referenceValues(
        preprocessed[component_value.is_first_col_idx],
        eval_log_size,
    );
    evaluations[1] = try referenceValues(
        preprocessed[component_value.is_active_col_idx],
        eval_log_size,
    );
    for (main[component_value.main_col_offset..][0..n_main], evaluations[2..][0..n_main]) |poly, *values| {
        values.* = try referenceValues(poly, eval_log_size);
    }
    const interaction_start = 2 + n_main;
    for (interaction[component_value.interaction_col_offset..][0..n_interaction], evaluations[interaction_start..]) |poly, *values| {
        values.* = try referenceValues(poly, eval_log_size);
    }

    var denominator_inv: [2]M31 = undefined;
    const trace_coset = canonic.CanonicCoset.new(component_value.log_size).coset();
    for (&denominator_inv, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            trace_coset,
            eval_domain.at(core_utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    const accumulators = try accumulator.columns(
        allocator,
        &.{.{ .log_size = eval_log_size, .n_cols = component_value.nConstraints() }},
    );
    defer allocator.free(accumulators);
    const column_accumulator = &accumulators[0];
    for (0..eval_size) |row| {
        const previous_row = core_utils.previousBitReversedCircleDomainIndex(
            row,
            component_value.log_size,
            eval_log_size,
        );
        const is_first = QM31.fromBase(evaluations[0][row]);
        const is_active = QM31.fromBase(evaluations[1][row]);
        const folded = switch (component_value.kind) {
            .merkle => merkle: {
                const row_main = referenceMain(
                    merkle_node.N_MAIN_COLUMNS,
                    evaluations,
                    2,
                    row,
                );
                var sums: [merkle_node.N_SUMS]QM31 = undefined;
                var previous: [merkle_node.N_SUMS]QM31 = undefined;
                referenceInteractions(
                    merkle_node.N_SUMS,
                    evaluations,
                    interaction_start,
                    row,
                    previous_row,
                    &sums,
                    &previous,
                );
                const constraints = merkle_node.evaluate(
                    row_main,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    component_value.merkle_claims,
                    component_value.relations,
                );
                break :merkle referenceFold(
                    column_accumulator.random_coeff_powers,
                    &constraints,
                );
            },
            .poseidon2 => poseidon: {
                const row_main = referenceMain(
                    poseidon2_air.N_MAIN_COLUMNS,
                    evaluations,
                    2,
                    row,
                );
                var sums: [poseidon2_air.N_SUMS]QM31 = undefined;
                var previous: [poseidon2_air.N_SUMS]QM31 = undefined;
                referenceInteractions(
                    poseidon2_air.N_SUMS,
                    evaluations,
                    interaction_start,
                    row,
                    previous_row,
                    &sums,
                    &previous,
                );
                const constraints = hash_component.poseidonConstraints(
                    row_main,
                    is_active,
                    is_first,
                    sums,
                    previous,
                    component_value.poseidon_claims,
                    component_value.relations,
                );
                break :poseidon referenceFold(
                    column_accumulator.random_coeff_powers,
                    &constraints,
                );
            },
        };
        column_accumulator.accumulate(
            row,
            folded.mulM31(denominator_inv[row >> @intCast(component_value.log_size)]),
        );
    }
}

test "hash component: exact shapes and prepared capability remain pinned" {
    try std.testing.expectEqual(@as(usize, 445), hash_component.nMainColumns(.poseidon2));
    try std.testing.expectEqual(@as(usize, 8), hash_component.nInteractionColumns(.poseidon2));
    try std.testing.expectEqual(@as(usize, 455), sourceCount(.poseidon2));
    try std.testing.expectEqual(@as(usize, 10), hash_component.nMainColumns(.merkle));
    try std.testing.expectEqual(@as(usize, 12), hash_component.nInteractionColumns(.merkle));
    try std.testing.expectEqual(@as(usize, 24), sourceCount(.merkle));
    try std.testing.expectEqual(@as(usize, 2), hash_component.PREPARED_DENOMINATOR_COUNT);

    const relations = relations_mod.Relations.dummy();
    for ([_]Kind{ .merkle, .poseidon2 }) |kind| {
        const value = component(kind, &relations);
        const prover = value.asProverComponent();
        try std.testing.expect(prover.prepare_domain_evaluator != null);
        try std.testing.expect(prover.domain_parallel_evaluator == null);
        try std.testing.expect(!prover.pool_exclusive_domain);
    }
}

test "hash component: RISC-V Poseidon shell binds selector and narrow mode" {
    const row = poseidon2_air.fill(poseidon2_air.Call.narrow(1, 2));
    var main: [poseidon2_air.N_MAIN_COLUMNS]QM31 = undefined;
    for (&main, row) |*dst, value| dst.* = QM31.fromBase(value);
    const zeros = [_]QM31{QM31.zero()} ** poseidon2_air.N_SUMS;
    const relations = relations_mod.Relations.dummy();
    const honest = hash_component.poseidonConstraints(
        main,
        QM31.one(),
        QM31.one(),
        zeros,
        zeros,
        zeros,
        &relations,
    );
    for (honest[0..poseidon2_air.N_CONSTRAINTS]) |constraint| {
        try std.testing.expect(constraint.isZero());
    }
    try std.testing.expect(honest[poseidon2_air.N_CONSTRAINTS].isZero());
    try std.testing.expect(honest[poseidon2_air.N_CONSTRAINTS + 1].isZero());
    try std.testing.expect(honest[poseidon2_air.N_CONSTRAINTS + 2].isZero());

    const inactive = hash_component.poseidonConstraints(
        main,
        QM31.zero(),
        QM31.one(),
        zeros,
        zeros,
        zeros,
        &relations,
    );
    for (inactive[0..poseidon2_air.N_CONSTRAINTS], honest[0..poseidon2_air.N_CONSTRAINTS]) |actual, expected| {
        try std.testing.expect(actual.eql(expected));
    }
    try std.testing.expect(!inactive[poseidon2_air.N_CONSTRAINTS].isZero());

    var wide_call = poseidon2_air.Call.narrow(1, 2);
    wide_call.wide = true;
    const wide_row = poseidon2_air.fill(wide_call);
    for (&main, wide_row) |*dst, value| dst.* = QM31.fromBase(value);
    const wide = hash_component.poseidonConstraints(
        main,
        QM31.one(),
        QM31.one(),
        zeros,
        zeros,
        zeros,
        &relations,
    );
    for (wide[0..poseidon2_air.N_CONSTRAINTS]) |constraint| {
        try std.testing.expect(constraint.isZero());
    }
    try std.testing.expect(!wide[poseidon2_air.N_CONSTRAINTS + 1].isZero());
    try std.testing.expect(wide[poseidon2_air.N_CONSTRAINTS + 2].isZero());

    var io_call = poseidon2_air.Call.narrow(1, 2);
    io_call.io = true;
    const io_row = poseidon2_air.fill(io_call);
    for (&main, io_row) |*dst, value| dst.* = QM31.fromBase(value);
    const io = hash_component.poseidonConstraints(
        main,
        QM31.one(),
        QM31.one(),
        zeros,
        zeros,
        zeros,
        &relations,
    );
    for (io[0..poseidon2_air.N_CONSTRAINTS]) |constraint| {
        try std.testing.expect(constraint.isZero());
    }
    try std.testing.expect(io[poseidon2_air.N_CONSTRAINTS + 1].isZero());
    try std.testing.expect(!io[poseidon2_air.N_CONSTRAINTS + 2].isZero());
}

test "hash prepared domain matches an independent canonical reference without worker allocation" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    for ([_]Kind{ .merkle, .poseidon2 }) |kind| {
        const value = component(kind, &relations);
        var fixture = try DomainFixture.init(allocator, &value, .borrowed_lde);
        defer fixture.deinit();
        var trace_data = fixture.trace();

        var reference_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
            allocator,
            QM31.fromU32Unchecked(3, 1, 4, 1),
            EVAL_LOG_SIZE,
            value.nConstraints(),
        );
        defer reference_accumulator.deinit();
        try evaluateReferenceDomain(
            allocator,
            &value,
            &trace_data,
            &reference_accumulator,
        );
        var reference = try reference_accumulator.finalize();
        defer reference.deinit(allocator);

        var wrapper_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
            allocator,
            QM31.fromU32Unchecked(3, 1, 4, 1),
            EVAL_LOG_SIZE,
            value.nConstraints(),
        );
        defer wrapper_accumulator.deinit();
        try value.evaluateConstraintQuotientsOnDomain(&trace_data, &wrapper_accumulator);
        var wrapper = try wrapper_accumulator.finalize();
        defer wrapper.deinit(allocator);
        try expectSameColumn(&reference, &wrapper);

        var failing = std.testing.FailingAllocator.init(allocator, .{});
        const prepared_allocator = failing.allocator();
        var prepared_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
            prepared_allocator,
            QM31.fromU32Unchecked(3, 1, 4, 1),
            EVAL_LOG_SIZE,
            value.nConstraints(),
        );
        defer prepared_accumulator.deinit();
        var prepared = try prepare(
            prepared_allocator,
            &value,
            &trace_data,
            &prepared_accumulator,
        );
        defer prepared.deinit();
        try std.testing.expectEqual(prover_task_graph.TaskClass.leaf, prepared.task_class);
        try std.testing.expectEqual(
            (@as(usize, 1) << @intCast(EVAL_LOG_SIZE)) *
                qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31),
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
        try runPreparedOnBoundedHelper(&prepared);
        try std.testing.expectEqual(allocation_count, failing.alloc_index);
        try std.testing.expectEqual(resize_count, failing.resize_index);
        try std.testing.expect(!failing.has_induced_failure);
        failing.fail_index = std.math.maxInt(usize);
        failing.resize_fail_index = std.math.maxInt(usize);
        var actual = try prepared_accumulator.finalize();
        defer actual.deinit(prepared_allocator);
        try expectSameColumn(&reference, &actual);
    }
}

const ResourceSnapshot = struct {
    final_output_bytes: usize,
    shared_resident_bytes: usize,
};

fn resourceSnapshot(
    allocator: std.mem.Allocator,
    kind: Kind,
    mode: SourceMode,
) !ResourceSnapshot {
    const relations = relations_mod.Relations.dummy();
    const value = component(kind, &relations);
    var fixture = try DomainFixture.init(allocator, &value, mode);
    defer fixture.deinit();
    var trace_data = fixture.trace();
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        EVAL_LOG_SIZE,
        value.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = try prepare(allocator, &value, &trace_data, &accumulator);
    defer prepared.deinit();
    return .{
        .final_output_bytes = prepared.resources.final_output_bytes,
        .shared_resident_bytes = prepared.resources.shared_resident_bytes,
    };
}

test "hash prepared resources own exact source and extension bytes" {
    const allocator = std.testing.allocator;
    const merkle_borrowed = try resourceSnapshot(allocator, .merkle, .borrowed_lde);
    const poseidon_borrowed = try resourceSnapshot(allocator, .poseidon2, .borrowed_lde);
    const merkle_owned = try resourceSnapshot(allocator, .merkle, .owned_extension);
    const eval_size = @as(usize, 1) << @intCast(EVAL_LOG_SIZE);
    const expected_output = eval_size * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31);
    try std.testing.expectEqual(expected_output, merkle_borrowed.final_output_bytes);
    try std.testing.expectEqual(expected_output, poseidon_borrowed.final_output_bytes);
    try std.testing.expectEqual(expected_output, merkle_owned.final_output_bytes);
    try std.testing.expectEqual(
        (sourceCount(.poseidon2) - sourceCount(.merkle)) * @sizeOf([]const M31),
        poseidon_borrowed.shared_resident_bytes - merkle_borrowed.shared_resident_bytes,
    );
    try std.testing.expectEqual(
        sourceCount(.merkle) * (@sizeOf([]M31) + eval_size * @sizeOf(M31)),
        merkle_owned.shared_resident_bytes - merkle_borrowed.shared_resident_bytes,
    );
}

test "hash prepared cancellation returns without publishing a competing error" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    for ([_]Kind{ .merkle, .poseidon2 }) |kind| {
        const value = component(kind, &relations);
        var fixture = try DomainFixture.init(allocator, &value, .borrowed_lde);
        defer fixture.deinit();
        var trace_data = fixture.trace();
        var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
            allocator,
            QM31.one(),
            EVAL_LOG_SIZE,
            value.nConstraints(),
        );
        defer accumulator.deinit();
        var prepared = try prepare(allocator, &value, &trace_data, &accumulator);
        defer prepared.deinit();
        var cancellation = prover_task_graph.CancellationToken{};
        _ = cancellation.request();
        var task_context = testLeafTaskContext(prepared.context, &cancellation);
        try prepared.run(&task_context);
        var output = try accumulator.finalize();
        defer output.deinit(allocator);
        for (0..output.len()) |row| try std.testing.expect(output.at(row).isZero());
    }
}

fn attemptPrepare(
    component_value: *const HashComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !void {
    var prepared = try prepare(
        std.testing.allocator,
        component_value,
        trace_data,
        accumulator,
    );
    defer prepared.deinit();
}

test "hash prepared domain rejects overflow and malformed source shapes" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const valid = component(.merkle, &relations);
    var fixture = try DomainFixture.init(allocator, &valid, .borrowed_lde);
    defer fixture.deinit();
    var trace_data = fixture.trace();

    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        EVAL_LOG_SIZE,
        valid.nConstraints(),
    );
    defer accumulator.deinit();
    var malformed = valid;
    malformed.main_col_offset = std.math.maxInt(usize);
    try std.testing.expectError(
        error.InvalidProofShape,
        attemptPrepare(&malformed, &trace_data, &accumulator),
    );
    malformed = valid;
    malformed.interaction_col_offset = std.math.maxInt(usize);
    try std.testing.expectError(
        error.InvalidProofShape,
        attemptPrepare(&malformed, &trace_data, &accumulator),
    );
    malformed = valid;
    malformed.log_size = std.math.maxInt(u32);
    try std.testing.expectError(
        error.InvalidProofShape,
        attemptPrepare(&malformed, &trace_data, &accumulator),
    );
    malformed = valid;
    malformed.log_size = 0;
    try std.testing.expectError(
        error.InvalidProofShape,
        attemptPrepare(&malformed, &trace_data, &accumulator),
    );
    malformed = valid;
    malformed.n_rows = (@as(u32, 1) << @intCast(LOG_SIZE)) + 1;
    try std.testing.expectError(
        error.InvalidProofShape,
        attemptPrepare(&malformed, &trace_data, &accumulator),
    );

    const saved = fixture.preprocessed[valid.is_first_col_idx];
    fixture.preprocessed[valid.is_first_col_idx].values = fixture.values[0 .. fixture.values.len - 1];
    try std.testing.expectError(
        error.InvalidColumnLength,
        attemptPrepare(&valid, &trace_data, &accumulator),
    );
    fixture.preprocessed[valid.is_first_col_idx] = saved;

    var extended = try DomainFixture.init(allocator, &valid, .owned_extension);
    defer extended.deinit();
    var extended_trace = extended.trace();
    extended.preprocessed[valid.is_first_col_idx].coefficients = null;
    var extended_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        EVAL_LOG_SIZE,
        valid.nConstraints(),
    );
    defer extended_accumulator.deinit();
    try std.testing.expectError(
        error.InvalidProofShape,
        attemptPrepare(&valid, &extended_trace, &extended_accumulator),
    );
}

fn prepareAndRunAllocationCase(
    allocator: std.mem.Allocator,
    kind: Kind,
    mode: SourceMode,
) !void {
    const relations = relations_mod.Relations.dummy();
    const value = component(kind, &relations);
    var fixture = try DomainFixture.init(allocator, &value, mode);
    defer fixture.deinit();
    var trace_data = fixture.trace();
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(5, 2, 1, 0),
        EVAL_LOG_SIZE,
        value.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = try prepare(allocator, &value, &trace_data, &accumulator);
    defer prepared.deinit();
    var cancellation = prover_task_graph.CancellationToken{};
    var task_context = testLeafTaskContext(prepared.context, &cancellation);
    try prepared.run(&task_context);
    var output = try accumulator.finalize();
    defer output.deinit(allocator);
}

test "hash prepared coordinator allocations roll back completely" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareAndRunAllocationCase,
        .{ Kind.poseidon2, SourceMode.borrowed_lde },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareAndRunAllocationCase,
        .{ Kind.merkle, SourceMode.owned_extension },
    );
}

fn allocateHashMetadata(
    allocator: std.mem.Allocator,
    component_value: *const HashComponent,
) !void {
    var bounds = try component_value.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    var masks = try component_value.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        component_value.maxConstraintLogDegreeBound(),
    );
    defer masks.deinitDeep(allocator);
    const indices = try component_value.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
}

test "hash component: metadata allocations roll back completely" {
    const relations = relations_mod.Relations.dummy();
    const value = component(.poseidon2, &relations);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateHashMetadata,
        .{&value},
    );
}

comptime {
    std.debug.assert(merkle_node.N_INTERACTION_COLUMNS == 4 * merkle_node.N_SUMS);
    std.debug.assert(poseidon2_air.N_INTERACTION_COLUMNS == 4 * poseidon2_air.N_SUMS);
}
