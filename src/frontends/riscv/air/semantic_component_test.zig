const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const circle = @import("stwo_core").circle;
const core_constraints = @import("stwo_core").constraints;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs = @import("stwo_core").pcs;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const SemanticComponent = @import("semantic_component.zig").SemanticComponent;
const semantic_eval = @import("semantic_eval.zig");
const trace = @import("../runner/trace.zig");

test "semantic component owns exact main bounds for every compatible family" {
    const allocator = std.testing.allocator;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!semantic_eval.isTraceCompatible(family)) {
            try std.testing.expectError(
                error.IncompatibleCommittedTrace,
                SemanticComponent.init(family, 4, 7, 11),
            );
            continue;
        }
        const component = try SemanticComponent.init(family, 4, 7, 11);
        try std.testing.expectEqual(semantic_eval.mainColumnCount(family), component.mainColumnCount());
        try std.testing.expectEqual(semantic_eval.constraintCount(family), component.nConstraints());
        _ = component.asVerifierComponent();
        const prover = component.asProverComponent();
        try std.testing.expect(prover.prepare_domain_evaluator != null);

        var bounds = try component.traceLogDegreeBounds(allocator);
        defer bounds.deinitDeep(allocator);
        try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
        try std.testing.expectEqual(@as(usize, 1), bounds.items[0].len);
        try std.testing.expectEqual(component.mainColumnCount(), bounds.items[1].len);
        try std.testing.expectEqual(@as(usize, 0), bounds.items[2].len);
        for (bounds.items[0]) |log_size| try std.testing.expectEqual(@as(u32, 4), log_size);
        for (bounds.items[1]) |log_size| try std.testing.expectEqual(@as(u32, 4), log_size);

        const indices = try component.preprocessedColumnIndices(allocator);
        defer allocator.free(indices);
        try std.testing.expectEqualSlices(usize, &.{7}, indices);
    }
}

test "semantic component fails closed on row-window binding corruption" {
    var component = try SemanticComponent.init(.lui, 4, 7, 11);
    const original = component.mask_binding;

    component.mask_binding.geometry_source_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidWindowDigest,
        component.traceLogDegreeBounds(std.testing.allocator),
    );
    component.mask_binding = original;
    component.mask_binding.owned_main_current_columns += 1;
    try std.testing.expectError(
        error.InvalidWindowDigest,
        component.maskPoints(
            std.testing.allocator,
            circle.SECURE_FIELD_CIRCLE_GEN,
            5,
        ),
    );
    component.mask_binding = original;
    component.family = .auipc;
    try std.testing.expectError(
        error.InvalidProofShape,
        component.preprocessedColumnIndices(std.testing.allocator),
    );
}

test "semantic component delegates identical row semantics for every family" {
    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        if (!semantic_eval.isTraceCompatible(family)) continue;
        const component = try SemanticComponent.init(family, 4, 0, 0);
        const main = columns[0..component.mainColumnCount()];
        const expected = try semantic_eval.evaluate(family, main, QM31.zero());
        const actual = try component.evaluateRow(main, QM31.zero());
        try std.testing.expectEqual(expected.len, actual.len);
        for (expected.values[0..expected.len], actual.values[0..actual.len]) |lhs, rhs| {
            try std.testing.expect(lhs.eql(rhs));
        }
        try std.testing.expect(actual.allZero());
        try std.testing.expect(!(try component.evaluateRow(main, QM31.one())).allZero());
    }
}

test "semantic component OODS uses exact global offsets and rejects bad shapes" {
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 4;
    const active_index: usize = 2;
    const main_offset: usize = 3;
    const component = try SemanticComponent.init(family, log_size, active_index, main_offset);
    const n_main = component.mainColumnCount();

    var preprocessed_storage = [_][1]QM31{.{QM31.fromU32Unchecked(17, 3, 5, 7)}} ** 4;
    preprocessed_storage[active_index][0] = QM31.zero();
    var preprocessed: [preprocessed_storage.len][]QM31 = undefined;
    for (&preprocessed, &preprocessed_storage) |*column, *values| column.* = values;
    var main_storage = [_][1]QM31{.{QM31.fromU32Unchecked(19, 2, 11, 13)}} **
        (trace.MAX_FAMILY_COLUMNS + main_offset + 2);
    for (main_storage[main_offset..][0..n_main]) |*value| value[0] = QM31.zero();
    var main: [main_storage.len][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var interaction = [_][]QM31{};
    var trees = [_][][]QM31{ &preprocessed, &main, &interaction };
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

    preprocessed_storage[active_index][0] = QM31.one();
    var mutated = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &mutated,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!mutated.finalize().isZero());

    var ignored = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsAtPoint(point, &mask, &ignored, log_size - 1),
    );
    var short_trees = [_][][]QM31{
        &preprocessed,
        main[0 .. main_offset + n_main - 1],
        &interaction,
    };
    const short_mask = core_air_components.MaskValues.initOwned(&short_trees);
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsAtPoint(
            point,
            &short_mask,
            &ignored,
            component.maxConstraintLogDegreeBound(),
        ),
    );
}

test "semantic component on-domain path observes the active selector" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const eval_log_size: u32 = log_size + 1;
    const eval_size = @as(usize, 1) << @intCast(eval_log_size);
    const active_index: usize = 2;
    const main_offset: usize = 3;
    const random_coeff = QM31.fromU32Unchecked(3, 1, 4, 1);
    const component = try SemanticComponent.init(.base_alu_imm, log_size, active_index, main_offset);
    const zero_values = try allocator.alloc(M31, eval_size);
    defer allocator.free(zero_values);
    @memset(zero_values, M31.zero());
    const one_values = try allocator.alloc(M31, eval_size);
    defer allocator.free(one_values);
    @memset(one_values, M31.one());
    const zero_poly = prover_component.Poly{ .log_size = eval_log_size, .values = zero_values };
    const one_poly = prover_component.Poly{ .log_size = eval_log_size, .values = one_values };
    var preprocessed = [_]prover_component.Poly{zero_poly} ** (active_index + 1);
    var main = [_]prover_component.Poly{zero_poly} **
        (trace.MAX_FAMILY_COLUMNS + main_offset);
    var interaction = [_]prover_component.Poly{};
    var trees = [_][]const prover_component.Poly{ &preprocessed, &main, &interaction };
    const trace_data = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };

    var honest = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer honest.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace_data, &honest);
    var honest_result = try honest.finalize();
    defer honest_result.deinit(allocator);
    for (0..honest_result.len()) |row| try std.testing.expect(honest_result.at(row).isZero());

    var main_values: [trace.MAX_FAMILY_COLUMNS + main_offset][eval_size]M31 = undefined;
    for (&main_values, 0..) |*values, column| {
        for (values, 0..) |*value, row| {
            value.* = M31.fromU64(31 + column * 41 + row * 17);
        }
        main[column] = .{ .log_size = eval_log_size, .values = values };
    }
    preprocessed[active_index] = one_poly;
    var reference = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        eval_log_size,
        component.nConstraints(),
    );
    defer reference.deinit();
    try evaluateSemanticReference(&component, &trace_data, &reference);
    var reference_result = try reference.finalize();
    defer reference_result.deinit(allocator);

    var mutated = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        eval_log_size,
        component.nConstraints(),
    );
    defer mutated.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace_data, &mutated);
    var mutated_result = try mutated.finalize();
    defer mutated_result.deinit(allocator);
    try expectSecureColumnsEqual(&reference_result, &mutated_result);
    var saw_nonzero = false;
    for (0..mutated_result.len()) |row| saw_nonzero = saw_nonzero or !mutated_result.at(row).isZero();
    try std.testing.expect(saw_nonzero);

    // Prepare every owner-side allocation, poison the allocator, then execute
    // the production row loop and compare it with the independent traversal.
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
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(
        prepared_allocator,
        &trace_data,
        &prepared_accumulator,
    )).?;
    defer prepared.deinit();
    try std.testing.expectEqual(
        eval_size * @sizeOf(QM31),
        prepared.resources.final_output_bytes,
    );
    try std.testing.expectEqual(@as(usize, 0), prepared.resources.exclusive_scratch_bytes);
    try std.testing.expect(prepared.resources.shared_resident_bytes > 0);
    try std.testing.expectEqual(
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        prepared.resources.worker_stack_bytes,
    );

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

    var short_trees = [_][]const prover_component.Poly{
        &preprocessed,
        main[0 .. main_offset + component.mainColumnCount() - 1],
        &interaction,
    };
    const short_trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&short_trees),
    };
    var shape = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer shape.deinit();
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsOnDomain(&short_trace, &shape),
    );
}

fn allocateMetadata(
    allocator: std.mem.Allocator,
    component: *const SemanticComponent,
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

test "semantic component metadata allocations roll back completely" {
    const component = try SemanticComponent.init(.base_alu_imm, 4, 7, 11);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateMetadata,
        .{&component},
    );
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
        .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    });
    defer pool.deinit();
    try std.testing.expectEqual(
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
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

fn evaluateSemanticReference(
    component: *const SemanticComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !void {
    const allocator = accumulator.allocator;
    const preprocessed = trace_data.polys.items[0];
    const main = trace_data.polys.items[1];
    const n_main = component.mainColumnCount();
    const eval_log_size = component.maxConstraintLogDegreeBound();
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const eval_size = eval_domain.size();
    const evaluations = try allocator.alloc([]const M31, 1 + n_main);
    defer allocator.free(evaluations);
    var extension_buffers = std.ArrayList([]M31).empty;
    defer {
        for (extension_buffers.items) |values| allocator.free(values);
        extension_buffers.deinit(allocator);
    }

    evaluations[0] = try referenceEvaluationValues(
        allocator,
        preprocessed[component.is_active_col_idx],
        component.log_size,
        eval_log_size,
        eval_size,
        &extension_buffers,
    );
    for (main[component.main_col_offset..][0..n_main], evaluations[1..]) |poly, *values| {
        values.* = try referenceEvaluationValues(
            allocator,
            poly,
            component.log_size,
            eval_log_size,
            eval_size,
            &extension_buffers,
        );
    }
    if (extension_buffers.items.len != 0) {
        var twiddles = try prover_twiddles.precomputeM31(allocator, eval_domain.half_coset);
        defer prover_twiddles.deinitM31(allocator, &twiddles);
        try prover_poly.evaluateBuffersWithTwiddles(
            extension_buffers.items,
            eval_domain,
            prover_twiddles.TwiddleTree([]const M31).init(
                twiddles.root_coset,
                twiddles.twiddles,
                twiddles.itwiddles,
            ),
        );
    }

    const denominator_inv = try referenceQuotientDenominators(
        allocator,
        component.log_size,
        eval_log_size,
        eval_domain,
    );
    defer allocator.free(denominator_inv);
    const accumulators = try accumulator.columns(
        allocator,
        &.{.{ .log_size = eval_log_size, .n_cols = component.nConstraints() }},
    );
    defer allocator.free(accumulators);
    const column_accumulator = &accumulators[0];
    const powers = column_accumulator.random_coeff_powers;
    const denominator_shift: std.math.Log2Int(usize) = @intCast(component.log_size);
    for (0..eval_size) |row| {
        var sampled: [trace.MAX_FAMILY_COLUMNS]semantic_eval.BaseScalar = undefined;
        for (sampled[0..n_main], evaluations[1..]) |*value, column| {
            value.* = semantic_eval.BaseScalar.fromBase(column[row]);
        }
        const evaluation = try semantic_eval.BaseEval.evaluate(
            component.family,
            sampled[0..n_main],
            semantic_eval.BaseScalar.fromBase(evaluations[0][row]),
        );
        var folded = QM31.zero();
        for (evaluation.values[0..evaluation.len], 0..) |constraint, index| {
            folded = folded.add(
                powers[powers.len - 1 - index].mulM31(constraint.value),
            );
        }
        column_accumulator.accumulate(
            row,
            folded.mulM31(denominator_inv[row >> denominator_shift]),
        );
    }
}

fn referenceEvaluationValues(
    allocator: std.mem.Allocator,
    poly: prover_component.Poly,
    trace_log_size: u32,
    eval_log_size: u32,
    eval_size: usize,
    extension_buffers: *std.ArrayList([]M31),
) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log_size) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size) return error.InvalidProofShape;
    const values = try allocator.alloc(M31, eval_size);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try extension_buffers.append(allocator, values);
    return values;
}

fn referenceQuotientDenominators(
    allocator: std.mem.Allocator,
    log_size: u32,
    eval_log_size: u32,
    eval_domain: anytype,
) ![]M31 {
    const extension_bits: u5 = @intCast(eval_log_size - log_size);
    const result = try allocator.alloc(M31, @as(usize, 1) << extension_bits);
    errdefer allocator.free(result);
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (result, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, extension_bits)),
        ).inv();
    }
    return result;
}

fn expectSecureColumnsEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(expected.len(), actual.len());
    for (0..expected.len()) |row| {
        try std.testing.expect(expected.at(row).eql(actual.at(row)));
    }
}

fn prepareOwnedExtensionCase(allocator: std.mem.Allocator) !void {
    const log_size: u32 = 4;
    const eval_log_size: u32 = log_size + 1;
    const trace_size = @as(usize, 1) << @intCast(log_size);
    const active_index: usize = 2;
    const main_offset: usize = 3;
    const component = try SemanticComponent.init(
        .base_alu_imm,
        log_size,
        active_index,
        main_offset,
    );
    var values = [_]M31{M31.zero()} ** trace_size;
    const coefficients = try prover_poly.CircleCoefficients.initBorrowed(&values);
    const poly = prover_component.Poly{
        .log_size = log_size,
        .values = &values,
        .coefficients = coefficients,
    };
    var preprocessed = [_]prover_component.Poly{poly} ** (active_index + 1);
    var main = [_]prover_component.Poly{poly} **
        (trace.MAX_FAMILY_COLUMNS + main_offset);
    var interaction = [_]prover_component.Poly{};
    var trees = [_][]const prover_component.Poly{ &preprocessed, &main, &interaction };
    const trace_data = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(
        allocator,
        &trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();
    var cancellation = prover_task_graph.CancellationToken{};
    var task_context = testLeafTaskContext(prepared.context, &cancellation);
    try prepared.run(&task_context);
}

test "semantic prepared extension rolls back every coordinator allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareOwnedExtensionCase,
        .{},
    );
}

test "semantic prepared extension is allocation-free with exact resident geometry" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const eval_log_size: u32 = log_size + 1;
    const trace_size = @as(usize, 1) << @intCast(log_size);
    const eval_size = @as(usize, 1) << @intCast(eval_log_size);
    const active_index: usize = 2;
    const main_offset: usize = 3;
    const random_coeff = QM31.fromU32Unchecked(3, 1, 4, 1);
    const component = try SemanticComponent.init(
        .base_alu_imm,
        log_size,
        active_index,
        main_offset,
    );
    const source_count = 1 + component.mainColumnCount();

    // Establish the exact no-extension baseline for the same evaluator.
    var committed_values = [_]M31{M31.zero()} ** eval_size;
    const committed_poly = prover_component.Poly{
        .log_size = eval_log_size,
        .values = &committed_values,
    };
    var committed_preprocessed = [_]prover_component.Poly{committed_poly} **
        (active_index + 1);
    var committed_main = [_]prover_component.Poly{committed_poly} **
        (trace.MAX_FAMILY_COLUMNS + main_offset);
    var committed_interaction = [_]prover_component.Poly{};
    var committed_trees = [_][]const prover_component.Poly{
        &committed_preprocessed,
        &committed_main,
        &committed_interaction,
    };
    const committed_trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&committed_trees),
    };
    var committed_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        eval_log_size,
        component.nConstraints(),
    );
    defer committed_accumulator.deinit();
    const prover = component.asProverComponent();
    var committed = (try prover.prepareConstraintQuotientsOnDomain(
        allocator,
        &committed_trace,
        &committed_accumulator,
    )).?;
    const baseline_resident_bytes = committed.resources.shared_resident_bytes;
    committed.deinit();

    var coefficient_values = [_]M31{M31.zero()} ** trace_size;
    coefficient_values[0] = M31.one();
    const coefficients = try prover_poly.CircleCoefficients.initBorrowed(&coefficient_values);
    const extension_poly = prover_component.Poly{
        .log_size = log_size,
        .values = &coefficient_values,
        .coefficients = coefficients,
    };
    var preprocessed = [_]prover_component.Poly{extension_poly} ** (active_index + 1);
    var main = [_]prover_component.Poly{extension_poly} **
        (trace.MAX_FAMILY_COLUMNS + main_offset);
    var interaction = [_]prover_component.Poly{};
    var trees = [_][]const prover_component.Poly{ &preprocessed, &main, &interaction };
    const trace_data = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };

    var reference = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        eval_log_size,
        component.nConstraints(),
    );
    defer reference.deinit();
    try evaluateSemanticReference(&component, &trace_data, &reference);
    var reference_result = try reference.finalize();
    defer reference_result.deinit(allocator);

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const prepared_allocator = failing.allocator();
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        prepared_allocator,
        random_coeff,
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(
        prepared_allocator,
        &trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();
    const per_owned_source_bytes = @sizeOf([]M31) + eval_size * @sizeOf(M31);
    try std.testing.expectEqual(
        baseline_resident_bytes + source_count * per_owned_source_bytes,
        prepared.resources.shared_resident_bytes,
    );

    const allocation_count = failing.alloc_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = failing.resize_index;
    var cancellation = prover_task_graph.CancellationToken{};
    try runPreparedOnReviewedStack(&prepared, &cancellation);
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    failing.resize_fail_index = std.math.maxInt(usize);
    var result = try accumulator.finalize();
    defer result.deinit(prepared_allocator);
    try expectSecureColumnsEqual(&reference_result, &result);
    var saw_nonzero = false;
    for (0..result.len()) |row| saw_nonzero = saw_nonzero or !result.at(row).isZero();
    try std.testing.expect(saw_nonzero);
}
