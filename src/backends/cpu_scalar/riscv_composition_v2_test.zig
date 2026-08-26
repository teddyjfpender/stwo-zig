//! Authenticated and prepared V2 CPU composition tests.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition = @import("riscv_composition.zig");
const lanes = @import("riscv_composition_lanes.zig");
const profile_test = @import("riscv_composition_profile_test.zig");
const composition_work = prover.air.composition_work;

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
const LookupProgramV2 = prover.air.component_prover.OwnedLookupPolynomialProgramV2;
const LookupAuthorityV2 = prover.air.component_prover.LookupPolynomialAuthorityV2;
const Poly = prover.air.component_prover.Poly;
const Trace = prover.air.component_prover.Trace;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const ColumnAccumulator = prover.air.accumulation.ColumnAccumulator;
const PreparedDomainEvaluation = prover.air.prepared_domain.PreparedDomainEvaluation;
const TaskContext = prover.task_graph.TaskContext;

const evaluate = composition.evaluate;
const evaluateWithExecution = composition.evaluateWithExecution;
const telemetrySnapshot = composition.telemetrySnapshot;
const DifferentialPair = @import("riscv_composition_fixture.zig").DifferentialPair;

fn testAuthenticatedV2Uniform() !void {
    try v2CompositionDifferential(false);
}

fn testAuthenticatedV2SelectedPair() !void {
    try v2CompositionDifferential(true);
}

fn testPreparedV2LaneLifecycle() !void {
    try std.testing.expectEqual(
        @as(usize, 0),
        lanes.LOOKUP_V2_ROW_ALLOCATION_COUNT,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        lanes.LOOKUP_V2_ROW_HASH_COUNT,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        lanes.LOOKUP_V2_ROW_PARTITION_SEARCH_COUNT,
    );
    const expected = 2 * @sizeOf(PackedM31) + 2 * @sizeOf(PackedQM31);
    try std.testing.expectEqual(
        expected,
        try lanes.lookupV2ScratchBytes(2, 2),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        try lanes.lookupV2ScratchBytes(0, 0),
    );
    try std.testing.expectError(
        error.InvalidPreparedCapacity,
        lanes.lookupV2ScratchBytes(
            prover.air.lookup_polynomial_v2.MAX_PROGRAM_NODES + 1,
            1,
        ),
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preparedLookupV2AllocationFailureCase,
        .{},
    );
    var prepared = try lanes.PreparedLookupV2.init(
        std.testing.allocator,
        2,
        2,
    );
    defer prepared.deinit();
    try std.testing.expectEqual(
        expected,
        prepared.resources().shared_resident_bytes,
    );
    try std.testing.expectEqual(
        prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        prepared.resources().worker_stack_bytes,
    );
}

fn v2CompositionDifferential(selected_pair: bool) !void {
    const allocator = std.testing.allocator;
    const eval_log_size: u32 = 13;
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    var mock = DifferentialPair{
        .trace_log_size = eval_log_size - 1,
        .relation_z = QM31.fromU32Unchecked(3, 5, 7, 11),
        .relation_alpha = QM31.fromU32Unchecked(13, 17, 19, 23),
        .relation_z_2 = QM31.fromU32Unchecked(29, 31, 37, 41),
        .relation_alpha_2 = QM31.fromU32Unchecked(43, 47, 53, 59),
        .claim = QM31.fromU32Unchecked(61, 67, 71, 73),
        .selected_pair = selected_pair,
    };
    try mock.initializeV2Authority(allocator);

    var v2_program = try DifferentialPair.exportLookupProgramV2(
        &mock,
        allocator,
    );
    defer v2_program.deinit();
    try v2_program.validateAgainst(&mock.lookup_v2_authority);
    if (!selected_pair) {
        var v1_program = try DifferentialPair.exportLookupProgram(
            &mock,
            allocator,
        );
        defer v1_program.deinit();
        try std.testing.expect(v2_program.isExactUniformV1(&v1_program));
    } else {
        try std.testing.expectEqual(@as(usize, 2), v2_program.entries.len);
        try std.testing.expectEqual(@as(usize, 1), v2_program.batchCount());
        try std.testing.expectEqual(@as(u8, 2), v2_program.batches[0].entry_count);
    }

    const is_first = try allocator.alloc(M31, row_count);
    defer allocator.free(is_first);
    const is_active = try allocator.alloc(M31, row_count);
    defer allocator.free(is_active);
    const main_0 = try allocator.alloc(M31, row_count);
    defer allocator.free(main_0);
    const main_1 = try allocator.alloc(M31, row_count);
    defer allocator.free(main_1);
    var interaction_values: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    var initialized_interaction: usize = 0;
    defer for (interaction_values[0..initialized_interaction]) |values|
        allocator.free(values);
    for (&interaction_values) |*values| {
        values.* = try allocator.alloc(M31, row_count);
        initialized_interaction += 1;
    }
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
    const interaction = try allocator.alloc(
        Poly,
        qm31.SECURE_EXTENSION_DEGREE,
    );
    defer allocator.free(interaction);
    for (interaction, interaction_values) |*poly, values| {
        poly.* = .{ .log_size = eval_log_size, .values = values };
    }
    const tree_items = try allocator.dupe([]const Poly, &.{
        preprocessed,
        main,
        interaction,
    });
    var trace = Trace{
        .polys = core.pcs.TreeVec([]const Poly).initOwned(tree_items),
    };
    defer trace.polys.deinit(allocator);

    const components = [_]Component{
        mock.semanticComponent(),
        mock.lookupV2Component(),
    };
    const component_provers = prover.air.component_prover.ComponentProvers{
        .components = components[0..],
        .n_preprocessed_columns = preprocessed.len,
    };
    const random_coeff = QM31.fromU32Unchecked(79, 83, 89, 97);
    var reference = try component_provers.computeCompositionEvaluation(
        allocator,
        random_coeff,
        &trace,
    );
    defer reference.deinit(allocator);

    var unauthenticated_capture: composition_work.Capture = .{};
    try std.testing.expect(try evaluateWithExecution(
        allocator,
        components[0..],
        random_coeff,
        &trace,
        .{ .work_capture = &unauthenticated_capture },
    ) == null);
    try std.testing.expect(unauthenticated_capture.receipt == null);

    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    });
    defer pool.deinit();
    var expected_receipt: ?composition_work.Receipt = null;
    var duplicate_capture: composition_work.Capture = .{};
    for ([_]usize{ 1, 2, 4 }) |worker_count| {
        var capture: composition_work.Capture = .{};
        const active_capture = if (worker_count == 4)
            &duplicate_capture
        else
            &capture;
        const before = telemetrySnapshot();
        var result = (try evaluateWithExecution(
            allocator,
            components[0..],
            random_coeff,
            &trace,
            .{
                .worker_budget = try prover.work_pool.WorkerBudget.init(worker_count),
                .pool = if (worker_count == 1) null else &pool,
                .requested_worker_count = worker_count,
                .pool_capacity = if (worker_count == 1) 1 else pool.workerCount(),
                .lookup_v2_activation = .authenticated_statement_v2,
                .work_capture = active_capture,
            },
        )).?;
        defer result.deinit(allocator);
        try expectSecureColumnsEqual(&reference, &result);

        const receipt = active_capture.receipt orelse
            return error.MissingCompositionWorkReceipt;
        try receipt.validate();
        try std.testing.expectEqual(
            composition_work.Route.cpu_riscv_packed,
            receipt.route,
        );
        try std.testing.expectEqual(@as(u32, components.len), receipt.component_count);
        try std.testing.expect(receipt.operations.additions != 0);
        try std.testing.expect(receipt.operations.multiplications != 0);
        if (expected_receipt) |expected| {
            try std.testing.expect(std.meta.eql(expected, receipt));
        } else expected_receipt = receipt;

        const snapshot = telemetrySnapshot().delta(before);
        try std.testing.expectEqual(@as(u64, 1), snapshot.admissions);
        try std.testing.expectEqual(@as(u64, 1), snapshot.eligible_pairs);
        try std.testing.expectEqual(@as(u64, 2), snapshot.row_tiles);
        try std.testing.expectEqual(
            @as(u64, @intCast(@min(worker_count, 2))),
            snapshot.execution_lanes,
        );
    }

    const sealed_receipt = duplicate_capture.receipt orelse
        return error.MissingCompositionWorkReceipt;
    const duplicate_before = telemetrySnapshot();
    try std.testing.expectError(error.DuplicateCompletion, evaluateWithExecution(
        allocator,
        components[0..],
        random_coeff,
        &trace,
        .{
            .worker_budget = try prover.work_pool.WorkerBudget.init(4),
            .pool = &pool,
            .requested_worker_count = 4,
            .pool_capacity = pool.workerCount(),
            .lookup_v2_activation = .authenticated_statement_v2,
            .work_capture = &duplicate_capture,
        },
    ));
    const duplicate_snapshot = telemetrySnapshot().delta(duplicate_before);
    try std.testing.expectEqual(@as(u64, 1), duplicate_snapshot.admissions);
    try std.testing.expectEqual(@as(u64, 1), duplicate_snapshot.structured_executions);
    try std.testing.expect(std.meta.eql(
        sealed_receipt,
        duplicate_capture.receipt.?,
    ));

    var wrong = mock;
    wrong.lookup_v2_authority.program_identity[0] ^= 1;
    const wrong_components = [_]Component{
        wrong.semanticComponent(),
        wrong.lookupV2Component(),
    };
    try std.testing.expect(try evaluateWithExecution(
        allocator,
        wrong_components[0..],
        random_coeff,
        &trace,
        .{ .lookup_v2_activation = .authenticated_statement_v2 },
    ) == null);
}

fn preparedLookupV2AllocationFailureCase(allocator: std.mem.Allocator) !void {
    var prepared = try lanes.PreparedLookupV2.init(allocator, 2, 2);
    defer prepared.deinit();
}

fn expectSecureColumnsEqual(
    expected: *const prover.secure_column.SecureColumnByCoords,
    actual: *const prover.secure_column.SecureColumnByCoords,
) !void {
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        try std.testing.expectEqualSlices(
            M31,
            expected.columns[coordinate],
            actual.columns[coordinate],
        );
    }
}

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
    var accelerated = try profile_test.serialEvaluation(
        allocator,
        components[0..],
        random_coeff,
        &trace,
        row_count,
    );
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
    try profile_test.expectParallelEvaluations(
        allocator,
        components[0..],
        random_coeff,
        &trace,
        &reference,
        row_count,
    );

    var preflight_pool: prover.work_pool.WorkPool = undefined;
    try preflight_pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    });
    defer preflight_pool.deinit();
    const preflight_workers = try prover.work_pool.WorkerBudget.init(4);
    const helper_reservation = try preflight_pool.helperReservationBytes(preflight_workers);
    var preflight_failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const preflight_before = telemetrySnapshot();
    try std.testing.expectError(error.TaskMemoryBudgetExceeded, evaluateWithExecution(
        preflight_failing.allocator(),
        components[0..],
        random_coeff,
        &trace,
        .{
            .worker_budget = preflight_workers,
            .pool = &preflight_pool,
            .byte_budget = helper_reservation - 1,
        },
    ));
    try std.testing.expect(!preflight_failing.has_induced_failure);
    const preflight_snapshot = telemetrySnapshot().delta(preflight_before);
    try std.testing.expectEqual(@as(u64, 1), preflight_snapshot.finite_budget_rejections);
    try std.testing.expectEqual(@as(u64, 0), preflight_snapshot.attempts);
    try std.testing.expectEqual(@as(u64, 0), preflight_snapshot.structured_executions);

    var finite_admitted = (try evaluateWithExecution(
        allocator,
        components[0..],
        random_coeff,
        &trace,
        .{ .byte_budget = 128 * 1024 * 1024 },
    )).?;
    defer finite_admitted.deinit(allocator);
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        try std.testing.expectEqualSlices(
            M31,
            reference.columns[coordinate],
            finite_admitted.columns[coordinate],
        );
    }

    const finite_budget_before = telemetrySnapshot();
    var finite_failing = std.testing.FailingAllocator.init(allocator, .{});
    finite_failing.fail_index = finite_failing.alloc_index;
    finite_failing.resize_fail_index = finite_failing.resize_index;
    try std.testing.expectError(
        error.TaskMemoryBudgetExceeded,
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
    const strict_contention_before = telemetrySnapshot();
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
                .byte_budget = 128 * 1024 * 1024,
            },
        ),
    );
    const strict_contention = telemetrySnapshot().delta(strict_contention_before);
    try std.testing.expectEqual(@as(u64, 0), strict_contention.finite_budget_rejections);
    const contention_before = telemetrySnapshot();
    var contention_fallback = try profile_test.compatibilityEvaluation(
        allocator,
        components[0..],
        random_coeff,
        &trace,
        &contention_pool,
        row_count,
    );
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
    try std.testing.expectEqual(@as(u64, 0), contention_snapshot.finite_budget_rejections);
    const mismatched = [_]Component{
        mock.semanticComponent(),
        mock.lookupComponent(true),
    };
    const declined_before = telemetrySnapshot();
    try profile_test.expectSpecializationDecline(
        allocator,
        mismatched[0..],
        random_coeff,
        &trace,
    );
    const declined = telemetrySnapshot().delta(declined_before);
    try std.testing.expectEqual(@as(u64, 1), declined.attempts);
    try std.testing.expectEqual(@as(u64, 0), declined.admissions);
    try std.testing.expectEqual(@as(u64, 1), declined.declines);
    try std.testing.expectError(
        error.TaskMemoryBudgetExceeded,
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
    var mixed_accelerated = try profile_test.mixedEvaluation(
        allocator,
        mixed[0..],
        random_coeff,
        &trace,
        row_count,
    );
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

test "cpu RISC-V composition: authenticated V2 uniform receipts are stable and exact-once" {
    try testAuthenticatedV2Uniform();
}

test "cpu RISC-V composition: authenticated V2 selected-pair receipts are stable and exact-once" {
    try testAuthenticatedV2SelectedPair();
}

test "cpu RISC-V composition: V2 prepared lane lifecycle and resources are bounded" {
    try testPreparedV2LaneLifecycle();
}
