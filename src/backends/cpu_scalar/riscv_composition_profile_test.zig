//! Focused flat-profile assertions for the CPU RISC-V composition graph.

const std = @import("std");
const prover = @import("stwo_prover_engine");
const composition = @import("riscv_composition.zig");

const QM31 = @import("stwo_core").fields.qm31.QM31;
const Component = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const SecureColumn = prover.secure_column.SecureColumnByCoords;

pub fn serialEvaluation(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    row_count: usize,
) !SecureColumn {
    var recorder = initRecorder(allocator, "riscv-profiled-serial");
    defer recorder.deinit();
    var result = (try composition.evaluateWithExecution(
        allocator,
        components,
        random_coeff,
        trace,
        serialOptions(&recorder),
    )).?;
    errdefer result.deinit(allocator);
    try expectRecorder(&recorder, allocator, 1, 1, 1, 1, row_count);
    return result;
}

pub fn expectParallelEvaluations(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    reference: *const SecureColumn,
    row_count: usize,
) !void {
    for ([_]usize{ 2, 4 }) |worker_count| {
        var pool: prover.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{
            .worker_count = worker_count,
            .stack_size = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        });
        defer pool.deinit();
        var recorder = initRecorder(allocator, "riscv-profiled-parallel");
        defer recorder.deinit();
        const before = composition.telemetrySnapshot();
        var result = (try composition.evaluateWithExecution(
            allocator,
            components,
            random_coeff,
            trace,
            try poolOptions(worker_count, &pool, false, &recorder),
        )).?;
        defer result.deinit(allocator);
        try expectEqualColumns(reference, &result);

        const snapshot = composition.telemetrySnapshot().delta(before);
        try std.testing.expectEqual(@as(u64, 4), snapshot.row_tiles);
        try std.testing.expectEqual(@as(u64, @intCast(worker_count)), snapshot.execution_lanes);
        try std.testing.expectEqual(@as(u64, 0), snapshot.pool_lease_declines);
        try std.testing.expectEqual(@as(u64, 0), snapshot.finite_budget_rejections);
        try std.testing.expect(snapshot.max_graph_peak_active >= worker_count);
        try expectRecorder(
            &recorder,
            allocator,
            worker_count,
            worker_count,
            worker_count,
            pool.workerCount(),
            row_count,
        );
    }
}

pub fn compatibilityEvaluation(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    pool: *prover.work_pool.WorkPool,
    row_count: usize,
) !SecureColumn {
    var recorder = initRecorder(allocator, "riscv-profiled-contention");
    defer recorder.deinit();
    var result = (try composition.evaluateWithExecution(
        allocator,
        components,
        random_coeff,
        trace,
        try poolOptions(2, pool, true, &recorder),
    )).?;
    errdefer result.deinit(allocator);
    // The declined two-worker attempt reserves nothing. Only its admitted
    // serial retry publishes, while preserving the original request truth.
    try expectRecorder(&recorder, allocator, 2, 2, 1, 2, row_count);
    return result;
}

pub fn mixedEvaluation(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    row_count: usize,
) !SecureColumn {
    var recorder = initRecorder(allocator, "riscv-profiled-mixed");
    defer recorder.deinit();
    var result = (try composition.evaluateWithExecution(
        allocator,
        components,
        random_coeff,
        trace,
        serialOptions(&recorder),
    )).?;
    errdefer result.deinit(allocator);

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const graph = profile.graphs[0];
    try std.testing.expectEqual(@as(usize, 2), graph.events.len);
    try std.testing.expectEqual(@as(usize, 3), graph.contributions.len);
    try std.testing.expectEqual(@as(usize, 3), graph.component_work.len);
    try std.testing.expectEqual(@as(u32, 0), graph.events[0].contribution_range.start);
    try std.testing.expectEqual(@as(u32, 1), graph.events[0].contribution_range.len);
    try std.testing.expectEqual(@as(u32, 1), graph.events[1].contribution_range.start);
    try std.testing.expectEqual(@as(u32, 2), graph.events[1].contribution_range.len);

    const expected_roles = [_]prover.task_profile.ContributionRole{
        .exclusive,
        .semantic_constraints,
        .lookup_constraints,
    };
    for (graph.component_work, expected_roles, 0..) |work, role, index| {
        try std.testing.expectEqual(@as(u32, @intCast(index)), work.component_registry_index);
        try std.testing.expectEqual(role, work.role);
        try std.testing.expectEqual(@as(u64, 1), work.task_count);
        try std.testing.expectEqual(@as(u64, @intCast(row_count)), work.planned_rows);
        try std.testing.expectEqual(@as(?u64, @intCast(row_count)), work.completed_rows);
    }
    return result;
}

pub fn expectSpecializationDecline(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
) !void {
    var recorder = initRecorder(allocator, "riscv-profiled-decline");
    defer recorder.deinit();
    try std.testing.expect(try composition.evaluateWithExecution(
        allocator,
        components,
        random_coeff,
        trace,
        .{ .task_recorder = &recorder },
    ) == null);
    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    // A specialization decline did not execute a bounded graph and must not
    // invent a task record merely because capture was requested.
    try std.testing.expectEqual(@as(usize, 0), profile.graphs.len);
}

fn expectEqualColumns(expected: *const SecureColumn, actual: *const SecureColumn) !void {
    for (expected.columns, actual.columns) |expected_coordinate, actual_coordinate| {
        for (expected_coordinate, actual_coordinate) |expected_value, actual_value| {
            try std.testing.expect(expected_value.eql(actual_value));
        }
    }
}

pub fn serialOptions(
    recorder: *prover.stage_profile.Recorder,
) composition.ExecutionOptions {
    return .{
        .requested_worker_count = 1,
        .pool_capacity = 1,
        .task_recorder = recorder,
    };
}

pub fn poolOptions(
    worker_count: usize,
    pool: *prover.work_pool.WorkPool,
    serial_on_contention: bool,
    recorder: *prover.stage_profile.Recorder,
) !composition.ExecutionOptions {
    return .{
        .worker_budget = try prover.work_pool.WorkerBudget.init(worker_count),
        .pool = pool,
        .byte_budget = 128 * 1024 * 1024,
        .serial_on_contention = serial_on_contention,
        .requested_worker_count = worker_count,
        .pool_capacity = pool.workerCount(),
        .task_recorder = recorder,
    };
}

pub fn initRecorder(
    allocator: std.mem.Allocator,
    example: []const u8,
) prover.stage_profile.Recorder {
    return prover.stage_profile.Recorder.init(allocator, "Debug", example);
}

pub fn expectRecorder(
    recorder: *const prover.stage_profile.Recorder,
    allocator: std.mem.Allocator,
    expected_tasks: usize,
    requested_workers: usize,
    admitted_workers: usize,
    pool_capacity: usize,
    row_count: usize,
) !void {
    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    try expectProfile(
        &profile,
        expected_tasks,
        requested_workers,
        admitted_workers,
        pool_capacity,
        row_count,
    );
}

fn expectProfile(
    profile: anytype,
    expected_tasks: usize,
    requested_workers: usize,
    admitted_workers: usize,
    pool_capacity: usize,
    row_count: usize,
) !void {
    try std.testing.expectEqual(@as(usize, 1), profile.graphs.len);
    const graph = profile.graphs[0];
    try std.testing.expectEqualStrings("cpu_composition_riscv", graph.graph_id);
    try std.testing.expectEqual(expected_tasks, graph.events.len);
    try std.testing.expectEqual(expected_tasks * 2, graph.contributions.len);
    try std.testing.expectEqual(@as(usize, 2), graph.component_work.len);
    try std.testing.expectEqual(
        @as(u32, @intCast(requested_workers)),
        graph.summary.requested_workers,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(admitted_workers)),
        graph.summary.admitted_workers,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(pool_capacity)),
        graph.summary.pool_capacity,
    );
    try std.testing.expectEqual(@as(u64, @intCast(expected_tasks)), graph.summary.planned_tasks);
    try std.testing.expectEqual(@as(u64, @intCast(expected_tasks)), graph.summary.submitted_tasks);
    try std.testing.expectEqual(@as(u64, @intCast(expected_tasks)), graph.summary.completed_tasks);
    try std.testing.expectEqual(@as(u64, 0), graph.summary.failed_tasks);
    try std.testing.expectEqual(@as(u64, 0), graph.summary.cancelled_tasks);
    try std.testing.expectEqual(@as(u64, 0), graph.summary.unsubmitted_cancelled_tasks);
    try std.testing.expectEqual(@as(u64, @intCast(expected_tasks)), graph.summary.started_tasks);
    try std.testing.expectEqual(@as(u64, @intCast(expected_tasks)), graph.summary.finished_tasks);
    try std.testing.expectEqual(@as(u64, 0), graph.summary.duplicate_starts);
    try std.testing.expectEqual(@as(u64, 0), graph.summary.duplicate_finishes);
    const peak_workers = graph.summary.peak_active_workers orelse
        return error.MissingCompositionWorkerPeak;
    try std.testing.expect(graph.summary.peak_active_tasks >= 1);
    try std.testing.expect(peak_workers >= 1);
    try std.testing.expect(
        @as(usize, peak_workers) <= admitted_workers,
    );
    try std.testing.expectEqual(graph.summary.peak_active_tasks, peak_workers);
    const worker_busy_ns = graph.summary.worker_busy_ns orelse
        return error.MissingCompositionWorkerBusyTime;
    try std.testing.expectEqual(graph.summary.task_run_ns, worker_busy_ns);
    try std.testing.expect(graph.summary.critical_path_ns != null);
    try std.testing.expectEqual(@as(u64, @intCast(row_count)), graph.summary.total_work_estimate);
    try std.testing.expectEqual(@as(u64, 0), graph.summary.completed_rows);
    try std.testing.expectEqual(@as(u64, 4), graph.summary.completed_tiles);
    try std.testing.expect(graph.summary.scheduler == .central_queue_no_steal);
    try std.testing.expectEqual(@as(u64, 0), graph.summary.steal_count);

    var event_work: u64 = 0;
    var event_tiles: u64 = 0;
    for (graph.events, 0..) |event, index| {
        try std.testing.expectEqual(@as(u16, 1), event.key.stage_rank);
        try std.testing.expectEqual(std.math.maxInt(u32), event.key.component_registry_index);
        try std.testing.expectEqual(@as(u32, @intCast(index)), event.key.shard_or_chunk_index);
        try std.testing.expectEqual(@as(u32, @intCast(index * 2)), event.contribution_range.start);
        try std.testing.expectEqual(@as(u32, 2), event.contribution_range.len);
        try std.testing.expectEqualStrings("composition_domain", event.stage_id);
        try std.testing.expectEqualStrings("riscv_pair_lane", event.component_kind);
        try std.testing.expect(event.task_class == .leaf);
        try std.testing.expect(event.parallel_eligible);
        try std.testing.expectEqual(@as(u8, 0), event.dependency_count);
        try std.testing.expect(event.submitted and event.started and event.finished);
        try std.testing.expect(event.ready_ns != null);
        try std.testing.expect(event.submitted_ns != null);
        try std.testing.expect(event.start_ns != null);
        try std.testing.expect(event.finish_ns != null);
        try std.testing.expectEqual(@as(u32, @intCast(admitted_workers)), event.configured_workers);
        try std.testing.expect(event.worker_slot != null and event.worker_kind != null);
        try std.testing.expect(event.terminal_status == .completed);
        try std.testing.expect(event.error_name == null);
        try std.testing.expect(event.cancellation_winner == null);
        try std.testing.expect(event.cancellation_reason == null);
        try std.testing.expect(event.cleanup_complete);
        try std.testing.expectEqual(@as(u64, 0), event.completed_rows);
        try std.testing.expect(event.completed_tiles > 0);
        try std.testing.expect(event.bytes.final_output_bytes > 0);
        try std.testing.expect(event.bytes.shared_resident_bytes > 0);

        event_work = try std.math.add(u64, event_work, event.work_estimate);
        event_tiles = try std.math.add(u64, event_tiles, event.completed_tiles);
        const semantic = graph.contributions[index * 2];
        const lookup = graph.contributions[index * 2 + 1];
        try std.testing.expectEqual(@as(u32, 0), semantic.component_registry_index);
        try std.testing.expectEqualStrings("riscv_semantic_component", semantic.component_kind);
        try std.testing.expectEqual(
            prover.task_profile.ContributionRole.semantic_constraints,
            semantic.role,
        );
        try std.testing.expectEqual(@as(u32, 1), lookup.component_registry_index);
        try std.testing.expectEqualStrings("riscv_lookup_component", lookup.component_kind);
        try std.testing.expectEqual(
            prover.task_profile.ContributionRole.lookup_constraints,
            lookup.role,
        );
        try std.testing.expectEqual(semantic.planned_rows, semantic.completed_rows.?);
        try std.testing.expectEqual(lookup.planned_rows, lookup.completed_rows.?);
        try std.testing.expectEqual(event.completed_tiles, semantic.planned_tiles);
        try std.testing.expectEqual(event.completed_tiles, lookup.planned_tiles);
    }
    try std.testing.expectEqual(@as(u64, @intCast(row_count)), event_work);
    try std.testing.expectEqual(@as(u64, 4), event_tiles);
    const semantic_work = graph.component_work[0];
    try std.testing.expectEqual(@as(u32, 0), semantic_work.component_registry_index);
    try std.testing.expectEqualStrings("riscv_semantic_component", semantic_work.component_kind);
    try std.testing.expectEqual(
        prover.task_profile.ContributionRole.semantic_constraints,
        semantic_work.role,
    );
    try std.testing.expectEqual(@as(u64, @intCast(expected_tasks)), semantic_work.task_count);
    try std.testing.expectEqual(@as(u64, @intCast(row_count)), semantic_work.work_estimate);
    try std.testing.expectEqual(@as(u64, @intCast(row_count)), semantic_work.planned_rows);
    try std.testing.expectEqual(@as(?u64, @intCast(row_count)), semantic_work.completed_rows);
    try std.testing.expectEqual(event_tiles, semantic_work.planned_tiles);
    try std.testing.expectEqual(@as(?u64, event_tiles), semantic_work.completed_tiles);

    const lookup_work = graph.component_work[1];
    try std.testing.expectEqual(@as(u32, 1), lookup_work.component_registry_index);
    try std.testing.expectEqualStrings("riscv_lookup_component", lookup_work.component_kind);
    try std.testing.expectEqual(
        prover.task_profile.ContributionRole.lookup_constraints,
        lookup_work.role,
    );
    try std.testing.expectEqual(semantic_work.task_count, lookup_work.task_count);
    try std.testing.expectEqual(semantic_work.work_estimate, lookup_work.work_estimate);
    try std.testing.expectEqual(semantic_work.planned_rows, lookup_work.planned_rows);
    try std.testing.expectEqual(semantic_work.completed_rows, lookup_work.completed_rows);
}
