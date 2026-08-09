//! Private execution state machine for the bounded component task graph.
//!
//! `task_graph.zig` owns the public model. This module is generic over that
//! model to keep the dependency direction acyclic while isolating scheduling,
//! cancellation, and optional capture from the public facade.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const task_context = @import("task_graph_context.zig");
const task_graph_profile = @import("task_graph_profile.zig");
const work_pool = @import("work_pool.zig");

const task_profile = prover_api.task_profile;
const ComponentTaskId = task_context.ComponentTaskId;
const MAX_COMPONENT_TASKS = task_context.MAX_COMPONENT_TASKS;

pub fn execute(graph: anytype, options: anytype) anyerror!@TypeOf(graph.report()) {
    if (graph.executed) return error.TaskGraphAlreadyExecuted;
    if (graph.count != graph.capacity) return error.TaskCountMismatch;
    _ = try work_pool.WorkerBudget.init(options.worker_budget.count);
    if (options.worker_budget.count > 1 and options.pool == null) {
        return error.WorkPoolRequired;
    }
    if (options.task_profile_recorder != null) {
        try task_graph_profile.validateConfiguration(
            options.requested_worker_count orelse options.worker_budget.count,
            options.worker_budget.count,
            options.pool_capacity orelse
                if (options.pool) |pool| pool.workerCount() else 1,
        );
    }
    const admission = try finalizePlan(graph, options);

    var lease_storage: work_pool.WorkLease = undefined;
    const lease: ?*work_pool.WorkLease = if (options.pool) |pool| lease: {
        lease_storage = try pool.acquire(options.worker_budget);
        break :lease &lease_storage;
    } else null;
    defer if (lease) |active_lease| active_lease.deinit();

    graph.executed = true;
    graph.ready_policy = options.ready_policy;
    graph.configured_workers = options.worker_budget.count;
    graph.admitted_worker_stack_bytes = admission.worker_stack_bytes;
    graph.admitted_submission_bytes = admission.submission_bytes;
    graph.fixed_resident_bytes = admission.fixed_resident_bytes;
    graph.peak_reserved_bytes = admission.baseline_bytes;

    var capture_storage: task_graph_profile.Capture = undefined;
    var capture_initialized = false;
    defer if (capture_initialized) capture_storage.deinit();
    if (options.task_profile_recorder) |recorder| {
        capture_storage = try task_graph_profile.Capture.init(
            graph.allocator,
            recorder,
            graph.count,
            task_graph_profile.componentCount(graph),
            options.task_profile_clock,
        );
        capture_initialized = true;
        try capture_storage.initializeEvents(graph, options.worker_budget.count);
        graph.active_capture = &capture_storage;
    }
    defer graph.active_capture = null;

    while (terminalCount(graph) < graph.count) {
        if (graph.cancellation.isCancelled()) {
            cancelQueued(graph);
            break;
        }

        var ready: [MAX_COMPONENT_TASKS]ComponentTaskId = undefined;
        const ready_ns = if (graph.active_capture) |capture|
            capture.sample()
        else
            null;
        const ready_count = collectReady(graph, &ready, ready_ns);
        if (ready_count == 0) {
            if (terminalCount(graph) == graph.count) break;
            return error.DeadlockDetected;
        }
        const ReadyOrder = readyOrder(@TypeOf(graph));
        std.sort.heap(
            ComponentTaskId,
            ready[0..ready_count],
            graph,
            ReadyOrder.lessThan,
        );

        var wave: [work_pool.MAX_WORKERS]ComponentTaskId = undefined;
        var wave_count: usize = 0;
        var scratch_bytes: usize = 0;
        if (graph.active_capture) |capture| {
            capture.clearResourceBlocks(ready[0..ready_count]);
        }
        const first = graph.slots[ready[0]];
        if (first.class == .leaf) {
            for (ready[0..ready_count]) |id| {
                const slot = graph.slots[id];
                if (slot.class != .leaf) continue;
                if (wave_count == options.worker_budget.count) break;
                if (slot.resources.exclusive_scratch_bytes >
                    admission.scratch_budget - scratch_bytes)
                {
                    if (graph.active_capture) |capture| {
                        capture.markResourceBlocked(id);
                    }
                    continue;
                }
                wave[wave_count] = id;
                wave_count += 1;
                scratch_bytes += slot.resources.exclusive_scratch_bytes;
            }
        } else {
            wave[0] = ready[0];
            wave_count = 1;
            scratch_bytes = first.resources.exclusive_scratch_bytes;
        }
        std.debug.assert(wave_count > 0);
        const reserved_bytes = std.math.add(
            usize,
            admission.baseline_bytes,
            scratch_bytes,
        ) catch return error.ResourceReservationOverflow;
        graph.peak_reserved_bytes = @max(
            graph.peak_reserved_bytes,
            reserved_bytes,
        );

        const wave_start_ns = if (graph.active_capture) |capture|
            capture.sample()
        else
            null;
        try executeWave(
            graph,
            wave[0..wave_count],
            options.worker_budget,
            lease,
            wave_start_ns,
        );
        if (graph.active_capture) |capture| {
            capture.finishWaveWait(
                ready[0..ready_count],
                wave_start_ns,
                capture.sample(),
            );
        }
    }

    const execution_report = graph.report();
    const canonical_failure = firstFailure(graph);
    var profile_failure: ?anyerror = null;
    if (graph.active_capture) |capture| {
        capture.finalizeAndPublish(
            graph,
            options.task_profile_graph_id,
            .{
                .requested_workers = options.requested_worker_count orelse
                    options.worker_budget.count,
                .admitted_workers = options.worker_budget.count,
                .pool_capacity = options.pool_capacity orelse
                    if (options.pool) |pool| pool.workerCount() else 1,
                .worker_stack_bytes = execution_report.admitted_worker_stack_bytes,
                .peak_active_tasks = execution_report.peak_active_tasks,
                .planned_tasks = graph.count,
                .submitted_tasks = execution_report.submitted_tasks,
                .completed_tasks = execution_report.succeeded_tasks,
                .failed_tasks = execution_report.failed_tasks,
                .cancelled_tasks = execution_report.cancelled_tasks,
                .unsubmitted_cancelled_tasks = execution_report.unsubmitted_cancelled_tasks,
                .started_tasks = execution_report.started_tasks,
                .finished_tasks = execution_report.finished_tasks,
                .duplicate_starts = execution_report.duplicate_starts,
                .duplicate_finishes = execution_report.duplicate_finishes,
                .peak_reserved_bytes = execution_report.peak_reserved_bytes,
            },
        ) catch |failure| {
            profile_failure = failure;
        };
    }
    if (canonical_failure) |failure| return failure;
    if (profile_failure) |failure| return failure;
    return execution_report;
}

const ResourceAdmission = struct {
    fixed_resident_bytes: usize,
    worker_stack_bytes: usize,
    submission_bytes: usize,
    baseline_bytes: usize,
    scratch_budget: usize,
};

fn finalizePlan(graph: anytype, options: anytype) !ResourceAdmission {
    var reverse_index = graph.count;
    while (reverse_index > 0) {
        reverse_index -= 1;
        const id: ComponentTaskId = @intCast(reverse_index);
        var remaining_level: u16 = 0;
        for (graph.slots[reverse_index + 1 ..]) |dependent| {
            var direct_dependent = false;
            for (dependent.deps[0..dependent.n_deps]) |dependency| {
                if (dependency == id) {
                    direct_dependent = true;
                    break;
                }
            }
            if (!direct_dependent) continue;
            const candidate = std.math.add(
                u16,
                dependent.remaining_dependency_level,
                1,
            ) catch return error.DependencyLevelOverflow;
            remaining_level = @max(remaining_level, candidate);
        }
        graph.slots[reverse_index].remaining_dependency_level = remaining_level;
    }

    const stack_size = if (options.pool) |pool|
        pool.stackSize()
    else
        work_pool.WORKER_STACK_SIZE;
    var fixed_resident_bytes: usize = 0;
    for (graph.slots) |slot| {
        if (slot.resources.worker_stack_bytes > stack_size) {
            return error.TaskWorkerStackExceeded;
        }
        fixed_resident_bytes = std.math.add(
            usize,
            fixed_resident_bytes,
            try slot.resources.residentBytes(),
        ) catch return error.ResourceReservationOverflow;
    }
    const worker_stack_bytes = std.math.mul(
        usize,
        options.worker_budget.helperCount(),
        stack_size,
    ) catch return error.ResourceReservationOverflow;
    const submission_bytes = std.math.mul(
        usize,
        options.worker_budget.helperCount(),
        work_pool.STRUCTURED_JOB_RESERVATION_BYTES,
    ) catch return error.ResourceReservationOverflow;
    const helper_resident_bytes = std.math.add(
        usize,
        worker_stack_bytes,
        submission_bytes,
    ) catch return error.ResourceReservationOverflow;
    const baseline_bytes = std.math.add(
        usize,
        fixed_resident_bytes,
        helper_resident_bytes,
    ) catch return error.ResourceReservationOverflow;
    if (baseline_bytes > options.byte_budget) {
        return error.TaskMemoryBudgetExceeded;
    }
    const scratch_budget = options.byte_budget - baseline_bytes;
    for (graph.slots) |slot| {
        if (slot.resources.exclusive_scratch_bytes > scratch_budget) {
            return error.TaskMemoryBudgetExceeded;
        }
    }
    return .{
        .fixed_resident_bytes = fixed_resident_bytes,
        .worker_stack_bytes = worker_stack_bytes,
        .submission_bytes = submission_bytes,
        .baseline_bytes = baseline_bytes,
        .scratch_budget = scratch_budget,
    };
}

fn collectReady(
    graph: anytype,
    ready: *[MAX_COMPONENT_TASKS]ComponentTaskId,
    ready_ns: ?u64,
) usize {
    var ready_count: usize = 0;
    var slot_index: usize = 0;
    while (slot_index < graph.count) : (slot_index += 1) {
        const status = graph.slots[slot_index].status;
        if (status != .pending and status != .ready) continue;
        var all_done = true;
        var dependency_cancelled = false;
        const dependency_count = graph.slots[slot_index].n_deps;
        for (graph.slots[slot_index].deps[0..dependency_count]) |dependency| {
            switch (graph.slots[dependency].status) {
                .done => {},
                .failed, .cancelled => {
                    dependency_cancelled = true;
                    all_done = false;
                    break;
                },
                else => all_done = false,
            }
        }
        if (dependency_cancelled) {
            terminalizeUnsubmittedCancellation(graph, @intCast(slot_index));
            continue;
        }
        if (!all_done) continue;
        if (graph.slots[slot_index].status == .pending) {
            if (graph.active_capture) |capture| {
                capture.eventAt(slot_index).ready_ns = ready_ns;
            }
            graph.slots[slot_index].status = .ready;
        }
        ready[ready_count] = @intCast(slot_index);
        ready_count += 1;
    }
    return ready_count;
}

fn executeWave(
    graph: anytype,
    ids: []const ComponentTaskId,
    budget: work_pool.WorkerBudget,
    lease: ?*work_pool.WorkLease,
    submitted_ns: ?u64,
) !void {
    std.debug.assert(ids.len > 0);
    std.debug.assert(ids.len <= budget.count);
    const Envelope = RunEnvelope(@TypeOf(graph));
    var envelopes: [work_pool.MAX_WORKERS]Envelope = undefined;
    for (ids, 0..) |id, index| {
        const slot = &graph.slots[id];
        slot.status = .running;
        std.debug.assert(!slot.submitted);
        slot.submitted = true;
        _ = graph.submitted.fetchAdd(1, .monotonic);
        const profile_event = if (graph.active_capture) |capture| event: {
            const event = capture.eventAt(id);
            event.submitted = true;
            event.submitted_ns = submitted_ns;
            event.worker_slot = @intCast(index);
            event.worker_kind = if (index == 0) .coordinator else .helper;
            break :event event;
        } else null;
        envelopes[index] = .{
            .graph = graph,
            .id = id,
            .profile_event = profile_event,
            .visible_budget = if (slot.class == .pool_exclusive)
                budget
            else
                work_pool.WorkerBudget.serial(),
            .exclusive_lease = if (slot.class == .pool_exclusive)
                lease
            else
                null,
        };
    }

    var wait_group = std.Thread.WaitGroup{};
    if (ids.len > 1) {
        const active_lease = lease orelse return error.WorkPoolRequired;
        for (envelopes[1..ids.len]) |*envelope| {
            try active_lease.spawnWg(
                &wait_group,
                Envelope.run,
                .{@as(*Envelope, envelope)},
            );
        }
    }
    Envelope.run(&envelopes[0]);
    wait_group.wait();
    if (ids.len > 1) lease.?.completeWave();
}

fn RunEnvelope(comptime GraphPointer: type) type {
    return struct {
        const Self = @This();

        graph: GraphPointer,
        id: ComponentTaskId,
        profile_event: ?*task_profile.TaskEvent,
        visible_budget: work_pool.WorkerBudget,
        exclusive_lease: ?*work_pool.WorkLease,

        fn run(envelope: *Self) void {
            const graph = envelope.graph;
            const slot = &graph.slots[envelope.id];
            // Sample before the acquire-load cancellation gate. The profiled
            // cancellation handshake publishes `started` before the graph
            // flag and samples its request time afterward, so every task that
            // passes this gate has a causally earlier start timestamp.
            const start_candidate_ns = if (graph.active_capture) |capture|
                capture.sample()
            else
                null;
            const profiled_cancellation = if (graph.active_capture) |capture|
                capture.cancellationStarted()
            else
                false;
            if (profiled_cancellation or graph.cancellation.isCancelled()) {
                terminalizeSubmittedCancellation(graph, envelope.id);
                return;
            }

            if (slot.started) {
                _ = graph.duplicate_starts.fetchAdd(1, .monotonic);
            }
            slot.started = true;
            if (envelope.profile_event) |event| {
                event.started = true;
                event.start_ns = start_candidate_ns;
            }
            _ = graph.started.fetchAdd(1, .monotonic);
            const active = graph.active.fetchAdd(1, .monotonic) + 1;
            updatePeak(&graph.peak_active, active);
            defer {
                _ = graph.active.fetchSub(1, .release);
                if (slot.finished) {
                    _ = graph.duplicate_finishes.fetchAdd(1, .monotonic);
                }
                slot.finished = true;
                slot.cleanup_complete = true;
                if (envelope.profile_event) |event| {
                    event.finished = true;
                    if (graph.active_capture) |capture| {
                        capture.waitForCancellationTimestamp();
                        event.finish_ns = capture.sample();
                    }
                }
                _ = graph.finished.fetchAdd(1, .release);
            }

            var child_wait_group = std.Thread.WaitGroup{};
            var context = task_context.TaskContext{
                .user_context = slot.context,
                .cancellation = &graph.cancellation,
                .key = slot.key,
                .worker_budget = envelope.visible_budget,
                .task_class = slot.class,
                .exclusive_lease = envelope.exclusive_lease,
                .child_wait_group = if (slot.class == .pool_exclusive)
                    &child_wait_group
                else
                    null,
                .profile_event = envelope.profile_event,
                .work_unit = slot.work_unit,
                .planned_work_units = slot.planned_work_units,
            };
            var task_failure: ?anyerror = null;
            slot.func(&context) catch |failure| {
                task_failure = failure;
            };
            if (task_failure) |failure| {
                slot.failure = failure;
                slot.status = .failed;
                _ = graph.failed.fetchAdd(1, .monotonic);
                if (graph.active_capture) |capture| {
                    // One owner publishes the handshake before the graph flag.
                    // Losing failures leave cancellation publication to that
                    // owner and wait at their finish boundary below.
                    if (capture.beginCancellation()) {
                        if (graph.cancellation.request()) {
                            graph.cancellation_winner.store(envelope.id, .release);
                            if (envelope.profile_event) |event| {
                                event.cancellation_requested_ns = capture.sample();
                            }
                        }
                        capture.finishCancellationTimestamp();
                    }
                } else if (graph.cancellation.request()) {
                    graph.cancellation_winner.store(envelope.id, .release);
                }
                context.joinChildren();
                return;
            }
            context.joinChildren();
            if (envelope.profile_event) |event| {
                if (!graph.cancellation.isCancelled() and
                    !context.profile_completion_recorded and
                    slot.planned_work_units != 0 and
                    event.completed_rows == 0 and event.completed_tiles == 0)
                {
                    switch (slot.work_unit) {
                        .unspecified => {},
                        .rows => event.completed_rows = slot.planned_work_units,
                        .tiles => event.completed_tiles = slot.planned_work_units,
                    }
                }
            }
            slot.status = .done;
            _ = graph.succeeded.fetchAdd(1, .monotonic);
        }
    };
}

fn terminalCount(graph: anytype) usize {
    var count: usize = 0;
    for (graph.slots[0..graph.count]) |slot| switch (slot.status) {
        .done, .failed, .cancelled => count += 1,
        else => {},
    };
    return count;
}

fn cancelQueued(graph: anytype) void {
    for (graph.slots[0..graph.count], 0..) |slot, index| {
        if (slot.status == .pending or slot.status == .ready) {
            terminalizeUnsubmittedCancellation(graph, @intCast(index));
        }
    }
}

fn terminalizeUnsubmittedCancellation(
    graph: anytype,
    id: ComponentTaskId,
) void {
    const slot = &graph.slots[id];
    std.debug.assert(slot.status == .pending or slot.status == .ready);
    std.debug.assert(!slot.submitted and !slot.started and !slot.finished);
    slot.status = .cancelled;
    slot.finished = true;
    slot.cleanup_complete = true;
    _ = graph.unsubmitted_cancelled.fetchAdd(1, .monotonic);
    if (graph.active_capture) |capture| {
        capture.waitForCancellationTimestamp();
        capture.eventAt(id).finish_ns = capture.sample();
    }
}

fn terminalizeSubmittedCancellation(
    graph: anytype,
    id: ComponentTaskId,
) void {
    const slot = &graph.slots[id];
    std.debug.assert(slot.submitted and !slot.started and !slot.finished);
    slot.status = .cancelled;
    slot.finished = true;
    slot.cleanup_complete = true;
    _ = graph.cancelled.fetchAdd(1, .monotonic);
    _ = graph.finished.fetchAdd(1, .release);
    if (graph.active_capture) |capture| {
        capture.waitForCancellationTimestamp();
        capture.eventAt(id).finish_ns = capture.sample();
    }
}

fn firstFailure(graph: anytype) ?anyerror {
    var selected_key: ?@TypeOf(graph.slots[0].key) = null;
    var selected_error: ?anyerror = null;
    for (graph.slots[0..graph.count]) |slot| {
        const failure = slot.failure orelse continue;
        if (selected_key == null or slot.key.lessThan(selected_key.?)) {
            selected_key = slot.key;
            selected_error = failure;
        }
    }
    return selected_error;
}

fn updatePeak(peak: *std.atomic.Value(usize), candidate: usize) void {
    var observed = peak.load(.monotonic);
    while (candidate > observed) {
        if (peak.cmpxchgWeak(
            observed,
            candidate,
            .monotonic,
            .monotonic,
        )) |actual| {
            observed = actual;
        } else {
            return;
        }
    }
}

fn readyOrder(comptime GraphPointer: type) type {
    return struct {
        fn lessThan(
            graph: GraphPointer,
            lhs: ComponentTaskId,
            rhs: ComponentTaskId,
        ) bool {
            const left = graph.slots[lhs];
            const right = graph.slots[rhs];
            if (graph.ready_policy == .critical_path) {
                if (left.remaining_dependency_level != right.remaining_dependency_level) {
                    return left.remaining_dependency_level > right.remaining_dependency_level;
                }
                if (left.work_estimate != right.work_estimate) {
                    return left.work_estimate > right.work_estimate;
                }
            }
            return left.key.lessThan(right.key);
        }
    };
}
