//! Cold-path timing support for `ComponentTaskGraph` captures.
//!
//! The ordinary executor never constructs a `Clock` or reserves task events.
//! A profiled execution reserves public event storage before launch and uses
//! this module only at scheduler/task boundaries. Workers write unique slots.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const attribution = @import("task_graph_attribution.zig");
const task_context = @import("task_graph_context.zig");

const stage_profile = prover_api.stage_profile;
pub const wire = prover_api.task_profile;

pub const ClockFailure = enum(u8) {
    none,
    unavailable,
    regression,
    counter_overflow,
};

/// Test-only/custom monotonic source. Values are arbitrary monotonic ticks in
/// nanoseconds; `Clock.start` subtracts the first value so receipts always use
/// offsets from the graph origin. The callback and its context must be safe for
/// concurrent use because coordinator and helper tasks sample the same source.
pub const ClockSource = struct {
    context: *anyopaque,
    now_fn: *const fn (context: *anyopaque) anyerror!u64,

    pub fn now(self: ClockSource) anyerror!u64 {
        return self.now_fn(self.context);
    }
};

const CustomClock = struct {
    source: ClockSource,
    origin_ns: u64,
};

/// One immutable origin shared by all graph workers. Unlike `std.time.Timer`,
/// this value has no mutable `previous` sample and is therefore safe to read
/// concurrently.
pub const Clock = union(enum) {
    system: std.time.Instant,
    custom: CustomClock,

    pub fn start(source: ?ClockSource) !Clock {
        if (source) |custom| {
            return .{ .custom = .{
                .source = custom,
                .origin_ns = custom.now() catch
                    return error.TaskProfileClockUnavailable,
            } };
        }
        return .{ .system = std.time.Instant.now() catch
            return error.TaskProfileClockUnavailable };
    }

    /// Returns an offset from this graph's origin. A sampling failure is
    /// retained in `failure`; workers continue to their structured join and
    /// the coordinator reports the profile error afterward.
    pub fn sample(
        self: *const Clock,
        failure: *std.atomic.Value(u8),
    ) ?u64 {
        return switch (self.*) {
            .system => |origin| system: {
                const now = std.time.Instant.now() catch {
                    recordClockFailure(failure, .unavailable);
                    break :system null;
                };
                if (now.order(origin) == .lt) {
                    recordClockFailure(failure, .regression);
                    break :system null;
                }
                break :system now.since(origin);
            },
            .custom => |custom| custom_block: {
                const now_ns = custom.source.now() catch {
                    recordClockFailure(failure, .unavailable);
                    break :custom_block null;
                };
                if (now_ns < custom.origin_ns) {
                    recordClockFailure(failure, .regression);
                    break :custom_block null;
                }
                break :custom_block now_ns - custom.origin_ns;
            },
        };
    }
};

pub fn clockError(failure: *const std.atomic.Value(u8)) ?anyerror {
    return switch (@as(ClockFailure, @enumFromInt(failure.load(.acquire)))) {
        .none => null,
        .unavailable => error.TaskProfileClockUnavailable,
        .regression => error.TaskProfileClockRegression,
        .counter_overflow => error.TaskProfileCounterOverflow,
    };
}

pub fn recordCounterOverflow(failure: *std.atomic.Value(u8)) void {
    recordClockFailure(failure, .counter_overflow);
}

fn recordClockFailure(
    failure: *std.atomic.Value(u8),
    value: ClockFailure,
) void {
    // Enum order is the fixed diagnostic precedence. This CAS-max makes the
    // reported profile failure independent of which concurrent sampler wins:
    // counter overflow > clock regression > clock unavailable.
    const candidate = @intFromEnum(value);
    var observed = failure.load(.acquire);
    while (candidate > observed) {
        if (failure.cmpxchgWeak(
            observed,
            candidate,
            .acq_rel,
            .acquire,
        )) |actual| {
            observed = actual;
        } else {
            return;
        }
    }
}

/// Exact API-owned event reservation plus the small scheduler sidecar that is
/// meaningful only while a profiled graph is executing.
pub const Capture = struct {
    allocator: std.mem.Allocator,
    recorder: *stage_profile.Recorder,
    pending: wire.PendingGraph,
    attribution_mode: attribution.Mode,
    clock: Clock,
    failure: std.atomic.Value(u8) = .init(@intFromEnum(ClockFailure.none)),
    cancellation_started: std.atomic.Value(bool) = .init(false),
    cancellation_timestamp_ready: std.Thread.ResetEvent = .{},
    resource_blocked: []bool,

    pub fn init(
        allocator: std.mem.Allocator,
        recorder: *stage_profile.Recorder,
        graph: anytype,
        source: ?ClockSource,
    ) !Capture {
        const shape = try attribution.deriveShape(allocator, graph);
        var pending = switch (shape.mode) {
            .compatibility => try recorder.reserveTaskGraph(
                shape.reservation.event_count,
                shape.reservation.component_work_count,
            ),
            .semantic => try recorder.reserveTaskGraphShape(shape.reservation),
        };
        errdefer pending.deinit();
        const resource_blocked = try allocator.alloc(bool, graph.count);
        errdefer allocator.free(resource_blocked);
        @memset(resource_blocked, false);
        return .{
            .allocator = allocator,
            .recorder = recorder,
            .pending = pending,
            .attribution_mode = shape.mode,
            .clock = try Clock.start(source),
            .resource_blocked = resource_blocked,
        };
    }

    pub fn deinit(self: *Capture) void {
        self.pending.deinit();
        self.allocator.free(self.resource_blocked);
        self.* = undefined;
    }

    pub fn eventAt(self: *Capture, id: usize) *wire.TaskEvent {
        return &self.pending.events[id];
    }

    pub fn sample(self: *Capture) ?u64 {
        return self.clock.sample(&self.failure);
    }

    /// Claims the profiled cancellation transition before the graph flag, so
    /// a task start cannot slip between its timestamp and the request.
    pub fn beginCancellation(self: *Capture) bool {
        return self.cancellation_started.cmpxchgStrong(
            false,
            true,
            .acq_rel,
            .acquire,
        ) == null;
    }

    pub fn cancellationStarted(self: *const Capture) bool {
        return self.cancellation_started.load(.acquire);
    }

    /// Releases tasks that observed the cancellation transition only after
    /// the winning request timestamp has been sampled (or its failure has
    /// been recorded). External cancellation never enters this handshake.
    pub fn finishCancellationTimestamp(self: *Capture) void {
        std.debug.assert(self.cancellationStarted());
        self.cancellation_timestamp_ready.set();
    }

    pub fn waitForCancellationTimestamp(self: *Capture) void {
        if (self.cancellationStarted()) {
            self.cancellation_timestamp_ready.wait();
        }
    }

    pub fn clearResourceBlocks(
        self: *Capture,
        ready_ids: []const u16,
    ) void {
        for (ready_ids) |id| self.resource_blocked[id] = false;
    }

    pub fn markResourceBlocked(self: *Capture, id: u16) void {
        self.resource_blocked[id] = true;
    }

    pub fn finishWaveWait(
        self: *Capture,
        ready_ids: []const u16,
        wave_start_ns: ?u64,
        wave_finish_ns: ?u64,
    ) void {
        const start_ns = wave_start_ns orelse return;
        const finish_ns = wave_finish_ns orelse return;
        const elapsed_ns = checkedElapsed(start_ns, finish_ns) catch {
            recordClockFailure(&self.failure, .regression);
            return;
        };
        for (ready_ids) |id| {
            if (!self.resource_blocked[id]) continue;
            const event = self.eventAt(id);
            event.resource_wait_ns = checkedAdd(
                event.resource_wait_ns,
                elapsed_ns,
            ) catch {
                recordCounterOverflow(&self.failure);
                return;
            };
        }
    }

    pub fn errorValue(self: *const Capture) ?anyerror {
        return clockError(&self.failure);
    }

    /// Moves the API-owned slices into the recorder. Call only after all event
    /// validation and checked summary arithmetic has succeeded.
    pub fn publish(
        self: *Capture,
        graph_id: []const u8,
        summary: wire.RequestSummary,
    ) !void {
        try self.recorder.publishTaskGraphAfterJoin(
            &self.pending,
            .{ .graph_id = graph_id },
            summary,
        );
    }

    pub fn initializeEvents(
        self: *Capture,
        graph: anytype,
        configured_workers: usize,
    ) !void {
        const configured = try castU32(configured_workers);
        for (graph.slots[0..graph.count], self.pending.events) |slot, *event| {
            event.* = .{
                .key = profileKey(slot.key),
                .stage_id = slot.stage_id,
                .component_kind = slot.component_kind,
                .task_class = profileClass(slot.class),
                .dependency_count = slot.n_deps,
                .parallel_eligible = slot.parallel_eligible,
                .configured_workers = configured,
                .bytes = .{
                    .final_output_bytes = try castU64(slot.resources.final_output_bytes),
                    .exclusive_scratch_bytes = try castU64(
                        slot.resources.exclusive_scratch_bytes,
                    ),
                    .shared_resident_bytes = try castU64(
                        slot.resources.shared_resident_bytes,
                    ),
                    .device_resident_bytes = try castU64(
                        slot.resources.device_resident_bytes,
                    ),
                    .worker_stack_bytes = try castU64(
                        slot.resources.worker_stack_bytes,
                    ),
                },
                .work_estimate = slot.work_estimate,
                .planned_rows = if (slot.work_unit == .rows)
                    slot.planned_work_units
                else
                    0,
                .planned_tiles = if (slot.work_unit == .tiles)
                    slot.planned_work_units
                else
                    0,
            };
            for (slot.deps[0..slot.n_deps], 0..) |dependency, index| {
                event.dependencies[index] = profileKey(graph.slots[dependency].key);
            }
        }
        if (self.attribution_mode == .semantic) {
            attribution.initialize(
                graph,
                self.pending.events,
                self.pending.contributions,
            );
        }
    }

    pub fn finalizeAndPublish(
        self: *Capture,
        graph: anytype,
        graph_id: []const u8,
        accounting: Accounting,
    ) !void {
        const graph_finish_ns = self.sample();
        if (self.errorValue()) |failure| return failure;
        const graph_elapsed_ns = graph_finish_ns orelse
            return error.TaskProfileClockUnavailable;

        const winner = graph.cancellationWinner();
        const winner_key = if (winner) |key| profileKey(key) else null;
        const externally_cancelled = winner_key == null and
            graph.cancellation.isCancelled();
        var cancellation_requested_ns: ?u64 = null;
        if (winner_key) |key| {
            for (self.pending.events) |event| {
                if (event.key.eql(key)) {
                    cancellation_requested_ns = event.cancellation_requested_ns;
                    break;
                }
            }
            if (cancellation_requested_ns == null) {
                return error.TaskProfileMissingCancellationTimestamp;
            }
        }

        var critical_end: [task_context.MAX_COMPONENT_TASKS]u64 = undefined;
        var critical_path_ns: u64 = 0;
        var all_completed = true;
        for (graph.slots[0..graph.count], self.pending.events, 0..) |
            slot,
            *event,
            index,
        | {
            event.submitted = slot.submitted;
            event.started = slot.started;
            event.finished = slot.finished;
            event.cleanup_complete = slot.cleanup_complete;
            event.error_name = if (slot.failure) |failure| @errorName(failure) else null;
            event.cancellation_winner = winner_key;
            event.cancellation_requested_ns = cancellation_requested_ns;
            event.terminal_status = switch (slot.status) {
                .done => .completed,
                .failed => .failed,
                .cancelled => .cancelled,
                else => return error.TaskProfileNonTerminalEvent,
            };
            event.cancellation_reason = if (slot.status == .cancelled)
                if (externally_cancelled) .request_cancelled else .sibling_failure
            else
                null;
            try finalizeDurations(event);
            if (cancellation_requested_ns) |requested_ns| {
                if ((event.start_ns != null and event.start_ns.? > requested_ns) or
                    (slot.status == .cancelled and
                        event.finish_ns.? < requested_ns))
                {
                    return error.TaskProfileCancellationCausalityViolation;
                }
            }

            if (slot.status != .done) all_completed = false;
            var dependency_path_ns: u64 = 0;
            for (slot.deps[0..slot.n_deps]) |dependency| {
                dependency_path_ns = @max(
                    dependency_path_ns,
                    critical_end[dependency],
                );
            }
            critical_end[index] = try checkedAdd(
                dependency_path_ns,
                event.run_ns,
            );
            critical_path_ns = @max(critical_path_ns, critical_end[index]);
        }

        canonicalizeEvents(self.pending.events);
        if (self.attribution_mode == .semantic) {
            attribution.finish(
                self.pending.events,
                self.pending.contributions,
            );
        }
        var summary = try summarize(
            self.pending.events,
            accounting,
            graph_elapsed_ns,
        );
        summary.critical_path_ns = if (all_completed)
            critical_path_ns
        else
            null;
        try self.publish(graph_id, summary);
    }
};

pub const Accounting = struct {
    requested_workers: usize,
    admitted_workers: usize,
    pool_capacity: usize,
    worker_stack_bytes: usize,
    peak_active_tasks: usize,
    planned_tasks: usize,
    submitted_tasks: usize,
    completed_tasks: usize,
    failed_tasks: usize,
    cancelled_tasks: usize,
    unsubmitted_cancelled_tasks: usize,
    started_tasks: usize,
    finished_tasks: usize,
    duplicate_starts: usize,
    duplicate_finishes: usize,
    peak_reserved_bytes: usize,
};

/// Rejects impossible or unencodable request metadata before task launch, so
/// a correctly executed graph cannot be discarded afterward.
pub fn validateConfiguration(
    requested_workers: usize,
    admitted_workers: usize,
    pool_capacity: usize,
) !void {
    if (requested_workers == 0 or
        admitted_workers == 0 or
        pool_capacity == 0 or
        admitted_workers > requested_workers or
        admitted_workers > pool_capacity)
    {
        return error.InvalidTaskProfileAccounting;
    }
    _ = try castU32(requested_workers);
    _ = try castU32(admitted_workers);
    _ = try castU32(pool_capacity);
}

fn finalizeDurations(event: *wire.TaskEvent) !void {
    if (event.submitted) {
        const submitted_ns = event.submitted_ns orelse
            return error.TaskProfileMissingSubmittedTimestamp;
        const queue_finish_ns = event.start_ns orelse event.finish_ns orelse
            return error.TaskProfileMissingFinishTimestamp;
        event.queue_wait_ns = try checkedElapsed(submitted_ns, queue_finish_ns);
        const ready_ns = event.ready_ns orelse
            return error.TaskProfileMissingReadyTimestamp;
        event.admission_wait_ns = try checkedElapsed(ready_ns, submitted_ns);
    }
    if (event.started) {
        event.run_ns = try checkedElapsed(
            event.start_ns orelse return error.TaskProfileMissingStartTimestamp,
            event.finish_ns orelse return error.TaskProfileMissingFinishTimestamp,
        );
    }
    if (event.finished and event.finish_ns == null) {
        return error.TaskProfileMissingFinishTimestamp;
    }
}

fn canonicalizeEvents(events: []wire.TaskEvent) void {
    std.sort.heap(wire.TaskEvent, events, {}, struct {
        fn lessThan(_: void, lhs: wire.TaskEvent, rhs: wire.TaskEvent) bool {
            return lhs.key.lessThan(rhs.key);
        }
    }.lessThan);
}

fn summarize(
    events: []const wire.TaskEvent,
    accounting: Accounting,
    graph_elapsed_ns: u64,
) !wire.RequestSummary {
    try validateAccounting(accounting);
    var useful_task_work_ns: u64 = 0;
    var queue_wait_ns: u64 = 0;
    var admission_wait_ns: u64 = 0;
    var resource_wait_ns: u64 = 0;
    var worker_busy_ns: u64 = 0;
    var parallel_eligible_ns: u64 = 0;
    var total_work_estimate: u64 = 0;
    var completed_rows: u64 = 0;
    var completed_tiles: u64 = 0;
    var cancellation_requested_ns: ?u64 = null;
    var latest_finish_ns: u64 = 0;
    var has_pool_exclusive = false;
    var observed_submitted: u64 = 0;
    var observed_started: u64 = 0;
    var observed_finished_submitted: u64 = 0;
    var observed_completed: u64 = 0;
    var observed_failed: u64 = 0;
    var observed_cancelled: u64 = 0;
    var observed_unsubmitted_cancelled: u64 = 0;
    for (events) |event| {
        has_pool_exclusive = has_pool_exclusive or
            event.task_class == .pool_exclusive;
        queue_wait_ns = try checkedAdd(queue_wait_ns, event.queue_wait_ns);
        admission_wait_ns = try checkedAdd(
            admission_wait_ns,
            event.admission_wait_ns,
        );
        resource_wait_ns = try checkedAdd(
            resource_wait_ns,
            event.resource_wait_ns,
        );
        worker_busy_ns = try checkedAdd(worker_busy_ns, event.run_ns);
        if (event.terminal_status == .completed) {
            useful_task_work_ns = try checkedAdd(
                useful_task_work_ns,
                event.run_ns,
            );
            if (event.parallel_eligible and event.ready_ns != null) {
                parallel_eligible_ns = try checkedAdd(
                    parallel_eligible_ns,
                    event.run_ns,
                );
            }
        }
        total_work_estimate = try checkedAdd(
            total_work_estimate,
            event.work_estimate,
        );
        completed_rows = try checkedAdd(completed_rows, event.completed_rows);
        completed_tiles = try checkedAdd(completed_tiles, event.completed_tiles);
        if (event.cancellation_requested_ns) |timestamp| {
            cancellation_requested_ns = timestamp;
        }
        if (event.finish_ns) |timestamp| latest_finish_ns = @max(
            latest_finish_ns,
            timestamp,
        );
        if (event.submitted) {
            observed_submitted = try checkedAdd(observed_submitted, 1);
            if (event.started) observed_started = try checkedAdd(observed_started, 1);
            if (event.finished) {
                observed_finished_submitted = try checkedAdd(
                    observed_finished_submitted,
                    1,
                );
            }
            switch (event.terminal_status) {
                .completed => observed_completed = try checkedAdd(observed_completed, 1),
                .failed => observed_failed = try checkedAdd(observed_failed, 1),
                .cancelled => observed_cancelled = try checkedAdd(observed_cancelled, 1),
            }
        } else if (event.terminal_status == .cancelled) {
            observed_unsubmitted_cancelled = try checkedAdd(
                observed_unsubmitted_cancelled,
                1,
            );
        } else {
            return error.InvalidTaskProfileAccounting;
        }
    }
    if (observed_submitted != try castU64(accounting.submitted_tasks) or
        observed_started != try castU64(accounting.started_tasks) or
        observed_finished_submitted != try castU64(accounting.finished_tasks) or
        observed_completed != try castU64(accounting.completed_tasks) or
        observed_failed != try castU64(accounting.failed_tasks) or
        observed_cancelled != try castU64(accounting.cancelled_tasks) or
        observed_unsubmitted_cancelled !=
            try castU64(accounting.unsubmitted_cancelled_tasks))
    {
        return error.InvalidTaskProfileAccounting;
    }
    const cancellation_latency_ns = if (cancellation_requested_ns) |requested|
        try checkedElapsed(requested, latest_finish_ns)
    else
        null;
    return .{
        .requested_workers = try castU32(accounting.requested_workers),
        .admitted_workers = try castU32(accounting.admitted_workers),
        .pool_capacity = try castU32(accounting.pool_capacity),
        .worker_stack_bytes = try castU64(accounting.worker_stack_bytes),
        .peak_active_tasks = try castU32(accounting.peak_active_tasks),
        .peak_active_workers = if (has_pool_exclusive)
            null
        else
            try castU32(accounting.peak_active_tasks),
        .planned_tasks = try castU64(accounting.planned_tasks),
        .submitted_tasks = try castU64(accounting.submitted_tasks),
        .completed_tasks = try castU64(accounting.completed_tasks),
        .failed_tasks = try castU64(accounting.failed_tasks),
        .cancelled_tasks = try castU64(accounting.cancelled_tasks),
        .unsubmitted_cancelled_tasks = try castU64(
            accounting.unsubmitted_cancelled_tasks,
        ),
        .started_tasks = try castU64(accounting.started_tasks),
        .finished_tasks = try castU64(accounting.finished_tasks),
        .duplicate_starts = try castU64(accounting.duplicate_starts),
        .duplicate_finishes = try castU64(accounting.duplicate_finishes),
        .useful_task_work_ns = useful_task_work_ns,
        .queue_wait_ns = queue_wait_ns,
        .admission_wait_ns = admission_wait_ns,
        .resource_wait_ns = resource_wait_ns,
        .task_run_ns = worker_busy_ns,
        .worker_busy_ns = if (has_pool_exclusive) null else worker_busy_ns,
        .worker_capacity_ns = try checkedMul(
            try castU64(accounting.admitted_workers),
            graph_elapsed_ns,
        ),
        .graph_elapsed_ns = graph_elapsed_ns,
        .parallel_eligible_ns = parallel_eligible_ns,
        .cancellation_latency_ns = cancellation_latency_ns,
        .peak_reserved_bytes = try castU64(accounting.peak_reserved_bytes),
        .total_work_estimate = total_work_estimate,
        .completed_rows = completed_rows,
        .completed_tiles = completed_tiles,
        .scheduler = .central_queue_no_steal,
        .steal_count = 0,
    };
}

fn validateAccounting(accounting: Accounting) !void {
    try validateConfiguration(
        accounting.requested_workers,
        accounting.admitted_workers,
        accounting.pool_capacity,
    );
    if (accounting.peak_active_tasks > accounting.admitted_workers or
        accounting.duplicate_starts != 0 or
        accounting.duplicate_finishes != 0)
    {
        return error.InvalidTaskProfileAccounting;
    }
    const completed_or_failed = try checkedAdd(
        try castU64(accounting.completed_tasks),
        try castU64(accounting.failed_tasks),
    );
    const all_submitted_outcomes = try checkedAdd(
        completed_or_failed,
        try castU64(accounting.cancelled_tasks),
    );
    const started = try castU64(accounting.started_tasks);
    if (started < completed_or_failed or
        started - completed_or_failed > try castU64(accounting.cancelled_tasks))
    {
        return error.InvalidTaskProfileAccounting;
    }
    if (try castU64(accounting.submitted_tasks) != all_submitted_outcomes or
        try castU64(accounting.planned_tasks) != try checkedAdd(
            try castU64(accounting.submitted_tasks),
            try castU64(accounting.unsubmitted_cancelled_tasks),
        ) or
        accounting.finished_tasks != accounting.submitted_tasks)
    {
        return error.InvalidTaskProfileAccounting;
    }
}

fn profileKey(key: anytype) wire.TaskKey {
    return .{
        .epoch = key.epoch,
        .stage_rank = key.stage_rank,
        .component_registry_index = key.component_registry_index,
        .shard_or_chunk_index = key.shard_or_chunk_index,
    };
}

fn profileClass(class: anytype) wire.TaskClass {
    return switch (class) {
        .leaf => .leaf,
        .pool_exclusive => .pool_exclusive,
        .coordinator => .coordinator,
    };
}

fn castU64(value: usize) !u64 {
    return std.math.cast(u64, value) orelse
        error.TaskProfileCounterOverflow;
}

fn castU32(value: usize) !u32 {
    return std.math.cast(u32, value) orelse
        error.TaskProfileCounterOverflow;
}

pub fn checkedElapsed(start_ns: u64, finish_ns: u64) !u64 {
    if (finish_ns < start_ns) return error.TaskProfileClockRegression;
    return finish_ns - start_ns;
}

pub fn checkedAdd(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch
        error.TaskProfileCounterOverflow;
}

pub fn checkedMul(lhs: u64, rhs: u64) !u64 {
    return std.math.mul(u64, lhs, rhs) catch
        error.TaskProfileCounterOverflow;
}
