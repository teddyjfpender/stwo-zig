//! Exact-capacity task graph for structured prover concurrency.
//!
//! Planning is serial and fallible. Execution performs no graph allocation,
//! launches at most one admitted worker wave, joins every launched task, and
//! reports the lowest `TaskKey` failure independent of completion order.

const std = @import("std");
const work_pool = @import("work_pool.zig");
const task_context = @import("task_graph_context.zig");
const task_resources = @import("task_graph_resources.zig");

pub const MAX_TASKS: usize = 32;
pub const MAX_COMPONENT_TASKS: usize = 1024;
pub const MAX_DEPS_PER_TASK: usize = 8;

/// Compatibility identifier for the original 32-slot graph.
pub const TaskId = u8;
pub const ComponentTaskId = u16;

pub const TaskStatus = enum {
    pending,
    ready,
    running,
    done,
    failed,
    cancelled,
};

pub const TaskClass = task_context.TaskClass;
pub const TaskKey = task_context.TaskKey;
pub const CancellationToken = task_context.CancellationToken;
pub const TaskContext = task_context.TaskContext;
pub const ResourceReservation = task_resources.ResourceReservation;
pub const checkedWorkEstimate = task_resources.checkedWorkEstimate;

pub const ComponentTaskFn = *const fn (context: *TaskContext) anyerror!void;

pub const ComponentTaskSpec = struct {
    key: TaskKey,
    name: []const u8,
    func: ComponentTaskFn,
    context: *anyopaque,
    class: TaskClass = .leaf,
    deps: []const ComponentTaskId = &.{},
    resources: ResourceReservation = .{},
    work_estimate: u64 = 0,
};

pub const ReadyPolicy = enum {
    critical_path,
    canonical,
};

pub const ExecuteOptions = struct {
    worker_budget: work_pool.WorkerBudget = work_pool.WorkerBudget.serial(),
    pool: ?*work_pool.WorkPool = null,
    byte_budget: usize = std.math.maxInt(usize),
    ready_policy: ReadyPolicy = .critical_path,
};

pub const ExecutionReport = struct {
    configured_workers: usize,
    admitted_worker_stack_bytes: usize,
    admitted_submission_bytes: usize,
    fixed_resident_bytes: usize,
    submitted_tasks: usize,
    succeeded_tasks: usize,
    failed_tasks: usize,
    /// Submitted tasks cancelled before their callback started.
    cancelled_tasks: usize,
    /// Planned tasks cancelled without submission after a sibling failure.
    unsubmitted_cancelled_tasks: usize,
    started_tasks: usize,
    finished_tasks: usize,
    peak_active_tasks: usize,
    peak_reserved_bytes: usize,
    cancellation_winner: ?TaskKey,
    duplicate_starts: usize,
    duplicate_finishes: usize,
};

pub const TaskTerminalMetadata = struct {
    key: TaskKey,
    name: []const u8,
    class: TaskClass,
    dependencies: [MAX_DEPS_PER_TASK]TaskKey,
    dependency_count: u8,
    remaining_dependency_level: u16,
    work_estimate: u64,
    resources: ResourceReservation,
    submitted: bool,
    started: bool,
    finished: bool,
    cleanup_complete: bool,
    terminal_status: TaskStatus,
    failure_name: ?[]const u8,
    cancellation_winner: ?TaskKey,
};

const ComponentTaskSlot = struct {
    key: TaskKey,
    name: []const u8,
    func: ComponentTaskFn,
    context: *anyopaque,
    class: TaskClass,
    deps: [MAX_DEPS_PER_TASK]ComponentTaskId = .{0} ** MAX_DEPS_PER_TASK,
    n_deps: u8 = 0,
    resources: ResourceReservation,
    work_estimate: u64,
    remaining_dependency_level: u16 = 0,
    status: TaskStatus = .pending,
    failure: ?anyerror = null,
    submitted: bool = false,
    started: bool = false,
    finished: bool = false,
    cleanup_complete: bool = false,
};

pub const ComponentTaskGraph = struct {
    allocator: std.mem.Allocator,
    slots: []ComponentTaskSlot,
    capacity: usize,
    count: usize = 0,
    executed: bool = false,
    ready_policy: ReadyPolicy = .critical_path,
    cancellation: CancellationToken = .{},
    cancellation_winner: std.atomic.Value(ComponentTaskId) =
        .init(std.math.maxInt(ComponentTaskId)),
    submitted: std.atomic.Value(usize) = .init(0),
    started: std.atomic.Value(usize) = .init(0),
    succeeded: std.atomic.Value(usize) = .init(0),
    failed: std.atomic.Value(usize) = .init(0),
    cancelled: std.atomic.Value(usize) = .init(0),
    unsubmitted_cancelled: std.atomic.Value(usize) = .init(0),
    finished: std.atomic.Value(usize) = .init(0),
    duplicate_starts: std.atomic.Value(usize) = .init(0),
    duplicate_finishes: std.atomic.Value(usize) = .init(0),
    active: std.atomic.Value(usize) = .init(0),
    peak_active: std.atomic.Value(usize) = .init(0),
    configured_workers: usize = 0,
    admitted_worker_stack_bytes: usize = 0,
    admitted_submission_bytes: usize = 0,
    fixed_resident_bytes: usize = 0,
    peak_reserved_bytes: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        capacity: usize,
    ) !ComponentTaskGraph {
        if (capacity > MAX_COMPONENT_TASKS) return error.InvalidTaskCapacity;
        return .{
            .allocator = allocator,
            .slots = try allocator.alloc(ComponentTaskSlot, capacity),
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *ComponentTaskGraph) void {
        std.debug.assert(self.active.load(.acquire) == 0);
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    /// Adds one task without allocating. Dependencies must refer to earlier
    /// task IDs, making cycles and forward references impossible by
    /// construction.
    pub fn addTask(
        self: *ComponentTaskGraph,
        spec: ComponentTaskSpec,
    ) !ComponentTaskId {
        if (self.executed) return error.TaskGraphAlreadyExecuted;
        if (self.count >= self.capacity) return error.TaskCapacityExceeded;
        if (spec.deps.len > MAX_DEPS_PER_TASK) {
            return error.TooManyDependencies;
        }
        if (self.count > std.math.maxInt(ComponentTaskId)) {
            return error.InvalidTaskCapacity;
        }

        for (self.slots[0..self.count]) |slot| {
            if (slot.key.eql(spec.key)) return error.DuplicateTaskKey;
        }

        const id: ComponentTaskId = @intCast(self.count);
        var slot = ComponentTaskSlot{
            .key = spec.key,
            .name = spec.name,
            .func = spec.func,
            .context = spec.context,
            .class = spec.class,
            .resources = spec.resources,
            .work_estimate = spec.work_estimate,
        };
        for (spec.deps, 0..) |dep, dep_index| {
            if (dep >= id) return error.InvalidDependency;
            for (spec.deps[0..dep_index]) |earlier| {
                if (earlier == dep) return error.DuplicateDependency;
            }
            slot.deps[dep_index] = dep;
        }
        slot.n_deps = @intCast(spec.deps.len);
        self.slots[self.count] = slot;
        self.count += 1;
        return id;
    }

    pub fn status(self: *const ComponentTaskGraph, id: ComponentTaskId) TaskStatus {
        std.debug.assert(id < self.count);
        return self.slots[id].status;
    }

    pub fn remainingLevel(
        self: *const ComponentTaskGraph,
        id: ComponentTaskId,
    ) u16 {
        std.debug.assert(id < self.count);
        return self.slots[id].remaining_dependency_level;
    }

    pub fn cancellationWinner(self: *const ComponentTaskGraph) ?TaskKey {
        const id = self.cancellation_winner.load(.acquire);
        if (id == std.math.maxInt(ComponentTaskId)) return null;
        return self.slots[id].key;
    }

    pub fn report(self: *const ComponentTaskGraph) ExecutionReport {
        return .{
            .configured_workers = self.configured_workers,
            .admitted_worker_stack_bytes = self.admitted_worker_stack_bytes,
            .admitted_submission_bytes = self.admitted_submission_bytes,
            .fixed_resident_bytes = self.fixed_resident_bytes,
            .submitted_tasks = self.submitted.load(.acquire),
            .succeeded_tasks = self.succeeded.load(.acquire),
            .failed_tasks = self.failed.load(.acquire),
            .cancelled_tasks = self.cancelled.load(.acquire),
            .unsubmitted_cancelled_tasks = self.unsubmitted_cancelled.load(.acquire),
            .started_tasks = self.started.load(.acquire),
            .finished_tasks = self.finished.load(.acquire),
            .peak_active_tasks = self.peak_active.load(.acquire),
            .peak_reserved_bytes = self.peak_reserved_bytes,
            .cancellation_winner = self.cancellationWinner(),
            .duplicate_starts = self.duplicate_starts.load(.acquire),
            .duplicate_finishes = self.duplicate_finishes.load(.acquire),
        };
    }

    /// Writes one deterministic flat record per task in ascending TaskKey
    /// order. The caller owns the exact-sized destination.
    pub fn writeTerminalMetadata(
        self: *const ComponentTaskGraph,
        out: []TaskTerminalMetadata,
    ) !void {
        if (out.len != self.count) return error.MetadataBufferSizeMismatch;
        var order: [MAX_COMPONENT_TASKS]ComponentTaskId = undefined;
        for (order[0..self.count], 0..) |*id, index| id.* = @intCast(index);
        std.sort.heap(
            ComponentTaskId,
            order[0..self.count],
            self,
            metadataLessThan,
        );

        const winner = self.cancellationWinner();
        for (order[0..self.count], out) |id, *metadata| {
            const slot = self.slots[id];
            var dependencies = [_]TaskKey{.{
                .epoch = 0,
                .stage_rank = 0,
                .component_registry_index = 0,
                .shard_or_chunk_index = 0,
            }} ** MAX_DEPS_PER_TASK;
            for (slot.deps[0..slot.n_deps], 0..) |dep, index| {
                dependencies[index] = self.slots[dep].key;
            }
            metadata.* = .{
                .key = slot.key,
                .name = slot.name,
                .class = slot.class,
                .dependencies = dependencies,
                .dependency_count = slot.n_deps,
                .remaining_dependency_level = slot.remaining_dependency_level,
                .work_estimate = slot.work_estimate,
                .resources = slot.resources,
                .submitted = slot.submitted,
                .started = slot.started,
                .finished = slot.finished,
                .cleanup_complete = slot.cleanup_complete,
                .terminal_status = slot.status,
                .failure_name = if (slot.failure) |failure|
                    @errorName(failure)
                else
                    null,
                .cancellation_winner = winner,
            };
        }
    }

    pub fn execute(
        self: *ComponentTaskGraph,
        options: ExecuteOptions,
    ) anyerror!ExecutionReport {
        if (self.executed) return error.TaskGraphAlreadyExecuted;
        if (self.count != self.capacity) return error.TaskCountMismatch;
        _ = try work_pool.WorkerBudget.init(options.worker_budget.count);
        if (options.worker_budget.count > 1 and options.pool == null) {
            return error.WorkPoolRequired;
        }
        const admission = try self.finalizePlan(options);

        var lease_storage: work_pool.WorkLease = undefined;
        const lease: ?*work_pool.WorkLease = if (options.pool) |pool| lease: {
            lease_storage = try pool.acquire(options.worker_budget);
            break :lease &lease_storage;
        } else null;
        defer if (lease) |active_lease| active_lease.deinit();

        self.executed = true;
        self.ready_policy = options.ready_policy;
        self.configured_workers = options.worker_budget.count;
        self.admitted_worker_stack_bytes = admission.worker_stack_bytes;
        self.admitted_submission_bytes = admission.submission_bytes;
        self.fixed_resident_bytes = admission.fixed_resident_bytes;
        self.peak_reserved_bytes = admission.baseline_bytes;
        if (self.count == 0) return self.report();

        while (self.terminalCount() < self.count) {
            if (self.cancellation.isCancelled()) {
                self.cancelQueued();
                break;
            }

            var ready: [MAX_COMPONENT_TASKS]ComponentTaskId = undefined;
            const ready_count = self.collectReady(&ready);
            if (ready_count == 0) {
                if (self.terminalCount() == self.count) break;
                return error.DeadlockDetected;
            }
            std.sort.heap(
                ComponentTaskId,
                ready[0..ready_count],
                self,
                readyLessThan,
            );

            var wave: [work_pool.MAX_WORKERS]ComponentTaskId = undefined;
            var wave_count: usize = 0;
            var scratch_bytes: usize = 0;
            const first = self.slots[ready[0]];
            if (first.class == .leaf) {
                for (ready[0..ready_count]) |id| {
                    const slot = self.slots[id];
                    if (slot.class != .leaf) continue;
                    if (wave_count == options.worker_budget.count) break;
                    if (slot.resources.exclusive_scratch_bytes >
                        admission.scratch_budget - scratch_bytes)
                    {
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
            self.peak_reserved_bytes = @max(
                self.peak_reserved_bytes,
                reserved_bytes,
            );

            try self.executeWave(
                wave[0..wave_count],
                options.worker_budget,
                lease,
            );
        }

        if (self.firstFailure()) |failure| return failure;
        return self.report();
    }

    fn finalizePlan(
        self: *ComponentTaskGraph,
        options: ExecuteOptions,
    ) !ResourceAdmission {
        var reverse_index = self.count;
        while (reverse_index > 0) {
            reverse_index -= 1;
            const id: ComponentTaskId = @intCast(reverse_index);
            var remaining_level: u16 = 0;
            for (self.slots[reverse_index + 1 ..]) |dependent| {
                var direct_dependent = false;
                for (dependent.deps[0..dependent.n_deps]) |dep| {
                    if (dep == id) {
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
            self.slots[reverse_index].remaining_dependency_level = remaining_level;
        }

        const stack_size = if (options.pool) |pool|
            pool.stackSize()
        else
            work_pool.WORKER_STACK_SIZE;
        var fixed_resident_bytes: usize = 0;
        for (self.slots) |slot| {
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
        for (self.slots) |slot| {
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
        self: *ComponentTaskGraph,
        ready: *[MAX_COMPONENT_TASKS]ComponentTaskId,
    ) usize {
        var ready_count: usize = 0;
        for (self.slots[0..self.count], 0..) |*slot, slot_index| {
            if (slot.status != .pending and slot.status != .ready) continue;
            var all_done = true;
            for (slot.deps[0..slot.n_deps]) |dep| {
                switch (self.slots[dep].status) {
                    .done => {},
                    .failed, .cancelled => {
                        slot.status = .cancelled;
                        all_done = false;
                        break;
                    },
                    else => all_done = false,
                }
            }
            if (slot.status == .cancelled or !all_done) continue;
            slot.status = .ready;
            ready[ready_count] = @intCast(slot_index);
            ready_count += 1;
        }
        return ready_count;
    }

    fn executeWave(
        self: *ComponentTaskGraph,
        ids: []const ComponentTaskId,
        budget: work_pool.WorkerBudget,
        lease: ?*work_pool.WorkLease,
    ) !void {
        std.debug.assert(ids.len > 0);
        std.debug.assert(ids.len <= budget.count);

        var envelopes: [work_pool.MAX_WORKERS]RunEnvelope = undefined;
        for (ids, 0..) |id, index| {
            const slot = &self.slots[id];
            slot.status = .running;
            std.debug.assert(!slot.submitted);
            slot.submitted = true;
            _ = self.submitted.fetchAdd(1, .monotonic);
            envelopes[index] = .{
                .graph = self,
                .id = id,
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
                    runEnvelope,
                    .{@as(*RunEnvelope, envelope)},
                );
            }
        }
        runEnvelope(&envelopes[0]);
        wait_group.wait();
        if (ids.len > 1) lease.?.completeWave();
    }

    fn terminalCount(self: *const ComponentTaskGraph) usize {
        var count: usize = 0;
        for (self.slots[0..self.count]) |slot| {
            switch (slot.status) {
                .done, .failed, .cancelled => count += 1,
                else => {},
            }
        }
        return count;
    }

    fn cancelQueued(self: *ComponentTaskGraph) void {
        for (self.slots[0..self.count]) |*slot| {
            if (slot.status == .pending or slot.status == .ready) {
                slot.status = .cancelled;
                slot.finished = true;
                slot.cleanup_complete = true;
                _ = self.unsubmitted_cancelled.fetchAdd(1, .monotonic);
            }
        }
    }

    fn firstFailure(self: *const ComponentTaskGraph) ?anyerror {
        var selected_key: ?TaskKey = null;
        var selected_error: ?anyerror = null;
        for (self.slots[0..self.count]) |slot| {
            const failure = slot.failure orelse continue;
            if (selected_key == null or slot.key.lessThan(selected_key.?)) {
                selected_key = slot.key;
                selected_error = failure;
            }
        }
        return selected_error;
    }
};

const ResourceAdmission = struct {
    fixed_resident_bytes: usize,
    worker_stack_bytes: usize,
    submission_bytes: usize,
    baseline_bytes: usize,
    scratch_budget: usize,
};

const RunEnvelope = struct {
    graph: *ComponentTaskGraph,
    id: ComponentTaskId,
    visible_budget: work_pool.WorkerBudget,
    exclusive_lease: ?*work_pool.WorkLease,
};

fn runEnvelope(envelope: *RunEnvelope) void {
    const graph = envelope.graph;
    const slot = &graph.slots[envelope.id];
    if (graph.cancellation.isCancelled()) {
        slot.status = .cancelled;
        slot.finished = true;
        slot.cleanup_complete = true;
        _ = graph.cancelled.fetchAdd(1, .monotonic);
        _ = graph.finished.fetchAdd(1, .release);
        return;
    }

    if (slot.started) {
        _ = graph.duplicate_starts.fetchAdd(1, .monotonic);
    }
    slot.started = true;
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
        _ = graph.finished.fetchAdd(1, .release);
    }

    var child_wait_group = std.Thread.WaitGroup{};
    var context = TaskContext{
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
    };
    var task_failure: ?anyerror = null;
    slot.func(&context) catch |failure| {
        task_failure = failure;
    };
    if (task_failure) |failure| {
        slot.failure = failure;
        slot.status = .failed;
        _ = graph.failed.fetchAdd(1, .monotonic);
        if (graph.cancellation.request()) {
            graph.cancellation_winner.store(envelope.id, .release);
        }
        // Children observe cancellation, and ownership remains live until join.
        context.joinChildren();
        return;
    }
    // The executor, not the callback, owns the final join on success too.
    context.joinChildren();
    slot.status = .done;
    _ = graph.succeeded.fetchAdd(1, .monotonic);
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

fn readyLessThan(
    graph: *ComponentTaskGraph,
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

fn metadataLessThan(
    graph: *const ComponentTaskGraph,
    lhs: ComponentTaskId,
    rhs: ComponentTaskId,
) bool {
    return graph.slots[lhs].key.lessThan(graph.slots[rhs].key);
}

// Compatibility surface ----------------------------------------------------

pub const TaskFn = *const fn (context: *anyopaque) anyerror!void;

pub const TaskDesc = struct {
    name: []const u8,
    func: TaskFn,
    context: *anyopaque,
    deps: [MAX_DEPS_PER_TASK]TaskId = .{0} ** MAX_DEPS_PER_TASK,
    n_deps: u8 = 0,
};

/// Original non-fallible builder retained for existing callers. Execution is
/// delegated to the structured graph with a one-worker budget.
pub const TaskGraph = struct {
    tasks: [MAX_TASKS]TaskDesc = undefined,
    status: [MAX_TASKS]TaskStatus = .{.pending} ** MAX_TASKS,
    n_tasks: usize = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TaskGraph {
        return .{ .allocator = allocator };
    }

    pub fn addTask(
        self: *TaskGraph,
        name: []const u8,
        func: TaskFn,
        context: *anyopaque,
    ) TaskId {
        if (self.n_tasks >= MAX_TASKS) @panic("task graph capacity exceeded");
        const id: TaskId = @intCast(self.n_tasks);
        self.tasks[id] = .{ .name = name, .func = func, .context = context };
        self.status[id] = .ready;
        self.n_tasks += 1;
        return id;
    }

    pub fn addTaskWithDeps(
        self: *TaskGraph,
        name: []const u8,
        func: TaskFn,
        context: *anyopaque,
        deps: []const TaskId,
    ) TaskId {
        if (self.n_tasks >= MAX_TASKS) @panic("task graph capacity exceeded");
        if (deps.len > MAX_DEPS_PER_TASK) @panic("too many task dependencies");
        const id: TaskId = @intCast(self.n_tasks);
        var desc = TaskDesc{ .name = name, .func = func, .context = context };
        for (deps, 0..) |dep, index| desc.deps[index] = dep;
        desc.n_deps = @intCast(deps.len);
        self.tasks[id] = desc;
        self.status[id] = .pending;
        self.n_tasks += 1;
        return id;
    }

    pub fn execute(self: *TaskGraph) !void {
        var graph = try ComponentTaskGraph.init(self.allocator, self.n_tasks);
        defer graph.deinit();

        for (self.tasks[0..self.n_tasks], 0..) |*desc, index| {
            var deps: [MAX_DEPS_PER_TASK]ComponentTaskId = undefined;
            for (desc.deps[0..desc.n_deps], 0..) |dep, dep_index| {
                deps[dep_index] = dep;
            }
            _ = graph.addTask(.{
                .key = .{
                    .epoch = 0,
                    .stage_rank = 0,
                    .component_registry_index = @intCast(index),
                    .shard_or_chunk_index = 0,
                },
                .name = desc.name,
                .func = LegacyAdapter.run,
                .context = @ptrCast(desc),
                .class = .coordinator,
                .deps = deps[0..desc.n_deps],
            }) catch return error.DeadlockDetected;
        }

        _ = graph.execute(.{ .ready_policy = .canonical }) catch {
            copyStatuses(self, &graph);
            return error.TaskFailed;
        };
        copyStatuses(self, &graph);
    }
};

const LegacyAdapter = struct {
    fn run(context: *TaskContext) !void {
        const desc: *TaskDesc = @ptrCast(@alignCast(context.user_context));
        try desc.func(desc.context);
    }
};

fn copyStatuses(legacy: *TaskGraph, graph: *const ComponentTaskGraph) void {
    for (graph.slots[0..graph.count], 0..) |slot, index| {
        legacy.status[index] = slot.status;
    }
}
