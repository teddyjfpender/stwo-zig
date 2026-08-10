//! Exact-capacity task graph for structured prover concurrency.
//!
//! Planning is serial and fallible. Execution performs no graph allocation,
//! launches at most one admitted worker wave, joins every launched task, and
//! reports the lowest `TaskKey` failure independent of completion order.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const work_pool = @import("work_pool.zig");
const task_context = @import("task_graph_context.zig");
const task_graph_execution = @import("task_graph_execution.zig");
const task_graph_profile = @import("task_graph_profile.zig");
const task_resources = @import("task_graph_resources.zig");

const stage_profile = prover_api.stage_profile;

pub const MAX_TASKS: usize = 32;
pub const MAX_COMPONENT_TASKS = task_context.MAX_COMPONENT_TASKS;
pub const MAX_DEPS_PER_TASK: usize = 8;

/// Compatibility identifier for the original 32-slot graph.
pub const TaskId = u8;
pub const ComponentTaskId = task_context.ComponentTaskId;

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

pub const WorkUnit = task_context.WorkUnit;

pub const ContributionRole = prover_api.task_profile.ContributionRole;

/// Pre-launch semantic attribution for one component touched by a physical
/// task. Completion is derived from the task's terminal lifecycle; producers
/// cannot publish an optimistic completion value here.
pub const TaskContributionPlan = struct {
    component_registry_index: u32,
    /// Borrowed until the recorder is destroyed or its final snapshot has
    /// deep-copied the string.
    component_kind: []const u8,
    role: ContributionRole,
    work_estimate: u64 = 0,
    planned_rows: u64 = 0,
    planned_tiles: u64 = 0,
};

pub const ComponentTaskSpec = struct {
    key: TaskKey,
    name: []const u8,
    /// Stable borrowed identifiers. When profiling is enabled their storage
    /// must outlive the recorder or its final task snapshot.
    stage_id: []const u8 = "component_task_graph",
    component_kind: []const u8 = "unspecified",
    func: ComponentTaskFn,
    context: *anyopaque,
    class: TaskClass = .leaf,
    parallel_eligible: ?bool = null,
    deps: []const ComponentTaskId = &.{},
    resources: ResourceReservation = .{},
    work_estimate: u64 = 0,
    work_unit: WorkUnit = .unspecified,
    planned_work_units: u64 = 0,
    /// `null` selects the compatibility attribution path. An explicit graph
    /// must provide a non-null slice for every task; an empty slice is valid
    /// for a physical coordination lane with no semantic component work. The
    /// slice backing store must remain alive until `execute` returns.
    contributions: ?[]const TaskContributionPlan = null,
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
    /// Optional flat capture. A reservation is acquired only after resource
    /// validation and pool admission have succeeded.
    task_profile_recorder: ?*stage_profile.Recorder = null,
    /// Stable borrowed identifier with the same lifetime as the recorder or
    /// its final task snapshot.
    task_profile_graph_id: []const u8 = "component_task_graph",
    requested_worker_count: ?usize = null,
    pool_capacity: ?usize = null,
    /// Injectable only for deterministic clock tests.
    task_profile_clock: ?task_graph_profile.ClockSource = null,
};

pub const ExecutionReport = struct {
    configured_workers: usize,
    admitted_worker_stack_bytes: usize,
    admitted_submission_bytes: usize,
    fixed_resident_bytes: usize,
    submitted_tasks: usize,
    succeeded_tasks: usize,
    failed_tasks: usize,
    /// Submitted tasks cancelled either before callback start or cooperatively
    /// after a running callback observes the graph cancellation token.
    cancelled_tasks: usize,
    /// Planned tasks cancelled without submission after a sibling failure.
    unsubmitted_cancelled_tasks: usize,
    started_tasks: usize,
    finished_tasks: usize,
    /// Peak concurrent top-level graph callbacks. Nested pool-exclusive helper
    /// activity is deliberately not relabelled as a graph task.
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
    stage_id: []const u8,
    component_kind: []const u8,
    func: ComponentTaskFn,
    context: *anyopaque,
    class: TaskClass,
    parallel_eligible: bool,
    deps: [MAX_DEPS_PER_TASK]ComponentTaskId = .{0} ** MAX_DEPS_PER_TASK,
    n_deps: u8 = 0,
    resources: ResourceReservation,
    work_estimate: u64,
    work_unit: WorkUnit,
    planned_work_units: u64,
    contributions: ?[]const TaskContributionPlan,
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
    active_capture: ?*task_graph_profile.Capture = null,

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
            .stage_id = spec.stage_id,
            .component_kind = spec.component_kind,
            .func = spec.func,
            .context = spec.context,
            .class = spec.class,
            .parallel_eligible = spec.parallel_eligible orelse
                (spec.class != .coordinator),
            .resources = spec.resources,
            .work_estimate = spec.work_estimate,
            .work_unit = spec.work_unit,
            .planned_work_units = spec.planned_work_units,
            .contributions = spec.contributions,
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
        return task_graph_execution.execute(self, options);
    }
};

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
