//! Stable flat task telemetry for bounded prover graphs.
//!
//! The executor owns clocks and writes each preassigned event slot. This
//! module only reserves exact storage, publishes it after the executor has
//! joined every task, and produces deep-owned snapshots.

const std = @import("std");

/// Version of the flat task-profile schema. This is intentionally independent
/// from `stage_profile.SCHEMA_VERSION`.
pub const TASK_PROFILE_SCHEMA_VERSION: u32 = 1;

pub const MAX_DEPENDENCIES: usize = 8;

pub const SchedulerKind = enum {
    central_queue_no_steal,
};

pub const TaskClass = enum {
    leaf,
    pool_exclusive,
    coordinator,
};

pub const WorkerKind = enum {
    coordinator,
    helper,
};

pub const TerminalStatus = enum {
    completed,
    failed,
    cancelled,
};

pub const CancellationReason = enum {
    sibling_failure,
    request_cancelled,
};

/// Stable task identity. Lexicographic order is the canonical event order.
pub const TaskKey = struct {
    epoch: u16 = 0,
    stage_rank: u16 = 0,
    component_registry_index: u32 = 0,
    shard_or_chunk_index: u32 = 0,

    pub fn lessThan(lhs: TaskKey, rhs: TaskKey) bool {
        if (lhs.epoch != rhs.epoch) return lhs.epoch < rhs.epoch;
        if (lhs.stage_rank != rhs.stage_rank) return lhs.stage_rank < rhs.stage_rank;
        if (lhs.component_registry_index != rhs.component_registry_index) {
            return lhs.component_registry_index < rhs.component_registry_index;
        }
        return lhs.shard_or_chunk_index < rhs.shard_or_chunk_index;
    }

    pub fn eql(lhs: TaskKey, rhs: TaskKey) bool {
        return lhs.epoch == rhs.epoch and
            lhs.stage_rank == rhs.stage_rank and
            lhs.component_registry_index == rhs.component_registry_index and
            lhs.shard_or_chunk_index == rhs.shard_or_chunk_index;
    }
};

/// The five disjoint resource classes required by ADR-0027.
pub const ByteClasses = struct {
    final_output_bytes: u64 = 0,
    exclusive_scratch_bytes: u64 = 0,
    shared_resident_bytes: u64 = 0,
    device_resident_bytes: u64 = 0,
    worker_stack_bytes: u64 = 0,
};

/// One terminal event. All nanoseconds are raw integers in one monotonic
/// request-local clock domain supplied by the executor.
///
/// String fields are borrowed while an event is pending or recorder-resident.
/// `Recorder.snapshot` duplicates them into the returned owned profile.
pub const TaskEvent = struct {
    key: TaskKey = .{},
    stage_id: []const u8 = "",
    component_kind: []const u8 = "",
    task_class: TaskClass = .leaf,
    dependencies: [MAX_DEPENDENCIES]TaskKey = [_]TaskKey{.{}} ** MAX_DEPENDENCIES,
    dependency_count: u8 = 0,
    parallel_eligible: bool = false,

    submitted: bool = false,
    started: bool = false,
    finished: bool = false,
    submitted_ns: ?u64 = null,
    ready_ns: ?u64 = null,
    start_ns: ?u64 = null,
    cancellation_requested_ns: ?u64 = null,
    finish_ns: ?u64 = null,

    configured_workers: u32 = 0,
    worker_slot: ?u32 = null,
    worker_kind: ?WorkerKind = null,
    /// Time from dependency readiness until submission/admission.
    admission_wait_ns: u64 = 0,
    /// Time from submission until task start (or terminal cancellation).
    queue_wait_ns: u64 = 0,
    run_ns: u64 = 0,
    resource_wait_ns: u64 = 0,
    bytes: ByteClasses = .{},

    terminal_status: TerminalStatus = .cancelled,
    error_name: ?[]const u8 = null,
    cancellation_winner: ?TaskKey = null,
    cancellation_reason: ?CancellationReason = null,
    cleanup_complete: bool = false,

    work_estimate: u64 = 0,
    planned_rows: u64 = 0,
    planned_tiles: u64 = 0,
    completed_rows: u64 = 0,
    completed_tiles: u64 = 0,

    pub fn dependencySlice(self: *const TaskEvent) []const TaskKey {
        return self.dependencies[0..self.dependency_count];
    }
};

/// Raw per-component totals; presentation layers may derive ratios from these
/// integers, but floating-point values are never task-profile authority.
pub const ComponentWork = struct {
    component_registry_index: u32 = 0,
    component_kind: []const u8 = "",
    task_count: u64 = 0,
    work_estimate: u64 = 0,
    completed_rows: u64 = 0,
    completed_tiles: u64 = 0,
    run_ns: u64 = 0,
};

/// Raw integer summary for one joined graph execution.
pub const RequestSummary = struct {
    requested_workers: u32 = 0,
    admitted_workers: u32 = 0,
    pool_capacity: u32 = 0,
    worker_stack_bytes: u64 = 0,
    /// Exact concurrency of outer task callbacks.
    peak_active_tasks: u32 = 0,
    /// Exact physical-worker concurrency when observable. This is absent for
    /// graphs with uninstrumented `pool_exclusive` child work; an occupied
    /// lease width is not relabelled as an observed peak.
    peak_active_workers: ?u32 = null,

    planned_tasks: u64 = 0,
    submitted_tasks: u64 = 0,
    completed_tasks: u64 = 0,
    failed_tasks: u64 = 0,
    cancelled_tasks: u64 = 0,
    unsubmitted_cancelled_tasks: u64 = 0,
    started_tasks: u64 = 0,
    finished_tasks: u64 = 0,
    duplicate_starts: u64 = 0,
    duplicate_finishes: u64 = 0,

    useful_task_work_ns: u64 = 0,
    /// Longest dependency path for a fully completed graph. Failed,
    /// cancelled, incomplete, or clock-invalid graphs leave this absent rather
    /// than presenting an executed prefix as the graph's critical path.
    critical_path_ns: ?u64 = null,
    admission_wait_ns: u64 = 0,
    queue_wait_ns: u64 = 0,
    resource_wait_ns: u64 = 0,
    /// Sum of outer task callback run intervals, including failed work.
    task_run_ns: u64 = 0,
    /// Aggregate physical-worker busy time when observable. This is absent
    /// when nested child work is not instrumented exactly.
    worker_busy_ns: ?u64 = null,
    worker_capacity_ns: u64 = 0,
    /// Time from this graph capture's monotonic origin through its joined
    /// terminal state. Full proof-and-verification request duration belongs to
    /// the outer performance receipt and must not be inferred from this value.
    graph_elapsed_ns: u64 = 0,
    parallel_eligible_ns: u64 = 0,
    cancellation_latency_ns: ?u64 = null,
    peak_reserved_bytes: u64 = 0,

    total_work_estimate: u64 = 0,
    completed_rows: u64 = 0,
    completed_tiles: u64 = 0,
    scheduler: SchedulerKind = .central_queue_no_steal,
    steal_count: u64 = 0,
};

pub const GraphHeader = struct {
    graph_id: []const u8,
};

/// Deep-owned graph in a `TaskProfile` snapshot.
pub const GraphRecord = struct {
    graph_id: []const u8,
    events: []TaskEvent,
    component_work: []ComponentWork,
    summary: RequestSummary,

    pub fn deinit(self: *GraphRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.graph_id);
        for (self.events) |event| {
            allocator.free(event.stage_id);
            allocator.free(event.component_kind);
            if (event.error_name) |name| allocator.free(name);
        }
        allocator.free(self.events);
        for (self.component_work) |component| {
            allocator.free(component.component_kind);
        }
        allocator.free(self.component_work);
        self.* = undefined;
    }
};

/// Deep-owned flat profile. Call `deinit` with the snapshot allocator.
pub const TaskProfile = struct {
    schema_version: u32 = TASK_PROFILE_SCHEMA_VERSION,
    runtime: []const u8,
    example: []const u8,
    graphs: []GraphRecord,

    pub fn deinit(self: *TaskProfile, allocator: std.mem.Allocator) void {
        allocator.free(self.runtime);
        allocator.free(self.example);
        for (self.graphs) |*graph| graph.deinit(allocator);
        allocator.free(self.graphs);
        self.* = undefined;
    }
};

const StoredGraph = struct {
    graph_id: []const u8,
    events: []TaskEvent,
    component_work: []ComponentWork,
    summary: RequestSummary,

    fn deinit(self: *StoredGraph, allocator: std.mem.Allocator) void {
        allocator.free(self.events);
        allocator.free(self.component_work);
        self.* = undefined;
    }
};

/// Move-only exact-capacity reservation. The executor may assign one unique
/// slot to each task, but must join all tasks before either publishing or
/// calling `deinit`. `deinit` is a no-op after successful publication.
pub const PendingGraph = struct {
    recorder: *Recorder,
    events: []TaskEvent,
    component_work: []ComponentWork,
    active: bool = true,

    pub fn deinit(self: *PendingGraph) void {
        if (!self.active) return;
        std.debug.assert(self.recorder.reservation_active);
        self.recorder.allocator.free(self.events);
        self.recorder.allocator.free(self.component_work);
        self.recorder.reservation_active = false;
        self.events = &.{};
        self.component_work = &.{};
        self.active = false;
    }
};

/// Coordinator-owned recorder. It contains no clock and exposes no event
/// mutation method. Reservation is fallible before launch; publication after
/// join is an allocation-free ownership move.
pub const Recorder = struct {
    allocator: std.mem.Allocator,
    runtime: []const u8,
    example: []const u8,
    graphs: std.ArrayList(StoredGraph),
    reservation_active: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        runtime: []const u8,
        example: []const u8,
    ) Recorder {
        return .{
            .allocator = allocator,
            .runtime = runtime,
            .example = example,
            .graphs = .empty,
        };
    }

    pub fn deinit(self: *Recorder) void {
        std.debug.assert(!self.reservation_active);
        for (self.graphs.items) |*graph| graph.deinit(self.allocator);
        self.graphs.deinit(self.allocator);
        self.* = undefined;
    }

    /// Reserves all mutable graph storage and the recorder append slot before
    /// any task launches. Only one graph reservation may be active at a time.
    pub fn reserveTaskGraph(
        self: *Recorder,
        event_count: usize,
        component_work_count: usize,
    ) !PendingGraph {
        if (self.reservation_active) return error.TaskGraphReservationActive;
        try self.graphs.ensureUnusedCapacity(self.allocator, 1);

        const events = try self.allocator.alloc(TaskEvent, event_count);
        errdefer self.allocator.free(events);
        @memset(events, .{});

        const component_work = try self.allocator.alloc(ComponentWork, component_work_count);
        errdefer self.allocator.free(component_work);
        @memset(component_work, .{});

        self.reservation_active = true;
        return .{
            .recorder = self,
            .events = events,
            .component_work = component_work,
        };
    }

    /// Publishes a fully joined reservation without allocation or copying.
    /// Header and event strings remain borrowed until this recorder is
    /// destroyed; snapshots duplicate them.
    pub fn publishTaskGraphAfterJoin(
        self: *Recorder,
        pending: *PendingGraph,
        header: GraphHeader,
        summary: RequestSummary,
    ) void {
        std.debug.assert(pending.active);
        std.debug.assert(pending.recorder == self);
        std.debug.assert(self.reservation_active);
        std.debug.assert(summary.planned_tasks == pending.events.len);
        std.debug.assert(summary.scheduler == .central_queue_no_steal);
        std.debug.assert(summary.steal_count == 0);

        self.graphs.appendAssumeCapacity(.{
            .graph_id = header.graph_id,
            .events = pending.events,
            .component_work = pending.component_work,
            .summary = summary,
        });
        self.reservation_active = false;
        pending.events = &.{};
        pending.component_work = &.{};
        pending.active = false;
    }

    pub fn snapshot(self: *const Recorder, allocator: std.mem.Allocator) !TaskProfile {
        std.debug.assert(!self.reservation_active);
        const runtime = try allocator.dupe(u8, self.runtime);
        errdefer allocator.free(runtime);
        const example = try allocator.dupe(u8, self.example);
        errdefer allocator.free(example);
        return .{
            .runtime = runtime,
            .example = example,
            .graphs = try snapshotGraphs(allocator, self.graphs.items),
        };
    }
};

fn snapshotGraphs(
    allocator: std.mem.Allocator,
    source: []const StoredGraph,
) ![]GraphRecord {
    const graphs = try allocator.alloc(GraphRecord, source.len);
    errdefer allocator.free(graphs);
    var initialized: usize = 0;
    errdefer for (graphs[0..initialized]) |*graph| graph.deinit(allocator);

    for (source, graphs) |stored, *graph| {
        graph.* = try snapshotGraph(allocator, stored);
        initialized += 1;
    }
    return graphs;
}

fn snapshotGraph(allocator: std.mem.Allocator, source: StoredGraph) !GraphRecord {
    const graph_id = try allocator.dupe(u8, source.graph_id);
    errdefer allocator.free(graph_id);

    const events = try allocator.alloc(TaskEvent, source.events.len);
    errdefer allocator.free(events);
    var initialized_events: usize = 0;
    errdefer {
        for (events[0..initialized_events]) |event| {
            allocator.free(event.stage_id);
            allocator.free(event.component_kind);
            if (event.error_name) |name| allocator.free(name);
        }
    }
    for (source.events, events) |event, *owned| {
        owned.* = event;
        owned.stage_id = try allocator.dupe(u8, event.stage_id);
        errdefer allocator.free(owned.stage_id);
        owned.component_kind = try allocator.dupe(u8, event.component_kind);
        errdefer allocator.free(owned.component_kind);
        owned.error_name = if (event.error_name) |name|
            try allocator.dupe(u8, name)
        else
            null;
        initialized_events += 1;
    }

    const components = try allocator.alloc(ComponentWork, source.component_work.len);
    errdefer allocator.free(components);
    var initialized_components: usize = 0;
    errdefer {
        for (components[0..initialized_components]) |component| {
            allocator.free(component.component_kind);
        }
    }
    for (source.component_work, components) |component, *owned| {
        owned.* = component;
        owned.component_kind = try allocator.dupe(u8, component.component_kind);
        initialized_components += 1;
    }

    return .{
        .graph_id = graph_id,
        .events = events,
        .component_work = components,
        .summary = source.summary,
    };
}

test "task profile: reservation publishes by move and snapshot owns strings" {
    const allocator = std.testing.allocator;
    var recorder = Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var pending = try recorder.reserveTaskGraph(1, 1);
    defer pending.deinit();
    pending.events[0] = .{
        .key = .{ .epoch = 1, .stage_rank = 2, .component_registry_index = 3 },
        .stage_id = "composition",
        .component_kind = "opcode",
        .parallel_eligible = true,
        .submitted = true,
        .started = true,
        .finished = true,
        .ready_ns = 10,
        .submitted_ns = 11,
        .start_ns = 12,
        .finish_ns = 20,
        .configured_workers = 4,
        .worker_slot = 1,
        .worker_kind = .helper,
        .admission_wait_ns = 1,
        .queue_wait_ns = 1,
        .run_ns = 8,
        .terminal_status = .completed,
        .cleanup_complete = true,
        .work_estimate = 16,
        .planned_rows = 16,
        .completed_rows = 16,
    };
    pending.component_work[0] = .{
        .component_registry_index = 3,
        .component_kind = "opcode",
        .task_count = 1,
        .work_estimate = 16,
        .completed_rows = 16,
        .run_ns = 8,
    };
    const event_address = @intFromPtr(pending.events.ptr);
    recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "composition" }, .{
        .requested_workers = 4,
        .admitted_workers = 4,
        .pool_capacity = 4,
        .peak_active_tasks = 1,
        .peak_active_workers = 1,
        .planned_tasks = 1,
        .submitted_tasks = 1,
        .completed_tasks = 1,
        .started_tasks = 1,
        .finished_tasks = 1,
        .useful_task_work_ns = 8,
        .admission_wait_ns = 1,
        .queue_wait_ns = 1,
        .task_run_ns = 8,
        .worker_busy_ns = 8,
        .worker_capacity_ns = 32,
        .graph_elapsed_ns = 20,
        .parallel_eligible_ns = 8,
        .total_work_estimate = 16,
        .completed_rows = 16,
    });
    try std.testing.expect(!pending.active);
    try std.testing.expectEqual(event_address, @intFromPtr(recorder.graphs.items[0].events.ptr));

    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    try std.testing.expectEqual(TASK_PROFILE_SCHEMA_VERSION, profile.schema_version);
    try std.testing.expectEqualStrings("zig", profile.runtime);
    try std.testing.expectEqualStrings("riscv", profile.example);
    try std.testing.expectEqual(@as(usize, 1), profile.graphs.len);
    try std.testing.expectEqualStrings("composition", profile.graphs[0].graph_id);
    try std.testing.expectEqualStrings("opcode", profile.graphs[0].events[0].component_kind);
    try std.testing.expectEqual(@as(u64, 16), profile.graphs[0].events[0].planned_rows);
    try std.testing.expectEqual(@as(u64, 1), profile.graphs[0].summary.admission_wait_ns);
    try std.testing.expectEqual(@as(u64, 16), profile.graphs[0].summary.total_work_estimate);
}

test "task profile: abort releases exact reservation" {
    const allocator = std.testing.allocator;
    var recorder = Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var pending = try recorder.reserveTaskGraph(2, 0);
    pending.deinit();
    try std.testing.expect(!recorder.reservation_active);

    var replacement = try recorder.reserveTaskGraph(0, 0);
    defer replacement.deinit();
}

test "task profile: reservation and snapshot clean up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseAllocationFailureCleanup,
        .{},
    );
}

fn exerciseAllocationFailureCleanup(allocator: std.mem.Allocator) !void {
    var recorder = Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var pending = try recorder.reserveTaskGraph(2, 1);
    defer pending.deinit();
    pending.events[0].stage_id = "composition";
    pending.events[0].component_kind = "opcode";
    pending.events[1].stage_id = "composition";
    pending.events[1].component_kind = "table";
    pending.component_work[0].component_kind = "mixed";
    recorder.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "composition" },
        .{ .planned_tasks = 2 },
    );

    var snapshot = try recorder.snapshot(allocator);
    defer snapshot.deinit(allocator);
}
