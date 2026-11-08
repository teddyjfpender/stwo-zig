//! Stable flat task telemetry for bounded prover graphs.
//!
//! The executor owns clocks and writes each preassigned event slot. This
//! module only reserves exact storage, publishes it after the executor has
//! joined every task, and produces deep-owned snapshots.

const std = @import("std");
const attribution = @import("task_profile_contributions.zig");

/// Version of the flat task-profile schema. This is intentionally independent
/// from `stage_profile.SCHEMA_VERSION`.
pub const TASK_PROFILE_SCHEMA_VERSION: u32 = 2;

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

/// The semantic relationship between a physical task and a registry
/// component. `exclusive` is reserved for lanes that execute exactly one
/// component, including graphs admitted through the v1-producer adapter.
pub const ContributionRole = attribution.Role;
pub const ContributionRange = attribution.Range;
pub const Contribution = attribution.Contribution;

/// Exact storage shape decided before any task launches.
pub const ReservationShape = struct {
    event_count: usize,
    contribution_count: usize,
    component_work_count: usize,
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
    contribution_range: ContributionRange = .{},

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

/// Semantic per-component totals derived from contributions at publication.
/// Physical run time remains exclusively event-owned and is intentionally not
/// attributed to components in a fused lane.
pub const ComponentWork = attribution.ComponentWork;

/// Raw integer summary for one joined graph execution.
pub const RequestSummary = struct {
    requested_workers: u32 = 0,
    admitted_workers: u32 = 0,
    pool_capacity: u32 = 0,
    worker_stack_bytes: u64 = 0,
    /// Exact concurrency of outer task callbacks.
    peak_active_tasks: u32 = 0,
    /// Exact physical-worker callback concurrency. Profiled pool-exclusive
    /// child work is observed at fixed-envelope callback boundaries.
    peak_active_workers: ?u32 = null,

    planned_tasks: u64 = 0,
    submitted_tasks: u64 = 0,
    completed_tasks: u64 = 0,
    failed_tasks: u64 = 0,
    /// Includes callbacks cancelled before start and running callbacks that
    /// cooperatively returned after observing graph cancellation.
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
    /// Aggregate physical-worker callback time: outer task run intervals plus
    /// exactly observed pool-exclusive child callback intervals.
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
    contributions: []Contribution,
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
        for (self.contributions) |contribution| {
            allocator.free(contribution.component_kind);
        }
        allocator.free(self.contributions);
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
    contributions: []Contribution,
    component_work: []ComponentWork,
    summary: RequestSummary,

    fn deinit(self: *StoredGraph, allocator: std.mem.Allocator) void {
        allocator.free(self.events);
        allocator.free(self.contributions);
        allocator.free(self.component_work);
        self.* = undefined;
    }
};

const ActiveReservation = struct {
    generation: u64,
    events: []TaskEvent,
    contributions: []Contribution,
    component_work: []ComponentWork,
    compatibility_one_contribution_per_event: bool,
};

// Recorder identities are assigned lazily on the cold reservation path. Zero
// remains the invalid identity carried by consumed handles.
var next_recorder_identity = std.atomic.Value(u64).init(1);

fn claimRecorderIdentity() !u64 {
    var candidate = next_recorder_identity.load(.monotonic);
    while (true) {
        if (candidate == std.math.maxInt(u64)) {
            return error.TaskGraphRecorderIdentityExhausted;
        }
        if (next_recorder_identity.cmpxchgWeak(
            candidate,
            candidate + 1,
            .monotonic,
            .monotonic,
        )) |observed| {
            candidate = observed;
        } else {
            return candidate;
        }
    }
}

/// Exact-capacity reservation capability. Zig values are copyable, so recorder
/// identity and generation -- not a handle-local boolean -- determine whether
/// this capability still owns the active allocation. The executor may assign
/// one unique slot to each task, but must join all tasks before publication or
/// abort. The recorder must outlive every handle copy.
pub const PendingGraph = struct {
    recorder: *Recorder,
    recorder_identity: u64,
    generation: u64,
    events: []TaskEvent,
    contributions: []Contribution,
    component_work: []ComponentWork,
    compatibility_one_contribution_per_event: bool,

    /// Aborts only when this handle is the recorder's current capability.
    /// Stale copies return an error and cannot free a later reservation.
    pub fn abort(self: *PendingGraph) !void {
        try self.recorder.abortTaskGraph(self);
    }

    pub fn deinit(self: *PendingGraph) void {
        self.abort() catch self.invalidate();
    }

    fn invalidate(self: *PendingGraph) void {
        self.recorder_identity = 0;
        self.generation = 0;
        self.events = &.{};
        self.contributions = &.{};
        self.component_work = &.{};
        self.compatibility_one_contribution_per_event = false;
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
    recorder_identity: u64 = 0,
    next_generation: u64 = 0,
    active_reservation: ?ActiveReservation = null,

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
        if (self.active_reservation) |active| {
            self.allocator.free(active.events);
            self.allocator.free(active.contributions);
            self.allocator.free(active.component_work);
        }
        for (self.graphs.items) |*graph| graph.deinit(self.allocator);
        self.graphs.deinit(self.allocator);
        self.* = undefined;
    }

    /// Compatibility reservation for schema-v1 producers. It pre-reserves one
    /// `.exclusive` contribution per event and synthesizes those contributions
    /// from the legacy event work fields at publication, without allocation.
    /// New semantic producers must call `reserveTaskGraphShape`.
    pub fn reserveTaskGraph(
        self: *Recorder,
        event_count: usize,
        component_work_count: usize,
    ) !PendingGraph {
        return self.reserveTaskGraphInternal(.{
            .event_count = event_count,
            .contribution_count = event_count,
            .component_work_count = component_work_count,
        }, true);
    }

    /// Reserves every graph-owned slice and the recorder append slot before
    /// launch. Only one graph reservation may be active at a time.
    pub fn reserveTaskGraphShape(
        self: *Recorder,
        shape: ReservationShape,
    ) !PendingGraph {
        return self.reserveTaskGraphInternal(shape, false);
    }

    fn reserveTaskGraphInternal(
        self: *Recorder,
        shape: ReservationShape,
        compatibility_one_contribution_per_event: bool,
    ) !PendingGraph {
        if (self.active_reservation != null) {
            return error.TaskGraphReservationActive;
        }
        if (shape.contribution_count > std.math.maxInt(u32)) {
            return error.TaskProfileContributionCountOverflow;
        }
        if (shape.component_work_count > shape.contribution_count) {
            return error.TaskProfileComponentWorkCountImpossible;
        }
        const generation = std.math.add(
            u64,
            self.next_generation,
            1,
        ) catch return error.TaskGraphReservationGenerationExhausted;
        if (self.recorder_identity == 0) {
            self.recorder_identity = try claimRecorderIdentity();
        }
        try self.graphs.ensureUnusedCapacity(self.allocator, 1);

        const events = try self.allocator.alloc(TaskEvent, shape.event_count);
        errdefer self.allocator.free(events);
        @memset(events, .{});

        const contributions = try self.allocator.alloc(
            Contribution,
            shape.contribution_count,
        );
        errdefer self.allocator.free(contributions);
        @memset(contributions, .{});

        const component_work = try self.allocator.alloc(
            ComponentWork,
            shape.component_work_count,
        );
        errdefer self.allocator.free(component_work);
        @memset(component_work, .{});

        self.next_generation = generation;
        self.active_reservation = .{
            .generation = generation,
            .events = events,
            .contributions = contributions,
            .component_work = component_work,
            .compatibility_one_contribution_per_event = compatibility_one_contribution_per_event,
        };
        return .{
            .recorder = self,
            .recorder_identity = self.recorder_identity,
            .generation = generation,
            .events = events,
            .contributions = contributions,
            .component_work = component_work,
            .compatibility_one_contribution_per_event = compatibility_one_contribution_per_event,
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
    ) !void {
        const active = try self.validatePending(pending);
        const event_count = std.math.cast(u64, active.events.len) orelse
            return error.TaskProfileTaskCountOverflow;
        if (summary.planned_tasks != event_count) {
            return error.TaskProfilePlannedTaskCountMismatch;
        }
        if (summary.scheduler != .central_queue_no_steal) {
            return error.TaskProfileUnsupportedScheduler;
        }
        if (summary.steal_count != 0) {
            return error.TaskProfileUnexpectedStealCount;
        }
        if (active.compatibility_one_contribution_per_event) {
            attribution.synthesizeCompatibility(active.events, active.contributions);
        }
        try attribution.deriveComponentWork(
            active.events,
            active.contributions,
            active.component_work,
        );

        self.graphs.appendAssumeCapacity(.{
            .graph_id = header.graph_id,
            .events = active.events,
            .contributions = active.contributions,
            .component_work = active.component_work,
            .summary = summary,
        });
        self.active_reservation = null;
        pending.invalidate();
    }

    pub fn snapshot(self: *const Recorder, allocator: std.mem.Allocator) !TaskProfile {
        if (self.active_reservation != null) {
            return error.TaskGraphReservationActive;
        }
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

    fn abortTaskGraph(self: *Recorder, pending: *PendingGraph) !void {
        const active = try self.validatePending(pending);
        self.allocator.free(active.events);
        self.allocator.free(active.contributions);
        self.allocator.free(active.component_work);
        self.active_reservation = null;
        pending.invalidate();
    }

    fn validatePending(
        self: *const Recorder,
        pending: *const PendingGraph,
    ) !ActiveReservation {
        if (pending.recorder != self) {
            return error.TaskGraphReservationWrongRecorder;
        }
        if (pending.recorder_identity == 0 or
            pending.recorder_identity != self.recorder_identity)
        {
            return error.TaskGraphReservationStale;
        }
        const active = self.active_reservation orelse
            return error.TaskGraphReservationStale;
        if (pending.generation == 0 or pending.generation != active.generation) {
            return error.TaskGraphReservationStale;
        }
        if (pending.events.ptr != active.events.ptr or
            pending.events.len != active.events.len or
            pending.contributions.ptr != active.contributions.ptr or
            pending.contributions.len != active.contributions.len or
            pending.component_work.ptr != active.component_work.ptr or
            pending.component_work.len != active.component_work.len or
            pending.compatibility_one_contribution_per_event !=
                active.compatibility_one_contribution_per_event)
        {
            return error.TaskGraphReservationStorageMismatch;
        }
        return active;
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

    const contributions = try allocator.alloc(Contribution, source.contributions.len);
    errdefer allocator.free(contributions);
    var initialized_contributions: usize = 0;
    errdefer {
        for (contributions[0..initialized_contributions]) |contribution| {
            allocator.free(contribution.component_kind);
        }
    }
    for (source.contributions, contributions) |contribution, *owned| {
        owned.* = contribution;
        owned.component_kind = try allocator.dupe(u8, contribution.component_kind);
        initialized_contributions += 1;
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
        .contributions = contributions,
        .component_work = components,
        .summary = source.summary,
    };
}
