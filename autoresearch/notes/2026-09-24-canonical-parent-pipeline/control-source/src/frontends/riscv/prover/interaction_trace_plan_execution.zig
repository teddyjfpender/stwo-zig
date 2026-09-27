//! Prepared, joined execution of the RISC-V Tree-2 interaction epoch.
//!
//! Preparation allocates all graph metadata. The caller's production kernel
//! must likewise prepare final destinations and component scratch before this
//! owner is constructed. `execute` then retains one finite worker lease across
//! three drained waves and performs no allocation:
//!
//!     reserve -> independent descriptor producers -> canonical seal
//!
//! A producer publishes only its statement-assigned column and detailed-claim
//! ranges. Total success publishes the epoch; every error or cancellation
//! drains all later waves and leaves the epoch transactionally unpublished.

const std = @import("std");
const prover_engine = @import("stwo_prover_engine");
const statement_mod = @import("../air/statement.zig");
const trace_mod = @import("../runner/trace.zig");
const plan_mod = @import("interaction_trace_plan.zig");

const task_graph = prover_engine.task_graph;
const work_pool = prover_engine.work_pool;

pub const WAVE_COUNT: usize = 3;

pub const Wave = enum(u8) {
    reserve,
    producers,
    seal,
};

pub const TaskKind = enum {
    reserve,
    opcode,
    program,
    memory,
    merkle,
    poseidon2,
    clock_update,
    lookup_table,
    seal,
};

/// One immutable, allocation-free callback descriptor. Dispatch happens once
/// per component, outside every row loop. A production adapter may switch on
/// `kind` here and call its already-prepared monomorphic `runInto` kernel.
pub const Task = struct {
    key: task_graph.TaskKey,
    kind: TaskKind,
    class: task_graph.TaskClass,
    registry_index: ?u32,
    component_index: ?u16,
    infra_index: ?u16,
    opcode_family: ?trace_mod.OpcodeFamily,
    infra_kind: ?statement_mod.InfraKind,
    log_size: u32,
    n_rows: u32,
    columns: ?plan_mod.ColumnRange,
    claims: ?plan_mod.ClaimRange,
};

/// `context` owns all final buffers, claim slots, retained main-column views,
/// the one shared relations pointer, and prepared generator scratch. It must
/// outlive this epoch. Successful return from a producer transfers logical
/// ownership of exactly the ranges in `task` to the epoch result ledger. A
/// row kernel must poll `task_context.isCancelled()` at least once per
/// `plan_mod.MAX_CANCELLATION_TILE_ROWS`; the executor joins every callback but
/// cannot make an opaque arithmetic loop cooperative on the kernel's behalf.
pub const Kernel = struct {
    context: *anyopaque,
    run: *const fn (
        context: *anyopaque,
        task: *const Task,
        task_context: *task_graph.TaskContext,
    ) anyerror!void,
};

pub const Admission = struct {
    host_byte_budget: usize,
    planned_host_bytes: usize,
    final_output_bytes: usize,
    shared_resident_bytes: usize,
    prepared_generator_bytes: usize,
    retained_input_bytes: usize,
    helper_worker_stack_bytes: usize,
    helper_submission_bytes: usize,
};

pub const Lifecycle = enum {
    prepared,
    executing,
    published,
    failed,
};

pub const EpochReport = struct {
    configured_workers: usize,
    planned_tasks: usize,
    attempted_waves: usize,
    submitted_tasks: usize,
    succeeded_tasks: usize,
    failed_tasks: usize,
    cancelled_tasks: usize,
    unsubmitted_cancelled_tasks: usize,
    started_tasks: usize,
    finished_tasks: usize,
    duplicate_starts: usize,
    duplicate_finishes: usize,
    peak_active_tasks: usize,
    peak_reserved_bytes: usize,
    published_producers: usize,
    cancellation_winner: ?task_graph.TaskKey,
};

const TaskRecord = struct {
    descriptor: Task,
    kernel: Kernel,
    visible_worker_count: usize,
    started: std.atomic.Value(bool) = .init(false),
    completed: std.atomic.Value(bool) = .init(false),
    output_published: std.atomic.Value(bool) = .init(false),

    fn run(context: *task_graph.TaskContext) anyerror!void {
        const self: *TaskRecord = @ptrCast(@alignCast(context.user_context));
        if (!context.key.eql(self.descriptor.key) or
            context.task_class != self.descriptor.class or
            context.worker_budget.count != self.visible_worker_count)
        {
            return error.InvalidTree2TaskContext;
        }
        if (self.started.swap(true, .acq_rel)) {
            return error.DuplicateTree2TaskStart;
        }
        try self.kernel.run(self.kernel.context, &self.descriptor, context);
        if (context.isCancelled()) return;
        if (isProducer(self.descriptor.kind)) {
            self.output_published.store(true, .release);
        }
        self.completed.store(true, .release);
    }
};

const TaskRange = struct {
    start: usize = 0,
    len: usize = 0,
};

const Prepared = struct {
    allocator: std.mem.Allocator,
    admission: Admission,
    graphs: [WAVE_COUNT]task_graph.ComponentTaskGraph,
    task_ranges: [WAVE_COUNT]TaskRange,
    tasks: []TaskRecord,

    fn deinit(self: *Prepared) void {
        for (&self.graphs) |*graph| graph.deinit();
        self.allocator.free(self.tasks);
        self.* = undefined;
    }
};

const State = struct {
    allocator: std.mem.Allocator,
    plan: plan_mod.Plan,
    prepared: Prepared,
    wave_reports: [WAVE_COUNT]?task_graph.ExecutionReport =
        .{null} ** WAVE_COUNT,
    lifecycle: Lifecycle = .prepared,
    attempted: bool = false,
};

/// Non-copyable-by-convention owner for one exact-capacity Tree-2 attempt.
pub const PreparedEpoch = struct {
    state: *State,

    pub fn prepare(
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        statement: *const statement_mod.RiscVStatement,
        kernel: Kernel,
    ) !PreparedEpoch {
        try plan_mod.validate(plan, statement);
        var prepared = try prepareGraphs(allocator, plan, statement, kernel);
        errdefer prepared.deinit();
        const state = try allocator.create(State);
        state.* = .{
            .allocator = allocator,
            .plan = plan.*,
            .prepared = prepared,
        };
        return .{ .state = state };
    }

    pub fn prepareForOrdinarySteps(
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        statement: *const statement_mod.RiscVStatement,
        ordinary_steps: u32,
        kernel: Kernel,
    ) !PreparedEpoch {
        try plan_mod.validateForOrdinarySteps(plan, statement, ordinary_steps);
        var prepared = try prepareGraphs(allocator, plan, statement, kernel);
        errdefer prepared.deinit();
        const state = try allocator.create(State);
        state.* = .{
            .allocator = allocator,
            .plan = plan.*,
            .prepared = prepared,
        };
        return .{ .state = state };
    }

    pub fn deinit(self: *PreparedEpoch) void {
        const state = self.state;
        state.prepared.deinit();
        state.allocator.destroy(state);
        self.* = undefined;
    }

    /// Executes under one retained request lease. No graph, result, profile,
    /// or callback storage is allocated after the lifecycle transition.
    pub fn execute(
        self: *PreparedEpoch,
        pool: ?*work_pool.WorkPool,
    ) anyerror!EpochReport {
        const state = self.state;
        if (state.lifecycle != .prepared) {
            return error.Tree2EpochAlreadyAttempted;
        }
        try validatePool(&state.plan, pool);
        state.lifecycle = .executing;
        state.attempted = true;

        const budget = try work_pool.WorkerBudget.init(
            state.plan.planned_worker_count,
        );
        var lease_storage: work_pool.WorkLease = undefined;
        const retained_lease: ?*work_pool.WorkLease = if (pool) |active_pool| lease: {
            lease_storage = active_pool.acquire(budget) catch |failure| {
                state.lifecycle = .failed;
                return failure;
            };
            break :lease &lease_storage;
        } else null;
        defer if (retained_lease) |lease| lease.deinit();

        for (0..WAVE_COUNT) |wave_index| {
            if (wave_index == waveIndex(.seal)) {
                validateProducerPublication(state) catch |failure| {
                    drainCancelledWaves(
                        state,
                        wave_index,
                        budget,
                        retained_lease,
                    );
                    state.lifecycle = .failed;
                    return failure;
                };
            }
            const graph_report = state.prepared.graphs[wave_index].execute(
                graphOptions(state, budget, retained_lease),
            ) catch |failure| {
                state.wave_reports[wave_index] =
                    state.prepared.graphs[wave_index].report();
                drainCancelledWaves(
                    state,
                    wave_index + 1,
                    budget,
                    retained_lease,
                );
                state.lifecycle = .failed;
                return failure;
            };
            state.wave_reports[wave_index] = graph_report;
            if (graph_report.failed_tasks != 0 or
                graph_report.cancelled_tasks != 0 or
                graph_report.unsubmitted_cancelled_tasks != 0)
            {
                drainCancelledWaves(
                    state,
                    wave_index + 1,
                    budget,
                    retained_lease,
                );
                state.lifecycle = .failed;
                return error.Tree2EpochCancelled;
            }
        }

        for (state.prepared.task_ranges, 0..) |range, wave_index| {
            for (
                state.prepared.tasks[range.start .. range.start + range.len],
                0..,
            ) |*record, local_index| {
                if (!record.completed.load(.acquire) or
                    state.prepared.graphs[wave_index].status(
                        @intCast(local_index),
                    ) != .done)
                {
                    state.lifecycle = .failed;
                    return error.Tree2TaskDidNotComplete;
                }
            }
        }
        try validateProducerPublication(state);
        state.lifecycle = .published;
        return aggregateReport(state);
    }

    /// Safe before or concurrently with `execute`. The active graph joins its
    /// callbacks and later graphs drain as unsubmitted cancellation.
    pub fn requestCancellation(self: *PreparedEpoch) bool {
        var won = false;
        for (&self.state.prepared.graphs) |*graph| {
            won = graph.cancellation.request() or won;
        }
        return won;
    }

    pub fn lifecycle(self: *const PreparedEpoch) Lifecycle {
        return self.state.lifecycle;
    }

    pub fn admission(self: *const PreparedEpoch) Admission {
        return self.state.prepared.admission;
    }

    pub fn plannedTaskCount(self: *const PreparedEpoch) usize {
        return self.state.prepared.tasks.len;
    }

    pub fn report(self: *const PreparedEpoch) ?EpochReport {
        return if (self.state.attempted)
            aggregateReport(self.state)
        else
            null;
    }

    pub fn waveReport(
        self: *const PreparedEpoch,
        wave: Wave,
    ) ?task_graph.ExecutionReport {
        return self.state.wave_reports[waveIndex(wave)];
    }

    /// Canonical descriptors become observable only after whole-epoch success.
    pub fn publishedTask(
        self: *const PreparedEpoch,
        index: usize,
    ) !*const Task {
        if (self.state.lifecycle != .published) {
            return error.Tree2EpochNotPublished;
        }
        if (index >= self.state.prepared.tasks.len) {
            return error.InvalidTree2TaskIndex;
        }
        return &self.state.prepared.tasks[index].descriptor;
    }
};

fn prepareGraphs(
    allocator: std.mem.Allocator,
    plan: *const plan_mod.Plan,
    statement: *const statement_mod.RiscVStatement,
    kernel: Kernel,
) !Prepared {
    const counts = [_]usize{
        plan.task_counts.reserve_wave,
        plan.task_counts.producer_wave,
        plan.task_counts.seal_wave,
    };
    const total_tasks = try plan.task_counts.total();
    const tasks = try allocator.alloc(TaskRecord, total_tasks);
    errdefer allocator.free(tasks);

    var graphs: [WAVE_COUNT]task_graph.ComponentTaskGraph = undefined;
    var initialized_graphs: usize = 0;
    errdefer for (graphs[0..initialized_graphs]) |*graph| graph.deinit();
    for (counts, 0..) |capacity, index| {
        graphs[index] = try task_graph.ComponentTaskGraph.init(
            allocator,
            capacity,
        );
        initialized_graphs += 1;
    }

    const admission = try admissionFor(plan);
    var ranges = [_]TaskRange{.{}} ** WAVE_COUNT;
    var cursor: usize = 0;
    try beginWave(&ranges, .reserve, cursor, counts);
    try appendTask(
        &graphs[waveIndex(.reserve)],
        tasks,
        &cursor,
        kernel,
        admission,
        plan,
        coordinatorTask(.reserve, plan_mod.reserveTaskKey()),
    );

    try beginWave(&ranges, .producers, cursor, counts);
    for (0..@as(usize, plan.n_components)) |component_index| {
        const desc = statement.component_descs[component_index];
        const registry_index = component_index;
        try appendTask(
            &graphs[waveIndex(.producers)],
            tasks,
            &cursor,
            kernel,
            admission,
            plan,
            .{
                .key = try plan.producerTaskKey(registry_index),
                .kind = .opcode,
                .class = plan.descriptorClass(registry_index) orelse
                    return error.InvalidTree2Plan,
                .registry_index = @intCast(registry_index),
                .component_index = @intCast(component_index),
                .infra_index = null,
                .opcode_family = desc.family,
                .infra_kind = null,
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .columns = plan.componentColumnRange(component_index),
                .claims = plan.componentClaimRange(component_index),
            },
        );
    }
    for (0..@as(usize, plan.n_infra)) |infra_index| {
        const desc = statement.infra_descs[infra_index];
        const registry_index = @as(usize, plan.n_components) + infra_index;
        try appendTask(
            &graphs[waveIndex(.producers)],
            tasks,
            &cursor,
            kernel,
            admission,
            plan,
            .{
                .key = try plan.producerTaskKey(registry_index),
                .kind = taskKindForInfrastructure(desc.kind),
                .class = plan.descriptorClass(registry_index) orelse
                    return error.InvalidTree2Plan,
                .registry_index = @intCast(registry_index),
                .component_index = null,
                .infra_index = @intCast(infra_index),
                .opcode_family = null,
                .infra_kind = desc.kind,
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .columns = plan.infrastructureColumnRange(infra_index),
                .claims = plan.infrastructureClaimRange(infra_index),
            },
        );
    }

    try beginWave(&ranges, .seal, cursor, counts);
    try appendTask(
        &graphs[waveIndex(.seal)],
        tasks,
        &cursor,
        kernel,
        admission,
        plan,
        coordinatorTask(.seal, plan_mod.sealTaskKey()),
    );
    if (cursor != tasks.len) return error.InvalidTree2Plan;
    for (graphs, counts) |graph, expected_count| {
        if (graph.count != expected_count or graph.capacity != expected_count) {
            return error.InvalidTree2Plan;
        }
    }
    try validateCanonicalOrder(tasks);
    return .{
        .allocator = allocator,
        .admission = admission,
        .graphs = graphs,
        .task_ranges = ranges,
        .tasks = tasks,
    };
}

fn admissionFor(plan: *const plan_mod.Plan) !Admission {
    const planned_host_bytes = try plan.requiredHostBytes();
    const final_output_bytes = try plan.resources.finalOutputBytes();
    const helper_bytes = try plan.resources.helperBytes();
    if (planned_host_bytes > plan.host_byte_budget or
        helper_bytes > planned_host_bytes or
        final_output_bytes > planned_host_bytes - helper_bytes)
    {
        return error.TaskMemoryBudgetExceeded;
    }
    return .{
        .host_byte_budget = plan.host_byte_budget,
        .planned_host_bytes = planned_host_bytes,
        .final_output_bytes = final_output_bytes,
        .shared_resident_bytes = planned_host_bytes - helper_bytes -
            final_output_bytes,
        .prepared_generator_bytes = plan.resources.prepared_generator_bytes,
        .retained_input_bytes = plan.resources.retained_input_bytes,
        .helper_worker_stack_bytes = plan.resources.helper_worker_stack_bytes,
        .helper_submission_bytes = plan.resources.helper_submission_bytes,
    };
}

fn appendTask(
    graph: *task_graph.ComponentTaskGraph,
    records: []TaskRecord,
    cursor: *usize,
    kernel: Kernel,
    admission: Admission,
    plan: *const plan_mod.Plan,
    descriptor: Task,
) !void {
    if (cursor.* >= records.len) return error.InvalidTree2Plan;
    if ((descriptor.columns == null) != (descriptor.claims == null) or
        isProducer(descriptor.kind) != (descriptor.columns != null))
    {
        return error.InvalidTree2TaskDescriptor;
    }
    const visible_workers = if (descriptor.class == .pool_exclusive)
        @as(usize, plan.planned_worker_count)
    else
        1;
    const record = &records[cursor.*];
    record.* = .{
        .descriptor = descriptor,
        .kernel = kernel,
        .visible_worker_count = visible_workers,
    };
    const anchor = graph.count == 0;
    const work_units = try taskWorkUnits(&descriptor);
    _ = try graph.addTask(.{
        .key = descriptor.key,
        .name = taskName(descriptor.kind),
        .stage_id = "riscv.interaction_trace.tree2",
        .component_kind = taskName(descriptor.kind),
        .func = TaskRecord.run,
        .context = record,
        .class = descriptor.class,
        .parallel_eligible = descriptor.class == .leaf,
        .resources = .{
            .final_output_bytes = if (anchor)
                admission.final_output_bytes
            else
                0,
            .shared_resident_bytes = if (anchor)
                admission.shared_resident_bytes
            else
                0,
            .worker_stack_bytes = plan.worker_stack_bytes,
        },
        .work_estimate = work_units,
        .work_unit = if (isProducer(descriptor.kind)) .rows else .unspecified,
        .planned_work_units = if (isProducer(descriptor.kind))
            @as(u64, 1) << @intCast(descriptor.log_size)
        else
            0,
    });
    cursor.* += 1;
}

fn beginWave(
    ranges: *[WAVE_COUNT]TaskRange,
    wave: Wave,
    cursor: usize,
    counts: [WAVE_COUNT]usize,
) !void {
    const index = waveIndex(wave);
    ranges[index] = .{ .start = cursor, .len = counts[index] };
    if (index > 0) {
        const previous = ranges[index - 1];
        if (previous.start + previous.len != cursor) {
            return error.InvalidTree2Plan;
        }
    }
}

fn graphOptions(
    state: *State,
    budget: work_pool.WorkerBudget,
    retained_lease: ?*work_pool.WorkLease,
) task_graph.ExecuteOptions {
    return .{
        .worker_budget = budget,
        .retained_lease = retained_lease,
        .byte_budget = state.plan.host_byte_budget,
        .ready_policy = .canonical,
        .requested_worker_count = state.plan.requested_worker_count,
        .pool_capacity = state.plan.pool_capacity,
    };
}

fn drainCancelledWaves(
    state: *State,
    start: usize,
    budget: work_pool.WorkerBudget,
    retained_lease: ?*work_pool.WorkLease,
) void {
    for (start..WAVE_COUNT) |wave_index| {
        _ = state.prepared.graphs[wave_index].cancellation.request();
        state.wave_reports[wave_index] =
            state.prepared.graphs[wave_index].execute(graphOptions(
                state,
                budget,
                retained_lease,
            )) catch state.prepared.graphs[wave_index].report();
    }
}

fn validateProducerPublication(state: *const State) !void {
    const range = state.prepared.task_ranges[waveIndex(.producers)];
    for (state.prepared.tasks[range.start .. range.start + range.len]) |*record| {
        if (!record.output_published.load(.acquire)) {
            return error.Tree2ProducerDidNotPublish;
        }
    }
}

fn aggregateReport(state: *const State) EpochReport {
    var result = EpochReport{
        .configured_workers = state.plan.planned_worker_count,
        .planned_tasks = state.prepared.tasks.len,
        .attempted_waves = 0,
        .submitted_tasks = 0,
        .succeeded_tasks = 0,
        .failed_tasks = 0,
        .cancelled_tasks = 0,
        .unsubmitted_cancelled_tasks = 0,
        .started_tasks = 0,
        .finished_tasks = 0,
        .duplicate_starts = 0,
        .duplicate_finishes = 0,
        .peak_active_tasks = 0,
        .peak_reserved_bytes = 0,
        .published_producers = 0,
        .cancellation_winner = null,
    };
    for (state.wave_reports) |maybe_report| {
        const report = maybe_report orelse continue;
        result.attempted_waves += 1;
        result.submitted_tasks += report.submitted_tasks;
        result.succeeded_tasks += report.succeeded_tasks;
        result.failed_tasks += report.failed_tasks;
        result.cancelled_tasks += report.cancelled_tasks;
        result.unsubmitted_cancelled_tasks += report.unsubmitted_cancelled_tasks;
        result.started_tasks += report.started_tasks;
        result.finished_tasks += report.finished_tasks;
        result.duplicate_starts += report.duplicate_starts;
        result.duplicate_finishes += report.duplicate_finishes;
        result.peak_active_tasks = @max(
            result.peak_active_tasks,
            report.peak_active_tasks,
        );
        result.peak_reserved_bytes = @max(
            result.peak_reserved_bytes,
            report.peak_reserved_bytes,
        );
        if (report.cancellation_winner) |winner| {
            if (result.cancellation_winner == null or
                winner.lessThan(result.cancellation_winner.?))
            {
                result.cancellation_winner = winner;
            }
        }
    }
    const range = state.prepared.task_ranges[waveIndex(.producers)];
    for (state.prepared.tasks[range.start .. range.start + range.len]) |*record| {
        if (record.output_published.load(.acquire)) {
            result.published_producers += 1;
        }
    }
    return result;
}

fn validatePool(plan: *const plan_mod.Plan, pool: ?*work_pool.WorkPool) !void {
    if (plan.planned_worker_count > 1 and pool == null) {
        return error.WorkPoolRequired;
    }
    if (pool) |active_pool| {
        if (active_pool.workerCount() != @as(usize, plan.pool_capacity)) {
            return error.Tree2PoolCapacityMismatch;
        }
        if (active_pool.stackSize() != plan.worker_stack_bytes) {
            return error.Tree2PoolStackSizeMismatch;
        }
    }
}

fn validateCanonicalOrder(tasks: []const TaskRecord) !void {
    for (tasks[1..], tasks[0 .. tasks.len - 1]) |current, previous| {
        if (!previous.descriptor.key.lessThan(current.descriptor.key)) {
            return error.NonCanonicalTree2TaskOrder;
        }
    }
}

fn coordinatorTask(kind: TaskKind, key: task_graph.TaskKey) Task {
    return .{
        .key = key,
        .kind = kind,
        .class = .coordinator,
        .registry_index = null,
        .component_index = null,
        .infra_index = null,
        .opcode_family = null,
        .infra_kind = null,
        .log_size = 0,
        .n_rows = 0,
        .columns = null,
        .claims = null,
    };
}

fn taskKindForInfrastructure(kind: statement_mod.InfraKind) TaskKind {
    return switch (kind) {
        .program => .program,
        .memory => .memory,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .clock_update => .clock_update,
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => .lookup_table,
    };
}

fn taskName(kind: TaskKind) []const u8 {
    return switch (kind) {
        .reserve => "interaction-reserve",
        .opcode => "interaction-opcode",
        .program => "interaction-program",
        .memory => "interaction-memory",
        .merkle => "interaction-merkle",
        .poseidon2 => "interaction-poseidon2",
        .clock_update => "interaction-clock",
        .lookup_table => "interaction-table",
        .seal => "interaction-seal",
    };
}

fn taskWorkUnits(task: *const Task) !u64 {
    if (!isProducer(task.kind)) return 0;
    const columns = task.columns orelse return error.InvalidTree2TaskDescriptor;
    return std.math.mul(
        u64,
        columns.len,
        @as(u64, 1) << @intCast(task.log_size),
    ) catch error.Tree2WorkEstimateOverflow;
}

fn isProducer(kind: TaskKind) bool {
    return switch (kind) {
        .reserve, .seal => false,
        else => true,
    };
}

fn waveIndex(wave: Wave) usize {
    return @intFromEnum(wave);
}
