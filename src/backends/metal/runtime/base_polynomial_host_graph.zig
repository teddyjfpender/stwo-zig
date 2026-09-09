//! Prepared host-fallback authority for profiled resident Metal composition.
//!
//! Ordinary Metal composition deliberately retains its overlap-oriented
//! ambient-pool scheduler. A profiled request instead prepares every host
//! fallback before launch and executes those exact components through the
//! caller-supplied structured execution authority. The graph drains before
//! synchronous device dispatch, so no host work is duplicated or attributed
//! to workers outside the requested arm.

const std = @import("std");
const prover = @import("stwo_prover_engine");

const Component = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const Execution = prover.air.composition_execution.Execution;

/// Diagnostic wall accounting for the existing schedule, independent of the
/// structured task recorder. Worker intervals overlap these caller phases.
pub const WallTiming = struct {
    pub const env = "STWO_ZIG_RISCV_METAL_COMPOSITION_TIMING";
    pub const Phase = enum {
        preparation,
        host_launch_or_inline,
        device_preparation,
        semantic_dispatch,
        lookup_dispatch,
        device_partition_parity,
        scratch_release,
        framework_dispatch,
        host_wait,
        partition_parity,
        device_merge,
        work_receipt,
        accumulation,
        full_parity,
        publication,
        cleanup,
    };
    const count = @typeInfo(Phase).@"enum".fields.len;
    origin: std.time.Instant,
    cursor: u64 = 0,
    phase: Phase = .preparation,
    durations: [count]u64 = @splat(0),
    completed: bool = false,
    scheduler: enum { unresolved, inline_host, pool, structured } = .unresolved,

    pub fn requested() ?WallTiming {
        const value = std.posix.getenv(env) orelse return null;
        if (!std.mem.eql(u8, value, "1")) return null;
        return .{ .origin = std.time.Instant.now() catch return null };
    }

    fn advanceAt(self: *WallTiming, next: Phase, now: u64) void {
        std.debug.assert(now >= self.cursor);
        std.debug.assert(@intFromEnum(next) >= @intFromEnum(self.phase));
        self.durations[@intFromEnum(self.phase)] += now - self.cursor;
        self.cursor = now;
        self.phase = next;
    }

    pub fn enter(self: *WallTiming, next: Phase) void {
        const now = std.time.Instant.now() catch return;
        self.advanceAt(next, now.since(self.origin));
        const sample = prover.measurement.process_usage.sample() catch return;
        std.log.info(
            "metal composition resource: phase={s} elapsed_ns={} process_current_phys_bytes={?} process_lifetime_peak_phys_bytes={?}",
            .{ @tagName(next), self.cursor, sample.current_physical_footprint_bytes, sample.lifetime_peak_physical_footprint_bytes },
        );
    }

    // Registered before resource defers: successful cleanup is included. On
    // early failure/decline the last active phase also includes its unwind.
    pub fn finish(self: *WallTiming) void {
        const now = std.time.Instant.now() catch return;
        self.advanceAt(.cleanup, now.since(self.origin));
        var sum: u64 = 0;
        inline for (@typeInfo(Phase).@"enum".fields) |field| {
            const elapsed = self.durations[field.value];
            std.log.info("metal composition phase: phase={s} start_ns={} end_ns={} wall_ns={}", .{ field.name, sum, sum + elapsed, elapsed });
            sum += elapsed;
        }
        std.debug.assert(sum == self.cursor);
        std.log.info(
            "metal composition wall: completed={} scheduler={s} wall_ns={} phase_sum_ns={} host_spans_overlap=true device_ms_separate=true",
            .{ self.completed, @tagName(self.scheduler), self.cursor, sum },
        );
    }
};

pub const WorkerTiming = struct {
    origin: ?std.time.Instant = null,
    start_ns: ?u64 = null,
    end_ns: ?u64 = null,
    mode: enum { legacy, parallel, prepared } = .legacy,

    fn begin(self: *WorkerTiming, mode: @TypeOf(self.mode)) void {
        const origin = self.origin orelse return;
        const now = std.time.Instant.now() catch return;
        self.mode = mode;
        self.start_ns = now.since(origin);
    }

    fn end(self: *WorkerTiming) void {
        const origin = self.origin orelse return;
        const now = std.time.Instant.now() catch return;
        self.end_ns = now.since(origin);
    }
};

pub const Worker = struct {
    component: Component,
    trace: *const Trace,
    accumulator: Accumulator,
    expected_next_power_index: usize,
    component_registry_index: u32,
    prepared: prover.air.prepared_domain.PreparedDomainEvaluation = undefined,
    prepared_initialized: bool = false,
    err: ?anyerror = null,
    timing: WorkerTiming = .{},

    pub fn prepare(self: *Worker, allocator: std.mem.Allocator) !void {
        self.prepared = (try self.component.prepareConstraintQuotientsOnDomain(
            allocator,
            self.trace,
            &self.accumulator,
        )) orelse return error.UnpreparedMetalCompositionFallback;
        self.prepared_initialized = true;
        if (self.accumulator.next_power_index != self.expected_next_power_index) {
            return error.InvalidCompositionPowerOrder;
        }
    }

    pub fn runLegacy(self: *Worker) void {
        self.timing.begin(.legacy);
        defer self.timing.end();
        self.component.evaluateConstraintQuotientsOnDomain(
            self.trace,
            &self.accumulator,
        ) catch |err| {
            self.err = err;
        };
    }

    pub fn runParallel(self: *Worker, pool: *prover.work_pool.WorkPool) void {
        self.timing.begin(.parallel);
        defer self.timing.end();
        self.component.evaluateConstraintQuotientsOnDomainParallel(
            self.trace,
            &self.accumulator,
            pool,
        ) catch |err| {
            self.err = err;
        };
    }

    fn runTask(context: *prover.task_graph.TaskContext) anyerror!void {
        const self: *Worker = @ptrCast(@alignCast(context.user_context));
        self.timing.begin(.prepared);
        defer self.timing.end();
        self.prepared.run(context) catch |err| {
            self.err = err;
            return err;
        };
    }

    fn taskClass(self: *const Worker) prover.task_graph.TaskClass {
        std.debug.assert(self.prepared_initialized);
        return self.prepared.task_class;
    }

    fn resources(self: *const Worker) prover.task_graph.ResourceReservation {
        std.debug.assert(self.prepared_initialized);
        return self.prepared.resources;
    }

    fn plannedRows(self: *const Worker) !u64 {
        const log_size = self.component.maxConstraintLogDegreeBound();
        if (log_size >= @bitSizeOf(u64)) return error.WorkEstimateOverflow;
        return @as(u64, 1) << @intCast(log_size);
    }

    fn workEstimate(self: *const Worker, rows: u64) !u64 {
        return prover.task_graph.checkedWorkEstimate(&.{
            rows,
            std.math.cast(u64, self.component.nConstraints()) orelse
                return error.WorkEstimateOverflow,
        });
    }

    fn validateCompletion(self: *const Worker) !void {
        if (self.accumulator.next_power_index != self.expected_next_power_index) {
            return error.InvalidCompositionPowerOrder;
        }
    }

    pub fn reportTiming(self: *const Worker) void {
        const start = self.timing.start_ns orelse return;
        const end = self.timing.end_ns orelse return;
        std.log.info(
            "metal composition host: component_index={} constraints={} eval_log={} evaluator=0x{x} mode={s} start_ns={} end_ns={} wall_ns={} failed={}",
            .{ self.component_registry_index, self.component.nConstraints(), self.component.maxConstraintLogDegreeBound(), @intFromPtr(self.component.vtable.evaluateConstraintQuotientsOnDomain), @tagName(self.timing.mode), start, end, end - start, self.err != null },
        );
    }

    pub fn deinit(self: *Worker) void {
        if (self.prepared_initialized) self.prepared.deinit();
        self.accumulator.deinit();
        self.* = undefined;
    }
};

/// Executes the already-prepared host workers under the exact public request.
/// One exclusive contribution owns every component; completion is derived by
/// the graph from the terminal task lifecycle rather than worker publication.
pub fn execute(
    allocator: std.mem.Allocator,
    workers: []Worker,
    execution: Execution,
) !void {
    return executeTyped(Worker, allocator, workers, execution);
}

fn executeTyped(
    comptime WorkerType: type,
    allocator: std.mem.Allocator,
    workers: []WorkerType,
    execution: Execution,
) !void {
    if (workers.len == 0) return error.ProfiledMetalHostTaskSetEmpty;
    try execution.validateCapacity();

    var graph = try prover.task_graph.ComponentTaskGraph.init(allocator, workers.len);
    defer graph.deinit();
    const contributions = try allocator.alloc(
        prover.task_graph.TaskContributionPlan,
        workers.len,
    );
    defer allocator.free(contributions);

    for (workers, 0..) |*worker, task_index| {
        if (!worker.prepared_initialized) return error.UnpreparedMetalCompositionFallback;
        const planned_rows = try worker.plannedRows();
        const work_estimate = try worker.workEstimate(planned_rows);
        contributions[task_index] = .{
            .component_registry_index = worker.component_registry_index,
            .component_kind = "riscv_fallback_component",
            .role = .exclusive,
            .work_estimate = work_estimate,
            .planned_rows = planned_rows,
        };
        _ = try graph.addTask(.{
            .key = .{
                .epoch = 0,
                .stage_rank = 0,
                .component_registry_index = worker.component_registry_index,
                .shard_or_chunk_index = 0,
            },
            .name = "metal-composition-host-fallback",
            .stage_id = "composition_domain",
            .component_kind = "riscv_fallback_component",
            .func = WorkerType.runTask,
            .context = worker,
            .class = worker.taskClass(),
            .resources = worker.resources(),
            .work_estimate = work_estimate,
            .work_unit = .rows,
            .planned_work_units = planned_rows,
            .contributions = contributions[task_index .. task_index + 1],
        });
    }

    _ = try graph.execute(.{
        .worker_budget = execution.worker_budget,
        .pool = execution.pool,
        .byte_budget = execution.host_byte_budget,
        .ready_policy = .critical_path,
        .task_profile_recorder = execution.task_recorder,
        .task_profile_graph_id = "metal_composition_riscv",
        .requested_worker_count = execution.requestedWorkerCount(),
        .pool_capacity = execution.poolCapacity(),
    });

    for (workers) |*worker| try worker.validateCompletion();
}

test "profiled Metal host graph attributes exact 1 2 4 and max worker arms" {
    // Synthetic monotonic boundaries establish exact accounting even when
    // overlapping host spans would sum to more than the caller wall time.
    var timing = WallTiming{ .origin = try std.time.Instant.now() };
    timing.advanceAt(.host_launch_or_inline, 10);
    timing.advanceAt(.semantic_dispatch, 20);
    timing.advanceAt(.host_wait, 70);
    timing.advanceAt(.cleanup, 100);
    try std.testing.expectEqual(@as(u64, 10), timing.durations[@intFromEnum(WallTiming.Phase.preparation)]);
    try std.testing.expectEqual(@as(u64, 50), timing.durations[@intFromEnum(WallTiming.Phase.semantic_dispatch)]);
    var phase_sum: u64 = 0;
    for (timing.durations) |elapsed| phase_sum += elapsed;
    try std.testing.expectEqual(timing.cursor, phase_sum);
    var disabled = WorkerTiming{};
    disabled.begin(.legacy);
    disabled.end();
    try std.testing.expect(disabled.start_ns == null and disabled.end_ns == null);
    var enabled = WorkerTiming{ .origin = timing.origin };
    enabled.begin(.parallel);
    enabled.end();
    try std.testing.expect(enabled.end_ns.? >= enabled.start_ns.?);
    try std.testing.expectEqual(.parallel, enabled.mode);

    const Fixture = struct {
        calls: usize = 0,
        fail: bool = false,
        fn evaluate(ctx: *const anyopaque, _: *const Trace, _: *Accumulator) !void {
            const self: *@This() = @ptrCast(@alignCast(@constCast(ctx)));
            self.calls += 1;
            if (self.fail) return error.TimingFixtureFailure;
        }
        fn parallel(ctx: *const anyopaque, trace: *const Trace, accumulator: *Accumulator, _: *prover.work_pool.WorkPool) !void {
            return evaluate(ctx, trace, accumulator);
        }
    };
    var fixture = Fixture{};
    // The callbacks deliberately inspect no trace/accumulator data; the test
    // exercises the unchanged worker's dispatch and error publication itself.
    var vtable: prover.air.component_prover.ComponentProverVTable = undefined;
    vtable.evaluateConstraintQuotientsOnDomain = Fixture.evaluate;
    var trace: Trace = undefined;
    var fixture_worker = Worker{
        .component = .{ .ctx = &fixture, .vtable = &vtable, .domain_parallel_evaluator = Fixture.parallel },
        .trace = &trace,
        .accumulator = try Accumulator.initForComponent(&.{}, std.testing.allocator, 4, 0),
        .expected_next_power_index = 0,
        .component_registry_index = 0,
    };
    defer fixture_worker.deinit();
    Worker.runLegacy(&fixture_worker);
    try std.testing.expectEqual(@as(usize, 1), fixture.calls);
    try std.testing.expect(fixture_worker.timing.start_ns == null and fixture_worker.err == null);
    fixture_worker.timing.origin = timing.origin;
    Worker.runLegacy(&fixture_worker);
    try std.testing.expectEqual(@as(usize, 2), fixture.calls);
    try std.testing.expect(fixture_worker.timing.end_ns.? >= fixture_worker.timing.start_ns.?);
    fixture.fail = true;
    var unused_pool: prover.work_pool.WorkPool = undefined;
    Worker.runParallel(&fixture_worker, &unused_pool);
    try std.testing.expectEqual(@as(usize, 3), fixture.calls);
    try std.testing.expectEqual(error.TimingFixtureFailure, fixture_worker.err.?);
    try std.testing.expect(fixture_worker.timing.end_ns.? >= fixture_worker.timing.start_ns.?);
    try std.testing.expectEqual(.parallel, fixture_worker.timing.mode);

    const AtomicUsize = std.atomic.Value(usize);
    const TestWorker = struct {
        component_registry_index: u32,
        completed: *AtomicUsize,
        prepared_initialized: bool = true,

        fn runTask(context: *prover.task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            _ = self.completed.fetchAdd(1, .monotonic);
            try context.setCompletedWork(16);
        }

        fn taskClass(_: *const @This()) prover.task_graph.TaskClass {
            return .leaf;
        }

        fn resources(_: *const @This()) prover.task_graph.ResourceReservation {
            return .{ .worker_stack_bytes = 64 * 1024 };
        }

        fn plannedRows(_: *const @This()) !u64 {
            return 16;
        }

        fn workEstimate(_: *const @This(), rows: u64) !u64 {
            return prover.task_graph.checkedWorkEstimate(&.{ rows, 2 });
        }

        fn validateCompletion(_: *const @This()) !void {}
    };

    const allocator = std.testing.allocator;
    for ([_]usize{ 1, 2, 4, 8 }) |worker_count| {
        var pool: prover.work_pool.WorkPool = undefined;
        const pool_ptr: ?*prover.work_pool.WorkPool = if (worker_count == 1)
            null
        else pool: {
            try pool.initInPlaceWithOptions(.{
                .worker_count = worker_count,
                .stack_size = 128 * 1024,
            });
            break :pool &pool;
        };
        defer if (pool_ptr != null) pool.deinit();

        var completed = AtomicUsize.init(0);
        var workers: [8]TestWorker = undefined;
        for (&workers, 0..) |*worker, registry_index| {
            worker.* = .{
                .component_registry_index = @intCast(registry_index),
                .completed = &completed,
            };
        }
        var recorder = prover.stage_profile.Recorder.init(
            allocator,
            "Debug",
            "metal-profiled-host-graph",
        );
        defer recorder.deinit();
        try executeTyped(TestWorker, allocator, &workers, .{
            .worker_budget = try prover.work_pool.WorkerBudget.init(worker_count),
            .pool = pool_ptr,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
            .explicit = true,
            .requested_worker_count = worker_count,
            .pool_capacity = worker_count,
            .task_recorder = &recorder,
        });
        try std.testing.expectEqual(@as(usize, workers.len), completed.load(.acquire));

        var profile = try recorder.taskSnapshot(allocator);
        defer profile.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), profile.graphs.len);
        const graph = profile.graphs[0];
        try std.testing.expectEqualStrings("metal_composition_riscv", graph.graph_id);
        try std.testing.expectEqual(@as(usize, workers.len), graph.events.len);
        try std.testing.expectEqual(@as(usize, workers.len), graph.contributions.len);
        try std.testing.expectEqual(@as(usize, workers.len), graph.component_work.len);
        try std.testing.expectEqual(
            @as(u32, @intCast(worker_count)),
            graph.summary.requested_workers,
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(worker_count)),
            graph.summary.admitted_workers,
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(worker_count)),
            graph.summary.pool_capacity,
        );
        for (graph.events, 0..) |event, registry_index| {
            try std.testing.expect(event.task_class == .leaf);
            try std.testing.expect(event.parallel_eligible);
            try std.testing.expect(event.terminal_status == .completed);
            try std.testing.expectEqual(@as(u64, 16), event.completed_rows);
            try std.testing.expectEqual(
                @as(u32, @intCast(registry_index)),
                event.key.component_registry_index,
            );
        }
    }

    var completed = AtomicUsize.init(0);
    var unprepared = [_]TestWorker{.{
        .component_registry_index = 0,
        .completed = &completed,
        .prepared_initialized = false,
    }};
    try std.testing.expectError(
        error.UnpreparedMetalCompositionFallback,
        executeTyped(TestWorker, allocator, &unprepared, .{
            .worker_budget = prover.work_pool.WorkerBudget.serial(),
            .pool = null,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
            .explicit = true,
            .requested_worker_count = 1,
            .pool_capacity = 1,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), completed.load(.acquire));

    var contended_pool: prover.work_pool.WorkPool = undefined;
    try contended_pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = 128 * 1024,
    });
    defer contended_pool.deinit();
    var held_lease = try contended_pool.acquire(
        try prover.work_pool.WorkerBudget.init(2),
    );
    defer held_lease.deinit();
    var contended_workers = [_]TestWorker{
        .{ .component_registry_index = 0, .completed = &completed },
        .{ .component_registry_index = 1, .completed = &completed },
    };
    var contended_recorder = prover.stage_profile.Recorder.init(
        allocator,
        "Debug",
        "metal-profiled-host-contention",
    );
    defer contended_recorder.deinit();
    try std.testing.expectError(
        error.WorkerBudgetUnavailable,
        executeTyped(TestWorker, allocator, &contended_workers, .{
            .worker_budget = try prover.work_pool.WorkerBudget.init(2),
            .pool = &contended_pool,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .compatibility,
            .explicit = true,
            .requested_worker_count = 2,
            .pool_capacity = 2,
            .task_recorder = &contended_recorder,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), completed.load(.acquire));
    var contended_profile = try contended_recorder.taskSnapshot(allocator);
    defer contended_profile.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), contended_profile.graphs.len);
}
