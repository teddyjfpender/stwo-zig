//! Parallel composition scheduling for heterogeneous AIR components.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const accumulation = @import("accumulation.zig");
const prepared_domain = @import("prepared_domain.zig");
const secure_column = @import("../secure_column.zig");
const task_graph = @import("../task_graph.zig");
const work_pool = @import("../work_pool.zig");

const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

/// Evaluates components into independent coefficient ranges, then combines
/// their domain buckets in protocol order. The default overlaps component leaf
/// jobs and lets one dominant component subdivide its domain. Components that
/// opt into `pool_exclusive_domain` instead run breadth-first, one component at
/// a time, so every large row domain can use the bounded pool without nested
/// waits or oversubscription.
pub fn compute(
    allocator: std.mem.Allocator,
    components: anytype,
    max_log_size: u32,
    total_constraints: usize,
    random_coeff: QM31,
    trace: anytype,
    pool: *work_pool.WorkPool,
) anyerror!SecureColumnByCoords {
    if (components.len == 0) return error.EmptyComponentSet;
    if (allComponentsPrepared(components)) {
        return computePrepared(
            allocator,
            components,
            max_log_size,
            total_constraints,
            random_coeff,
            trace,
            pool,
        );
    }
    return computeLegacy(
        allocator,
        components,
        max_log_size,
        total_constraints,
        random_coeff,
        trace,
        pool,
    );
}

/// Structured path used only after every component has crossed the prepared
/// ownership boundary. A mixed stage retains the protocol-preserving legacy
/// scheduler until its final component is migrated.
fn computePrepared(
    allocator: std.mem.Allocator,
    components: anytype,
    max_log_size: u32,
    total_constraints: usize,
    random_coeff: QM31,
    trace: anytype,
    pool: *work_pool.WorkPool,
) anyerror!SecureColumnByCoords {
    const Component = @TypeOf(components[0]);
    const Worker = struct {
        component: Component,
        accumulator: accumulation.DomainEvaluationAccumulator,
        expected_next_power_index: usize,
        prepared: prepared_domain.PreparedDomainEvaluation = undefined,
        prepared_initialized: bool = false,

        fn run(context: *task_graph.TaskContext) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            try self.prepared.run(context);
        }
    };

    // Reject an inadmissible task count before any component is prepared.
    // Preparation may allocate large domain buffers and may expose external
    // resources whose owners must otherwise be rolled back.
    var graph = try task_graph.ComponentTaskGraph.init(
        allocator,
        components.len,
    );
    defer graph.deinit();

    const powers = try accumulation.generateSecurePowers(
        allocator,
        random_coeff,
        total_constraints,
    );
    defer allocator.free(powers);

    const workers = try allocator.alloc(Worker, components.len);
    defer allocator.free(workers);
    var initialized_workers: usize = 0;
    defer {
        var index = initialized_workers;
        while (index > 0) {
            index -= 1;
            if (workers[index].prepared_initialized) {
                workers[index].prepared.deinit();
            }
            workers[index].accumulator.deinit();
        }
    }

    var power_cursor = total_constraints;
    for (components, workers) |component, *worker| {
        const constraint_count = component.nConstraints();
        if (constraint_count > power_cursor) {
            return error.ConstraintPowerRangeUnderflow;
        }
        const next_power_cursor = power_cursor - constraint_count;
        worker.* = .{
            .component = component,
            .accumulator = try accumulation.DomainEvaluationAccumulator.initForComponent(
                powers,
                allocator,
                max_log_size,
                power_cursor,
            ),
            .expected_next_power_index = next_power_cursor,
        };
        initialized_workers += 1;
        worker.prepared = (try component.prepareConstraintQuotientsOnDomain(
            allocator,
            trace,
            &worker.accumulator,
        )) orelse return error.PreparedDomainCapabilityDisappeared;
        worker.prepared_initialized = true;
        power_cursor = next_power_cursor;
    }
    if (power_cursor != 0) return error.ConstraintPowerRangeMismatch;

    for (workers, 0..) |*worker, index| {
        _ = try graph.addTask(.{
            .key = .{
                .epoch = 0,
                .stage_rank = 0,
                .component_registry_index = @intCast(index),
                .shard_or_chunk_index = 0,
            },
            .name = "composition-domain",
            .func = Worker.run,
            .context = worker,
            .class = worker.prepared.task_class,
            .resources = worker.prepared.resources,
            .work_estimate = try componentWorkEstimate(worker.component),
        });
    }

    _ = graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(pool.workerCount()),
        .pool = pool,
        .ready_policy = .critical_path,
    }) catch |failure| switch (failure) {
        // The ordinary prover does not promise exclusive ownership of the
        // process-wide pool. Contention is therefore a scheduling decline,
        // not a proof failure: no task has started when lease admission fails,
        // so the exact prepared plan can execute serially without rebuilding
        // or reallocating component state. This compatibility fallback is not
        // an M7 scaling arm; the explicit request executor must report a lease
        // decline rather than relabel it as the requested worker count.
        error.WorkerBudgetUnavailable => try graph.execute(.{
            .worker_budget = work_pool.WorkerBudget.serial(),
            .ready_policy = .critical_path,
        }),
        else => return failure,
    };

    try validatePowerRanges(workers);
    for (workers[1..]) |*worker| {
        workers[0].accumulator.merge(&worker.accumulator);
    }
    workers[0].accumulator.next_power_index = 0;
    return workers[0].accumulator.finalize();
}

fn computeLegacy(
    allocator: std.mem.Allocator,
    components: anytype,
    max_log_size: u32,
    total_constraints: usize,
    random_coeff: QM31,
    trace: anytype,
    pool: *work_pool.WorkPool,
) anyerror!SecureColumnByCoords {
    const Component = @TypeOf(components[0]);
    const TracePointer = @TypeOf(trace);
    const Worker = struct {
        component: Component,
        trace: TracePointer,
        accumulator: accumulation.DomainEvaluationAccumulator,
        expected_next_power_index: usize,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.component.evaluateConstraintQuotientsOnDomain(
                self.trace,
                &self.accumulator,
            ) catch |err| {
                self.err = err;
            };
        }

        fn runParallel(self: *@This(), shared_pool: *work_pool.WorkPool) void {
            self.component.evaluateConstraintQuotientsOnDomainParallel(
                self.trace,
                &self.accumulator,
                shared_pool,
            ) catch |err| {
                self.err = err;
            };
        }
    };

    const powers = try accumulation.generateSecurePowers(
        allocator,
        random_coeff,
        total_constraints,
    );
    defer allocator.free(powers);

    const workers = try allocator.alloc(Worker, components.len);
    defer allocator.free(workers);
    var initialized_workers: usize = 0;
    defer for (workers[0..initialized_workers]) |*worker|
        worker.accumulator.deinit();

    var power_cursor = total_constraints;
    for (components, workers) |component, *worker| {
        const constraint_count = component.nConstraints();
        if (constraint_count > power_cursor) {
            return error.ConstraintPowerRangeUnderflow;
        }
        const next_power_cursor = power_cursor - constraint_count;
        worker.* = .{
            .component = component,
            .trace = trace,
            .accumulator = try accumulation.DomainEvaluationAccumulator.initForComponent(
                powers,
                allocator,
                max_log_size,
                power_cursor,
            ),
            .expected_next_power_index = next_power_cursor,
        };
        initialized_workers += 1;
        power_cursor = next_power_cursor;
    }
    if (power_cursor != 0) return error.ConstraintPowerRangeMismatch;

    if (hasPoolExclusiveDomain(components)) {
        return computePoolExclusive(workers, components, pool);
    }

    const caller_index = dominantDomainComponent(components);
    var wait_group = std.Thread.WaitGroup{};
    for (workers, 0..) |*worker, index| {
        if (index == caller_index) continue;
        pool.spawnWg(&wait_group, Worker.run, .{worker});
    }
    if (workers[caller_index].component.domain_parallel_evaluator != null) {
        Worker.runParallel(&workers[caller_index], pool);
    } else {
        Worker.run(&workers[caller_index]);
    }
    wait_group.wait();

    for (workers) |worker| if (worker.err) |err| return err;
    try validatePowerRanges(workers);
    for (workers[1..]) |*worker|
        workers[0].accumulator.merge(&worker.accumulator);
    workers[0].accumulator.next_power_index = 0;
    return workers[0].accumulator.finalize();
}

fn allComponentsPrepared(components: anytype) bool {
    for (components) |component| {
        if (component.prepare_domain_evaluator == null) return false;
    }
    return true;
}

fn componentWorkEstimate(component: anytype) !u64 {
    const log_size = component.maxConstraintLogDegreeBound();
    if (log_size >= @bitSizeOf(u64)) return error.WorkEstimateOverflow;
    const rows = @as(u64, 1) << @intCast(log_size);
    const constraints = std.math.cast(u64, component.nConstraints()) orelse
        return error.WorkEstimateOverflow;
    return task_graph.checkedWorkEstimate(&.{ rows, constraints });
}

fn validatePowerRanges(workers: anytype) !void {
    for (workers) |worker| {
        if (worker.accumulator.next_power_index != worker.expected_next_power_index) {
            return error.ConstraintPowerRangeMismatch;
        }
    }
}

fn computePoolExclusive(workers: anytype, components: anytype, pool: *work_pool.WorkPool) anyerror!SecureColumnByCoords {
    const caller_index = dominantPoolExclusiveComponent(components);
    var wait_group = std.Thread.WaitGroup{};
    for (workers, components) |*worker, component| {
        if (component.pool_exclusive_domain) continue;
        pool.spawnWg(&wait_group, @TypeOf(worker.*).run, .{worker});
    }

    @TypeOf(workers[0]).runParallel(&workers[caller_index], pool);
    wait_group.wait();
    for (workers) |worker| if (worker.err) |err| return err;

    for (workers, components, 0..) |*worker, component, index| {
        if (!component.pool_exclusive_domain or index == caller_index) continue;
        @TypeOf(worker.*).runParallel(worker, pool);
        if (worker.err) |err| return err;
        if (worker.accumulator.next_power_index != worker.expected_next_power_index) {
            return error.ConstraintPowerRangeMismatch;
        }
    }
    try validatePowerRanges(workers);

    for (workers[1..]) |*worker|
        workers[0].accumulator.merge(&worker.accumulator);
    workers[0].accumulator.next_power_index = 0;
    return workers[0].accumulator.finalize();
}

fn hasPoolExclusiveDomain(components: anytype) bool {
    for (components) |component| {
        if (component.pool_exclusive_domain) {
            std.debug.assert(component.domain_parallel_evaluator != null);
            return true;
        }
    }
    return false;
}

fn dominantPoolExclusiveComponent(components: anytype) usize {
    var selected: ?usize = null;
    var selected_work: u128 = 0;
    for (components, 0..) |component, index| {
        if (!component.pool_exclusive_domain) continue;
        const rows = @as(u128, 1) << @intCast(component.maxConstraintLogDegreeBound());
        const work = rows * component.nConstraints();
        if (selected == null or work > selected_work) {
            selected = index;
            selected_work = work;
        }
    }
    return selected.?;
}

fn dominantDomainComponent(components: anytype) usize {
    var caller_index: usize = 0;
    var caller_log_size: u32 = 0;
    for (components, 0..) |component, index| {
        if (component.domain_parallel_evaluator == null) continue;
        const log_size = component.maxConstraintLogDegreeBound();
        if (components[caller_index].domain_parallel_evaluator == null or
            log_size > caller_log_size)
        {
            caller_index = index;
            caller_log_size = log_size;
        }
    }
    return caller_index;
}
