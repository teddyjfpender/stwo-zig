//! Parallel composition scheduling for heterogeneous AIR components.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const qm31 = @import("stwo_core").fields.qm31;
const accumulation = @import("accumulation.zig");
const composition_execution = @import("composition_execution.zig");
const prepared_domain = @import("prepared_domain.zig");
const host_budget_allocator = @import("../host_budget_allocator.zig");
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
    return computeWithRecorder(
        allocator,
        components,
        max_log_size,
        total_constraints,
        random_coeff,
        trace,
        pool,
        null,
    );
}

/// The proof path borrows its existing stage recorder here. Legacy composition
/// remains deliberately unprofiled because it does not execute a bounded task
/// graph; the prepared path publishes one flat graph after its joined run.
pub fn computeWithRecorder(
    allocator: std.mem.Allocator,
    components: anytype,
    max_log_size: u32,
    total_constraints: usize,
    random_coeff: QM31,
    trace: anytype,
    pool: *work_pool.WorkPool,
    recorder: ?*prover_api.stage_profile.Recorder,
) anyerror!SecureColumnByCoords {
    return computeWithRecorderDiagnosed(
        allocator,
        components,
        max_log_size,
        total_constraints,
        random_coeff,
        trace,
        pool,
        recorder,
        null,
    );
}

pub fn computeWithRecorderDiagnosed(
    allocator: std.mem.Allocator,
    components: anytype,
    max_log_size: u32,
    total_constraints: usize,
    random_coeff: QM31,
    trace: anytype,
    pool: *work_pool.WorkPool,
    recorder: ?*prover_api.stage_profile.Recorder,
    diagnostic: ?*?prover_api.EvaluationDiagnostic,
) anyerror!SecureColumnByCoords {
    if (components.len == 0) {
        prover_api.EvaluationDiagnostic.recordFirst(diagnostic, .{
            .stage = .trace_shape,
            .cause = error.EmptyComponentSet,
            .actual = 0,
            .expected = 1,
        });
        return error.EmptyComponentSet;
    }
    if (allComponentsPrepared(components)) {
        const execution = composition_execution.Execution{
            .worker_budget = try work_pool.WorkerBudget.init(pool.workerCount()),
            .pool = pool,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .compatibility,
            .explicit = false,
            .requested_worker_count = pool.workerCount(),
            .pool_capacity = pool.workerCount(),
            .task_recorder = recorder,
            .evaluation_diagnostic = diagnostic,
        };
        return computePrepared(
            allocator,
            components,
            max_log_size,
            total_constraints,
            random_coeff,
            trace,
            execution,
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
        diagnostic,
        .auto,
        .{},
    );
}

/// Scheduler selection for the unprepared (legacy-capability) path.
/// `auto` uses the cooperative work queue whenever at least one component
/// declares `cooperative_domain`, and the established breadth-first
/// scheduler otherwise. `STWO_ZIG_COMPOSITION_SCHEDULER=legacy` forces the
/// established scheduler for A/B measurement. Both produce identical bytes.
pub const Scheduler = enum { auto, legacy, queue };

/// Options of the cooperative composition queue.
pub const QueueOptions = struct {
    /// Soft admission bound on the estimated working set of components that
    /// are expanded at the same time. One component is always admitted when
    /// none is running, so this never fails a proof. Null selects
    /// `composition_execution.defaultQueueAdmissionBytes`.
    admission_bytes: ?usize = null,
};

/// Same contract as `compute`, with an explicit scheduler. Used by the
/// scheduler equivalence tests.
pub fn computeWithScheduler(
    allocator: std.mem.Allocator,
    components: anytype,
    max_log_size: u32,
    total_constraints: usize,
    random_coeff: QM31,
    trace: anytype,
    pool: *work_pool.WorkPool,
    scheduler: Scheduler,
    options: QueueOptions,
) anyerror!SecureColumnByCoords {
    if (components.len == 0) return error.EmptyComponentSet;
    return computeLegacy(
        allocator,
        components,
        max_log_size,
        total_constraints,
        random_coeff,
        trace,
        pool,
        null,
        scheduler,
        options,
    );
}

/// Executes an exact public request without letting generic composition
/// rediscover or exceed the request's worker and host-memory budgets.
pub fn computeRequested(
    allocator: std.mem.Allocator,
    components: anytype,
    max_log_size: u32,
    total_constraints: usize,
    random_coeff: QM31,
    trace: anytype,
    execution: composition_execution.Execution,
) anyerror!SecureColumnByCoords {
    if (components.len == 0) {
        prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
            .stage = .trace_shape,
            .cause = error.EmptyComponentSet,
            .actual = 0,
            .expected = 1,
        });
        return error.EmptyComponentSet;
    }
    const adjusted = execution.adjustedForAvailablePool();
    adjusted.validateCapacity() catch |err| {
        prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
            .stage = .plan,
            .cause = err,
            .actual = adjusted.worker_budget.count,
            .expected = adjusted.poolCapacity(),
        });
        return err;
    };
    const fully_prepared = allComponentsPrepared(components);
    if (!fully_prepared) {
        if (adjusted.isStrict()) {
            prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
                .stage = .plan,
                .cause = error.UnpreparedCompositionFallback,
            });
            return error.UnpreparedCompositionFallback;
        }
    }
    if (!fully_prepared and adjusted.host_byte_budget != std.math.maxInt(usize)) {
        prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
            .stage = .plan,
            .cause = error.FiniteCompositionByteBudgetUnsupported,
        });
        return error.FiniteCompositionByteBudgetUnsupported;
    }
    if (!fully_prepared) {
        return computeSequential(
            allocator,
            components,
            max_log_size,
            total_constraints,
            random_coeff,
            trace,
            execution.evaluation_diagnostic,
        );
    }
    if (adjusted.host_byte_budget != std.math.maxInt(usize)) {
        const helper_bytes = try adjusted.helperResidentBytes();
        const heap_budget = std.math.sub(
            usize,
            adjusted.host_byte_budget,
            helper_bytes,
        ) catch return error.TaskMemoryBudgetExceeded;
        var bounded = host_budget_allocator.HostBudgetAllocator.init(
            allocator,
            heap_budget,
        );
        return computePrepared(
            bounded.allocator(),
            components,
            max_log_size,
            total_constraints,
            random_coeff,
            trace,
            adjusted,
        ) catch |failure| {
            if (failure == error.OutOfMemory and bounded.didExceedBudget()) {
                return error.TaskMemoryBudgetExceeded;
            }
            return failure;
        };
    }
    return computePrepared(
        allocator,
        components,
        max_log_size,
        total_constraints,
        random_coeff,
        trace,
        adjusted,
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
    execution: composition_execution.Execution,
) anyerror!SecureColumnByCoords {
    const Component = @TypeOf(components[0]);
    const Worker = struct {
        component: Component,
        component_index: ?u32,
        accumulator: accumulation.DomainEvaluationAccumulator,
        expected_next_power_index: usize,
        prepared: prepared_domain.PreparedDomainEvaluation = undefined,
        prepared_initialized: bool = false,
        diagnostic: ?*?prover_api.EvaluationDiagnostic,
        err: ?anyerror = null,

        fn run(context: *task_graph.TaskContext) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.prepared.run(context) catch |err| {
                self.err = err;
                return err;
            };
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
    for (components, workers, 0..) |component, *worker, component_index| {
        const constraint_count = component.nConstraints();
        if (constraint_count > power_cursor) {
            prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
                .stage = .plan,
                .cause = error.ConstraintPowerRangeUnderflow,
                .component_index = std.math.cast(u32, component_index),
                .actual = constraint_count,
                .expected = power_cursor,
            });
            return error.ConstraintPowerRangeUnderflow;
        }
        const next_power_cursor = power_cursor - constraint_count;
        worker.* = .{
            .component = component,
            .component_index = std.math.cast(u32, component_index),
            .accumulator = try accumulation.DomainEvaluationAccumulator.initForComponent(
                powers,
                allocator,
                max_log_size,
                power_cursor,
            ),
            .expected_next_power_index = next_power_cursor,
            .diagnostic = execution.evaluation_diagnostic,
        };
        initialized_workers += 1;
        worker.prepared = (component.prepareConstraintQuotientsOnDomain(
            allocator,
            trace,
            &worker.accumulator,
        ) catch |err| {
            prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
                .stage = .component_evaluation,
                .cause = err,
                .component_index = worker.component_index,
            });
            return err;
        }) orelse {
            prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
                .stage = .component_evaluation,
                .cause = error.PreparedDomainCapabilityDisappeared,
                .component_index = worker.component_index,
            });
            return error.PreparedDomainCapabilityDisappeared;
        };
        worker.prepared_initialized = true;
        if (worker.accumulator.next_power_index != next_power_cursor) {
            prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
                .stage = .component_evaluation,
                .cause = error.ConstraintPowerRangeMismatch,
                .component_index = worker.component_index,
                .actual = worker.accumulator.next_power_index,
                .expected = next_power_cursor,
            });
            return error.ConstraintPowerRangeMismatch;
        }
        power_cursor = next_power_cursor;
        if (execution.preparation == .streamed) {
            var single = try task_graph.ComponentTaskGraph.init(allocator, 1);
            defer single.deinit();
            const planned_rows = try componentRows(worker.component);
            if (execution.host_byte_budget != std.math.maxInt(usize))
                try requireHeapBackedResources(worker.prepared.resources);
            _ = try single.addTask(.{
                .key = .{ .epoch = 0, .stage_rank = 0, .component_registry_index = @intCast(component_index), .shard_or_chunk_index = 0 },
                .name = "composition-domain",
                .stage_id = "composition_domain",
                .component_kind = "generic_air_component",
                .func = Worker.run,
                .context = worker,
                .class = worker.prepared.task_class,
                .resources = worker.prepared.resources,
                .work_estimate = try componentWorkEstimate(worker.component, planned_rows),
                .work_unit = .rows,
                .planned_work_units = planned_rows,
            });
            try executePreparedGraph(&single, execution, workers[component_index..][0..1]);
            if (worker.accumulator.next_power_index != next_power_cursor)
                return error.ConstraintPowerRangeMismatch;
            // Graph execution joins all children before returning; no task or
            // subsequent cohort borrows these source evaluation buffers.
            worker.prepared.deinit();
            worker.prepared_initialized = false;
            if (component_index != 0) workers[0].accumulator.merge(&worker.accumulator);
        }
    }
    if (power_cursor != 0) {
        prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
            .stage = .plan,
            .cause = error.ConstraintPowerRangeMismatch,
            .actual = power_cursor,
            .expected = 0,
        });
        return error.ConstraintPowerRangeMismatch;
    }

    if (execution.preparation == .streamed) {
        workers[0].accumulator.next_power_index = 0;
        return workers[0].accumulator.finalize();
    }

    var has_max_bucket = false;
    var has_lower_bucket = false;
    var polynomial_extension_logs: u64 = 0;
    for (workers) |worker| {
        for (worker.accumulator.sub_accumulations, 0..) |bucket, log_size| {
            if (bucket == null) continue;
            if (log_size == max_log_size) has_max_bucket = true else has_lower_bucket = true;
        }
        if (worker.accumulator.polynomial_extension_accumulations) |extensions| {
            for (extensions, 0..) |bucket, log_size| {
                if (bucket == null) continue;
                if (log_size >= @bitSizeOf(u64))
                    return error.InvalidLogSize;
                polynomial_extension_logs |= @as(u64, 1) << @intCast(log_size);
            }
        }
    }
    const polynomial_extension_resource_bytes = try polynomialExtensionResourceBytes(
        polynomial_extension_logs,
        max_log_size,
    );
    var prepared_output: ?SecureColumnByCoords = if (polynomial_extension_logs == 0 and
        (has_lower_bucket or !has_max_bucket))
        try SecureColumnByCoords.uninitialized(
            allocator,
            @as(usize, 1) << @intCast(max_log_size),
        )
    else
        null;
    defer if (prepared_output) |*output| output.deinit(allocator);
    for (workers, 0..) |*worker, index| {
        const planned_rows = try componentRows(worker.component);
        var resources = worker.prepared.resources;
        if (index == 0) {
            resources.shared_resident_bytes = std.math.add(
                usize,
                resources.shared_resident_bytes,
                polynomial_extension_resource_bytes,
            ) catch return error.ResourceReservationOverflow;
        }
        if (execution.host_byte_budget != std.math.maxInt(usize)) {
            try requireHeapBackedResources(resources);
        }
        _ = try graph.addTask(.{
            .key = .{
                .epoch = 0,
                .stage_rank = 0,
                .component_registry_index = @intCast(index),
                .shard_or_chunk_index = 0,
            },
            .name = "composition-domain",
            .stage_id = "composition_domain",
            .component_kind = "generic_air_component",
            .func = Worker.run,
            .context = worker,
            .class = worker.prepared.task_class,
            .resources = resources,
            .work_estimate = try componentWorkEstimate(worker.component, planned_rows),
            .work_unit = .rows,
            .planned_work_units = planned_rows,
        });
    }

    try executePreparedGraph(&graph, execution, workers);

    for (workers) |worker| {
        if (worker.accumulator.next_power_index != worker.expected_next_power_index) {
            prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
                .stage = .component_evaluation,
                .cause = error.ConstraintPowerRangeMismatch,
                .component_index = worker.component_index,
                .actual = worker.accumulator.next_power_index,
                .expected = worker.expected_next_power_index,
            });
            return error.ConstraintPowerRangeMismatch;
        }
    }
    for (workers[1..]) |*worker| {
        workers[0].accumulator.merge(&worker.accumulator);
    }
    workers[0].accumulator.next_power_index = 0;
    if (prepared_output) |*output| {
        workers[0].accumulator.finalizeInto(output) catch |err| {
            prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
                .stage = .lift_accumulation,
                .cause = err,
                .actual = output.len(),
                .expected = @as(usize, 1) << @intCast(max_log_size),
            });
            return err;
        };
        const result = output.*;
        prepared_output = null;
        return result;
    }
    return workers[0].accumulator.finalize() catch |err| {
        prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
            .stage = .final_length,
            .cause = err,
            .actual = workers[0].accumulator.next_power_index,
            .expected = 0,
        });
        return err;
    };
}

/// Exact additional host reservation for aggregate polynomial extension.
/// One target secure column remains resident for every distinct source log;
/// only the largest target-domain twiddle pair is live at once.  A separate
/// max-domain output is also reserved because materialization may leave more
/// than one nonconstant bucket for the ordinary finalizer to combine.
fn polynomialExtensionResourceBytes(
    source_logs: u64,
    max_log_size: u32,
) !usize {
    var secure_bytes: usize = 0;
    var max_twiddle_bytes: usize = 0;
    var remaining = source_logs;
    while (remaining != 0) {
        const source_log: u32 = @intCast(@ctz(remaining));
        remaining &= remaining - 1;
        const target_log = std.math.add(u32, source_log, 1) catch
            return error.InvalidLogSize;
        if (target_log > max_log_size or target_log >= @bitSizeOf(usize))
            return error.InvalidLogSize;
        const rows = @as(usize, 1) << @intCast(target_log);
        const coordinate_values = std.math.mul(
            usize,
            rows,
            qm31.SECURE_EXTENSION_DEGREE,
        ) catch return error.ResourceReservationOverflow;
        const target_bytes = std.math.mul(
            usize,
            coordinate_values,
            @sizeOf(@import("stwo_core").fields.m31.M31),
        ) catch return error.ResourceReservationOverflow;
        secure_bytes = std.math.add(usize, secure_bytes, target_bytes) catch
            return error.ResourceReservationOverflow;
        const twiddle_bytes = std.math.mul(
            usize,
            rows,
            @sizeOf(@import("stwo_core").fields.m31.M31),
        ) catch return error.ResourceReservationOverflow;
        max_twiddle_bytes = @max(max_twiddle_bytes, twiddle_bytes);
    }
    if (source_logs != 0) {
        if (max_log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
        const final_rows = @as(usize, 1) << @intCast(max_log_size);
        const final_values = std.math.mul(
            usize,
            final_rows,
            qm31.SECURE_EXTENSION_DEGREE,
        ) catch return error.ResourceReservationOverflow;
        const final_bytes = std.math.mul(
            usize,
            final_values,
            @sizeOf(@import("stwo_core").fields.m31.M31),
        ) catch return error.ResourceReservationOverflow;
        secure_bytes = std.math.add(usize, secure_bytes, final_bytes) catch
            return error.ResourceReservationOverflow;
    }
    return std.math.add(usize, secure_bytes, max_twiddle_bytes) catch
        error.ResourceReservationOverflow;
}

fn requireHeapBackedResources(resources: task_graph.ResourceReservation) !void {
    if (resources.exclusive_scratch_bytes != 0 or resources.device_resident_bytes != 0) {
        return error.FiniteCompositionByteBudgetUnsupported;
    }
}

fn computeSequential(
    allocator: std.mem.Allocator,
    components: anytype,
    max_log_size: u32,
    total_constraints: usize,
    random_coeff: QM31,
    trace: anytype,
    diagnostic: ?*?prover_api.EvaluationDiagnostic,
) anyerror!SecureColumnByCoords {
    var accumulator = try accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        max_log_size,
        total_constraints,
    );
    defer accumulator.deinit();
    for (components, 0..) |component, component_index| {
        component.evaluateConstraintQuotientsOnDomain(trace, &accumulator) catch |err| {
            prover_api.EvaluationDiagnostic.recordFirst(diagnostic, .{
                .stage = .component_evaluation,
                .cause = err,
                .component_index = std.math.cast(u32, component_index),
            });
            return err;
        };
    }
    return accumulator.finalize() catch |err| {
        prover_api.EvaluationDiagnostic.recordFirst(diagnostic, .{
            .stage = .final_length,
            .cause = err,
            .actual = accumulator.next_power_index,
            .expected = 0,
        });
        return err;
    };
}

fn computeLegacy(
    allocator: std.mem.Allocator,
    components: anytype,
    max_log_size: u32,
    total_constraints: usize,
    random_coeff: QM31,
    trace: anytype,
    pool: *work_pool.WorkPool,
    diagnostic: ?*?prover_api.EvaluationDiagnostic,
    scheduler: Scheduler,
    queue_options: QueueOptions,
) anyerror!SecureColumnByCoords {
    const Component = @TypeOf(components[0]);
    const TracePointer = @TypeOf(trace);
    const Worker = struct {
        component: Component,
        component_index: ?u32,
        trace: TracePointer,
        accumulator: accumulation.DomainEvaluationAccumulator,
        expected_next_power_index: usize,
        diagnostic: ?*?prover_api.EvaluationDiagnostic,
        err: ?anyerror = null,
        exclusive_done: bool = false,

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
    for (components, workers, 0..) |component, *worker, component_index| {
        const constraint_count = component.nConstraints();
        if (constraint_count > power_cursor) {
            prover_api.EvaluationDiagnostic.recordFirst(diagnostic, .{
                .stage = .plan,
                .cause = error.ConstraintPowerRangeUnderflow,
                .component_index = std.math.cast(u32, component_index),
                .actual = constraint_count,
                .expected = power_cursor,
            });
            return error.ConstraintPowerRangeUnderflow;
        }
        const next_power_cursor = power_cursor - constraint_count;
        worker.* = .{
            .component = component,
            .component_index = std.math.cast(u32, component_index),
            .trace = trace,
            .accumulator = try accumulation.DomainEvaluationAccumulator.initForComponent(
                powers,
                allocator,
                max_log_size,
                power_cursor,
            ),
            .expected_next_power_index = next_power_cursor,
            .diagnostic = diagnostic,
        };
        initialized_workers += 1;
        power_cursor = next_power_cursor;
    }
    if (power_cursor != 0) {
        prover_api.EvaluationDiagnostic.recordFirst(diagnostic, .{
            .stage = .plan,
            .cause = error.ConstraintPowerRangeMismatch,
            .actual = power_cursor,
            .expected = 0,
        });
        return error.ConstraintPowerRangeMismatch;
    }

    if (selectQueue(components, scheduler)) {
        return computeQueued(allocator, workers, components, pool, max_log_size, queue_options);
    }
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

    if (firstWorkerError(workers)) |err| return err;
    try validatePowerRanges(workers);
    for (workers[1..]) |*worker|
        workers[0].accumulator.merge(&worker.accumulator);
    workers[0].accumulator.next_power_index = 0;
    return workers[0].accumulator.finalize() catch |err| {
        prover_api.EvaluationDiagnostic.recordFirst(diagnostic, .{
            .stage = .final_length,
            .cause = err,
            .actual = workers[0].accumulator.next_power_index,
            .expected = 0,
        });
        return err;
    };
}

fn allComponentsPrepared(components: anytype) bool {
    for (components) |component| {
        if (component.prepare_domain_evaluator == null) return false;
    }
    return true;
}

fn componentWorkEstimate(component: anytype, rows: u64) !u64 {
    const constraints = std.math.cast(u64, component.nConstraints()) orelse
        return error.WorkEstimateOverflow;
    return task_graph.checkedWorkEstimate(&.{ rows, constraints });
}

fn componentRows(component: anytype) !u64 {
    const log_size = component.maxConstraintLogDegreeBound();
    if (log_size >= @bitSizeOf(u64)) return error.WorkEstimateOverflow;
    return @as(u64, 1) << @intCast(log_size);
}

fn validatePowerRanges(workers: anytype) !void {
    for (workers) |worker| {
        if (worker.accumulator.next_power_index != worker.expected_next_power_index) {
            prover_api.EvaluationDiagnostic.recordFirst(worker.diagnostic, .{
                .stage = .component_evaluation,
                .cause = error.ConstraintPowerRangeMismatch,
                .component_index = worker.component_index,
                .actual = worker.accumulator.next_power_index,
                .expected = worker.expected_next_power_index,
            });
            return error.ConstraintPowerRangeMismatch;
        }
    }
}

fn firstWorkerError(workers: anytype) ?anyerror {
    for (workers) |worker| {
        if (worker.err) |err| {
            prover_api.EvaluationDiagnostic.recordFirst(worker.diagnostic, .{
                .stage = .component_evaluation,
                .cause = err,
                .component_index = worker.component_index,
            });
            return err;
        }
    }
    return null;
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
    if (firstWorkerError(workers)) |err| return err;

    for (workers, components, 0..) |*worker, component, index| {
        if (!component.pool_exclusive_domain or index == caller_index) continue;
        @TypeOf(worker.*).runParallel(worker, pool);
        if (worker.err != null) return firstWorkerError(workers).?;
        if (worker.accumulator.next_power_index != worker.expected_next_power_index) {
            prover_api.EvaluationDiagnostic.recordFirst(worker.diagnostic, .{
                .stage = .component_evaluation,
                .cause = error.ConstraintPowerRangeMismatch,
                .component_index = worker.component_index,
                .actual = worker.accumulator.next_power_index,
                .expected = worker.expected_next_power_index,
            });
            return error.ConstraintPowerRangeMismatch;
        }
    }
    try validatePowerRanges(workers);

    for (workers[1..]) |*worker|
        workers[0].accumulator.merge(&worker.accumulator);
    workers[0].accumulator.next_power_index = 0;
    return workers[0].accumulator.finalize() catch |err| {
        prover_api.EvaluationDiagnostic.recordFirst(workers[0].diagnostic, .{
            .stage = .final_length,
            .cause = err,
            .actual = workers[0].accumulator.next_power_index,
            .expected = 0,
        });
        return err;
    };
}

fn isCooperative(component: anytype) bool {
    if (comptime !@hasField(@TypeOf(component), "cooperative_domain")) return false;
    return component.cooperative_domain;
}

fn selectQueue(components: anytype, scheduler: Scheduler) bool {
    switch (scheduler) {
        .legacy => return false,
        .queue => return true,
        .auto => {},
    }
    if (std.process.hasEnvVarConstant("STWO_ZIG_COMPOSITION_SCHEDULER")) {
        // Only the established scheduler can be forced from the environment.
        const value = std.posix.getenv("STWO_ZIG_COMPOSITION_SCHEDULER") orelse "";
        if (std.mem.eql(u8, value, "legacy")) return false;
    }
    for (components) |component| {
        if (isCooperative(component)) return true;
    }
    return false;
}

/// A component joins the queue unless it needs the whole pool and cannot
/// split cooperatively.
fn queueEligible(component: anytype) bool {
    return !component.pool_exclusive_domain or isCooperative(component);
}

/// Conservative working-set estimate of one component's domain evaluation:
/// every trace column expanded to the evaluation domain plus its secure
/// output bucket. Over-estimation only lowers concurrency.
fn queueWorkingSetBytes(allocator: std.mem.Allocator, component: anytype) usize {
    const log_size = component.maxConstraintLogDegreeBound();
    if (log_size >= @bitSizeOf(usize) - 8) return std.math.maxInt(usize);
    const rows = @as(usize, 1) << @intCast(log_size);
    var columns: usize = component.nConstraints();
    if (comptime @hasDecl(@TypeOf(component), "traceLogDegreeBounds")) {
        if (component.traceLogDegreeBounds(allocator)) |bounds_value| {
            var bounds = bounds_value;
            defer bounds.deinitDeep(allocator);
            columns = 0;
            for (bounds.items) |tree| columns += tree.len;
        } else |_| {}
    }
    const column_bytes = std.math.mul(usize, columns, rows * @sizeOf(@import("stwo_core").fields.m31.M31)) catch
        return std.math.maxInt(usize);
    return std.math.add(usize, column_bytes, rows * @sizeOf(QM31)) catch std.math.maxInt(usize);
}

fn queueWorkEstimate(component: anytype) u128 {
    const rows = @as(u128, 1) << @intCast(@min(component.maxConstraintLogDegreeBound(), 100));
    return rows * component.nConstraints();
}

/// Cooperative work-queue scheduler.
///
/// Every queue-eligible component is a top-level queue item, admitted in
/// decreasing work order (first fit) while the estimated working set of the
/// running items stays within the admission budget. Inside an item, the
/// shared providers publish column-expansion and row-range batches on the same
/// queue; every leased thread draws those before admitting a new component.
/// Large components that used to run single-threaded therefore become row
/// parallel, small components overlap large ones, and no thread ever waits on
/// a nested pool lease. Components that are pool exclusive without a
/// cooperative split keep the established full-pool phase afterwards.
/// Each component still owns its power range and accumulator, and field
/// addition is exact, so the result is bit-identical to `computePoolExclusive`.
fn computeQueued(
    allocator: std.mem.Allocator,
    workers: anytype,
    components: anytype,
    pool: *work_pool.WorkPool,
    max_log_size: u32,
    options: QueueOptions,
) anyerror!SecureColumnByCoords {
    const Worker = @TypeOf(workers[0]);
    const timing = std.process.hasEnvVarConstant("STWO_ZIG_COMPOSITION_QUEUE_TIMING");
    var clock: ?std.time.Timer = if (timing) std.time.Timer.start() catch null else null;

    const order = try allocator.alloc(usize, workers.len);
    defer allocator.free(order);
    const bytes = try allocator.alloc(usize, workers.len);
    defer allocator.free(bytes);
    const taken = try allocator.alloc(bool, workers.len);
    defer allocator.free(taken);
    @memset(taken, false);
    var queued: usize = 0;
    for (components, 0..) |component, index| {
        bytes[index] = 0;
        if (!queueEligible(component)) continue;
        bytes[index] = queueWorkingSetBytes(allocator, component);
        order[queued] = index;
        queued += 1;
    }
    const Order = struct {
        components: @TypeOf(components),
        fn greater(self: @This(), lhs: usize, rhs: usize) bool {
            const l = queueWorkEstimate(self.components[lhs]);
            const r = queueWorkEstimate(self.components[rhs]);
            return if (l != r) l > r else lhs < rhs;
        }
    };
    std.sort.pdq(usize, order[0..queued], Order{ .components = components }, Order.greater);

    var threads: usize = 1;
    var lease: ?work_pool.WorkLease = null;
    if (pool.workerCount() > 1) {
        const available = pool.availableWorkers();
        if (available > 1) {
            if (work_pool.WorkerBudget.init(available)) |budget| {
                if (pool.acquire(budget)) |acquired| {
                    lease = acquired;
                    threads = available;
                } else |_| {}
            } else |_| {}
        }
    }
    defer if (lease) |*held| held.deinit();
    const admission = options.admission_bytes orelse
        composition_execution.defaultQueueAdmissionBytes(threads, max_log_size);

    const Source = struct {
        workers: []Worker,
        order: []const usize,
        taken: []bool,
        bytes: []const usize,
        remaining: usize,
        budget: usize,
        active: usize = 0,
        active_bytes: usize = 0,
        failed: bool = false,
        peak_active: usize = 0,
        peak_bytes: usize = 0,
        /// Optional per-item timeline (timing telemetry only).
        wave_start: ?std.time.Instant = null,
        item_start_ns: []u64 = &.{},
        item_end_ns: []u64 = &.{},

        fn take(context: *anyopaque) ?usize {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.failed) return null;
            for (self.order, 0..) |index, position| {
                if (self.taken[position]) continue;
                const need = self.bytes[index];
                if (self.active != 0 and
                    (self.active_bytes > self.budget or need > self.budget - self.active_bytes))
                    continue;
                self.taken[position] = true;
                self.remaining -= 1;
                self.active += 1;
                self.active_bytes +|= need;
                self.peak_active = @max(self.peak_active, self.active);
                self.peak_bytes = @max(self.peak_bytes, self.active_bytes);
                return index;
            }
            return null;
        }
        fn run(context: *anyopaque, item: usize) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.wave_start) |start| {
                if (std.time.Instant.now()) |now| self.item_start_ns[item] = now.since(start) else |_| {}
            }
            Worker.run(&self.workers[item]);
            if (self.wave_start) |start| {
                if (std.time.Instant.now()) |now| self.item_end_ns[item] = now.since(start) else |_| {}
            }
        }
        fn finish(context: *anyopaque, item: usize) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.active -= 1;
            self.active_bytes -|= self.bytes[item];
            if (self.workers[item].err != null) self.failed = true;
        }
        fn exhausted(context: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            return (self.remaining == 0 or self.failed) and self.active == 0;
        }
    };
    var source = Source{
        .workers = workers,
        .order = order[0..queued],
        .taken = taken[0..queued],
        .bytes = bytes,
        .remaining = queued,
        .budget = admission,
    };
    var queue = work_pool.cooperative.Queue.init(threads);
    queue.measure = timing;
    var timeline: []u64 = &.{};
    defer if (timeline.len != 0) allocator.free(timeline);
    if (timing) {
        if (allocator.alloc(u64, 2 * workers.len)) |storage| {
            timeline = storage;
            @memset(storage, 0);
            source.item_start_ns = storage[0..workers.len];
            source.item_end_ns = storage[workers.len..];
            source.wave_start = std.time.Instant.now() catch null;
        } else |_| {}
    }
    const top = work_pool.cooperative.TopLevel{
        .context = &source,
        .take = Source.take,
        .run = Source.run,
        .finish = Source.finish,
        .exhausted = Source.exhausted,
    };
    const Drive = struct {
        queue: *work_pool.cooperative.Queue,
        top: work_pool.cooperative.TopLevel,
        fn run(self: *@This()) void {
            self.queue.drive(self.top);
        }
    };
    var drive = Drive{ .queue = &queue, .top = top };
    // Timing telemetry only: per-component peak live bytes allocated through
    // the component's accumulator allocator (scratch, expansions, buckets).
    var counters: []PeakCounter = &.{};
    defer if (counters.len != 0) allocator.free(counters);
    if (timing) {
        if (allocator.alloc(PeakCounter, workers.len)) |storage| {
            counters = storage;
            for (counters, workers) |*counter, *worker| {
                counter.* = .{ .parent = worker.accumulator.allocator };
                worker.accumulator.allocator = counter.allocator();
            }
        } else |_| {}
    }
    defer for (counters, workers[0..counters.len]) |*counter, *worker| {
        worker.accumulator.allocator = counter.parent;
    };
    {
        var group = std.Thread.WaitGroup{};
        if (lease) |*held| {
            for (1..threads) |_| held.spawnWg(&group, Drive.run, .{&drive}) catch break;
        }
        drive.run();
        group.wait();
        if (lease) |*held| held.completeWave();
    }
    if (lease) |*held| {
        held.deinit();
        lease = null;
    }
    const queue_ns = if (clock) |*c| c.read() else 0;
    for (counters, workers[0..counters.len]) |*counter, *worker| worker.accumulator.allocator = counter.parent;
    if (firstWorkerError(workers)) |err| return err;

    // Exclusive components without a cooperative split: largest first, each
    // with the whole pool, exactly as the established scheduler's tail.
    var exclusive_count: usize = 0;
    while (true) {
        var selected: ?usize = null;
        var selected_work: u128 = 0;
        for (components, 0..) |component, index| {
            if (queueEligible(component) or exclusiveDone(workers[index])) continue;
            const work = queueWorkEstimate(component);
            if (selected == null or work > selected_work) {
                selected = index;
                selected_work = work;
            }
        }
        const index = selected orelse break;
        Worker.runParallel(&workers[index], pool);
        workers[index].exclusive_done = true;
        exclusive_count += 1;
        if (workers[index].err != null) return firstWorkerError(workers).?;
    }
    const exclusive_ns = if (clock) |*c| c.read() else 0;
    try validatePowerRanges(workers);

    for (workers[1..]) |*worker|
        workers[0].accumulator.merge(&worker.accumulator);
    workers[0].accumulator.next_power_index = 0;
    const merge_ns = if (clock) |*c| c.read() else 0;
    const result = finalizeParallel(&workers[0].accumulator, pool) catch |err| {
        prover_api.EvaluationDiagnostic.recordFirst(workers[0].diagnostic, .{
            .stage = .final_length,
            .cause = err,
            .actual = workers[0].accumulator.next_power_index,
            .expected = 0,
        });
        return err;
    };
    if (clock) |*c| {
        const total_ns = c.read();
        const wave_capacity = @as(f64, @floatFromInt(queue_ns)) * @as(f64, @floatFromInt(threads));
        const busy_fraction = if (wave_capacity == 0) 0 else 1.0 - @as(f64, @floatFromInt(queue.idle_ns)) / wave_capacity;
        std.log.info("composition queue: components={} queued={} exclusive={} threads={} admission_bytes={} peak_active={} peak_estimated_bytes={} batches={} batch_tasks={} helped={} queue_ms={d:.1} queue_busy_threads={d:.2} exclusive_ms={d:.1} merge_ms={d:.1} finalize_ms={d:.1}", .{
            workers.len,                                                  queued,                                                            exclusive_count,
            threads,                                                      admission,                                                         source.peak_active,
            source.peak_bytes,                                            queue.batches_published,                                           queue.batch_tasks_run,
            queue.helped_tasks,                                           @as(f64, @floatFromInt(queue_ns)) / 1e6,                           busy_fraction * @as(f64, @floatFromInt(threads)),
            @as(f64, @floatFromInt(exclusive_ns - queue_ns)) / 1e6,       @as(f64, @floatFromInt(merge_ns - exclusive_ns)) / 1e6,            @as(f64, @floatFromInt(total_ns - merge_ns)) / 1e6,
        });
        if (source.item_start_ns.len != 0) for (components, 0..) |component, index| {
            if (!queueEligible(component)) continue;
            std.log.info("composition queue item: index={} log={} constraints={} estimated_bytes={} peak_allocated_bytes={} start_ms={d:.1} end_ms={d:.1}", .{
                index,                                                           component.maxConstraintLogDegreeBound(),                     component.nConstraints(), bytes[index],
                if (counters.len != 0) counters[index].peak.load(.monotonic) else -1, @as(f64, @floatFromInt(source.item_start_ns[index])) / 1e6, @as(f64, @floatFromInt(source.item_end_ns[index])) / 1e6,
            });
        };
    }
    return result;
}

/// Diagnostic pass-through allocator recording live and peak bytes.
const PeakCounter = struct {
    parent: std.mem.Allocator,
    live: std.atomic.Value(isize) = .init(0),
    peak: std.atomic.Value(isize) = .init(0),

    fn allocator(self: *PeakCounter) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }
    const vtable = std.mem.Allocator.VTable{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
    fn from(context: *anyopaque) *PeakCounter {
        return @ptrCast(@alignCast(context));
    }
    fn add(self: *PeakCounter, delta: isize) void {
        const value = self.live.fetchAdd(delta, .monotonic) + delta;
        var observed = self.peak.load(.monotonic);
        while (value > observed) {
            observed = self.peak.cmpxchgWeak(observed, value, .monotonic, .monotonic) orelse break;
        }
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self = from(context);
        const result = self.parent.rawAlloc(len, alignment, ret) orelse return null;
        self.add(@intCast(len));
        return result;
    }
    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
        const self = from(context);
        if (!self.parent.rawResize(memory, alignment, new_len, ret)) return false;
        self.add(@as(isize, @intCast(new_len)) - @as(isize, @intCast(memory.len)));
        return true;
    }
    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const self = from(context);
        const result = self.parent.rawRemap(memory, alignment, new_len, ret) orelse return null;
        self.add(@as(isize, @intCast(new_len)) - @as(isize, @intCast(memory.len)));
        return result;
    }
    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self = from(context);
        self.parent.rawFree(memory, alignment, ret);
        self.add(-@as(isize, @intCast(memory.len)));
    }
};

fn exclusiveDone(worker: anytype) bool {
    return worker.exclusive_done;
}

/// Finalizes over disjoint position ranges on the pool. Each position is the
/// same ordered sum the serial finalizer computes; cases the serial finalizer
/// handles specially (aggregate polynomial extension, ownership transfer of
/// a sole full-domain bucket, small domains) delegate to it unchanged.
fn finalizeParallel(
    accumulator: *accumulation.DomainEvaluationAccumulator,
    pool: *work_pool.WorkPool,
) anyerror!SecureColumnByCoords {
    if (accumulator.next_power_index != 0) return accumulator.finalize();
    if (accumulator.hasPolynomialExtensions()) return accumulator.finalize();
    if (accumulator.max_log_size >= @bitSizeOf(usize) or accumulator.max_log_size < 16)
        return accumulator.finalize();
    var nonconstant: usize = 0;
    var only_log: usize = 0;
    for (accumulator.sub_accumulations, 0..) |bucket, log_size| {
        if (bucket != null) {
            nonconstant += 1;
            only_log = log_size;
        }
    }
    if (nonconstant == 0 or (nonconstant == 1 and only_log == accumulator.max_log_size))
        return accumulator.finalize();
    const available = pool.availableWorkers();
    if (pool.workerCount() <= 1 or available <= 1) return accumulator.finalize();
    var lease = pool.acquire(work_pool.WorkerBudget.init(available) catch return accumulator.finalize()) catch
        return accumulator.finalize();
    defer lease.deinit();

    const size = @as(usize, 1) << @intCast(accumulator.max_log_size);
    var out = try SecureColumnByCoords.uninitialized(accumulator.allocator, size);
    errdefer out.deinit(accumulator.allocator);
    const Job = struct {
        accumulator: *const accumulation.DomainEvaluationAccumulator,
        out: *SecureColumnByCoords,
        start: usize,
        end: usize,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.accumulator.finalizeRangeInto(self.out, self.start, self.end) catch |err| {
                self.failure = err;
            };
        }
    };
    const count = lease.workerCount();
    var jobs: [work_pool.MAX_WORKERS]Job = undefined;
    for (jobs[0..count], 0..) |*job, index| job.* = .{
        .accumulator = accumulator,
        .out = &out,
        .start = size * index / count,
        .end = size * (index + 1) / count,
    };
    {
        var group = std.Thread.WaitGroup{};
        defer {
            group.wait();
            lease.completeWave();
        }
        var submitted: usize = 1;
        while (submitted < count) : (submitted += 1) {
            lease.spawnWg(&group, Job.run, .{&jobs[submitted]}) catch break;
        }
        for (jobs[submitted..count]) |*job| job.run();
        jobs[0].run();
    }
    for (jobs[0..count]) |job| if (job.failure) |err| return err;
    return out;
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

fn executePreparedGraph(graph: *task_graph.ComponentTaskGraph, execution: composition_execution.Execution, workers: anytype) !void {
    const adjusted = execution.adjustedForAvailablePool();
    _ = graph.execute(.{
        .worker_budget = adjusted.worker_budget,
        .pool = adjusted.pool,
        .ready_policy = .critical_path,
        .task_profile_recorder = execution.task_recorder,
        .task_profile_graph_id = "cpu_composition_generic",
        .requested_worker_count = execution.requestedWorkerCount(),
        .pool_capacity = execution.poolCapacity(),
    }) catch |failure| switch (failure) {
        // The ordinary prover does not promise exclusive ownership of the
        // process-wide pool. Contention is therefore a scheduling decline,
        // not a proof failure: no task has started when lease admission fails,
        // so the exact prepared plan can execute serially without rebuilding
        // or reallocating component state. This compatibility fallback is not
        // an M7 scaling arm; the explicit request executor must report a lease
        // decline rather than relabel it as the requested worker count.
        error.WorkerBudgetUnavailable => if (!execution.isStrict())
            graph.execute(.{
                .worker_budget = work_pool.WorkerBudget.serial(),
                .ready_policy = .critical_path,
                .task_profile_recorder = execution.task_recorder,
                .task_profile_graph_id = "cpu_composition_generic",
                .requested_worker_count = execution.requestedWorkerCount(),
                .pool_capacity = execution.poolCapacity(),
            }) catch |retry_failure| {
                if (firstWorkerError(workers)) |err| return err;
                prover_api.EvaluationDiagnostic.recordFirst(
                    execution.evaluation_diagnostic,
                    .{
                        .stage = if (retry_failure == error.WorkerBudgetUnavailable)
                            .plan
                        else
                            .component_evaluation,
                        .cause = retry_failure,
                    },
                );
                return retry_failure;
            }
        else {
            prover_api.EvaluationDiagnostic.recordFirst(
                execution.evaluation_diagnostic,
                .{ .stage = .plan, .cause = failure },
            );
            return failure;
        },
        else => {
            if (firstWorkerError(workers)) |err| return err;
            prover_api.EvaluationDiagnostic.recordFirst(execution.evaluation_diagnostic, .{
                .stage = .component_evaluation,
                .cause = failure,
            });
            return failure;
        },
    };
}
