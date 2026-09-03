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
