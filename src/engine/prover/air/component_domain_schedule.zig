//! Compatibility-domain scheduling: sequential, heterogeneous and pool-exclusive evaluation.
const std = @import("std");
const prover_api = @import("stwo_prover_api");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("accumulation.zig");
const SecureColumnByCoords = @import("../secure_column.zig").SecureColumnByCoords;
const work_pool = @import("../work_pool.zig");
const queue = @import("component_queue.zig");
const Scheduler = queue.Scheduler;
const QueueOptions = queue.QueueOptions;
const state = @import("component_worker_state.zig");
const validatePowerRanges = state.validatePowerRanges;
const firstWorkerError = state.firstWorkerError;

pub fn computeSequential(
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

pub fn computeLegacy(
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

        pub fn run(self: *@This()) void {
            self.component.evaluateConstraintQuotientsOnDomain(
                self.trace,
                &self.accumulator,
            ) catch |err| {
                self.err = err;
            };
        }

        pub fn runParallel(self: *@This(), shared_pool: *work_pool.WorkPool) void {
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

    if (queue.select(components, scheduler)) {
        return queue.compute(allocator, workers, components, pool, max_log_size, queue_options);
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
