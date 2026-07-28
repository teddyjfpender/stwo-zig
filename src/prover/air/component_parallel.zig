//! Parallel composition scheduling for heterogeneous AIR components.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const accumulation = @import("accumulation.zig");
const secure_column = @import("../secure_column.zig");
const work_pool = @import("../work_pool.zig");

const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

/// Evaluates components into independent coefficient ranges, then combines
/// their domain buckets in protocol order. At most one component may subdivide
/// its own domain through `pool`; all other jobs are leaf work items.
pub fn compute(
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
        worker.* = .{
            .component = component,
            .trace = trace,
            .accumulator = try accumulation.DomainEvaluationAccumulator.initForComponent(
                powers,
                allocator,
                max_log_size,
                power_cursor,
            ),
        };
        initialized_workers += 1;
        power_cursor -= component.nConstraints();
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
    for (workers[1..]) |*worker|
        workers[0].accumulator.merge(&worker.accumulator);
    workers[0].accumulator.next_power_index = 0;
    return workers[0].accumulator.finalize();
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
