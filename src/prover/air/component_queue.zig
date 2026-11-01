//! Optional cooperative composition scheduling, independent of legacy execution.
const std = @import("std");
const prover_api = @import("stwo_prover_api");
const accumulation = @import("accumulation.zig");
const composition_execution = @import("composition_execution.zig");
const work_pool = @import("../work_pool.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const SecureColumnByCoords = @import("../secure_column.zig").SecureColumnByCoords;
const PeakCounter = @import("component_queue_metrics.zig").PeakCounter;
const state = @import("component_worker_state.zig");
const firstWorkerError = state.firstWorkerError;
const validatePowerRanges = state.validatePowerRanges;

/// Scheduler selection for the unprepared (legacy-capability) path.
/// `auto` preserves the established breadth-first scheduler. The cooperative
/// queue is experimental and requires `STWO_ZIG_COMPOSITION_SCHEDULER=queue`;
/// `legacy` explicitly selects the control path. Both produce identical bytes.
pub const Scheduler = enum { auto, legacy, queue };

/// Options of the cooperative composition queue.
pub const QueueOptions = struct {
    /// Soft admission bound on the estimated working set of components that
    /// are expanded at the same time. One component is always admitted when
    /// none is running, so this never fails a proof. Null selects
    /// `composition_execution.defaultQueueAdmissionBytes`.
    admission_bytes: ?usize = null,
};

fn isCooperative(component: anytype) bool {
    if (comptime !@hasField(@TypeOf(component), "cooperative_domain")) return false;
    return component.cooperative_domain;
}

pub fn select(components: anytype, scheduler: Scheduler) bool {
    switch (scheduler) {
        .legacy => return false,
        .queue => return true,
        .auto => {},
    }
    if (std.process.hasEnvVarConstant("STWO_ZIG_COMPOSITION_SCHEDULER")) {
        const value = std.posix.getenv("STWO_ZIG_COMPOSITION_SCHEDULER") orelse "";
        if (std.mem.eql(u8, value, "legacy")) return false;
        if (!std.mem.eql(u8, value, "queue")) return false;
    } else {
        return false;
    }
    for (components) |component| {
        if (isCooperative(component)) return true;
    }
    return false;
}

test "composition queue remains opt in despite cooperative component capability" {
    if (std.posix.getenv("STWO_ZIG_COMPOSITION_SCHEDULER") != null) return error.SkipZigTest;
    const Component = struct { cooperative_domain: bool };
    const components = [_]Component{.{ .cooperative_domain = true }};
    try std.testing.expect(!select(&components, .auto));
    try std.testing.expect(!select(&components, .legacy));
    try std.testing.expect(select(&components, .queue));
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
pub fn compute(
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
            workers.len,                                            queued,                                                 exclusive_count,
            threads,                                                admission,                                              source.peak_active,
            source.peak_bytes,                                      queue.batches_published,                                queue.batch_tasks_run,
            queue.helped_tasks,                                     @as(f64, @floatFromInt(queue_ns)) / 1e6,                busy_fraction * @as(f64, @floatFromInt(threads)),
            @as(f64, @floatFromInt(exclusive_ns - queue_ns)) / 1e6, @as(f64, @floatFromInt(merge_ns - exclusive_ns)) / 1e6, @as(f64, @floatFromInt(total_ns - merge_ns)) / 1e6,
        });
        if (source.item_start_ns.len != 0) for (components, 0..) |component, index| {
            if (!queueEligible(component)) continue;
            std.log.info("composition queue item: index={} log={} constraints={} estimated_bytes={} peak_allocated_bytes={} start_ms={d:.1} end_ms={d:.1}", .{
                index,                                                                component.maxConstraintLogDegreeBound(),                    component.nConstraints(),                                 bytes[index],
                if (counters.len != 0) counters[index].peak.load(.monotonic) else -1, @as(f64, @floatFromInt(source.item_start_ns[index])) / 1e6, @as(f64, @floatFromInt(source.item_end_ns[index])) / 1e6,
            });
        };
    }
    return result;
}

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
