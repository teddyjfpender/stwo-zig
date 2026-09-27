//! One bounded preparation stage overlapped with one persistent proving worker.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const artifact = @import("blake3_native_parent_artifact.zig");
pub const MAX_JOBS = 64;
pub const PREPARATION_STACK_BYTES = 8 * 1024 * 1024;
pub const Sizing = struct {
    preparation_workers: usize = 1,
    preparation_bytes: usize,
    worker_bytes: usize,
    queued_bytes: usize,
    external_reserved_bytes: usize,
};
pub const Admission = struct {
    cpu_tokens: usize,
    reserved_bytes: usize,
    worker_count: usize,
    preparation_workers: usize,
};
pub fn admit(comptime Adapter: type, policy: anytype, sizing: Sizing, count: usize) !Admission {
    try policy.validate();
    if (count == 0 or count > MAX_JOBS or sizing.preparation_bytes == 0 or sizing.worker_bytes == 0 or sizing.queued_bytes == 0) return error.InvalidParentPipelineLimits;
    if (sizing.preparation_workers == 0 or sizing.preparation_workers > 2) return error.InvalidParentPipelineLimits;
    if (sizing.preparation_workers > 1 and !@hasDecl(Adapter, "prepareWithPool")) return error.UnsupportedParallelParentPreparation;
    const workers = try policy.engineWorkerCount();
    const cpu = try std.math.add(usize, workers, sizing.preparation_workers);
    if (cpu > policy.total_cpu_tokens or cpu > policy.cpu_tokens_per_node) return error.ParentPipelineCpuBudgetExceeded;
    var bytes = try std.math.add(usize, sizing.preparation_bytes, sizing.worker_bytes);
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, 2, sizing.queued_bytes));
    bytes = try std.math.add(usize, bytes, sizing.external_reserved_bytes);
    bytes = try std.math.add(usize, bytes, PREPARATION_STACK_BYTES);
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, workers - 1, engine.work_pool.WORKER_STACK_SIZE));
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, sizing.preparation_workers - 1, engine.work_pool.WORKER_STACK_SIZE));
    const controls = @sizeOf(Adapter.Worker) + 4 * @sizeOf(engine.host_budget_allocator.SharedHostBudget) + 2 * @sizeOf(Adapter.Prepared) + 4096;
    bytes = try std.math.add(usize, bytes, controls);
    bytes = try std.math.add(usize, bytes, try std.math.mul(usize, count, @sizeOf(artifact.Owned) + @sizeOf(Spans)));
    if (bytes > policy.total_rss_bytes or bytes > policy.rss_bytes_per_node) return error.ParentPipelineMemoryBudgetExceeded;
    return .{ .cpu_tokens = cpu, .reserved_bytes = bytes, .worker_count = workers, .preparation_workers = sizing.preparation_workers };
}

pub const Interval = struct { start: u64 = 0, end: u64 = 0 };
pub const Spans = struct { preparation: Interval = .{}, proving: Interval = .{} };
pub const Report = struct {
    allocator: std.mem.Allocator,
    outputs: []artifact.Owned,
    spans: []Spans,
    admission: Admission,
    pub fn deinit(self: *Report) void {
        for (self.outputs) |*output| output.deinit();
        self.allocator.free(self.outputs);
        self.allocator.free(self.spans);
        self.* = undefined;
    }
    pub fn overlapNs(self: *const Report) u64 {
        var total: u64 = 0;
        for (self.spans, 0..) |a, i| for (self.spans, 0..) |b, j| {
            if (i == j) continue;
            const start = @max(a.preparation.start, b.proving.start);
            const end = @min(a.preparation.end, b.proving.end);
            if (end > start) total += end - start;
        };
        return total;
    }
};

/// Inputs and worker outlive this call. Output allocations retain worker-budget
/// leases. Policy must be the caller's validated execution authority; this local
/// runner does not mint or publish a production execution key.
pub fn run(comptime Adapter: type, a: std.mem.Allocator, policy: anytype, sizing: Sizing, worker: *Adapter.Worker, jobs: []const Adapter.Job) !Report {
    const Handoff = @import("owned_handoff.zig").Handoff(Adapter.Prepared);
    const admission = try admit(Adapter, policy, sizing, jobs.len);
    // Reserve the worker before allocating or starting preparation, and retain
    // ownership through producer cancellation/join on every exit path.
    var lease = try worker.acquire();
    defer lease.deinit();
    if (worker.pool.workerCount() != admission.worker_count or worker.budget.snapshot().limit != sizing.worker_bytes) return error.ParentPipelineWorkerMismatch;
    const spans = try a.alloc(Spans, jobs.len);
    errdefer a.free(spans);
    @memset(spans, .{});
    const outputs = try a.alloc(artifact.Owned, jobs.len);
    var completed: usize = 0;
    errdefer {
        for (outputs[0..completed]) |*output| output.deinit();
        a.free(outputs);
    }
    var queue = try Handoff.init(a, 1, sizing.queued_bytes);
    defer queue.deinit();
    const epoch = try std.time.Instant.now();
    const Producer = struct {
        allocator: std.mem.Allocator,
        jobs: []const Adapter.Job,
        spans: []Spans,
        queue: *Handoff,
        epoch: std.time.Instant,
        limit: usize,
        preparation_workers: usize,
        failure: ?anyerror = null,
        cancelled: std.atomic.Value(bool) = .init(false),
        fn execute(self: *@This()) void {
            defer self.queue.close();
            self.produce() catch |err| {
                self.failure = err;
            };
        }
        fn produce(self: *@This()) !void {
            var pool: engine.work_pool.WorkPool = undefined;
            try pool.initInPlaceWithOptions(.{ .worker_count = self.preparation_workers, .backing_allocator = self.allocator });
            defer pool.deinit();
            var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
            defer binding.deinit();
            for (self.jobs, self.spans) |job, *span| {
                if (self.cancelled.load(.acquire)) return;
                span.preparation.start = (try std.time.Instant.now()).since(self.epoch);
                var owned: ?Adapter.Prepared = if (@hasDecl(Adapter, "prepareWithPool")) try Adapter.prepareWithPool(self.allocator, job, self.limit, &pool) else try Adapter.prepare(self.allocator, job, self.limit);
                defer if (owned) |*value| value.deinit();
                span.preparation.end = (try std.time.Instant.now()).since(self.epoch);
                try self.queue.send(&owned);
            }
        }
    };
    var producer = Producer{ .allocator = a, .jobs = jobs, .spans = spans, .queue = &queue, .epoch = epoch, .limit = sizing.preparation_bytes, .preparation_workers = admission.preparation_workers };
    const thread = try std.Thread.spawn(.{ .stack_size = PREPARATION_STACK_BYTES }, Producer.execute, .{&producer});
    var joined = false;
    defer if (!joined) {
        producer.cancelled.store(true, .release);
        queue.cancel();
        thread.join();
    };
    while (queue.receive()) |value| {
        var prepared = value;
        defer prepared.deinit();
        spans[completed].proving.start = (try std.time.Instant.now()).since(epoch);
        outputs[completed] = try Adapter.prove(&lease, &prepared, jobs[completed]);
        completed += 1;
        spans[completed - 1].proving.end = (try std.time.Instant.now()).since(epoch);
    }
    thread.join();
    joined = true;
    if (producer.failure) |err| return err;
    if (completed != jobs.len) return error.IncompleteParentPipeline;
    return .{ .allocator = a, .outputs = outputs, .spans = spans, .admission = admission };
}
