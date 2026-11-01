//! Bounded independent worker scheduling. Each lane owns a stable intra-proof
//! pool; no helper implicitly creates a process-global pool. Phase barriers
//! belong to the caller and always join every thread before consuming results.
//! Lane count, per-lane workers and the memory admission cap are operational
//! only: every index executes exactly once with the same inputs regardless of
//! which lane runs it or when, so proof bytes cannot depend on the schedule.
const std = @import("std");
const Pool = @import("stwo_prover_engine").work_pool;
const Usage = @import("stwo_prover_api").stage_profile.process_usage;
pub const MAX_LANES = 4;
pub const MAX_TOTAL_WORKERS = 32;
pub const Policy = struct {
    lanes: u8 = 1,
    workers_per_lane: u8 = 8,
    /// Optional per-lane worker override; a zero entry uses workers_per_lane.
    lane_workers: [MAX_LANES]u8 = @splat(0),
    /// Admission cap on the summed estimated bytes of in-flight indices.
    /// Zero disables admission. One index is always admitted when nothing
    /// else is in flight, so an oversized estimate degrades to serial order.
    memory_cap_bytes: u64 = 0,
    pub fn workers(self: Policy, lane: usize) u8 {
        return if (lane < MAX_LANES and self.lane_workers[lane] != 0) self.lane_workers[lane] else self.workers_per_lane;
    }
    /// Reports resolved per-lane workers as numbers ([N]u8 would print as a string).
    pub fn jsonStringify(self: Policy, writer: anytype) !void {
        try writer.beginObject();
        try writer.objectField("lanes");
        try writer.write(self.lanes);
        try writer.objectField("workers_per_lane");
        try writer.write(self.workers_per_lane);
        try writer.objectField("lane_workers");
        try writer.beginArray();
        for (0..@min(self.lanes, MAX_LANES)) |lane| try writer.write(self.workers(lane));
        try writer.endArray();
        try writer.objectField("memory_cap_bytes");
        try writer.write(self.memory_cap_bytes);
        try writer.endObject();
    }
    pub fn validate(self: Policy) !void {
        if (self.lanes == 0 or self.lanes > MAX_LANES or self.workers_per_lane == 0 or self.workers_per_lane > MAX_TOTAL_WORKERS) return error.InvalidServiceSchedule;
        var total: u32 = 0;
        for (0..MAX_LANES) |lane| {
            if (lane >= self.lanes) {
                if (self.lane_workers[lane] != 0) return error.InvalidServiceSchedule;
                continue;
            }
            const w = self.workers(lane);
            if (w == 0 or w > MAX_TOTAL_WORKERS) return error.InvalidServiceSchedule;
            total += w;
        }
        if (total > MAX_TOTAL_WORKERS) return error.InvalidServiceSchedule;
    }
};
/// Optional per-index operational trace; never consumed by proof code.
pub const Trace = struct {
    lane: u8 = 0,
    workers: u8 = 0,
    estimate_bytes: u64 = 0,
    /// Nanoseconds since run start: index claimed, admitted, finished.
    claimed_ns: u64 = 0,
    started_ns: u64 = 0,
    finished_ns: u64 = 0,
    /// Estimated in-flight bytes including this index at admission.
    in_flight_bytes_at_start: u64 = 0,
};
pub const RunOptions = struct {
    /// Empty, or one estimate per index (required when the cap is enabled).
    estimates: []const u64 = &.{},
    /// Empty, or one slot per index.
    trace: []Trace = &.{},
};
/// The context's indexed slots must be disjoint and allocator thread-safe.
/// Default lane1 keeps the caller's already bound pool and old execution path.
pub fn run(comptime Context: type, a: std.mem.Allocator, context: *Context, count: usize, policy: Policy, comptime execute: fn (*Context, usize) anyerror!void) !void {
    return runWithOptions(Context, a, context, count, policy, .{}, execute);
}
/// Lane-local thread handles for attributable CPU telemetry. Storage is owned
/// by the caller and must outlive the binding.
fn laneThreads(pool: ?*Pool.WorkPool, storage: []std.Thread.Handle) Usage.LaneThreads {
    if (comptime @import("builtin").os.tag != .macos) return .{ .handles = &.{} };
    storage[0] = std.c.pthread_self();
    var n: usize = 1;
    if (pool) |p| if (p.pool_initialized) for (p.pool.threads) |thread| {
        if (n == storage.len) break;
        storage[n] = thread.getHandle();
        n += 1;
    };
    return .{ .handles = storage[0..n] };
}
pub fn runWithOptions(comptime Context: type, a: std.mem.Allocator, context: *Context, count: usize, policy: Policy, options: RunOptions, comptime execute: fn (*Context, usize) anyerror!void) !void {
    try policy.validate();
    if (options.estimates.len != 0 and options.estimates.len != count) return error.InvalidServiceSchedule;
    if (options.trace.len != 0 and options.trace.len != count) return error.InvalidServiceSchedule;
    if (policy.memory_cap_bytes != 0 and options.estimates.len != count) return error.MissingServiceMemoryEstimates;
    if (count == 0) return;
    var timer = try std.time.Timer.start();
    if (policy.lanes == 1 or count == 1) {
        var storage: [MAX_TOTAL_WORKERS + 1]std.Thread.Handle = undefined;
        const lane = laneThreads(Pool.currentScopedPool(), &storage);
        const previous = Usage.bindLane(&lane);
        defer _ = Usage.bindLane(previous);
        for (0..count) |index| {
            const start = timer.read();
            const estimate = if (options.estimates.len != 0) options.estimates[index] else 0;
            try execute(context, index);
            if (options.trace.len != 0) options.trace[index] = .{ .lane = 0, .workers = @intCast(if (Pool.currentScopedPool()) |p| p.workerCount() else 1), .estimate_bytes = estimate, .claimed_ns = start, .started_ns = start, .finished_ns = timer.read(), .in_flight_bytes_at_start = estimate };
        }
        return;
    }
    const Shared = struct {
        context: *Context,
        count: usize,
        policy: Policy,
        options: RunOptions,
        allocator: std.mem.Allocator,
        timer: *std.time.Timer,
        next: std.atomic.Value(usize) = .init(0),
        stop: std.atomic.Value(bool) = .init(false),
        errors: []?anyerror,
        lane_errors: [MAX_LANES]?anyerror = @splat(null),
        mutex: std.Thread.Mutex = .{},
        admitted: std.Thread.Condition = .{},
        in_flight: u64 = 0,
        fn fail(self: *@This()) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.stop.store(true, .release);
            self.admitted.broadcast();
        }
        /// Blocks until the estimate fits beside every in-flight index.
        fn admit(self: *@This(), estimate: u64) ?u64 {
            self.mutex.lock();
            defer self.mutex.unlock();
            const cap = self.policy.memory_cap_bytes;
            while (cap != 0 and self.in_flight != 0 and self.in_flight +| estimate > cap) {
                if (self.stop.load(.acquire)) return null;
                self.admitted.wait(&self.mutex);
            }
            if (self.stop.load(.acquire)) return null;
            self.in_flight += estimate;
            return self.in_flight;
        }
        fn release(self: *@This(), estimate: u64) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.in_flight -= estimate;
            self.admitted.broadcast();
        }
        fn lane(self: *@This(), ordinal: usize) void {
            var pool: Pool.WorkPool = .{};
            pool.initInPlaceWithOptions(.{ .worker_count = self.policy.workers(ordinal), .stack_size = 1024 * 1024, .backing_allocator = self.allocator }) catch |err| {
                self.lane_errors[ordinal] = err;
                self.fail();
                return;
            };
            defer pool.deinit();
            var binding = Pool.ScopedPoolBinding.init(&pool) catch |err| {
                self.lane_errors[ordinal] = err;
                self.fail();
                return;
            };
            defer binding.deinit();
            var storage: [MAX_TOTAL_WORKERS + 1]std.Thread.Handle = undefined;
            const threads = laneThreads(&pool, &storage);
            const previous = Usage.bindLane(&threads);
            defer _ = Usage.bindLane(previous);
            while (!self.stop.load(.acquire)) {
                const index = self.next.fetchAdd(1, .monotonic);
                if (index >= self.count) return;
                const claimed = self.timer.read();
                const estimate = if (self.options.estimates.len != 0) self.options.estimates[index] else 0;
                const in_flight = self.admit(estimate) orelse return;
                const started = self.timer.read();
                const result = execute(self.context, index);
                self.release(estimate);
                if (self.options.trace.len != 0) self.options.trace[index] = .{ .lane = @intCast(ordinal), .workers = self.policy.workers(ordinal), .estimate_bytes = estimate, .claimed_ns = claimed, .started_ns = started, .finished_ns = self.timer.read(), .in_flight_bytes_at_start = in_flight };
                result catch |err| {
                    self.errors[index] = err;
                    self.fail();
                    return;
                };
            }
        }
    };
    const errors = try a.alloc(?anyerror, count);
    defer a.free(errors);
    @memset(errors, null);
    var shared = Shared{ .context = context, .count = count, .policy = policy, .options = options, .allocator = a, .timer = &timer, .errors = errors };
    var threads: [MAX_LANES]std.Thread = undefined;
    var spawned: usize = 0;
    // Spawn failure also joins every started task before caller cleanup.
    errdefer {
        shared.fail();
        for (threads[0..spawned]) |thread| thread.join();
    }
    for (0..@min(count, policy.lanes)) |ordinal| {
        threads[ordinal] = try std.Thread.spawn(.{}, Shared.lane, .{ &shared, ordinal });
        spawned += 1;
    }
    for (threads[0..spawned]) |thread| thread.join();
    spawned = 0;
    for (shared.lane_errors) |err| if (err) |failure| return failure;
    for (errors) |err| if (err) |failure| return failure;
}
