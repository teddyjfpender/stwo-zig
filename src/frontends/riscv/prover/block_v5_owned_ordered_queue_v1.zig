//! One bounded ordered coordinator for independently owned payloads. This is
//! scheduling/ownership only; callbacks supply all verification authority.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Boundary = @import("block_v5_proof_boundary_v1.zig").Boundary;
pub const Options = struct {
    /// Maximum waiting captures, plus one active ordered coordinator.
    /// Single producer calls waitForSlot before creating the next capture.
    capacity: usize = 1,
    pub fn validate(self: Options) !void {
        if (self.capacity == 0 or self.capacity > 64) return error.InvalidV5OwnedQueueOptions;
    }
};
pub const Statistics = struct { submitted: usize = 0, completed: usize = 0, cancelled: usize = 0, queued: usize = 0, active: usize = 0, peak_pending: usize = 0, peak_owned: usize = 0 };
pub fn ForPayload(comptime Payload: type) type {
    return struct {
        const Self = @This();
        pub const Callbacks = struct {
            context: *anyopaque,
            run: *const fn (*anyopaque, u32, *Payload) anyerror!void,
            /// Always destroys payload on completion, failure or cancellation.
            destroy: *const fn (*anyopaque, *Payload) void,
        };
        const Job = struct { index: u32, payload: Payload };
        a: std.mem.Allocator,
        pool: *engine.work_pool.WorkPool,
        jobs: []Job,
        callbacks: Callbacks,
        expected: u32,
        external: ?Boundary,
        thread: ?std.Thread = null,
        head: usize = 0,
        closing: bool = false,
        aborting: bool = false,
        joined: bool = false,
        failure: ?anyerror = null,
        stats: Statistics = .{},
        mutex: std.Thread.Mutex = .{},
        changed: std.Thread.Condition = .{},
        pub fn start(a: std.mem.Allocator, pool: *engine.work_pool.WorkPool, expected: u32, callbacks: Callbacks, options: Options, external: ?Boundary) !*Self {
            try options.validate();
            const self = try a.create(Self);
            errdefer a.destroy(self);
            const jobs = try a.alloc(Job, options.capacity);
            errdefer a.free(jobs);
            self.* = .{ .a = a, .pool = pool, .jobs = jobs, .callbacks = callbacks, .expected = expected, .external = external };
            self.thread = try std.Thread.spawn(.{ .stack_size = engine.work_pool.WORKER_STACK_SIZE }, worker, .{self});
            return self;
        }
        pub fn deinit(self: *Self) void {
            self.abort();
            const a = self.a;
            a.free(self.jobs);
            a.destroy(self);
        }
        pub fn snapshot(self: *Self) Statistics {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.stats;
        }
        pub fn requireHealthy(self: *Self) !void {
            self.mutex.lock();
            const failure = self.failure;
            const aborting = self.aborting;
            self.mutex.unlock();
            if (failure) |err| return err;
            if (aborting) return error.AbortedV5OwnedQueue;
            if (self.external) |external| try external.check(external.context);
        }
        pub fn boundary(self: *Self) Boundary {
            return .{ .context = self, .check = checkBoundary };
        }
        fn checkBoundary(raw: *anyopaque) !void {
            const self: *Self = @ptrCast(@alignCast(raw));
            try self.requireHealthy();
        }
        /// Single foreground producer only. An available slot cannot be taken
        /// by another producer before capture creation/submit in this contract.
        pub fn waitForSlot(self: *Self, index: u32) !void {
            try self.requireHealthy();
            self.mutex.lock();
            defer self.mutex.unlock();
            if (index != self.stats.submitted or index >= self.expected) return error.InvalidV5OwnedQueueOrder;
            while (self.stats.queued == self.jobs.len and !self.closing and self.failure == null) self.changed.wait(&self.mutex);
            if (self.failure) |err| return err;
            if (self.closing) return error.ClosedV5OwnedQueue;
            if (index != self.stats.submitted or index >= self.expected) return error.InvalidV5OwnedQueueOrder;
        }
        /// Success transfers payload and poisons caller storage. Error leaves
        /// ownership with the caller. The queue never clones the payload.
        pub fn submit(self: *Self, index: u32, payload: *Payload) !void {
            try self.waitForSlot(index);
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.failure) |err| return err;
            if (self.closing) return error.ClosedV5OwnedQueue;
            if (index != self.stats.submitted or index >= self.expected) return error.InvalidV5OwnedQueueOrder;
            const slot = (self.head + self.stats.queued) % self.jobs.len;
            self.jobs[slot] = .{ .index = index, .payload = payload.* };
            payload.* = undefined;
            self.stats.submitted += 1;
            self.stats.queued += 1;
            self.stats.peak_pending = @max(self.stats.peak_pending, self.stats.queued);
            self.stats.peak_owned = @max(self.stats.peak_owned, self.stats.queued + self.stats.active);
            self.changed.broadcast();
        }
        /// Lifecycle operations are invoked by the one foreground owner.
        /// Joining precedes every borrowed callback/pool/cache/admission teardown.
        pub fn abort(self: *Self) void {
            self.closeAndJoin(true);
        }
        pub fn finish(self: *Self) !Statistics {
            self.closeAndJoin(false);
            try self.requireHealthy();
            if (self.stats.submitted != self.expected or self.stats.completed != self.expected or self.stats.queued != 0 or self.stats.active != 0) return error.IncompleteV5OwnedQueue;
            return self.stats;
        }
        fn closeAndJoin(self: *Self, cancel: bool) void {
            if (self.joined) return;
            self.mutex.lock();
            self.closing = true;
            if (cancel) self.aborting = true;
            self.changed.broadcast();
            self.mutex.unlock();
            if (self.thread) |thread| thread.join();
            self.joined = true;
            // Worker has relinquished all accesses; destroy unpublished queued
            // owners without holding a lock over potentially large frees.
            while (true) {
                self.mutex.lock();
                if (self.stats.queued == 0) {
                    self.mutex.unlock();
                    break;
                }
                var job = self.jobs[self.head];
                self.head = (self.head + 1) % self.jobs.len;
                self.stats.queued -= 1;
                self.stats.cancelled += 1;
                self.mutex.unlock();
                self.callbacks.destroy(self.callbacks.context, &job.payload);
            }
        }
        fn runJob(self: *Self, job: *Job) !void {
            try self.requireHealthy();
            var binding = try engine.work_pool.ScopedPoolBinding.init(self.pool);
            defer binding.deinit();
            try self.callbacks.run(self.callbacks.context, job.index, &job.payload);
        }
        fn worker(self: *Self) void {
            while (true) {
                self.mutex.lock();
                while (self.stats.queued == 0 and !self.closing and self.failure == null) self.changed.wait(&self.mutex);
                if (self.aborting or self.failure != null or (self.closing and self.stats.queued == 0)) {
                    self.mutex.unlock();
                    return;
                }
                var job = self.jobs[self.head];
                self.head = (self.head + 1) % self.jobs.len;
                self.stats.queued -= 1;
                self.stats.active = 1;
                self.changed.broadcast();
                self.mutex.unlock();
                var failure: ?anyerror = null;
                self.runJob(&job) catch |err| {
                    failure = err;
                };
                self.callbacks.destroy(self.callbacks.context, &job.payload);
                self.mutex.lock();
                self.stats.active = 0;
                if (failure) |err| {
                    if (self.failure == null) self.failure = err;
                    self.closing = true;
                } else self.stats.completed += 1;
                self.changed.broadcast();
                self.mutex.unlock();
            }
        }
    };
}
