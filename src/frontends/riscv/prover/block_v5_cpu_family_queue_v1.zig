//! Bounded coordinators for independent, already sealed proof families.
//! Helpers use the driver's one WorkPool; whole proofs never occupy helper
//! threads, so a proof can acquire nested structured leases without deadlock.
//! Reservations bound simultaneous admitted jobs. All job allocations still
//! use the driver's synchronized, hard aggregate HostBudget allocator.
const std = @import("std");
const engine = @import("stwo_prover_engine");

pub const Family = enum { caller, memory, program, lookup };
pub const Options = struct {
    coordinators: usize = 2,
    capacity: usize = 4,
    reservation_limit: usize = 16 * 1024 * 1024 * 1024,
    family_reservation: usize = 8 * 1024 * 1024 * 1024,

    pub fn validate(self: Options, aggregate_limit: usize) !void {
        if (self.coordinators == 0 or self.coordinators > engine.work_pool.MAX_WORKERS or
            self.capacity == 0 or self.capacity > 64 or self.reservation_limit == 0 or
            self.family_reservation == 0 or self.family_reservation > self.reservation_limit or
            self.reservation_limit >= aggregate_limit)
            return error.InvalidV5FamilyQueueOptions;
    }
};
pub const Job = struct {
    family: Family,
    context: *anyopaque,
    reservation: usize,
    /// Borrowed context must survive finish/abort. Success means publication
    /// completed, not that the family has acquired verifier authority.
    run: *const fn (*anyopaque) anyerror!void,
};
pub const Statistics = struct {
    submitted: usize = 0,
    completed: usize = 0,
    cancelled: usize = 0,
    active: usize = 0,
    peak_active: usize = 0,
    queued: usize = 0,
    live_reservation: usize = 0,
    peak_reservation: usize = 0,
    /// Overlapping family wall times; these must not be added as E2E time.
    family_ns: [4]u64 = @splat(0),
};

pub const Queue = struct {
    a: std.mem.Allocator,
    pool: *engine.work_pool.WorkPool,
    options: Options,
    jobs: []Job,
    threads: []std.Thread,
    started: usize = 0,
    head: usize = 0,
    closing: bool = false,
    aborting: bool = false,
    joined: bool = false,
    failure: ?anyerror = null,
    statistics: Statistics = .{},
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},

    pub fn start(a: std.mem.Allocator, pool: *engine.work_pool.WorkPool, options: Options, aggregate_limit: usize) !*Queue {
        try options.validate(aggregate_limit);
        const self = try a.create(Queue);
        errdefer a.destroy(self);
        const jobs = try a.alloc(Job, options.capacity);
        errdefer a.free(jobs);
        const threads = try a.alloc(std.Thread, options.coordinators);
        errdefer a.free(threads);
        self.* = .{ .a = a, .pool = pool, .options = options, .jobs = jobs, .threads = threads };
        errdefer self.closeAndJoin(true);
        for (threads) |*thread| {
            thread.* = try std.Thread.spawn(.{ .stack_size = engine.work_pool.WORKER_STACK_SIZE }, worker, .{self});
            self.started += 1;
        }
        return self;
    }

    pub fn deinit(self: *Queue) void {
        self.closeAndJoin(true);
        const a = self.a;
        a.free(self.threads);
        a.free(self.jobs);
        a.destroy(self);
    }

    pub fn abort(self: *Queue) void {
        self.closeAndJoin(true);
    }

    pub fn submit(self: *Queue, job: Job) !void {
        if (job.reservation == 0 or job.reservation > self.options.reservation_limit)
            return error.InvalidV5FamilyReservation;
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.statistics.queued == self.jobs.len and !self.closing and self.failure == null)
            self.changed.wait(&self.mutex);
        if (self.failure) |err| return err;
        if (self.closing) return error.ClosedV5FamilyQueue;
        const slot = (self.head + self.statistics.queued) % self.jobs.len;
        self.jobs[slot] = job;
        self.statistics.queued += 1;
        self.statistics.submitted += 1;
        self.changed.broadcast();
    }

    /// Error/cancellation joins active readers before any borrowed roster,
    /// writer, trace-source metadata or staged witness owner can be released.
    pub fn finish(self: *Queue) !Statistics {
        self.closeAndJoin(false);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.failure) |err| return err;
        if (self.aborting) return error.AbortedV5FamilyQueue;
        if (self.statistics.completed != self.statistics.submitted or
            self.statistics.active != 0 or self.statistics.queued != 0 or
            self.statistics.live_reservation != 0)
            return error.IncompleteV5FamilyQueue;
        return self.statistics;
    }

    pub fn snapshot(self: *Queue) Statistics {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.statistics;
    }

    /// Called at owned proof boundaries so a failing family does not let the
    /// foreground or another long family continue publishing later proofs.
    pub fn requireHealthy(self: *Queue) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.failure) |err| return err;
        if (self.aborting) return error.AbortedV5FamilyQueue;
    }

    pub fn boundary(self: *Queue) @import("block_v5_proof_boundary_v1.zig").Boundary {
        return .{ .context = self, .check = checkBoundary };
    }
    fn checkBoundary(raw: *anyopaque) !void {
        const self: *Queue = @ptrCast(@alignCast(raw));
        try self.requireHealthy();
    }

    fn cancelQueued(self: *Queue) void {
        self.statistics.cancelled += self.statistics.queued;
        self.statistics.queued = 0;
    }

    fn closeAndJoin(self: *Queue, cancel: bool) void {
        if (self.joined) return;
        self.mutex.lock();
        self.closing = true;
        if (cancel) {
            self.aborting = true;
            self.cancelQueued();
        }
        self.changed.broadcast();
        self.mutex.unlock();
        for (self.threads[0..self.started]) |thread| thread.join();
        self.joined = true;
    }

    fn runJob(self: *Queue, job: Job) !u64 {
        var timer = try std.time.Timer.start();
        var binding = try engine.work_pool.ScopedPoolBinding.init(self.pool);
        defer binding.deinit();
        try job.run(job.context);
        return timer.read();
    }

    fn worker(self: *Queue) void {
        while (true) {
            self.mutex.lock();
            while (true) {
                if (self.aborting or self.failure != null or (self.closing and self.statistics.queued == 0)) {
                    self.mutex.unlock();
                    return;
                }
                if (self.statistics.queued != 0 and
                    self.jobs[self.head].reservation <= self.options.reservation_limit - self.statistics.live_reservation) break;
                self.changed.wait(&self.mutex);
            }
            const job = self.jobs[self.head];
            self.head = (self.head + 1) % self.jobs.len;
            self.statistics.queued -= 1;
            self.statistics.active += 1;
            self.statistics.peak_active = @max(self.statistics.peak_active, self.statistics.active);
            self.statistics.live_reservation += job.reservation;
            self.statistics.peak_reservation = @max(self.statistics.peak_reservation, self.statistics.live_reservation);
            self.changed.broadcast();
            self.mutex.unlock();
            var failure: ?anyerror = null;
            const elapsed = self.runJob(job) catch |err| value: {
                failure = err;
                break :value 0;
            };
            self.mutex.lock();
            self.statistics.active -= 1;
            self.statistics.live_reservation -= job.reservation;
            if (failure) |err| {
                if (self.failure == null) self.failure = err;
                self.closing = true;
                self.cancelQueued();
            } else {
                self.statistics.completed += 1;
                self.statistics.family_ns[@intFromEnum(job.family)] +|= elapsed;
            }
            self.changed.broadcast();
            self.mutex.unlock();
        }
    }
};
