//! One lazily started request thread, reused until joined shutdown. Callbacks
//! execute outside the state lock; caller-owned job storage lives through run.
const std = @import("std");
pub const Lane = struct {
    const Job = struct { context: *anyopaque, callback: *const fn (*anyopaque) void };
    requests: std.Thread.Mutex = .{},
    state: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},
    thread: ?std.Thread = null,
    job: ?Job = null,
    stopping: bool = false,
    closed: bool = false,
    starts: u64 = 0,
    completed: u64 = 0,

    /// The lane must have a stable address from first run through shutdown.
    /// A concurrent/reentrant request fails instead of waiting behind its job.
    pub fn run(self: *Lane, context: *anyopaque, callback: *const fn (*anyopaque) void, stack_size: usize) !void {
        if (!self.requests.tryLock()) return error.RequestLaneBusy;
        defer self.requests.unlock();
        self.state.lock();
        defer self.state.unlock();
        if (self.closed or self.stopping) return error.RequestLaneClosed;
        if (self.thread == null) {
            self.thread = try std.Thread.spawn(.{ .stack_size = stack_size }, service, .{self});
            self.starts +|= 1;
        }
        self.job = .{ .context = context, .callback = callback };
        self.changed.signal();
        while (self.job != null) self.changed.wait(&self.state);
    }
    fn service(self: *Lane) void {
        self.state.lock();
        while (true) {
            while (self.job == null and !self.stopping) self.changed.wait(&self.state);
            if (self.stopping) {
                self.state.unlock();
                return;
            }
            const job = self.job.?;
            self.state.unlock();
            job.callback(job.context);
            self.state.lock();
            self.completed +|= 1;
            self.job = null;
            self.changed.broadcast();
        }
    }
    /// Caller first prevents new requests. Busy shutdown leaves the lane live.
    pub fn shutdown(self: *Lane) !void {
        if (!self.requests.tryLock()) return error.RequestLaneBusy;
        defer self.requests.unlock();
        self.state.lock();
        if (self.closed) {
            self.state.unlock();
            return;
        }
        self.stopping = true;
        self.changed.broadcast();
        const thread = self.thread;
        self.state.unlock();
        if (thread) |value| value.join();
        self.state.lock();
        self.thread = null;
        self.closed = true;
        self.state.unlock();
    }
    pub const Stats = struct { starts: u64, completed: u64, active: bool, closed: bool };
    pub fn snapshot(self: *Lane) Stats {
        self.state.lock();
        defer self.state.unlock();
        return .{ .starts = self.starts, .completed = self.completed, .active = self.job != null, .closed = self.closed };
    }
};
