//! Process-wide proving worker pool with explicit per-request leases.
//!
//! Existing callers may continue to submit directly. Structured task graphs
//! use `WorkerBudget` and `WorkLease` so a request cannot silently exceed its
//! admitted worker count or enqueue an unbounded wave of helper jobs.

const std = @import("std");
const builtin = @import("builtin");

/// Fixed storage ceiling, not a scheduling target.
pub const MAX_WORKERS: usize = 32;
pub const WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;

pub const WorkPoolError = error{
    InvalidStackSize,
    InvalidWorkerBudget,
    SingleThreaded,
    WorkerBudgetUnavailable,
    SubmissionLimitExceeded,
};

/// A request budget counts the coordinator as worker zero.
pub const WorkerBudget = struct {
    count: usize,

    pub fn init(count: usize) WorkPoolError!WorkerBudget {
        if (count == 0 or count > MAX_WORKERS) {
            return error.InvalidWorkerBudget;
        }
        return .{ .count = count };
    }

    pub fn serial() WorkerBudget {
        return .{ .count = 1 };
    }

    pub fn helperCount(self: WorkerBudget) usize {
        return self.count - 1;
    }
};

pub const InitOptions = struct {
    worker_count: usize,
    stack_size: usize = WORKER_STACK_SIZE,
};

pub const WorkPool = struct {
    pool: std.Thread.Pool = undefined,
    n_workers: usize = 0,
    worker_stack_size: usize = WORKER_STACK_SIZE,
    pool_initialized: bool = false,
    lease_mutex: std.Thread.Mutex = .{},
    leased_workers: usize = 0,

    /// Initializes at the final address because worker threads retain a
    /// pointer to `std.Thread.Pool`.
    pub fn initInPlace(self: *WorkPool) !void {
        const worker_count = detectWorkerCount();
        if (worker_count <= 1) return error.SingleThreaded;
        try self.initInPlaceWithOptions(.{ .worker_count = worker_count });
    }

    /// Explicit initialization is primarily useful to deterministic executors
    /// and tests. A one-worker pool owns no helper threads but can still admit
    /// a serial lease.
    pub fn initInPlaceWithOptions(self: *WorkPool, options: InitOptions) !void {
        if (options.worker_count == 0 or options.worker_count > MAX_WORKERS) {
            return error.InvalidWorkerBudget;
        }
        if (options.stack_size == 0) return error.InvalidStackSize;
        self.* = .{
            .n_workers = options.worker_count,
            .worker_stack_size = options.stack_size,
        };
        if (options.worker_count == 1) return;

        try self.pool.init(.{
            .allocator = std.heap.page_allocator,
            .n_jobs = options.worker_count - 1,
            .stack_size = options.stack_size,
        });
        self.pool_initialized = true;
    }

    pub fn deinit(self: *WorkPool) void {
        self.lease_mutex.lock();
        const leases_drained = self.leased_workers == 0;
        self.lease_mutex.unlock();
        std.debug.assert(leases_drained);
        if (self.pool_initialized) self.pool.deinit();
        self.* = undefined;
    }

    /// Compatibility path for existing kernels. New structured scheduling
    /// should acquire a lease and submit through `WorkLease.spawnWg`.
    pub fn spawnWg(
        self: *WorkPool,
        wg: *std.Thread.WaitGroup,
        comptime func: anytype,
        args: anytype,
    ) void {
        if (!self.pool_initialized) {
            @call(.auto, func, args);
            return;
        }
        self.pool.spawnWg(wg, func, args);
    }

    pub fn workerCount(self: *const WorkPool) usize {
        return self.n_workers;
    }

    pub fn stackSize(self: *const WorkPool) usize {
        return self.worker_stack_size;
    }

    pub fn acquire(self: *WorkPool, budget: WorkerBudget) WorkPoolError!WorkLease {
        _ = try WorkerBudget.init(budget.count);
        if (budget.count > self.n_workers) return error.WorkerBudgetUnavailable;

        self.lease_mutex.lock();
        defer self.lease_mutex.unlock();
        if (budget.count > self.n_workers - self.leased_workers) {
            return error.WorkerBudgetUnavailable;
        }
        self.leased_workers += budget.count;
        return .{
            .pool = self,
            .budget = budget,
        };
    }

    pub fn availableWorkers(self: *WorkPool) usize {
        self.lease_mutex.lock();
        defer self.lease_mutex.unlock();
        return self.n_workers - self.leased_workers;
    }

    fn release(self: *WorkPool, count: usize) void {
        self.lease_mutex.lock();
        defer self.lease_mutex.unlock();
        std.debug.assert(count <= self.leased_workers);
        self.leased_workers -= count;
    }
};

/// A non-copyable-by-convention request lease. At most `N - 1` helper jobs
/// may be submitted before the caller joins them and calls `completeWave`.
pub const WorkLease = struct {
    pool: *WorkPool,
    budget: WorkerBudget,
    helper_submissions: usize = 0,
    released: bool = false,

    pub fn workerCount(self: *const WorkLease) usize {
        return self.budget.count;
    }

    pub fn helperCount(self: *const WorkLease) usize {
        return self.budget.helperCount();
    }

    pub fn spawnWg(
        self: *WorkLease,
        wg: *std.Thread.WaitGroup,
        comptime func: anytype,
        args: anytype,
    ) WorkPoolError!void {
        if (!self.pool.pool_initialized or
            self.helper_submissions >= self.helperCount())
        {
            return error.SubmissionLimitExceeded;
        }
        self.helper_submissions += 1;
        self.pool.pool.spawnWg(wg, func, args);
    }

    /// Must be called only after the corresponding wait group has drained.
    pub fn completeWave(self: *WorkLease) void {
        self.helper_submissions = 0;
    }

    pub fn deinit(self: *WorkLease) void {
        std.debug.assert(self.helper_submissions == 0);
        std.debug.assert(!self.released);
        self.pool.release(self.budget.count);
        self.released = true;
    }
};

var global_state: struct {
    mutex: std.Thread.Mutex = .{},
    pool: WorkPool = undefined,
    pool_initialized: bool = false,
    init_failed: bool = false,
} = .{};

/// Gets or lazily initializes the process-wide pool. Tests use explicit local
/// pools so their worker budgets and lifetimes remain deterministic.
pub fn getGlobalPool() ?*WorkPool {
    if (comptime builtin.single_threaded) return null;
    if (comptime builtin.is_test) return null;

    global_state.mutex.lock();
    defer global_state.mutex.unlock();

    if (global_state.init_failed) return null;
    if (global_state.pool_initialized) return &global_state.pool;
    global_state.pool.initInPlace() catch {
        global_state.init_failed = true;
        return null;
    };
    global_state.pool_initialized = true;
    return &global_state.pool;
}

fn detectWorkerCount() usize {
    if (!builtin.is_test) {
        if (std.process.getEnvVarOwned(std.heap.page_allocator, "STWO_ZIG_WORKERS")) |val| {
            defer std.heap.page_allocator.free(val);
            if (std.fmt.parseInt(usize, val, 10)) |n| {
                return @min(@max(n, 1), MAX_WORKERS);
            } else |_| {}
        } else |_| {}
    }

    const cpu_count = std.Thread.getCpuCount() catch return 1;
    return @min(@max(cpu_count, 1), MAX_WORKERS);
}

test "work_pool: detection and test-global behavior" {
    const n = detectWorkerCount();
    try std.testing.expect(n >= 1);
    try std.testing.expect(n <= MAX_WORKERS);
    try std.testing.expect(getGlobalPool() == null);
}
