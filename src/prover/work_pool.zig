//! Process-wide proving worker pool with explicit per-request leases.
//!
//! Existing callers may continue to submit directly. Structured task graphs
//! use `WorkerBudget` and `WorkLease` so a request cannot silently exceed its
//! admitted worker count or enqueue an unbounded wave of helper jobs. A lease
//! reserves fixed submission envelopes and guarantees that its helpers are
//! queued without allocation or synchronous fallback. Legacy direct jobs can
//! still delay those helpers; a lease is bounded capacity, not priority.

const std = @import("std");
const builtin = @import("builtin");

/// Fixed storage ceiling, not a scheduling target.
pub const MAX_WORKERS: usize = 32;
pub const WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;
const MAX_HELPERS: usize = MAX_WORKERS - 1;
const STRUCTURED_JOB_SLOT_BYTES: usize = 256;
const STRUCTURED_JOB_SLOT_ALIGNMENT: usize = 16;

const StructuredJobSlot = struct {
    storage: [STRUCTURED_JOB_SLOT_BYTES]u8 align(STRUCTURED_JOB_SLOT_ALIGNMENT) = undefined,
    in_use: std.atomic.Value(bool) = .init(false),
    released: std.Thread.ResetEvent = .{},
};

pub const STRUCTURED_JOB_RESERVATION_BYTES: usize = @sizeOf(StructuredJobSlot);

comptime {
    if (@offsetOf(StructuredJobSlot, "storage") != 0) {
        @compileError("structured submission storage must lead each fixed slot");
    }
}

const StructuredSubmission = struct {
    pool: *WorkPool,
    slot_index: usize,
    consumed: bool = false,
};

threadlocal var structured_submission: ?StructuredSubmission = null;

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
    backing_allocator: std.mem.Allocator = std.heap.page_allocator,
};

pub const WorkPool = struct {
    pool: std.Thread.Pool = undefined,
    n_workers: usize = 0,
    worker_stack_size: usize = WORKER_STACK_SIZE,
    backing_allocator: std.mem.Allocator = std.heap.page_allocator,
    pool_initialized: bool = false,
    lease_mutex: std.Thread.Mutex = .{},
    leased_workers: usize = 0,
    structured_slots: [MAX_HELPERS]StructuredJobSlot =
        [_]StructuredJobSlot{.{}} ** MAX_HELPERS,
    structured_reserved: [MAX_HELPERS]bool = .{false} ** MAX_HELPERS,

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
        if (comptime builtin.single_threaded) {
            if (options.worker_count > 1) return error.SingleThreaded;
        }
        self.* = .{
            .n_workers = options.worker_count,
            .worker_stack_size = options.stack_size,
            .backing_allocator = options.backing_allocator,
        };
        if (options.worker_count == 1) return;

        try self.pool.init(.{
            .allocator = self.threadPoolAllocator(),
            .n_jobs = options.worker_count - 1,
            .stack_size = options.stack_size,
        });
        self.pool_initialized = true;
    }

    pub fn deinit(self: *WorkPool) void {
        self.lease_mutex.lock();
        const leases_drained = self.leased_workers == 0;
        const slots_released = std.mem.allEqual(bool, &self.structured_reserved, false);
        self.lease_mutex.unlock();
        std.debug.assert(leases_drained);
        std.debug.assert(slots_released);
        for (&self.structured_slots) |*slot| {
            std.debug.assert(!slot.in_use.load(.acquire));
        }
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

    /// Per-request shared-pool residency held by a structured lease. Helper
    /// stacks and fixed submission envelopes both preexist in the pool, but a
    /// request reserves their full capacity while its lease is active.
    pub fn helperReservationBytes(
        self: *const WorkPool,
        budget: WorkerBudget,
    ) error{ResourceReservationOverflow}!usize {
        const per_helper = std.math.add(
            usize,
            self.worker_stack_size,
            STRUCTURED_JOB_RESERVATION_BYTES,
        ) catch return error.ResourceReservationOverflow;
        return std.math.mul(
            usize,
            budget.helperCount(),
            per_helper,
        ) catch error.ResourceReservationOverflow;
    }

    pub fn acquire(self: *WorkPool, budget: WorkerBudget) WorkPoolError!WorkLease {
        _ = try WorkerBudget.init(budget.count);
        if (budget.count > self.n_workers) return error.WorkerBudgetUnavailable;

        self.lease_mutex.lock();
        defer self.lease_mutex.unlock();
        if (budget.count > self.n_workers - self.leased_workers) {
            return error.WorkerBudgetUnavailable;
        }
        var reserved_slots = [_]u8{0} ** MAX_HELPERS;
        var reserved_count: usize = 0;
        for (self.structured_reserved[0 .. self.n_workers - 1], 0..) |reserved, index| {
            if (reserved or reserved_count == budget.helperCount()) continue;
            self.structured_reserved[index] = true;
            reserved_slots[reserved_count] = @intCast(index);
            reserved_count += 1;
        }
        if (reserved_count != budget.helperCount()) {
            for (reserved_slots[0..reserved_count]) |index| {
                self.structured_reserved[index] = false;
            }
            return error.WorkerBudgetUnavailable;
        }
        self.leased_workers += budget.count;
        return .{
            .pool = self,
            .budget = budget,
            .reserved_slots = reserved_slots,
        };
    }

    pub fn availableWorkers(self: *WorkPool) usize {
        self.lease_mutex.lock();
        defer self.lease_mutex.unlock();
        return self.n_workers - self.leased_workers;
    }

    fn release(self: *WorkPool, count: usize, reserved_slots: []const u8) void {
        self.lease_mutex.lock();
        defer self.lease_mutex.unlock();
        std.debug.assert(count <= self.leased_workers);
        for (reserved_slots) |index| {
            std.debug.assert(self.structured_reserved[index]);
            std.debug.assert(!self.structured_slots[index].in_use.load(.acquire));
            self.structured_reserved[index] = false;
        }
        self.leased_workers -= count;
    }

    fn spawnStructuredWg(
        self: *WorkPool,
        slot_index: usize,
        wg: *std.Thread.WaitGroup,
        comptime func: anytype,
        args: anytype,
    ) void {
        comptime {
            const valid = switch (@typeInfo(@TypeOf(args))) {
                .@"struct" => |info| info.is_tuple and
                    (info.fields.len == 0 or
                        (info.fields.len == 1 and
                            @typeInfo(info.fields[0].type) == .pointer)),
                else => false,
            };
            if (!valid) {
                @compileError("structured work submissions require zero arguments or one pointer");
            }
        }
        if (structured_submission != null) {
            @panic("nested structured submission on one coordinator thread");
        }
        structured_submission = .{ .pool = self, .slot_index = slot_index };
        self.pool.spawnWg(wg, func, args);
        const consumed = structured_submission.?.consumed;
        structured_submission = null;
        if (!consumed) {
            @panic("std.Thread.Pool bypassed the reserved structured submission slot");
        }
    }

    fn waitForStructuredSlot(self: *WorkPool, slot_index: usize) void {
        const slot = &self.structured_slots[slot_index];
        slot.released.wait();
        std.debug.assert(!slot.in_use.load(.acquire));
    }

    fn threadPoolAllocator(self: *WorkPool) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &thread_pool_allocator_vtable };
    }

    fn structuredSlotIndex(self: *WorkPool, pointer: [*]u8) ?usize {
        const address = @intFromPtr(pointer);
        const first = @intFromPtr(&self.structured_slots[0].storage);
        if (address < first) return null;
        const stride = @sizeOf(StructuredJobSlot);
        const offset = address - first;
        if (offset % stride != 0) return null;
        const index = offset / stride;
        return if (index < self.structured_slots.len) index else null;
    }
};

const thread_pool_allocator_vtable = std.mem.Allocator.VTable{
    .alloc = threadPoolAlloc,
    .resize = threadPoolResize,
    .remap = threadPoolRemap,
    .free = threadPoolFree,
};

fn threadPoolAlloc(
    context: *anyopaque,
    len: usize,
    alignment: std.mem.Alignment,
    return_address: usize,
) ?[*]u8 {
    const self: *WorkPool = @ptrCast(@alignCast(context));
    if (structured_submission) |*submission| {
        if (submission.pool != self or submission.consumed) {
            @panic("invalid structured submission allocator context");
        }
        if (len > STRUCTURED_JOB_SLOT_BYTES or
            alignment.toByteUnits() > STRUCTURED_JOB_SLOT_ALIGNMENT)
        {
            @panic("structured submission closure exceeds its fixed slot");
        }
        const slot = &self.structured_slots[submission.slot_index];
        if (slot.in_use.swap(true, .acq_rel)) {
            @panic("structured submission slot reused before closure cleanup");
        }
        slot.released.reset();
        submission.consumed = true;
        return @ptrCast(&slot.storage);
    }
    return self.backing_allocator.rawAlloc(len, alignment, return_address);
}

fn threadPoolResize(
    context: *anyopaque,
    memory: []u8,
    alignment: std.mem.Alignment,
    new_len: usize,
    return_address: usize,
) bool {
    const self: *WorkPool = @ptrCast(@alignCast(context));
    if (self.structuredSlotIndex(memory.ptr) != null) {
        return new_len <= STRUCTURED_JOB_SLOT_BYTES;
    }
    return self.backing_allocator.rawResize(
        memory,
        alignment,
        new_len,
        return_address,
    );
}

fn threadPoolRemap(
    context: *anyopaque,
    memory: []u8,
    alignment: std.mem.Alignment,
    new_len: usize,
    return_address: usize,
) ?[*]u8 {
    const self: *WorkPool = @ptrCast(@alignCast(context));
    if (self.structuredSlotIndex(memory.ptr) != null) {
        return if (new_len <= STRUCTURED_JOB_SLOT_BYTES) memory.ptr else null;
    }
    return self.backing_allocator.rawRemap(
        memory,
        alignment,
        new_len,
        return_address,
    );
}

fn threadPoolFree(
    context: *anyopaque,
    memory: []u8,
    alignment: std.mem.Alignment,
    return_address: usize,
) void {
    const self: *WorkPool = @ptrCast(@alignCast(context));
    if (self.structuredSlotIndex(memory.ptr)) |slot_index| {
        const was_in_use = self.structured_slots[slot_index].in_use.swap(false, .release);
        std.debug.assert(was_in_use);
        self.structured_slots[slot_index].released.set();
        return;
    }
    self.backing_allocator.rawFree(memory, alignment, return_address);
}

/// A non-copyable-by-convention request lease. At most `N - 1` bounded-context
/// helper jobs may be submitted before the caller joins them and calls
/// `completeWave`.
pub const WorkLease = struct {
    pool: *WorkPool,
    budget: WorkerBudget,
    helper_submissions: usize = 0,
    released: bool = false,
    reserved_slots: [MAX_HELPERS]u8 = [_]u8{0} ** MAX_HELPERS,

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
        const slot_index = self.reserved_slots[self.helper_submissions];
        self.helper_submissions += 1;
        self.pool.spawnStructuredWg(slot_index, wg, func, args);
    }

    /// Must be called only after the corresponding wait group has drained.
    pub fn completeWave(self: *WorkLease) void {
        for (self.reserved_slots[0..self.helper_submissions]) |slot_index| {
            self.pool.waitForStructuredSlot(slot_index);
        }
        self.helper_submissions = 0;
    }

    pub fn deinit(self: *WorkLease) void {
        std.debug.assert(self.helper_submissions == 0);
        std.debug.assert(!self.released);
        self.pool.release(
            self.budget.count,
            self.reserved_slots[0..self.helperCount()],
        );
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

test "work_pool: structured leases submit without backing allocations" {
    if (comptime builtin.single_threaded) return error.SkipZigTest;

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var pool: WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 3,
        .stack_size = 64 * 1024,
        .backing_allocator = failing.allocator(),
    });
    defer {
        failing.fail_index = std.math.maxInt(usize);
        failing.resize_fail_index = std.math.maxInt(usize);
        pool.deinit();
    }

    const budget = try WorkerBudget.init(3);
    try std.testing.expectEqual(
        2 * (64 * 1024 + STRUCTURED_JOB_RESERVATION_BYTES),
        try pool.helperReservationBytes(budget),
    );
    var lease = try pool.acquire(budget);
    defer lease.deinit();

    const Job = struct {
        fn run(counter: *std.atomic.Value(usize)) void {
            _ = counter.fetchAdd(1, .monotonic);
        }
    };
    var counter = std.atomic.Value(usize).init(0);
    var wait_group = std.Thread.WaitGroup{};
    const allocation_count = failing.alloc_index;
    const resize_count = failing.resize_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = resize_count;
    try lease.spawnWg(&wait_group, Job.run, .{&counter});
    try lease.spawnWg(&wait_group, Job.run, .{&counter});
    wait_group.wait();
    lease.completeWave();

    try std.testing.expectEqual(@as(usize, 2), counter.load(.acquire));
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(resize_count, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
}
