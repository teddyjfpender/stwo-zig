//! Bounded CPU-only retirement after every device reader of a Prepared has joined.
//! The caller detaches its payload under its own mutex, then calls start outside
//! that mutex. Owner storage and allocator ancestry must survive join/deinit.
const std = @import("std");
const builtin = @import("builtin");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Recycler = @import("stwo_riscv_cpu_integration").rv64_large_block_recycler.LargeBlockRecycler;
const Policy = @import("resident_ready_policy.zig");
pub const stack_bytes: usize = 1 << 20;
const max_allocator_depth = 8;

/// Stable ready-runtime storage. Only the source-owned worker redistribution
/// may create an admitted permit; an environment flag cannot manufacture one.
pub const WorkerPermit = struct {
    admitted: bool = false,
    claimed: std.atomic.Value(bool) = .init(false),
    pub fn initAdmitted() WorkerPermit {
        return .{ .admitted = true };
    }
    pub fn isClaimed(self: *const WorkerPermit) bool {
        return self.claimed.load(.acquire);
    }
    fn claim(self: *WorkerPermit) !void {
        if (!self.admitted) return error.AssignmentRetirementWorkerNotAdmitted;
        if (self.claimed.cmpxchgStrong(false, true, .acq_rel, .acquire) != null)
            return error.AssignmentRetirementWorkerAlreadyClaimed;
    }
    fn release(self: *WorkerPermit) void {
        std.debug.assert(self.claimed.swap(false, .acq_rel));
    }
};

/// Exact adapters only. A synchronized budget does not make an arbitrary
/// heap_child thread-safe; follow known ancestry to a known thread-safe heap.
pub fn requireAllocator(a: std.mem.Allocator) !void {
    var current = a;
    for (0..max_allocator_depth) |_| {
        if (current.vtable == std.heap.smp_allocator.vtable or current.vtable == std.heap.page_allocator.vtable) return;
        if (Budget.fromAllocator(current)) |owner| {
            current = owner.heap_child;
        } else if (Recycler.fromAllocator(current)) |recycler| {
            current = recycler.child;
        } else return error.UnsupportedAssignmentRetirementAllocator;
    }
    return error.AssignmentRetirementAllocatorDepthExceeded;
}

fn budgetOwner(a: std.mem.Allocator) !*Budget {
    var current = a;
    for (0..max_allocator_depth) |_| {
        if (Budget.fromAllocator(current)) |owner| return owner;
        if (Recycler.fromAllocator(current)) |recycler| {
            current = recycler.child;
        } else return error.SharedAssignmentRetirementBudgetRequired;
    }
    return error.AssignmentRetirementAllocatorDepthExceeded;
}

fn enabledFromEnv() !bool {
    return parseEnabled(std.posix.getenv("STWO_RV64_OUTER_RETIRE_ASYNC"));
}
pub fn optionEnabled() !bool {
    return enabledFromEnv();
}
fn parseEnabled(text: ?[]const u8) !bool {
    const value = text orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidAssignmentRetirementOption;
}

pub fn Context(comptime T: type) type {
    return struct {
        const Self = @This();
        enabled: bool = false,
        worker_ns: u64 = 0,
        dispatch_ns: u64 = 0,
        join_wait_ns: u64 = 0,
        payload: ?T = null,
        thread: ?std.Thread = null,
        reservation: Budget.ExternalReservation = .{},
        worker_permit: ?*WorkerPermit = null,
        started: bool = false,
        /// No production behavior depends on this field.
        fail_spawn_for_test: bool = false,

        /// Reserve before any GPU work. Disabled mode preserves the existing
        /// allocator/lane route. Enabled mode currently admits one lane/device.
        pub fn init(a: std.mem.Allocator) !Self {
            return initWithPermit(a, null);
        }
        pub fn initWithPermit(a: std.mem.Allocator, permit: ?*WorkerPermit) !Self {
            const enabled = try enabledFromEnv();
            return initChecked(a, enabled, if (enabled) try Policy.lanesPerDevice() else 1, permit);
        }
        fn initChecked(a: std.mem.Allocator, enabled: bool, lanes: usize, supplied: ?*WorkerPermit) !Self {
            if (!enabled) return .{};
            if (lanes != 1) return error.AssignmentRetirementRequiresOneLanePerDevice;
            const permit = supplied orelse return error.AssignmentRetirementWorkerPermitRequired;
            try permit.claim();
            errdefer permit.release();
            try requireAllocator(a);
            const owner = try budgetOwner(a);
            return .{ .enabled = true, .worker_permit = permit, .reservation = try owner.reserveExternal(stack_bytes) };
        }

        /// Takes ownership even on error. A failed spawn leaves payload here
        /// for join/deinit; callers must not destroy their original copy.
        pub fn start(self: *Self, value: T) !void {
            if (self.started) {
                var rejected = value;
                rejected.deinit();
                return error.AssignmentRetirementAlreadyStarted;
            }
            self.started = true;
            self.payload = value;
            var timer = try std.time.Timer.start();
            defer self.dispatch_ns = timer.read();
            if (!self.enabled) {
                self.runPayload();
                return;
            }
            if (!self.reservation.active or self.reservation.owner == null or self.reservation.bytes != stack_bytes)
                return error.AssignmentRetirementStackNotReserved;
            const permit = self.worker_permit orelse return error.AssignmentRetirementWorkerPermitRequired;
            if (!permit.admitted or !permit.isClaimed()) return error.AssignmentRetirementWorkerNotAdmitted;
            if (builtin.is_test and self.fail_spawn_for_test) return error.AssignmentRetirementTestSpawnFailure;
            self.thread = try std.Thread.spawn(.{ .stack_size = stack_bytes }, run, .{self});
        }
        fn run(self: *Self) void {
            self.runPayload();
        }
        fn runPayload(self: *Self) void {
            var timer = std.time.Timer.start() catch null;
            if (self.payload) |*payload| payload.deinit();
            self.payload = null;
            self.worker_ns = if (timer) |*clock| clock.read() else 0;
        }
        /// Idempotent. Metrics are safe to read after join, and remain intact
        /// until deinit. Do not call while holding allocator/backend locks.
        pub fn join(self: *Self) void {
            if (self.thread) |thread| {
                var timer = std.time.Timer.start() catch null;
                thread.join();
                self.thread = null;
                self.join_wait_ns += if (timer) |*clock| clock.read() else 0;
            }
            // A spawn/timer failure transferred payload but created no worker.
            if (self.payload != null) self.runPayload();
        }
        pub fn deinit(self: *Self) void {
            self.join();
            // Even an already-finished worker still owns a live thread stack
            // until join. Never release this token from the worker itself.
            self.reservation.deinit();
            if (self.worker_permit) |permit| permit.release();
            self.* = .{};
        }
    };
}

const TestPayload = struct {
    a: std.mem.Allocator,
    bytes: []u8,
    calls: *std.atomic.Value(usize),
    finished: ?*std.Thread.Semaphore = null,
    fn deinit(self: *@This()) void {
        self.a.free(self.bytes);
        _ = self.calls.fetchAdd(1, .seq_cst);
        if (self.finished) |semaphore| semaphore.post();
    }
};

test "retirement transfers payload once and joins idempotently" {
    const owner = try Budget.create(std.heap.page_allocator, 4 << 20);
    defer owner.destroy();
    const a = owner.allocator();
    var calls = std.atomic.Value(usize).init(0);
    var permit = WorkerPermit.initAdmitted();
    var retirement = try Context(TestPayload).initChecked(a, true, 1, &permit);
    defer retirement.deinit();
    try retirement.start(.{ .a = a, .bytes = try a.alloc(u8, 4096), .calls = &calls });
    retirement.join();
    retirement.join();
    try std.testing.expectEqual(@as(usize, 1), calls.load(.seq_cst));
    try std.testing.expect(retirement.payload == null and retirement.thread == null);
    try std.testing.expectEqual(stack_bytes, owner.snapshot().external_live_bytes);
}

test "early worker completion retains stack charge through join and deinit" {
    const owner = try Budget.create(std.heap.page_allocator, 4 << 20);
    defer owner.destroy();
    const a = owner.allocator();
    var calls = std.atomic.Value(usize).init(0);
    var finished: std.Thread.Semaphore = .{};
    var permit = WorkerPermit.initAdmitted();
    var retirement = try Context(TestPayload).initChecked(a, true, 1, &permit);
    try retirement.start(.{ .a = a, .bytes = try a.alloc(u8, 32), .calls = &calls, .finished = &finished });
    finished.wait();
    try std.testing.expectEqual(stack_bytes, owner.snapshot().external_live_bytes);
    try std.testing.expect(permit.isClaimed());
    retirement.join();
    try std.testing.expectEqual(stack_bytes, owner.snapshot().external_live_bytes);
    try std.testing.expect(permit.isClaimed());
    retirement.deinit();
    try std.testing.expect(!permit.isClaimed());
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 1), calls.load(.seq_cst));
}

test "spawn failure and later source error retain and clean payload exactly once" {
    const owner = try Budget.create(std.heap.page_allocator, 4 << 20);
    defer owner.destroy();
    const a = owner.allocator();
    var calls = std.atomic.Value(usize).init(0);
    var permit = WorkerPermit.initAdmitted();
    var retirement = try Context(TestPayload).initChecked(a, true, 1, &permit);
    retirement.fail_spawn_for_test = true;
    try std.testing.expectError(error.AssignmentRetirementTestSpawnFailure, retirement.start(.{ .a = a, .bytes = try a.alloc(u8, 32), .calls = &calls }));
    try std.testing.expect(retirement.payload != null);
    retirement.deinit();
    try std.testing.expectEqual(@as(usize, 1), calls.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
    // An immediate enclosing source error is represented by deferred cleanup.
    {
        var running = try Context(TestPayload).initChecked(a, true, 1, &permit);
        defer running.deinit();
        try running.start(.{ .a = a, .bytes = try a.alloc(u8, 32), .calls = &calls });
    }
    try std.testing.expectEqual(@as(usize, 2), calls.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
}

test "disabled and duplicate retirement preserve ownership on every path" {
    var calls = std.atomic.Value(usize).init(0);
    const a = std.testing.allocator;
    var retirement: Context(TestPayload) = .{};
    defer retirement.deinit();
    try retirement.start(.{ .a = a, .bytes = try a.alloc(u8, 32), .calls = &calls });
    try std.testing.expectError(error.AssignmentRetirementAlreadyStarted, retirement.start(.{ .a = a, .bytes = try a.alloc(u8, 32), .calls = &calls }));
    try std.testing.expectEqual(@as(usize, 2), calls.load(.seq_cst));
}

test "retirement rejects unsupported ancestry, unbudgeted stacks and two lanes" {
    try requireAllocator(std.heap.smp_allocator);
    try requireAllocator(std.heap.page_allocator);
    var memory: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&memory);
    try std.testing.expectError(error.UnsupportedAssignmentRetirementAllocator, requireAllocator(fba.allocator()));
    const unsafe = try Budget.create(std.heap.page_allocator, 4 << 20);
    defer unsafe.destroy();
    unsafe.heap_child = fba.allocator();
    try std.testing.expectError(error.UnsupportedAssignmentRetirementAllocator, requireAllocator(unsafe.allocator()));
    var permit = WorkerPermit.initAdmitted();
    try std.testing.expectError(error.SharedAssignmentRetirementBudgetRequired, Context(TestPayload).initChecked(std.heap.page_allocator, true, 1, &permit));
    try std.testing.expectError(error.AssignmentRetirementRequiresOneLanePerDevice, Context(TestPayload).initChecked(std.heap.page_allocator, true, 2, null));
}

test "retirement admits exact recycler ancestry and refuses stack-budget exhaustion" {
    const owner = try Budget.create(std.heap.page_allocator, 4 << 20);
    defer owner.destroy();
    var recycler = Recycler.init(owner.allocator(), 1 << 20);
    defer recycler.deinit();
    try requireAllocator(recycler.allocator());
    var permit = WorkerPermit.initAdmitted();
    var retirement = try Context(TestPayload).initChecked(recycler.allocator(), true, 1, &permit);
    retirement.deinit();
    const small = try Budget.create(std.heap.page_allocator, stack_bytes - 1);
    defer small.destroy();
    try std.testing.expectError(error.OutOfMemory, Context(TestPayload).initChecked(small.allocator(), true, 1, &permit));
    try std.testing.expectEqual(@as(usize, 0), small.snapshot().live_bytes);
}

test "retirement option is strict and cyclic allocator ancestry is bounded" {
    try std.testing.expect(!try parseEnabled(null));
    try std.testing.expect(!try parseEnabled("0"));
    try std.testing.expect(try parseEnabled("1"));
    try std.testing.expectError(error.InvalidAssignmentRetirementOption, parseEnabled(""));
    try std.testing.expectError(error.InvalidAssignmentRetirementOption, parseEnabled("check"));
    const owner = try Budget.create(std.heap.page_allocator, 4 << 20);
    defer owner.destroy();
    owner.heap_child = owner.allocator();
    try std.testing.expectError(error.AssignmentRetirementAllocatorDepthExceeded, requireAllocator(owner.allocator()));
}

test "worker permit is exclusive and initialization failures release its claim" {
    const owner = try Budget.create(std.heap.page_allocator, 4 << 20);
    defer owner.destroy();
    var permit = WorkerPermit.initAdmitted();
    var first = try Context(TestPayload).initChecked(owner.allocator(), true, 1, &permit);
    try std.testing.expectError(error.AssignmentRetirementWorkerAlreadyClaimed, Context(TestPayload).initChecked(owner.allocator(), true, 1, &permit));
    first.join();
    try std.testing.expect(permit.isClaimed());
    first.deinit();
    try std.testing.expect(!permit.isClaimed());
    const small = try Budget.create(std.heap.page_allocator, stack_bytes - 1);
    defer small.destroy();
    try std.testing.expectError(error.OutOfMemory, Context(TestPayload).initChecked(small.allocator(), true, 1, &permit));
    try std.testing.expect(!permit.isClaimed());
    var memory: [128]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&memory);
    try std.testing.expectError(error.UnsupportedAssignmentRetirementAllocator, Context(TestPayload).initChecked(fba.allocator(), true, 1, &permit));
    try std.testing.expect(!permit.isClaimed());
    try std.testing.expectError(error.AssignmentRetirementWorkerPermitRequired, Context(TestPayload).initChecked(owner.allocator(), true, 1, null));
    var unadmitted: WorkerPermit = .{};
    try std.testing.expectError(error.AssignmentRetirementWorkerNotAdmitted, Context(TestPayload).initChecked(owner.allocator(), true, 1, &unadmitted));
    try std.testing.expect(!unadmitted.isClaimed());
}
