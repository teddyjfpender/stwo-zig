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

/// Type-erased boundary observer for one structured helper callback. The
/// observer owns no storage and must outlive the joined wave. It is used only
/// when task profiling is enabled; ordinary submissions retain the direct
/// `spawnWg` path and pay no clock or atomic-accounting cost.
pub const StructuredWorkerObserver = struct {
    context: *anyopaque,
    submitted_fn: *const fn (context: *anyopaque) void,
    begin_fn: *const fn (context: *anyopaque) ?u64,
    finish_fn: *const fn (context: *anyopaque, start_ns: ?u64) void,

    fn submitted(self: StructuredWorkerObserver) void {
        self.submitted_fn(self.context);
    }

    fn begin(self: StructuredWorkerObserver) ?u64 {
        return self.begin_fn(self.context);
    }

    fn finish(self: StructuredWorkerObserver, start_ns: ?u64) void {
        self.finish_fn(self.context, start_ns);
    }
};

pub const WorkPoolError = error{
    InvalidStackSize,
    InvalidWorkerBudget,
    ScopedPoolAlreadyBound,
    SingleThreaded,
    WorkerBudgetUnavailable,
    SubmissionLimitExceeded,
    RetainedLeaseReleased,
    RetainedLeaseWaveActive,
    RetainedLeaseBudgetMismatch,
};

/// Named proof boundaries used only by the orchestration acceptance audit.
/// Keeping the label here lets each consumer attest the pool it actually
/// resolved without adding an implementation pointer to the public request.
const audit_mod = @import("work_pool_audit.zig");
pub const ProofPoolStage = audit_mod.ProofPoolStage;
pub const TestProofPoolAuditConfig = audit_mod.TestProofPoolAuditConfig;
pub const TestProofPoolAuditSnapshot = audit_mod.TestProofPoolAuditSnapshot;
pub const TestProofPoolAudit = audit_mod.TestProofPoolAudit;

threadlocal var active_test_proof_pool_audit: ?*TestProofPoolAudit = null;

pub const TestProofPoolAuditBinding = struct {
    audit: *TestProofPoolAudit,
    active: bool = true,

    pub fn init(audit: *TestProofPoolAudit) !TestProofPoolAuditBinding {
        if (comptime !builtin.is_test) return error.TestOnly;
        if (active_test_proof_pool_audit != null) {
            return error.TestProofPoolAuditAlreadyBound;
        }
        active_test_proof_pool_audit = audit;
        return .{ .audit = audit };
    }

    pub fn deinit(self: *TestProofPoolAuditBinding) void {
        std.debug.assert(self.active);
        std.debug.assert(active_test_proof_pool_audit == self.audit);
        active_test_proof_pool_audit = null;
        self.active = false;
    }
};

/// Coordinator-thread binding for one caller-owned proof pool.
///
/// Public execution requests stay pointer-free. A proving transaction creates
/// its pool at a stable address, binds it for the coordinator, and every
/// execution-aware stage resolves the same pool through `getGlobalPool`.
/// Helper threads intentionally do not inherit the pointer: while any scoped
/// binding exists, an unbound thread receives null instead of lazily creating
/// the process-global pool, which prevents nested oversubscription.
pub const ScopedPoolBinding = struct {
    pool: *WorkPool,
    active: bool = true,

    pub fn init(pool: *WorkPool) WorkPoolError!ScopedPoolBinding {
        pool.assertStableAddress();
        global_state.mutex.lock();
        defer global_state.mutex.unlock();
        if (scoped_pool != null) return error.ScopedPoolAlreadyBound;
        scoped_pool = pool;
        _ = active_scoped_pools.fetchAdd(1, .acq_rel);
        if (comptime builtin.is_test) {
            if (pool.test_audit) |audit| audit.recordBindingInit(@intFromPtr(pool));
        }
        return .{ .pool = pool };
    }

    pub fn deinit(self: *ScopedPoolBinding) void {
        std.debug.assert(self.active);
        global_state.mutex.lock();
        defer global_state.mutex.unlock();
        std.debug.assert(scoped_pool == self.pool);
        scoped_pool = null;
        const previous = active_scoped_pools.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (comptime builtin.is_test) {
            if (self.pool.test_audit) |audit| audit.recordBindingDeinit(@intFromPtr(self.pool));
        }
        self.active = false;
    }
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
    /// Worker threads and the pool allocator retain this address. An
    /// initialized value may therefore be borrowed only through this exact
    /// location; copying or moving it is a use-after-move programming error.
    stable_address: usize = 0,
    n_workers: usize = 0,
    worker_stack_size: usize = WORKER_STACK_SIZE,
    backing_allocator: std.mem.Allocator = std.heap.page_allocator,
    pool_initialized: bool = false,
    test_audit: if (builtin.is_test) ?*TestProofPoolAudit else void =
        if (builtin.is_test) null else {},
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
            .stable_address = @intFromPtr(self),
            .n_workers = options.worker_count,
            .worker_stack_size = options.stack_size,
            .backing_allocator = options.backing_allocator,
            .test_audit = if (comptime builtin.is_test)
                active_test_proof_pool_audit
            else {},
        };
        if (options.worker_count == 1) {
            if (comptime builtin.is_test) {
                if (self.test_audit) |audit| audit.recordPoolInit(@intFromPtr(self));
            }
            return;
        }

        try self.pool.init(.{
            .allocator = self.threadPoolAllocator(),
            .n_jobs = options.worker_count - 1,
            .stack_size = options.stack_size,
        });
        self.pool_initialized = true;
        if (comptime builtin.is_test) {
            if (self.test_audit) |audit| audit.recordPoolInit(@intFromPtr(self));
        }
    }

    pub fn deinit(self: *WorkPool) void {
        self.assertStableAddress();
        const audit = self.test_audit;
        self.lease_mutex.lock();
        const residual_leased_workers = self.leased_workers;
        var residual_reserved_slots: usize = 0;
        for (self.structured_reserved) |reserved| {
            if (reserved) residual_reserved_slots += 1;
        }
        var residual_active_slots: usize = 0;
        for (&self.structured_slots) |*slot| {
            if (slot.in_use.load(.acquire)) residual_active_slots += 1;
        }
        self.lease_mutex.unlock();
        std.debug.assert(residual_leased_workers == 0);
        std.debug.assert(residual_reserved_slots == 0);
        std.debug.assert(residual_active_slots == 0);
        if (self.pool_initialized) self.pool.deinit();
        if (comptime builtin.is_test) {
            if (audit) |active| active.recordPoolDeinit(
                residual_leased_workers,
                residual_reserved_slots,
                residual_active_slots,
            );
        }
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
        self.assertStableAddress();
        if (!self.pool_initialized) {
            @call(.auto, func, args);
            return;
        }
        self.pool.spawnWg(wg, func, args);
    }

    pub fn workerCount(self: *const WorkPool) usize {
        self.assertStableAddress();
        return self.n_workers;
    }

    pub fn stackSize(self: *const WorkPool) usize {
        self.assertStableAddress();
        return self.worker_stack_size;
    }

    /// Per-request shared-pool residency held by a structured lease. Helper
    /// stacks and fixed submission envelopes both preexist in the pool, but a
    /// request reserves their full capacity while its lease is active.
    pub fn helperReservationBytes(
        self: *const WorkPool,
        budget: WorkerBudget,
    ) error{ResourceReservationOverflow}!usize {
        self.assertStableAddress();
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
        self.assertStableAddress();
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
        if (comptime builtin.is_test) {
            if (self.test_audit) |audit| {
                audit.recordLeaseAcquire(@intFromPtr(self), budget.count);
            }
        }
        return .{
            .pool = self,
            .budget = budget,
            .reserved_slots = reserved_slots,
        };
    }

    pub fn availableWorkers(self: *WorkPool) usize {
        self.assertStableAddress();
        self.lease_mutex.lock();
        defer self.lease_mutex.unlock();
        return self.n_workers - self.leased_workers;
    }

    fn release(self: *WorkPool, count: usize, reserved_slots: []const u8) void {
        self.assertStableAddress();
        self.lease_mutex.lock();
        defer self.lease_mutex.unlock();
        std.debug.assert(count <= self.leased_workers);
        for (reserved_slots) |index| {
            std.debug.assert(self.structured_reserved[index]);
            std.debug.assert(!self.structured_slots[index].in_use.load(.acquire));
            self.structured_reserved[index] = false;
        }
        self.leased_workers -= count;
        if (comptime builtin.is_test) {
            if (self.test_audit) |audit| {
                audit.recordLeaseRelease(@intFromPtr(self), count);
            }
        }
    }

    fn spawnStructuredWg(
        self: *WorkPool,
        slot_index: usize,
        wg: *std.Thread.WaitGroup,
        comptime func: anytype,
        args: anytype,
    ) void {
        self.assertStableAddress();
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
        if (comptime builtin.is_test) {
            if (self.test_audit) |audit| audit.recordStructuredSubmitted();
        }
        self.pool.spawnWg(wg, func, args);
        const consumed = structured_submission.?.consumed;
        structured_submission = null;
        if (!consumed) {
            @panic("std.Thread.Pool bypassed the reserved structured submission slot");
        }
    }

    fn spawnStructuredObservedWg(
        self: *WorkPool,
        slot_index: usize,
        wg: *std.Thread.WaitGroup,
        comptime func: anytype,
        args: anytype,
        observer: StructuredWorkerObserver,
    ) void {
        const args_info = @typeInfo(@TypeOf(args));
        comptime {
            const valid = switch (args_info) {
                .@"struct" => |info| info.is_tuple and
                    (info.fields.len == 0 or
                        (info.fields.len == 1 and
                            @typeInfo(info.fields[0].type) == .pointer)),
                else => false,
            };
            if (!valid) {
                @compileError("observed structured work submissions require zero arguments or one pointer");
            }
        }

        const Observed = struct {
            fn run(active: StructuredWorkerObserver, argument_address: usize) void {
                const start_ns = active.begin();
                defer active.finish(start_ns);
                if (comptime args_info.@"struct".fields.len == 0) {
                    @call(.auto, func, .{});
                } else {
                    const Pointer = args_info.@"struct".fields[0].type;
                    const argument: Pointer = @ptrFromInt(argument_address);
                    @call(.auto, func, .{argument});
                }
            }
        };
        const argument_address = if (comptime args_info.@"struct".fields.len == 0)
            0
        else
            @intFromPtr(args[0]);

        self.assertStableAddress();
        if (structured_submission != null) {
            @panic("nested structured submission on one coordinator thread");
        }
        structured_submission = .{ .pool = self, .slot_index = slot_index };
        if (comptime builtin.is_test) {
            if (self.test_audit) |audit| audit.recordStructuredSubmitted();
        }
        observer.submitted();
        self.pool.spawnWg(wg, Observed.run, .{ observer, argument_address });
        const consumed = structured_submission.?.consumed;
        structured_submission = null;
        if (!consumed) {
            @panic("std.Thread.Pool bypassed the reserved structured submission slot");
        }
    }

    fn waitForStructuredSlot(self: *WorkPool, slot_index: usize) void {
        self.assertStableAddress();
        const slot = &self.structured_slots[slot_index];
        slot.released.wait();
        std.debug.assert(!slot.in_use.load(.acquire));
    }

    fn threadPoolAllocator(self: *WorkPool) std.mem.Allocator {
        self.assertStableAddress();
        return .{ .ptr = self, .vtable = &thread_pool_allocator_vtable };
    }

    fn hasStableAddress(self: *const WorkPool) bool {
        return self.stable_address == @intFromPtr(self);
    }

    fn assertStableAddress(self: *const WorkPool) void {
        if (!self.hasStableAddress()) {
            @panic("initialized WorkPool moved from its stable address");
        }
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
    self.assertStableAddress();
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
    self.assertStableAddress();
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
    self.assertStableAddress();
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
    self.assertStableAddress();
    if (self.structuredSlotIndex(memory.ptr)) |slot_index| {
        const was_in_use = self.structured_slots[slot_index].in_use.swap(false, .release);
        std.debug.assert(was_in_use);
        if (comptime builtin.is_test) {
            if (self.test_audit) |audit| audit.recordStructuredCompleted();
        }
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

    pub fn poolCapacity(self: *const WorkLease) usize {
        return self.pool.workerCount();
    }

    pub fn stackSize(self: *const WorkLease) usize {
        return self.pool.stackSize();
    }

    /// Validates a borrowed lease at a drained-wave boundary. Structured
    /// graph execution never takes ownership of such a lease; its caller may
    /// retain the same reservation across multiple exact-capacity graphs.
    pub fn validateRetained(
        self: *const WorkLease,
        budget: WorkerBudget,
    ) WorkPoolError!void {
        if (self.released) return error.RetainedLeaseReleased;
        if (self.helper_submissions != 0) return error.RetainedLeaseWaveActive;
        if (self.budget.count != budget.count) {
            return error.RetainedLeaseBudgetMismatch;
        }
    }

    pub fn spawnWg(
        self: *WorkLease,
        wg: *std.Thread.WaitGroup,
        comptime func: anytype,
        args: anytype,
    ) WorkPoolError!void {
        if (self.released or
            !self.pool.pool_initialized or
            self.helper_submissions >= self.helperCount())
        {
            return error.SubmissionLimitExceeded;
        }
        const slot_index = self.reserved_slots[self.helper_submissions];
        self.helper_submissions += 1;
        self.pool.spawnStructuredWg(slot_index, wg, func, args);
    }

    /// Submits one helper through the same fixed closure slot as `spawnWg`,
    /// with exact begin/end observations around the physical helper callback.
    /// The accepted argument shape intentionally matches `spawnWg`: zero
    /// arguments or one pointer. No job allocation occurs on this path.
    pub fn spawnObservedWg(
        self: *WorkLease,
        wg: *std.Thread.WaitGroup,
        comptime func: anytype,
        args: anytype,
        observer: StructuredWorkerObserver,
    ) WorkPoolError!void {
        if (self.released or
            !self.pool.pool_initialized or
            self.helper_submissions >= self.helperCount())
        {
            return error.SubmissionLimitExceeded;
        }

        const Args = @TypeOf(args);
        const args_info = @typeInfo(Args);
        comptime {
            const valid = switch (args_info) {
                .@"struct" => |info| info.is_tuple and
                    (info.fields.len == 0 or
                        (info.fields.len == 1 and
                            @typeInfo(info.fields[0].type) == .pointer)),
                else => false,
            };
            if (!valid) {
                @compileError("observed structured work submissions require zero arguments or one pointer");
            }
        }

        const submission_index = self.helper_submissions;
        const slot_index = self.reserved_slots[submission_index];
        self.helper_submissions += 1;
        self.pool.spawnStructuredObservedWg(
            slot_index,
            wg,
            func,
            args,
            observer,
        );
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

threadlocal var scoped_pool: ?*WorkPool = null;
var active_scoped_pools: std.atomic.Value(usize) = .init(0);

/// Gets or lazily initializes the process-wide pool. Tests use explicit local
/// pools so their worker budgets and lifetimes remain deterministic.
pub fn getGlobalPool() ?*WorkPool {
    if (scoped_pool) |pool| {
        pool.assertStableAddress();
        recordGlobalResolutionForTest(pool);
        return pool;
    }
    if (comptime builtin.single_threaded) {
        recordGlobalResolutionForTest(null);
        return null;
    }

    global_state.mutex.lock();
    defer global_state.mutex.unlock();

    // A helper or unrelated unbound coordinator must never create a second
    // process pool while an explicit proof-scoped pool is live.
    if (active_scoped_pools.load(.acquire) != 0) {
        recordGlobalResolutionForTest(null);
        return null;
    }
    if (comptime builtin.is_test) {
        recordGlobalResolutionForTest(null);
        return null;
    }

    if (global_state.init_failed) {
        recordGlobalResolutionForTest(null);
        return null;
    }
    if (global_state.pool_initialized) {
        recordGlobalResolutionForTest(&global_state.pool);
        return &global_state.pool;
    }
    global_state.pool.initInPlace() catch {
        global_state.init_failed = true;
        recordGlobalResolutionForTest(null);
        return null;
    };
    global_state.pool_initialized = true;
    recordGlobalResolutionForTest(&global_state.pool);
    return &global_state.pool;
}

inline fn recordGlobalResolutionForTest(pool: ?*WorkPool) void {
    if (comptime !builtin.is_test) return;
    const audit = active_test_proof_pool_audit orelse return;
    audit.recordGlobalResolution(if (pool) |active| @intFromPtr(active) else 0);
}

/// Records the exact pool selected at a production stage. The optional failure
/// is injected only after the observation has been captured, so the receipt
/// proves how far the real orchestration progressed before unwinding.
pub inline fn observeProofPoolStageForTest(
    stage: ProofPoolStage,
    pool: ?*WorkPool,
) !void {
    if (comptime !builtin.is_test) return;
    const audit = active_test_proof_pool_audit orelse return;
    const address = if (pool) |active| @intFromPtr(active) else 0;
    const inject_failure = audit.recordStage(stage, address);

    if (pool) |active| {
        if (audit.takeNestedProbe()) {
            var helper_saw_pool = false;
            var wait_group: std.Thread.WaitGroup = .{};
            active.spawnWg(&wait_group, struct {
                fn run(saw_pool: *bool) void {
                    saw_pool.* = getGlobalPool() != null;
                }
            }.run, .{&helper_saw_pool});
            wait_group.wait();

            var nested_binding_denied = false;
            if (ScopedPoolBinding.init(active)) |binding_value| {
                var unexpected_binding = binding_value;
                unexpected_binding.deinit();
            } else |err| {
                nested_binding_denied = err == error.ScopedPoolAlreadyBound;
            }
            audit.recordNestedProbe(helper_saw_pool, nested_binding_denied);
        }
    }

    if (inject_failure) return error.ProofPoolAuditInjectedFailure;
}

/// Publication is deliberately separate from a stage observation: a failed
/// proof may visit every computational boundary but must never publish output.
pub inline fn recordProofPublicationForTest(pool: ?*WorkPool) void {
    if (comptime !builtin.is_test) return;
    const audit = active_test_proof_pool_audit orelse return;
    audit.recordPublication(if (pool) |active| @intFromPtr(active) else 0);
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

const Root = @This();

pub const testing = if (builtin.is_test) struct {
    pub const detectWorkerCount = Root.detectWorkerCount;

    pub fn activeScopedPoolCount() usize {
        return active_scoped_pools.load(.acquire);
    }

    pub fn hasStableAddress(pool: *const WorkPool) bool {
        return pool.hasStableAddress();
    }
} else struct {};
