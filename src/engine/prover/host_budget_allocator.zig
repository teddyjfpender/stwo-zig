//! Coordinator-only allocator wrapper for hard per-plan host-memory limits.
//!
//! Composition planning is single-threaded and routes every owned heap buffer
//! through this wrapper before workers launch. Helper-thread stacks and fixed
//! submission envelopes are reserved separately by the caller because they
//! belong to the shared pool, not to the child allocator.

const std = @import("std");

pub const HostBudgetAllocator = struct {
    child: std.mem.Allocator,
    limit: usize,
    live_bytes: usize = 0,
    external_live_bytes: usize = 0,
    peak_live_bytes: usize = 0,
    peak_host_bytes: usize = 0,
    peak_external_bytes: usize = 0,
    budget_exceeded: bool = false,

    pub fn init(child: std.mem.Allocator, limit: usize) HostBudgetAllocator {
        return .{ .child = child, .limit = limit };
    }

    pub fn allocator(self: *@This()) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    pub fn didExceedBudget(self: *const @This()) bool {
        return self.budget_exceeded;
    }

    fn admitsGrowth(self: *@This(), growth: usize) bool {
        // Both terms are admitted under the same synchronized owner mutex.
        // Subtract in stages so a refused combined request cannot overflow.
        if (self.live_bytes > self.limit or self.external_live_bytes > self.limit - self.live_bytes or
            growth > self.limit - self.live_bytes - self.external_live_bytes)
        {
            self.budget_exceeded = true;
            return false;
        }
        return true;
    }

    fn recordGrowth(self: *@This(), growth: usize) void {
        self.live_bytes += growth;
        self.peak_host_bytes = @max(self.peak_host_bytes, self.live_bytes);
        self.recordCombinedPeak();
    }

    fn recordCombinedPeak(self: *@This()) void {
        self.peak_live_bytes = @max(self.peak_live_bytes, self.live_bytes + self.external_live_bytes);
        self.peak_external_bytes = @max(self.peak_external_bytes, self.external_live_bytes);
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *HostBudgetAllocator = @ptrCast(@alignCast(context));
        if (!self.admitsGrowth(len)) return null;
        const result = self.child.rawAlloc(len, alignment, return_address) orelse return null;
        self.recordGrowth(len);
        return result;
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *HostBudgetAllocator = @ptrCast(@alignCast(context));
        const growth = new_len -| memory.len;
        if (!self.admitsGrowth(growth)) return false;
        if (!self.child.rawResize(memory, alignment, new_len, return_address)) return false;
        if (new_len >= memory.len) {
            self.recordGrowth(growth);
        } else {
            self.live_bytes -= memory.len - new_len;
        }
        return true;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *HostBudgetAllocator = @ptrCast(@alignCast(context));
        const growth = new_len -| memory.len;
        if (!self.admitsGrowth(growth)) return null;
        const result = self.child.rawRemap(
            memory,
            alignment,
            new_len,
            return_address,
        ) orelse return null;
        if (new_len >= memory.len) {
            self.recordGrowth(growth);
        } else {
            self.live_bytes -= memory.len - new_len;
        }
        return result;
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *HostBudgetAllocator = @ptrCast(@alignCast(context));
        std.debug.assert(memory.len <= self.live_bytes);
        self.child.rawFree(memory, alignment, return_address);
        self.live_bytes -= memory.len;
    }
};

test "host budget allocator admits the exact live-byte boundary" {
    var bounded = HostBudgetAllocator.init(std.testing.allocator, 48);
    const allocator = bounded.allocator();
    const first = try allocator.alloc(u8, 32);
    defer allocator.free(first);
    const second = try allocator.alloc(u8, 16);
    try std.testing.expectEqual(@as(usize, 48), bounded.live_bytes);
    try std.testing.expectEqual(@as(usize, 48), bounded.peak_live_bytes);
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    try std.testing.expect(bounded.didExceedBudget());
    allocator.free(second);
    const replacement = try allocator.alloc(u8, 1);
    allocator.free(replacement);
    try std.testing.expectEqual(@as(usize, 48), bounded.peak_live_bytes);
}

test "host budget allocator distinguishes child exhaustion from its limit" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = 0,
    });
    var bounded = HostBudgetAllocator.init(failing.allocator(), 1024);
    try std.testing.expectError(error.OutOfMemory, bounded.allocator().alloc(u8, 1));
    try std.testing.expect(!bounded.didExceedBudget());
    try std.testing.expectEqual(@as(usize, 0), bounded.live_bytes);
}

test "host budget allocator accounts in-place resize and remap" {
    var storage: [128]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var bounded = HostBudgetAllocator.init(fixed.allocator(), 64);
    const allocator = bounded.allocator();

    var memory = try allocator.alloc(u8, 32);
    try std.testing.expect(allocator.resize(memory, 48));
    memory.len = 48;
    try std.testing.expectEqual(@as(usize, 48), bounded.live_bytes);
    try std.testing.expect(allocator.resize(memory, 24));
    memory.len = 24;
    try std.testing.expectEqual(@as(usize, 24), bounded.live_bytes);

    memory = allocator.remap(memory, 40).?;
    try std.testing.expectEqual(@as(usize, 40), bounded.live_bytes);
    try std.testing.expectEqual(@as(usize, 48), bounded.peak_live_bytes);
    try std.testing.expect(allocator.remap(memory, 65) == null);
    try std.testing.expect(bounded.didExceedBudget());
    try std.testing.expectEqual(@as(usize, 40), bounded.live_bytes);

    allocator.free(memory);
    try std.testing.expectEqual(@as(usize, 0), bounded.live_bytes);
}

/// Stable, lock-free owner for allocations whose lifetimes cross threads.
/// The control object itself is allocated outside `limit`.
///
/// Admission is one atomic reserve on the combined heap+external total, so the
/// hard limit is never exceeded and no global mutex sits on the allocation
/// path. The heap child MUST itself be thread-safe (smp_allocator,
/// page_allocator, a thread-safe GPA, a LargeBlockRecycler, or another
/// SharedHostBudget); this owner no longer serializes it. Charges are the
/// requested length, exactly as before.
pub const SharedHostBudget = struct {
    child: std.mem.Allocator,
    /// Allocator that serves heap bytes. Equal to `child` unless a test swaps it
    /// before the first user allocation.
    heap_child: std.mem.Allocator,
    backing_owner: ?*SharedHostBudget = null,
    limit: usize,
    /// heap + external; the only admission counter. Invariant: total <= limit.
    total: std.atomic.Value(usize) = .init(0),
    heap_live: std.atomic.Value(usize) = .init(0),
    external_live: std.atomic.Value(usize) = .init(0),
    peak_total: std.atomic.Value(usize) = .init(0),
    peak_heap: std.atomic.Value(usize) = .init(0),
    peak_external: std.atomic.Value(usize) = .init(0),
    exceeded: std.atomic.Value(bool) = .init(false),
    references: std.atomic.Value(usize),

    pub const Snapshot = struct {
        /// Logical owned heap plus explicitly reserved external bytes. This
        /// is not process RSS: stacks/framework/control overhead are separate.
        live_bytes: usize,
        peak_live_bytes: usize,
        host_live_bytes: usize,
        external_live_bytes: usize,
        peak_host_bytes: usize,
        peak_external_bytes: usize,
        limit: usize,
        exceeded: bool,
    };

    pub fn create(child: std.mem.Allocator, limit: usize) !*SharedHostBudget {
        const self = try child.create(SharedHostBudget);
        self.* = .{ .child = child, .heap_child = child, .limit = limit, .references = .init(1) };
        return self;
    }

    /// Own an identifiable backing budget across all nested allocator leases.
    /// Other allocator kinds retain the normal borrowed-allocator contract.
    /// The control allocation remains charged to the backing allocator.
    pub fn createRetainingParent(child: std.mem.Allocator, limit: usize) !*SharedHostBudget {
        const parent = if (fromAllocator(child)) |owner| owner.retain() else null;
        errdefer if (parent) |owner| owner.destroy();
        const self = try create(child, limit);
        self.backing_owner = parent;
        return self;
    }

    /// Identifiable forwarding vtable lets allocation-policy selectors honor
    /// an explicit budget without inspecting arbitrary allocator contexts.
    const vtable: std.mem.Allocator.VTable = .{
        .alloc = sharedAlloc,
        .resize = sharedResize,
        .remap = sharedRemap,
        .free = sharedFree,
    };

    pub fn allocator(self: *SharedHostBudget) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn isAllocator(a: std.mem.Allocator) bool {
        return a.vtable == &vtable;
    }

    pub fn fromAllocator(a: std.mem.Allocator) ?*SharedHostBudget {
        if (!isAllocator(a)) return null;
        return @ptrCast(@alignCast(a.ptr));
    }

    /// Atomically reserve `growth` against the combined limit. A refusal
    /// changes no counter except the sticky `exceeded` flag.
    fn admit(self: *SharedHostBudget, growth: usize) bool {
        var current = self.total.load(.monotonic);
        while (true) {
            if (current > self.limit or growth > self.limit - current) {
                self.exceeded.store(true, .monotonic);
                return false;
            }
            current = self.total.cmpxchgWeak(current, current + growth, .monotonic, .monotonic) orelse {
                _ = self.peak_total.fetchMax(current + growth, .monotonic);
                return true;
            };
        }
    }

    /// Return admitted bytes that were never (or are no longer) used.
    fn unadmit(self: *SharedHostBudget, bytes: usize) void {
        const previous = self.total.fetchSub(bytes, .monotonic);
        if (previous < bytes) @panic("host budget total underflow");
    }

    fn heapGrew(self: *SharedHostBudget, growth: usize) void {
        const now = self.heap_live.fetchAdd(growth, .monotonic) + growth;
        _ = self.peak_heap.fetchMax(now, .monotonic);
    }

    fn heapShrank(self: *SharedHostBudget, shrink: usize) void {
        const previous = self.heap_live.fetchSub(shrink, .monotonic);
        if (previous < shrink) @panic("host budget heap underflow");
        self.unadmit(shrink);
    }

    fn externalGrew(self: *SharedHostBudget, growth: usize) void {
        const now = self.external_live.fetchAdd(growth, .monotonic) + growth;
        _ = self.peak_external.fetchMax(now, .monotonic);
    }

    fn externalShrank(self: *SharedHostBudget, shrink: usize) void {
        const previous = self.external_live.fetchSub(shrink, .monotonic);
        if (previous < shrink) @panic("copied external reservation released twice");
        self.unadmit(shrink);
    }

    /// Consuming local ownership token. take() clears the source, and deinit()
    /// is harmless when repeated on that same object. Raw struct copies do not
    /// acquire leases and are forbidden by this contract; Zig does not enforce
    /// move-only structs. Every charged token holds this owner's lifetime.
    pub const ExternalReservation = struct {
        owner: ?*SharedHostBudget = null,
        bytes: usize = 0,
        active: bool = false,

        pub fn empty() ExternalReservation {
            return .{};
        }
        pub fn unbudgeted(bytes: usize) ExternalReservation {
            return .{ .bytes = bytes, .active = true };
        }
        pub fn take(self: *ExternalReservation) ExternalReservation {
            const result = self.*;
            self.* = .empty();
            return result;
        }
        pub fn requireOwner(self: *const ExternalReservation, a: std.mem.Allocator, bytes: usize) !void {
            if (!self.active or self.owner == null or self.owner != SharedHostBudget.fromAllocator(a) or self.bytes != bytes) return error.InvalidExternalReservationOwner;
        }
        pub fn resize(self: *ExternalReservation, bytes: usize) !void {
            if (!self.active) return error.ExternalReservationReleased;
            if (self.owner) |owner| {
                if (bytes > self.bytes) {
                    const growth = bytes - self.bytes;
                    if (!owner.admit(growth)) return error.OutOfMemory;
                    owner.externalGrew(growth);
                } else {
                    owner.externalShrank(self.bytes - bytes);
                }
            }
            self.bytes = bytes;
        }
        pub fn deinit(self: *ExternalReservation) void {
            if (!self.active) return;
            const owner = self.owner;
            const bytes = self.bytes;
            self.* = .empty();
            if (owner) |retained| {
                retained.externalShrank(bytes);
                // The token's lease is still live until this release.
                retained.destroy();
            }
        }
    };

    /// Reserve before calling an external allocation factory. Failure changes
    /// no live count or lease; zero-byte aliases retain only owner lifetime.
    pub fn reserveExternal(self: *SharedHostBudget, bytes: usize) !ExternalReservation {
        if (!self.admit(bytes)) return error.OutOfMemory;
        _ = self.retain();
        self.externalGrew(bytes);
        return .{ .owner = self, .bytes = bytes, .active = true };
    }

    fn sharedAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *SharedHostBudget = @ptrCast(@alignCast(ctx));
        if (!self.admit(len)) return null;
        const result = self.heap_child.rawAlloc(len, alignment, ra) orelse {
            self.unadmit(len);
            return null;
        };
        self.heapGrew(len);
        return result;
    }

    fn sharedResize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        const self: *SharedHostBudget = @ptrCast(@alignCast(ctx));
        if (len > memory.len) {
            const growth = len - memory.len;
            if (!self.admit(growth)) return false;
            if (!self.heap_child.rawResize(memory, alignment, len, ra)) {
                self.unadmit(growth);
                return false;
            }
            self.heapGrew(growth);
            return true;
        }
        if (!self.heap_child.rawResize(memory, alignment, len, ra)) return false;
        self.heapShrank(memory.len - len);
        return true;
    }

    fn sharedRemap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const self: *SharedHostBudget = @ptrCast(@alignCast(ctx));
        if (len > memory.len) {
            const growth = len - memory.len;
            if (!self.admit(growth)) return null;
            const result = self.heap_child.rawRemap(memory, alignment, len, ra) orelse {
                self.unadmit(growth);
                return null;
            };
            self.heapGrew(growth);
            return result;
        }
        const result = self.heap_child.rawRemap(memory, alignment, len, ra) orelse return null;
        self.heapShrank(memory.len - len);
        return result;
    }

    fn sharedFree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *SharedHostBudget = @ptrCast(@alignCast(ctx));
        self.heap_child.rawFree(memory, alignment, ra);
        self.heapShrank(memory.len);
    }

    /// Counters are read individually; under concurrent traffic the fields
    /// are each exact but not one atomic cut. Quiescent snapshots are exact.
    pub fn snapshot(self: *SharedHostBudget) Snapshot {
        const heap = self.heap_live.load(.acquire);
        const ext = self.external_live.load(.acquire);
        return .{ .live_bytes = heap + ext, .peak_live_bytes = self.peak_total.load(.acquire), .host_live_bytes = heap, .external_live_bytes = ext, .peak_host_bytes = self.peak_heap.load(.acquire), .peak_external_bytes = self.peak_external.load(.acquire), .limit = self.limit, .exceeded = self.exceeded.load(.acquire) };
    }

    /// Opt-in stage snapshots for callers already routing through this budget.
    /// Never interprets an unrelated allocator context.
    pub fn reportStage(a: std.mem.Allocator, stage: []const u8) void {
        if (!std.process.hasEnvVarConstant("STWO_HOST_MEMORY_PROFILE")) return;
        @import("measurement/process_usage.zig").reportStage(stage);
        if (!isAllocator(a)) return;
        const self: *SharedHostBudget = @ptrCast(@alignCast(a.ptr));
        const usage = self.snapshot();
        std.debug.print("HOST_MEMORY_STAGE {s} live={d} peak={d} heap={d} external={d} heap_peak={d} external_peak={d}\n", .{ stage, usage.live_bytes, usage.peak_live_bytes, usage.host_live_bytes, usage.external_live_bytes, usage.peak_host_bytes, usage.peak_external_bytes });
    }

    /// The caller must hold a live lease throughout acquisition.
    pub fn retain(self: *SharedHostBudget) *SharedHostBudget {
        const previous = self.references.fetchAdd(1, .monotonic);
        if (previous >= std.math.maxInt(usize) / 2) @panic("too many host budget leases");
        return self;
    }

    /// Releases one lease. The last lease requires all allocations freed and
    /// allocator users joined. Raw pointer copies do not acquire leases.
    pub fn destroy(self: *SharedHostBudget) void {
        if (self.references.fetchSub(1, .acq_rel) != 1) return;
        const final = self.snapshot();
        if (final.live_bytes != 0) {
            std.debug.print("HOST_BUDGET_UNRELEASED heap={} external={} peak={} limit={} exceeded={}\n", .{ final.host_live_bytes, final.external_live_bytes, final.peak_live_bytes, final.limit, final.exceeded });
            @panic("destroying live heap/external allocation budget");
        }
        const child = self.child;
        const parent = self.backing_owner;
        child.destroy(self);
        if (parent) |owner| owner.destroy();
    }
};

test "shared host budget admits exactly once under heavy contention" {
    const owner = try SharedHostBudget.create(std.heap.page_allocator, 64 * 1000);
    defer owner.destroy();
    const Worker = struct {
        fn run(o: *SharedHostBudget, admitted: *std.atomic.Value(usize)) void {
            var held: [64][]u8 = undefined;
            var n: usize = 0;
            for (0..2000) |_| {
                if (n == held.len) {
                    for (held[0..n]) |h| o.allocator().free(h);
                    n = 0;
                }
                if (o.allocator().alloc(u8, 1000)) |b| {
                    held[n] = b;
                    n += 1;
                    _ = admitted.fetchAdd(1, .monotonic);
                    if (o.snapshot().peak_live_bytes > o.limit) @panic("limit exceeded");
                } else |_| {}
            }
            for (held[0..n]) |h| o.allocator().free(h);
        }
    };
    var admitted = std.atomic.Value(usize).init(0);
    var threads: [8]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{ owner, &admitted });
    for (threads) |t| t.join();
    const state = owner.snapshot();
    try std.testing.expectEqual(@as(usize, 0), state.live_bytes);
    try std.testing.expect(state.peak_live_bytes <= 64 * 1000);
    try std.testing.expect(admitted.load(.monotonic) > 0);
}

test "shared host budget preserves exact accounting across thread transfer" {
    const owner = try SharedHostBudget.create(std.testing.allocator, 32);
    defer owner.destroy();
    const a = owner.allocator();
    const bytes = try a.alloc(u8, 32);
    var alive = true;
    defer if (alive) a.free(bytes);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 1));
    try std.testing.expectEqual(@as(usize, 32), owner.snapshot().live_bytes);
    const Worker = struct {
        fn release(allocator: std.mem.Allocator, storage: []u8) void {
            allocator.free(storage);
        }
    };
    const thread = try std.Thread.spawn(.{}, Worker.release, .{ a, bytes });
    alive = false;
    thread.join();
    const state = owner.snapshot();
    try std.testing.expectEqual(@as(usize, 0), state.live_bytes);
    try std.testing.expectEqual(@as(usize, 32), state.peak_live_bytes);
    try std.testing.expect(state.exceeded);
}

test "shared host budget lease survives original owner release" {
    const original = try SharedHostBudget.create(std.testing.allocator, 16);
    const retained = original.retain();
    defer retained.destroy();
    const a = original.allocator();
    original.destroy();
    const bytes = try a.alloc(u8, 16);
    defer a.free(bytes);
    try std.testing.expectEqual(@as(usize, 16), retained.snapshot().live_bytes);
}

fn nestedBudgetOwnership(a: std.mem.Allocator) !void {
    const parent = try SharedHostBudget.create(a, 4096);
    var parent_owned = true;
    defer if (parent_owned) parent.destroy();
    const nested = try SharedHostBudget.createRetainingParent(parent.allocator(), 128);
    defer nested.destroy();
    parent.destroy();
    parent_owned = false;
    const bytes = try nested.allocator().alloc(u8, 128);
    defer nested.allocator().free(bytes);
    @memset(bytes, 0x5a);
    try std.testing.expectError(error.OutOfMemory, nested.allocator().alloc(u8, 1));
    try std.testing.expectEqual(@as(usize, 128), nested.snapshot().host_live_bytes);
    try std.testing.expectEqual(@as(usize, @sizeOf(SharedHostBudget) + 128), nested.backing_owner.?.snapshot().host_live_bytes);
    try std.testing.expect(std.mem.allEqual(u8, bytes, 0x5a));
}
test "shared host budget nested owner survives backing release and every allocation failure" {
    try nestedBudgetOwnership(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, nestedBudgetOwnership, .{});
}
test "shared host budget nested descendants and external lease preserve backing chain" {
    const parent = try SharedHostBudget.create(std.testing.allocator, 4096);
    var parent_owned = true;
    defer if (parent_owned) parent.destroy();
    const child = try SharedHostBudget.createRetainingParent(parent.allocator(), 3072);
    var child_owned = true;
    defer if (child_owned) child.destroy();
    const descendant = try SharedHostBudget.createRetainingParent(child.allocator(), 128);
    defer descendant.destroy();
    parent.destroy();
    parent_owned = false;
    child.destroy();
    child_owned = false;
    var reservation = try descendant.reserveExternal(16);
    defer reservation.deinit();
    const bytes = try descendant.allocator().alloc(u8, 112);
    defer descendant.allocator().free(bytes);
    try std.testing.expectError(error.OutOfMemory, descendant.allocator().alloc(u8, 1));
    try std.testing.expectEqual(@as(usize, 128), descendant.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 112), descendant.snapshot().host_live_bytes);
    try std.testing.expectEqual(@as(usize, 16), descendant.snapshot().external_live_bytes);
}
