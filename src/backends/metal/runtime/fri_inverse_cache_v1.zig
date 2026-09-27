//! Actual Metal inverse ownership. Explicit resident buffers replace the
//! runtime's unbudgeted legacy caches on canonical allocator-bearing calls.
//! Bank locks only pin slots; immutable inverse reader leases overlap across
//! same-budget proofs. Factories and checked completion never hold bank locks.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const runtime = @import("../runtime.zig");
const shared = @import("../shared_runtime.zig");
const generic = @import("fri_inverse_cache_budget_v1.zig");
pub const Key = generic.Key;
const Resource = struct {
    buffer: runtime.ResidentBuffer,
    pub fn deinit(self: *Resource) void {
        self.buffer.deinit();
        shared.releaseResidentResource();
    }
};
const Cache = generic.Cache(Resource);
const Slot = struct { runtime_handle: *anyopaque, owner: *engine.host_budget_allocator.SharedHostBudget, users: usize = 0, cache: Cache = .{} };
var lock: std.Thread.Mutex = .{};
var slots: [4]?Slot = @splat(null);
const Factory = struct {
    runtime: *runtime.Runtime,
    pub fn create(self: Factory, _: Key, bytes: usize) !Resource {
        const buffer = try self.runtime.allocateResidentBuffer(bytes);
        shared.retainResidentResource();
        return .{ .buffer = buffer };
    }
};
const BudgetedTransaction = struct {
    index: ?usize,
    inner: Cache.Transaction,
    pub fn take(self: *BudgetedTransaction) BudgetedTransaction {
        const index = self.index;
        self.index = null;
        return .{ .index = index, .inner = self.inner.take() };
    }
    pub fn handle(self: *BudgetedTransaction, kind: Key.Kind) ?*anyopaque {
        return if (self.inner.resource(kind)) |resource| resource.buffer.handle else null;
    }
    pub fn needsGeneration(self: *const BudgetedTransaction, kind: Key.Kind) bool {
        return self.inner.needsGeneration(kind);
    }
    pub fn complete(self: *BudgetedTransaction) !void {
        const index = self.index orelse return;
        self.inner.complete() catch |err| {
            self.index = null;
            releaseSlot(index);
            return err;
        };
        self.index = null;
        releaseSlot(index);
    }
    /// Cancels/joins outside all metadata locks before dropping reader leases.
    pub fn abort(self: *BudgetedTransaction) void {
        const index = self.index orelse return;
        self.inner.abort();
        self.index = null;
        releaseSlot(index);
    }
};
const Transient = @import("fri_inverse_transient_v1.zig").Transient(Resource);
pub const Transaction = union(enum) {
    shared: BudgetedTransaction,
    explicit_unbudgeted: Transient,
    pub fn take(self: *Transaction) Transaction {
        return switch (self.*) {
            .shared => |*owned| .{ .shared = owned.take() },
            .explicit_unbudgeted => |*owned| .{ .explicit_unbudgeted = owned.take() },
        };
    }
    pub fn handle(self: *Transaction, kind: Key.Kind) ?*anyopaque {
        return switch (self.*) {
            .shared => |*owned| owned.handle(kind),
            .explicit_unbudgeted => |*owned| if (owned.resource(kind)) |resource| resource.buffer.handle else null,
        };
    }
    pub fn needsGeneration(self: *const Transaction, kind: Key.Kind) bool {
        return switch (self.*) {
            .shared => |*owned| owned.needsGeneration(kind),
            .explicit_unbudgeted => |*owned| owned.needsGeneration(kind),
        };
    }
    pub fn complete(self: *Transaction) !void {
        switch (self.*) {
            .shared => |*owned| try owned.complete(),
            .explicit_unbudgeted => |*owned| try owned.complete(),
        }
    }
    pub fn abort(self: *Transaction) void {
        switch (self.*) {
            .shared => |*owned| owned.abort(),
            .explicit_unbudgeted => |*owned| owned.abort(),
        }
    }
};
pub fn begin(a: std.mem.Allocator, metal: *runtime.Runtime, keys: [2]?Key) !Transaction {
    var acquired = try beginShared(a, metal, keys);
    return .{ .shared = acquired.take() };
}
pub fn beginWithPolicy(a: std.mem.Allocator, metal: *runtime.Runtime, keys: [2]?Key, policy: @import("fri_allocation_policy_v1.zig").Policy) !Transaction {
    const binding = try @import("fri_allocation_policy_v1.zig").Binding.init(a, policy);
    if (binding.policy == .require_shared_budget) return begin(a, metal, keys);
    for (keys) |key| if (key) |value| if (value.runtime != @intFromPtr(metal.handle)) return error.InvalidFriInverseCacheRuntime;
    var acquired = try Transient.init(a, keys, Factory{ .runtime = metal });
    return .{ .explicit_unbudgeted = acquired.take() };
}
fn beginShared(a: std.mem.Allocator, metal: *runtime.Runtime, keys: [2]?Key) !BudgetedTransaction {
    const owner = engine.host_budget_allocator.SharedHostBudget.fromAllocator(a) orelse return error.SharedExternalBudgetRequired;
    if (keys[0] == null and keys[1] == null) return error.EmptyFriInverseCacheRequest;
    // Key admission precedes slot ownership or allocation.
    for (keys, 0..) |key, index| if (key) |value| {
        if (value.runtime != @intFromPtr(metal.handle)) return error.InvalidFriInverseCacheRuntime;
        if ((value.kind == .circle) != (index == 0)) return error.InvalidFriInverseCacheKey;
        _ = try value.bytes();
    };
    lock.lock();
    var locked = true;
    defer if (locked) lock.unlock();
    var selected: ?usize = null;
    for (&slots, 0..) |*slot, i| if (slot.*) |*entry| {
        if (entry.runtime_handle == metal.handle) {
            if (entry.owner != owner) return error.FriInverseCacheBudgetConflict;
            selected = i;
            break;
        }
    };
    if (selected == null) for (&slots, 0..) |*slot, i| if (slot.* == null) {
        // A slot lease is distinct from entry reservations: it protects the
        // allocator during factories, private misses and empty rollback.
        shared.retainResidentResource(); // Runtime lease even during a cold factory.
        slot.* = .{ .runtime_handle = metal.handle, .owner = owner.retain() };
        selected = i;
        break;
    };
    const index = selected orelse return error.FriInverseCacheCapacityExceeded;
    if (slots[index].?.users == generic.Limits.max_transactions) return error.FriInverseCacheCapacityExceeded;
    slots[index].?.users += 1;
    const cache = &slots[index].?.cache;
    lock.unlock();
    locked = false;
    errdefer releaseSlot(index);
    var inner = try cache.begin(a, keys, Factory{ .runtime = metal });
    return .{ .index = index, .inner = inner.take() };
}
fn releaseSlot(index: usize) void {
    lock.lock();
    defer lock.unlock();
    const entry = &slots[index].?;
    std.debug.assert(entry.users > 0);
    entry.users -= 1;
    if (entry.users == 0 and entry.cache.isEmpty()) {
        const owner = entry.owner;
        slots[index] = null;
        owner.destroy();
        shared.releaseResidentResource();
    }
}
/// Teardown never joins behind a proof. No entry is released when users are
/// live; caller must first cancel/join its outstanding proof transactions.
pub fn drain(a: std.mem.Allocator) !void {
    const owner = engine.host_budget_allocator.SharedHostBudget.fromAllocator(a) orelse return error.SharedExternalBudgetRequired;
    if (!lock.tryLock()) return error.RuntimeBusy;
    defer lock.unlock();
    for (&slots) |*slot| if (slot.*) |*entry| {
        if (entry.owner == owner and entry.users != 0) return error.RuntimeBusy;
    };
    for (&slots) |*slot| if (slot.*) |*entry| {
        if (entry.owner == owner) {
            try entry.cache.drain(a);
            const retained_owner = entry.owner;
            slot.* = null;
            retained_owner.destroy();
            shared.releaseResidentResource();
        }
    };
}
/// Bank/entry owners remain retained through resident buffer destruction. A
/// caller holding a live proof receives RuntimeBusy rather than self-deadlock.
pub fn drainAllForShutdown() error{RuntimeBusy}!void {
    if (!lock.tryLock()) return error.RuntimeBusy;
    defer lock.unlock();
    for (&slots) |*slot| if (slot.*) |*entry| {
        if (entry.users != 0) return error.RuntimeBusy;
    };
    for (&slots) |*slot| if (slot.*) |*entry| {
        const owner = entry.owner;
        entry.cache.drain(owner.allocator()) catch return error.RuntimeBusy;
        slot.* = null;
        owner.destroy();
        shared.releaseResidentResource();
    };
}
