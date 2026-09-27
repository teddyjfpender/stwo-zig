//! Device-free lifecycle of the production composition/hash scratch pool.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Reservation = engine.shared_external_memory.Reservation;
const Resource = struct {
    byte_length: usize,
    external_reservation: Reservation = .empty(),
    destroyed: *usize,
    pub fn deinit(self: *Resource) void {
        self.destroyed.* += 1;
        self.external_reservation.deinit();
        self.* = undefined;
    }
};
const Factory = struct {
    calls: *usize,
    destroyed: *usize,
    fail: bool = false,
    wrong_extent: bool = false,
    pub fn create(self: Factory, bytes: usize) !Resource {
        self.calls.* += 1;
        if (self.fail) return error.FactoryFailed;
        return .{ .byte_length = bytes + @intFromBool(self.wrong_extent), .destroyed = self.destroyed };
    }
};
const Pool = @import("backends/metal/runtime/composition_resident_pool_v1.zig").Pool(Resource, 2, 128);

test "composition pool: active and idle buffers retain exact charges and reuse only their owner" {
    const first = try Budget.create(std.testing.allocator, 256);
    defer first.destroy();
    const second = try Budget.create(std.testing.allocator, 256);
    defer second.destroy();
    var calls: usize = 0;
    var destroyed: usize = 0;
    const factory = Factory{ .calls = &calls, .destroyed = &destroyed };
    var pool: Pool = .{};
    const a = try pool.acquire(first.allocator(), 1, 64, factory);
    pool.release(first.allocator(), 1, a);
    try std.testing.expectEqual(@as(usize, 64), first.snapshot().external_live_bytes);
    const hit = try pool.acquire(first.allocator(), 1, 64, factory);
    try std.testing.expectEqual(@as(u64, 1), pool.snapshot().hits);
    const b = try pool.acquire(second.allocator(), 1, 64, factory);
    try std.testing.expectEqual(@as(usize, 64), second.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 2), calls);
    try std.testing.expectError(error.RuntimeBusy, pool.drainAll());
    try std.testing.expectError(error.CompositionScratchCapacityExceeded, pool.acquire(first.allocator(), 1, 64, factory));
    try std.testing.expectEqual(@as(usize, 2), calls);
    pool.release(first.allocator(), 1, hit);
    pool.release(second.allocator(), 1, b);
    try pool.drain(first.allocator());
    try std.testing.expectEqual(@as(usize, 0), first.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 64), second.snapshot().external_live_bytes);
    try pool.drainAll();
    try std.testing.expectEqual(@as(usize, 2), destroyed);
    try std.testing.expectEqual(@as(usize, 0), second.snapshot().external_live_bytes);
}

test "composition pool: admission precedes factory and every failure rolls back" {
    const owner = try Budget.create(std.testing.allocator, 64);
    defer owner.destroy();
    var calls: usize = 0;
    var destroyed: usize = 0;
    var factory = Factory{ .calls = &calls, .destroyed = &destroyed };
    var pool: Pool = .{};
    try std.testing.expectError(error.OutOfMemory, pool.acquire(owner.allocator(), 1, 65, factory));
    try std.testing.expectEqual(@as(usize, 0), calls);
    factory.fail = true;
    try std.testing.expectError(error.FactoryFailed, pool.acquire(owner.allocator(), 1, 64, factory));
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
    factory.fail = false;
    factory.wrong_extent = true;
    try std.testing.expectError(error.InvalidCompositionScratchResource, pool.acquire(owner.allocator(), 1, 64, factory));
    try std.testing.expectEqual(@as(usize, 1), destroyed);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 0), pool.active);
    try pool.drainAll();
}

test "composition pool: eviction and oversized release preserve live plus idle bound" {
    const owner = try Budget.create(std.testing.allocator, 512);
    defer owner.destroy();
    var calls: usize = 0;
    var destroyed: usize = 0;
    const factory = Factory{ .calls = &calls, .destroyed = &destroyed };
    var pool: Pool = .{};
    const first = try pool.acquire(owner.allocator(), 1, 64, factory);
    const second = try pool.acquire(owner.allocator(), 1, 128, factory);
    pool.release(owner.allocator(), 1, first);
    const different_runtime = try pool.acquire(owner.allocator(), 2, 64, factory);
    try std.testing.expectEqual(@as(usize, 1), destroyed);
    try std.testing.expectEqual(@as(usize, 3), calls);
    pool.release(owner.allocator(), 1, second);
    pool.release(owner.allocator(), 2, different_runtime);
    const large = try pool.acquire(owner.allocator(), 1, 256, factory);
    pool.release(owner.allocator(), 1, large);
    try std.testing.expectEqual(@as(usize, 1), pool.snapshot().pooled);
    try std.testing.expectEqual(@as(usize, 3), destroyed);
    try pool.drainAll();
    try std.testing.expectEqual(@as(usize, 4), destroyed);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
}

test "composition pool: cached charge survives original budget release and uncapped scope remains separate" {
    const owner = try Budget.create(std.testing.allocator, 256);
    var calls: usize = 0;
    var destroyed: usize = 0;
    const factory = Factory{ .calls = &calls, .destroyed = &destroyed };
    var pool: Pool = .{};
    const charged = try pool.acquire(owner.allocator(), 1, 64, factory);
    pool.release(owner.allocator(), 1, charged);
    owner.destroy();
    const uncapped = try pool.acquire(std.testing.allocator, 1, 64, factory);
    try std.testing.expect(uncapped.external_reservation.owner == null);
    try std.testing.expectEqual(@as(usize, 2), calls);
    pool.release(std.testing.allocator, 1, uncapped);
    try pool.drain(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), pool.snapshot().pooled);
    try pool.drainAll();
    try std.testing.expectEqual(@as(usize, 2), destroyed);
}
