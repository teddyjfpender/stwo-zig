const std = @import("std");
const B = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const R = @import("rv64_large_block_recycler.zig").LargeBlockRecycler;
const Access = @import("rv64_recursion_budget.zig");

test "ready budget admits exact direct and recycler-backed owner only" {
    const owner = try B.create(std.testing.allocator, 2 << 20);
    defer owner.destroy();
    var recycler = R.init(owner.allocator(), 1 << 20);
    defer recycler.deinit();
    try std.testing.expect((try Access.require(B, owner.allocator())) == owner);
    try std.testing.expect((try Access.require(B, recycler.allocator())) == owner);
    try std.testing.expect(B.fromAllocator(recycler.allocator()) == null);
    var unrelated = R.init(std.testing.allocator, 1 << 20);
    defer unrelated.deinit();
    var nested = R.init(recycler.allocator(), 1 << 20);
    defer nested.deinit();
    var wrapper = std.heap.ThreadSafeAllocator{ .child_allocator = owner.allocator() };
    try std.testing.expectError(error.SharedRecursionBudgetRequired, Access.require(B, unrelated.allocator()));
    try std.testing.expectError(error.SharedRecursionBudgetRequired, Access.require(B, nested.allocator()));
    try std.testing.expectError(error.SharedRecursionBudgetRequired, Access.require(B, wrapper.allocator()));
}

test "ready recycler keeps idle capacity charged alongside external reservations" {
    const owner = try B.create(std.testing.allocator, 2 << 20);
    defer owner.destroy();
    var recycler = R.init(owner.allocator(), 1 << 20);
    defer recycler.deinit();
    const a = recycler.allocator();
    const first = try a.alloc(u8, R.threshold + 1);
    const live = owner.snapshot().host_live_bytes;
    a.free(first);
    try std.testing.expect(recycler.stats().cached_bytes > R.threshold);
    try std.testing.expect(owner.snapshot().host_live_bytes >= live);
    const idle = owner.snapshot().host_live_bytes;
    var stack = try owner.reserveExternal(owner.snapshot().limit - idle);
    defer stack.deinit();
    // A cached block can be reused without new backing growth, while a new
    // capacity and unrelated external reservation both hit the same hard cap.
    const reused = try a.alloc(u8, R.threshold + 1);
    a.free(reused);
    try std.testing.expectEqual(@as(u64, 1), recycler.stats().reused_blocks);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, R.threshold * 2));
    try std.testing.expectError(error.OutOfMemory, owner.reserveExternal(1));
    stack.deinit();
    _ = recycler.releaseCached();
    try std.testing.expect(owner.snapshot().host_live_bytes < idle);
}

test "ready recycler reservation owner identity cannot cross budgets" {
    const one = try B.create(std.testing.allocator, 1 << 20);
    defer one.destroy();
    const two = try B.create(std.testing.allocator, 1 << 20);
    defer two.destroy();
    var recycler = R.init(one.allocator(), 0);
    defer recycler.deinit();
    const resolved = try Access.require(B, recycler.allocator());
    var right = try one.reserveExternal(4096);
    defer right.deinit();
    var wrong = try two.reserveExternal(4096);
    defer wrong.deinit();
    try right.requireOwner(resolved.allocator(), 4096);
    try std.testing.expectError(error.InvalidExternalReservationOwner, wrong.requireOwner(resolved.allocator(), 4096));
}
