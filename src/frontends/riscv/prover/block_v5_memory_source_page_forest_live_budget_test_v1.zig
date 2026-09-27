//! Pure budget/ordinary storage tests; no proof, capture or Fresh fabricated.
const std = @import("std");
const Lane = @import("block_v5_memory_source_page_forest_live_budget_v1.zig");
const Budget = Lane.Budget;
const Summary = @import("../recursion/block_v5_memory_source_page_forest_summary_bus_v1.zig");
test "PAGE durable catalogue: live scratch exceeds metadata cap while each independent cap remains enforced" {
    const aggregate = try Budget.create(std.testing.allocator, 1 << 20);
    defer aggregate.destroy();
    const metadata = try Budget.createRetainingParent(aggregate.allocator(), 32 << 10);
    defer metadata.destroy();
    const records = try metadata.allocator().alloc(u8, 8 << 10);
    defer metadata.allocator().free(records);
    const live = try Lane.create(aggregate.allocator(), metadata, 128 << 10);
    defer live.destroy();
    const workspace = try live.allocator().alloc(u8, 64 << 10);
    defer live.allocator().free(workspace);
    try std.testing.expectEqual(@as(usize, 8 << 10), metadata.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 64 << 10), live.snapshot().live_bytes);
    try std.testing.expect(live.snapshot().live_bytes > metadata.snapshot().limit);
    try std.testing.expectError(error.OutOfMemory, metadata.allocator().alloc(u8, (24 << 10) + 1));
    try std.testing.expectError(error.OutOfMemory, live.allocator().alloc(u8, (64 << 10) + 1));
    try std.testing.expectEqual(@as(usize, 8 << 10), metadata.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 64 << 10), live.snapshot().live_bytes);
}
test "PAGE durable catalogue: aggregate backing still rejects combined metadata and scratch demand" {
    const aggregate = try Budget.create(std.testing.allocator, 96 << 10);
    defer aggregate.destroy();
    const metadata = try Budget.createRetainingParent(aggregate.allocator(), 32 << 10);
    defer metadata.destroy();
    const records = try metadata.allocator().alloc(u8, 24 << 10);
    defer metadata.allocator().free(records);
    const live = try Lane.create(aggregate.allocator(), metadata, 128 << 10);
    defer live.destroy();
    try std.testing.expectError(error.OutOfMemory, live.allocator().alloc(u8, 80 << 10));
    try std.testing.expect(aggregate.snapshot().exceeded);
    try std.testing.expect(!live.snapshot().exceeded);
    try std.testing.expectEqual(@as(usize, 0), live.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 24 << 10), metadata.snapshot().live_bytes);
}
test "PAGE durable catalogue: live lane rejects metadata allocator and zero cap before allocation" {
    const metadata = try Budget.create(std.testing.allocator, 1 << 20);
    defer metadata.destroy();
    try std.testing.expectError(error.PageForestLiveBudgetUsesMetadata, Lane.create(metadata.allocator(), metadata, 128 << 10));
    try std.testing.expectEqual(@as(usize, 0), metadata.snapshot().live_bytes);
    try std.testing.expectError(error.InvalidPageForestLiveBudget, Lane.create(std.testing.failing_allocator, undefined, 0));
}
fn escapingLane(a: std.mem.Allocator) !void {
    const aggregate = try Budget.create(a, 1 << 20);
    var owns_aggregate = true;
    defer if (owns_aggregate) aggregate.destroy();
    const metadata = try Budget.createRetainingParent(aggregate.allocator(), 32 << 10);
    defer metadata.destroy();
    const records = try metadata.allocator().alloc(u8, 8 << 10);
    defer metadata.allocator().free(records);
    const live = try Lane.create(aggregate.allocator(), metadata, 128 << 10);
    var owns_live = true;
    defer if (owns_live) live.destroy();
    const scratch = live.allocator();
    // An UNADMITTED storage owner exercises the exact production lease. It is
    // never offered to authority(), Parent.verify or any actual proof receiver.
    var summary = Summary.Owner{ .allocator = scratch, .allocation_owner = live.retain(), .policy = undefined, .limits = .{}, .summary = undefined };
    var owns_summary = true;
    defer if (owns_summary) summary.deinit();
    var teardown: ?*Budget = null;
    defer if (teardown) |held| held.destroy();
    const workspace = try scratch.alloc(u8, 64 << 10);
    defer scratch.free(workspace);
    @memset(workspace, 73);
    live.destroy();
    owns_live = false;
    aggregate.destroy();
    owns_aggregate = false;
    try std.testing.expectEqual(@as(u8, 73), workspace[workspace.len - 1]);
    try std.testing.expectEqual(@as(usize, 1), live.references.load(.acquire));
    try std.testing.expectEqual(@as(usize, 8 << 10), metadata.snapshot().live_bytes);
    teardown = live.retain();
    summary.deinit();
    owns_summary = false;
    // Exact real Fresh teardown holds its allocator through the final control
    // free. Live storage then disappears before metadata/borrowed policy.
    try std.testing.expectEqual(@as(u8, 73), workspace[0]);
}
test "PAGE durable catalogue: escaping live summary lease and metadata lifetime survive every new allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, escapingLane, .{});
}
