//! Isolated allocator lifetime fixture; no fake ProofCapture or Fresh exists.
//! Unadmitted summary storage is never validated or offered as proof authority.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Summary = @import("../recursion/block_v5_memory_source_page_forest_summary_bus_v1.zig");
fn retainAfterCoordinator(a: std.mem.Allocator) !void {
    const parent = try Budget.create(a, 1 << 20);
    var parent_owned = true;
    defer if (parent_owned) parent.destroy();
    const child = try Budget.createRetainingParent(parent.allocator(), 1 << 18);
    var coordinator_owned = true;
    defer if (coordinator_owned) child.destroy();
    const scratch = child.allocator();
    // This is storage only. The production constructor independently admits
    // its statement before acquiring precisely this allocator lease.
    var unadmitted = Summary.Owner{ .allocator = scratch, .allocation_owner = child.retain(), .policy = undefined, .limits = .{}, .summary = undefined };
    var summary_owned = true;
    defer if (summary_owned) unadmitted.deinit();
    var teardown: ?*Budget = null;
    defer if (teardown) |held| held.destroy();
    const storage = try scratch.alloc(u32, 64);
    defer scratch.free(storage);
    @memset(storage, 17);
    child.destroy();
    coordinator_owned = false;
    parent.destroy();
    parent_owned = false;
    // Both original coordinators have gone away. The exact production Summary
    // lease still owns the control allocator and all its child allocations.
    try std.testing.expectEqual(@as(u32, 17), storage[63]);
    try std.testing.expectEqual(@as(usize, 1), child.references.load(.acquire));
    // Fresh.deinit uses an equivalent temporary hold around capture/summary/
    // outer-node frees. That genuine body is separately retained, not invoked.
    teardown = child.retain();
    unadmitted.deinit();
    summary_owned = false;
    try std.testing.expectEqual(@as(usize, 1), child.references.load(.acquire));
    try std.testing.expectEqual(@as(u32, 17), storage[0]);
}
test "PAGE durable catalogue: summary allocator lease survives parent and scratch coordinator release and every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, retainAfterCoordinator, .{});
}

test "PAGE durable catalogue: inactive raw and fold slots cannot accept original recursive proof bytes" {
    const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
    const Admission = @import("block_v5_memory_source_page_recursive_admission_v1.zig");
    const Leaves = @import("../recursion/block_v5_memory_source_page_forest_leaf_v1.zig");
    inline for ([_]Semantic.Kind{ .raw, .fold }) |kind| {
        var unadmitted: Admission.ForKind(kind).Prepared = undefined;
        unadmitted.limits = .{};
        unadmitted.limits.max_capture_bytes = 0;
        const Family = Leaves.ForKind(kind);
        var schedule: [1]@import("../recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind).Wire = undefined;
        const rejected = Family.Policy{ .admitted = &unadmitted, .claims = undefined, .key = undefined, .expected_id = undefined, .schedule = &schedule };
        // Undefined source/key fields deliberately remain unread: an idle slot
        // is storage, not an admission. No synthetic accepted key or capture.
        try std.testing.expectError(error.SourcePageRecursiveResourceLimit, Family.verify(std.testing.failing_allocator, rejected, "unverified proposal"));
    }
}
