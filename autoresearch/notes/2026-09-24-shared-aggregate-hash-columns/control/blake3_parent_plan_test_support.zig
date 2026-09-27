//! Ownership checks at the planning/emission boundary, using one verified child.
const std = @import("std");
const parent = @import("../recursion/blake3_execution_parent_preparation.zig");

pub fn check(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !void {
    var tracking = std.testing.FailingAllocator.init(a, .{});
    var discarded = try parent.State.plan(tracking.allocator(), admitted, capture, expected, 2);
    discarded.deinit();
    discarded.deinit();
    try std.testing.expectEqual(tracking.allocated_bytes, tracking.freed_bytes);
    try std.testing.expectError(error.ConsumedParentPlan, discarded.emit());

    var successful = try parent.State.plan(tracking.allocator(), admitted, capture, expected, 2);
    const begin = tracking.alloc_index;
    const layout = successful.layout;
    const state = try successful.emit();
    const allocations = tracking.alloc_index - begin;
    defer successful.deinit();
    try std.testing.expect(successful.state == null and successful.transcript == null);
    try std.testing.expectEqualDeep(layout, state.hash_columns.layout);
    try std.testing.expectError(error.ConsumedParentPlan, successful.emit());
    state.deinit();
    try std.testing.expectEqual(tracking.allocated_bytes, tracking.freed_bytes);
    try std.testing.expect(allocations > 3);

    // Cover initial storage, partial storage, interior emission and the final
    // allocation after planning ownership has moved into the live transcript.
    for ([_]usize{ 0, 2, allocations / 2, allocations - 1 }) |offset| {
        var failing = std.testing.FailingAllocator.init(a, .{});
        var plan = try parent.State.plan(failing.allocator(), admitted, capture, expected, 2);
        defer plan.deinit();
        failing.fail_index = failing.alloc_index + offset;
        failing.resize_fail_index = failing.resize_index;
        try std.testing.expectError(error.OutOfMemory, plan.emit());
        try std.testing.expect(plan.state == null and plan.transcript == null);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
    std.debug.print("PARENT_PLAN_LIFECYCLE abandoned=true consumed=true emission_failures=4 allocations={d}\n", .{allocations});
}
