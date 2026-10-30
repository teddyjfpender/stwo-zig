const std = @import("std");
const Scope = @import("prover/block_v7_multi_union_scope_v1.zig");
const Receiver = @import("prover/block_v7_execution_receiver_v1.zig");
const Placement = @import("prover/block_v7_multi_union_placement_v1.zig");
const Residency = @import("prover/block_v7_multi_union_residency_v1.zig");
fn instantiate(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Scope.Input, limits: Scope.Limits) !void {
    const scope = try Scope.Owned.init(a, trusted, input, limits);
    defer scope.deinit();
}
test "multi union scope original metadata admission instantiates" {
    std.mem.doNotOptimizeAway(&instantiate);
}
test "multi union placement preserves mixed access and exact family tree order" {
    const a = std.testing.allocator;
    const sources = [_]Placement.Source{
        .{ .family = .native, .index = 0, .root_count = 2 },
        .{ .family = .native, .index = 1, .root_count = 3 },
        .{ .family = .caller_fused, .index = 0, .root_count = 3 },
        .{ .family = .program, .index = 0, .root_count = 2 },
        .{ .family = .lookup, .index = 0, .root_count = 2 },
        .{ .family = .memory_joint, .index = 0, .root_count = 2 },
    };
    var p = try Placement.Plan.derive(a, &sources, 2, 1, 64);
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 16), p.trace_trees);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 9 }, p.parts[0].mapping());
    try std.testing.expectEqualSlices(usize, &.{ 0, 2, 3, 10 }, p.parts[1].mapping());
    try std.testing.expectEqualSlices(usize, &.{ 0, 4, 5, 11, 12 }, p.parts[2].mapping());
    var seen: [16]bool = @splat(false);
    for (p.parts) |part| for (part.mapping()[1..]) |tree| {
        try std.testing.expect(!seen[tree]);
        seen[tree] = true;
    };
    for (seen[1..]) |present| try std.testing.expect(present);
    try std.testing.expectError(error.MultiUnionTreeBudgetExceeded, Placement.Plan.derive(a, &sources, 2, 1, 15));
    var bad = sources;
    bad[0].root_count = 4;
    try std.testing.expectError(error.InvalidMultiUnionSourceTrees, Placement.Plan.derive(a, &bad, 2, 1, 64));
    bad = sources;
    std.mem.swap(Placement.Source, &bad[0], &bad[1]);
    try std.testing.expectError(error.InvalidMultiUnionRoster, Placement.Plan.derive(a, &bad, 2, 1, 64));
    try std.testing.expectError(error.InvalidMultiUnionRoster, Placement.Plan.derive(a, sources[0..5], 2, 1, 64));
}
test "multi union placement no caller and no access has no dummy tree" {
    const a = std.testing.allocator;
    const sources = [_]Placement.Source{ .{ .family = .native, .index = 0, .root_count = 2 }, .{ .family = .program, .index = 0, .root_count = 2 }, .{ .family = .lookup, .index = 0, .root_count = 2 }, .{ .family = .memory_joint, .index = 0, .root_count = 2 } };
    var p = try Placement.Plan.derive(a, &sources, 1, 0, 64);
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 9), p.trace_trees);
    for (p.parts) |part| try std.testing.expectEqual(@as(u32, 3), part.source_trees);
}
test "multi union residency bound is checked and rejects undersized policy" {
    var r: Residency.Estimate = .{};
    try r.addTree(&.{ 2, 3 }, 1);
    try std.testing.expectEqual(@as(u64, 96), r.lde_bytes);
    try std.testing.expectEqual(@as(u64, 48), r.coefficient_bytes);
    try std.testing.expectEqual(@as(u64, 31 * 32), r.merkle_bytes);
    try r.require(@intCast(r.total_bytes));
    try std.testing.expectError(error.MultiUnionRetainedPCSExceedsBudget, r.require(@intCast(r.total_bytes - 1)));
    try std.testing.expectError(error.InvalidMultiUnionRetainedLimit, r.require(0));
    try std.testing.expectError(error.InvalidMultiUnionResidency, r.addTree(&.{30}, 1));
    var overflow = Residency.Estimate{ .lde_bytes = std.math.maxInt(u64) };
    try std.testing.expectError(error.Overflow, overflow.addTree(&.{1}, 0));
}
