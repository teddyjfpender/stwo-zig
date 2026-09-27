//! Synchronous callback/token metadata only. No first roots, keys, complete
//! source record or accepted proof is created by these observer fixtures.
const std = @import("std");
const New = @import("block_v5_caller_readonly_collection_v2.zig");
const Collection = @import("block_v5_readonly_input_counter_collection_v2.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
pub const behavioral_test_count = 2;
const intervals = [_]Plan.Interval{ .{ .lower = 0, .upper = 1, .readonly = false, .value = 0 }, .{ .lower = 1, .upper = 2, .readonly = true, .value = 7 }, .{ .lower = 2, .upper = Plan.WORD_LIMIT, .readonly = false, .value = 0 } };
fn unused(_: *anyopaque, _: Collection.GroupView) !void {
    return error.UnexpectedObserverFlush;
}
fn collector(a: std.mem.Allocator, context: *u8) !Collection.Owned {
    return Collection.Owned.init(a, @splat(1), &intervals, 1, .{ .sink = .{ .context = context, .put_group = unused } });
}
fn lifetime(a: std.mem.Allocator) !void {
    var context: u8 = 0;
    var groups = try collector(a, &context);
    defer groups.deinit();
    // A real collector token is sufficient to exercise the callback. It stays
    // pending and is aborted: no fabricated native roots precede a caller.
    const token = try groups.beginSource(.native, 0, 3);
    var observation = New.Observation{ .groups = &groups, .token = token };
    const observer = observation.observer();
    try observer.observe(observer.context, 1);
    try observer.observe(observer.context, 0);
    try observer.observe(observer.context, 1);
    try std.testing.expectEqualSlices(u64, &.{ 1, 2, 0 }, groups.counts);
    try groups.abortSource(token);
    try std.testing.expect(groups.poisoned);
    try std.testing.expectEqual(@as(usize, 0), groups.source_count);
    try std.testing.expectError(error.ReadonlyCounterCollectionClosed, groups.finish());
}
test "caller readonly streaming collection: synchronous observer one job vector and allocation unwind" {
    try lifetime(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, lifetime, .{});
}
test "caller readonly streaming collection: changed stale tokens and intervals cannot add counters" {
    var context: u8 = 0;
    var groups = try collector(std.testing.allocator, &context);
    defer groups.deinit();
    const token = try groups.beginSource(.native, 0, 1);
    var observation = New.Observation{ .groups = &groups, .token = token };
    var observer = observation.observer();
    try std.testing.expectError(error.InvalidReadonlyCounterObservation, observer.observe(observer.context, @intCast(intervals.len)));
    observation.token.generation += 1;
    try std.testing.expectError(error.StaleReadonlyCounterSourceToken, observer.observe(observer.context, 0));
    try std.testing.expectEqualSlices(u64, &.{ 0, 0, 0 }, groups.counts);
    observation.token = token;
    try groups.abortSource(token);
    observer = observation.observer();
    try std.testing.expectError(error.StaleReadonlyCounterSourceToken, observer.observe(observer.context, 0));
    try std.testing.expectEqual(@as(usize, 0), groups.source_count);
}
