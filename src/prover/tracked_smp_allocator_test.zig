const std = @import("std");
const TrackedSmpAllocator = @import("tracked_smp_allocator.zig").TrackedSmpAllocator;

test "tracked SMP allocator preserves ownership through growth and concurrent release" {
    var tracked = TrackedSmpAllocator{};
    const allocator = tracked.allocator();
    var bytes = try allocator.alloc(u8, 31);
    bytes = try allocator.realloc(bytes, 4097);
    const live = tracked.snapshot();
    try std.testing.expectEqual(@as(usize, 1), live.active_allocations);
    try std.testing.expectEqual(@as(usize, 4097), live.active_bytes);
    try std.testing.expectEqual(@as(usize, 0), live.untracked_active_allocations);
    allocator.free(bytes);
    try std.testing.expect(tracked.isEmpty());
    try std.testing.expect(tracked.peakBytes() >= 4097);
    const before_report = tracked.snapshot();
    tracked.dumpLeaks();
    try std.testing.expectEqualDeep(before_report, tracked.snapshot());

    // Real transcript materialization exceeded the old 4096-record limit
    // while holding only a few MiB. Track every allocation beyond that limit.
    var allocations: [8193][]u8 = undefined;
    var allocated: usize = 0;
    defer for (allocations[0..allocated]) |allocation| allocator.free(allocation);
    for (&allocations) |*allocation| {
        allocation.* = try allocator.alloc(u8, 64);
        allocated += 1;
    }
    try std.testing.expectEqual(allocations.len, tracked.snapshot().active_allocations);
    try std.testing.expectEqual(allocations.len * 64, tracked.snapshot().active_bytes);
    for (&allocations) |*allocation| {
        allocation.* = try allocator.realloc(allocation.*, 32);
    }
    try std.testing.expectEqual(allocations.len * 32, tracked.snapshot().active_bytes);
    for (allocations) |allocation| allocator.free(allocation);
    allocated = 0;
    try std.testing.expect(tracked.isEmpty());

    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| thread.* = try std.Thread.spawn(
        .{},
        exerciseTrackedAllocator,
        .{ &tracked, index },
    );
    for (&threads) |*thread| thread.join();
    try std.testing.expect(tracked.isEmpty());
}

fn exerciseTrackedAllocator(
    tracked: *TrackedSmpAllocator,
    worker_index: usize,
) void {
    const allocator = tracked.allocator();
    for (0..256) |iteration| {
        const initial_len = 33 + ((worker_index + iteration) % 97);
        var bytes = allocator.alloc(u8, initial_len) catch
            @panic("tracked allocator concurrency fixture allocation failed");
        const grown_len = 4097 + ((worker_index * 257 + iteration) % 1021);
        bytes = allocator.realloc(bytes, grown_len) catch
            @panic("tracked allocator concurrency fixture resize failed");
        allocator.free(bytes);
    }
}
