//! Static recipe identity and worker publication only; no proof or job runs.
const std = @import("std");
const Cache = @import("source_authority_cache_v1.zig");
const Basic = struct {
    var count: std.atomic.Value(usize) = .init(0);
    const Stored = Cache.For(build);
    fn build() [32]u8 {
        _ = count.fetchAdd(1, .monotonic);
        var result: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash("immutable compiled source recipe", &result, .{});
        return result;
    }
};
test "static source authority: exact deterministic identity is constructed once" {
    var expected: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash("immutable compiled source recipe", &expected, .{});
    for (0..128) |_| try std.testing.expectEqual(expected, Basic.Stored.get());
    try std.testing.expectEqual(@as(usize, 1), Basic.count.load(.acquire));
}
const Worker = struct {
    var count: std.atomic.Value(usize) = .init(0);
    var mismatch: std.atomic.Value(bool) = .init(false);
    const Stored = Cache.For(build);
    fn build() [32]u8 {
        _ = count.fetchAdd(1, .monotonic);
        var result: [32]u8 = undefined;
        for (&result, 0..) |*byte, index| byte.* = @intCast(3 * index + 1);
        return result;
    }
    fn run() void {
        for (0..100) |_| {
            const result = Stored.get();
            for (result, 0..) |byte, index| if (byte != 3 * index + 1) mismatch.store(true, .release);
        }
    }
};
test "static source authority: concurrent workers observe one fully published identity" {
    var threads: [8]std.Thread = undefined;
    var made: usize = 0;
    errdefer for (threads[0..made]) |thread| thread.join();
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{});
        made += 1;
    }
    for (threads) |thread| thread.join();
    try std.testing.expectEqual(@as(usize, 1), Worker.count.load(.acquire));
    try std.testing.expect(!Worker.mismatch.load(.acquire));
}
const Other = struct {
    var count: std.atomic.Value(usize) = .init(0);
    const Stored = Cache.For(build);
    fn build() [32]u8 {
        _ = count.fetchAdd(1, .monotonic);
        return @splat(0xd7);
    }
};
test "static source authority: distinct recipes have distinct cache storage" {
    try std.testing.expectEqual(@as([32]u8, @splat(0xd7)), Other.Stored.get());
    try std.testing.expect(!std.meta.eql(Basic.Stored.get(), Other.Stored.get()));
    try std.testing.expectEqual(@as(usize, 1), Basic.count.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), Other.count.load(.acquire));
}
const Nested = struct {
    var count: std.atomic.Value(usize) = .init(0);
    const Stored = Cache.For(build);
    fn build() [32]u8 {
        _ = count.fetchAdd(1, .monotonic);
        const source = Other.Stored.get();
        var result: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(&source, &result, .{});
        return result;
    }
};
test "static source authority: dependency recipes can initialize safely without rebuilding" {
    var expected: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&@as([32]u8, @splat(0xd7)), &expected, .{});
    try std.testing.expectEqual(expected, Nested.Stored.get());
    try std.testing.expectEqual(expected, Nested.Stored.get());
    try std.testing.expectEqual(@as(usize, 1), Nested.count.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), Other.count.load(.acquire));
}
