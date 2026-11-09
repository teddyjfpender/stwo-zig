const std = @import("std");
const engine = @import("stwo_prover_engine");
const Native = @import("worker.zig");
const CacheModule = @import("outer_key_cache.zig");
const Template = @import("../pure_p2_gkr_template.zig");
fn lengths(a: std.mem.Allocator, key: *const Native.Key) ![]u8 {
    const instances = try (try key.geometry(.{ .calls = 1, .first_id = 1 })).instances();
    const out = try a.alloc(u8, try Template.countFor(&instances));
    @memset(out, 4);
    return out;
}
test "Miller immutable outer cache separates request identity and retires after all leases" {
    const a = std.testing.allocator;
    var key = try Native.Key.init(a, .op_target_b4_q72_p0_fold4_v1, 8, 15);
    defer key.deinit();
    const advice = try lengths(a, &key);
    defer a.free(advice);
    var cache = try CacheModule.Cache.init(a, 8 << 30, 1);
    defer cache.deinit() catch unreachable;
    var one = try cache.acquireForProving(&key, .{ .calls = 1, .first_id = 7 }, 3, advice);
    var two = try cache.acquireForProving(&key, .{ .calls = 1, .first_id = 17 }, 4, advice);
    try std.testing.expect((try one.key()) == (try two.key()));
    try std.testing.expect(!std.mem.eql(u8, &one.expected.statement, &two.expected.statement));
    try std.testing.expectEqual(@as(usize, 1), cache.snapshot().misses);
    try std.testing.expectEqual(@as(usize, 1), cache.snapshot().hits);
    try std.testing.expectError(error.MillerOuterCacheLiveLeases, cache.finishProving());
    try std.testing.expectError(error.MillerOuterCacheLiveLeases, cache.deinit());
    const source_identity = (try one.key()).base.identity;
    const fixed_root = (try one.key()).base.fixed_root;
    try one.release();
    try std.testing.expectError(error.MillerOuterCacheLeaseReleased, one.key());
    try std.testing.expectError(error.MillerOuterCacheLeaseReleased, one.release());
    try std.testing.expectError(error.MillerOuterCacheLiveLeases, cache.finishProving());
    try two.release();
    try cache.finishProving();
    try std.testing.expectError(error.MillerOuterCacheProvingClosed, cache.acquireForProving(&key, .{ .calls = 1, .first_id = 7 }, 3, advice));
    var retired = try cache.acquireForVerification(&key, .{ .calls = 1, .first_id = 99 }, 9, advice);
    defer retired.release() catch unreachable;
    try std.testing.expect((try retired.key()).base.fixed_tree == null);
    try std.testing.expectError(error.MillerOuterCacheProvingClosed, retired.requireProving());
    var changed = try a.dupe(u8, advice);
    defer a.free(changed);
    changed[0] = 3;
    try std.testing.expect(!std.mem.eql(u8, &try CacheModule.fingerprint(&key, .{ .calls = 1, .first_id = 7 }, advice), &try CacheModule.fingerprint(&key, .{ .calls = 1, .first_id = 7 }, changed)));
    try std.testing.expectError(error.MillerOuterCacheEntryLimit, cache.acquireForVerification(&key, .{ .calls = 1, .first_id = 7 }, 3, changed));
    // A final receiver independently constructs its own cache, not a VK import.
    var receiver = try CacheModule.Cache.initForVerification(a, 8 << 30, 1);
    defer receiver.deinit() catch unreachable;
    var fresh = try receiver.acquireForVerification(&key, .{ .calls = 1, .first_id = 17 }, 4, advice);
    defer fresh.release() catch unreachable;
    try std.testing.expectEqualSlices(u8, &source_identity, &(try fresh.key()).base.identity);
    try std.testing.expectEqualSlices(u8, &fixed_root, &(try fresh.key()).base.fixed_root);
    try std.testing.expect((try fresh.key()).base.fixed_tree == null);
    std.debug.print("OP_MILLER_OUTER_CACHE hits={} misses={} retained={} peak={} independently_rebuilt=true production=false\n", .{ cache.snapshot().hits, cache.snapshot().misses, cache.snapshot().bytes.live_bytes, cache.snapshot().bytes.peak_live_bytes });
}
test "Miller outer cache limit and failed publication preserve ownership" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidMillerOuterCacheLimits, CacheModule.Cache.init(std.testing.failing_allocator, 0, 1));
    try std.testing.expectError(error.InvalidMillerOuterCacheLimits, CacheModule.Cache.init(std.testing.failing_allocator, 100, 257));
    var key = try Native.Key.init(a, .op_target_b4_q72_p0_fold4_v1, 8, 15);
    defer key.deinit();
    const advice = try lengths(a, &key);
    defer a.free(advice);
    var cache = try CacheModule.Cache.init(a, 4096, 1);
    defer cache.deinit() catch unreachable;
    try std.testing.expectError(error.OutOfMemory, cache.acquireForProving(&key, .{ .calls = 1, .first_id = 1 }, 0, advice));
    try std.testing.expectEqual(@as(usize, 0), cache.snapshot().classes);
    try std.testing.expectEqual(@as(usize, 0), cache.snapshot().leases);
    try std.testing.expect(cache.snapshot().bytes.peak_live_bytes <= 4096);
    try std.testing.expectError(error.TowerMassBound, cache.acquireForProving(&key, .{ .calls = 0, .first_id = 1 }, 0, advice));
}
