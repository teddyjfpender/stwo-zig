const std = @import("std");
const core = @import("stwo_core");
const E = @import("../pcs_request_export.zig");
const F = @import("../fri.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
fn config(fold: u32) core.pcs.PcsConfig {
    return .{ .pow_bits = 20, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 108, .fold_step = fold } };
}
test "PCS geometry cache preserves framing and keeps every new transcript and root fresh" {
    const a = std.testing.allocator;
    var cache = E.GeometryCache.init(a, 1 << 20);
    defer cache.deinit();
    const coefficients = [_]D.M{D.M.one()} ** 32;
    const columns = [_]D.Column{.{ .log_size = 5, .coefficients = &coefficients }};
    var trees = [_]D.Tree{.{ .root = @splat(7), .columns = &columns }};
    var points = [_]D.Point{.{ .x = D.O.one(), .y = D.O.zero() }};
    var columns_points = [_][]D.Point{&points};
    var trees_points = [_][][]D.Point{&columns_points};
    var request = D.Request{ .config = config(4), .lifting_log_size = 6, .trees = &trees, .points = .initOwned(&trees_points) };
    var channel = D.Channel.init();
    var plain = try E.prepareRequest(a, request, channel);
    defer plain.deinit(a);
    var cached = try E.prepareRequestWithCache(a, request, channel, &cache);
    defer cached.deinit(a);
    for (plain.section_storage, cached.section_storage) |expected, actual| try std.testing.expectEqualSlices(u32, expected, actual);
    try std.testing.expectEqual(@as(u64, 1), cache.misses);
    for (12..15) |index| try std.testing.expect(!cached.section_owned[index]);
    channel.mixU32s(&.{ 91, 72 });
    trees[0].root = @splat(9);
    points[0] = .{ .x = D.O.zero(), .y = D.O.one() };
    request.config.pow_bits = 21;
    request.config.fri_config.n_queries = 109;
    var fresh = try E.prepareRequestWithCache(a, request, channel, &cache);
    defer fresh.deinit(a);
    var fresh_plain = try E.prepareRequest(a, request, channel);
    defer fresh_plain.deinit(a);
    for (fresh_plain.section_storage, fresh.section_storage) |expected, actual| try std.testing.expectEqualSlices(u32, expected, actual);
    try std.testing.expectEqual(@as(u64, 1), cache.hits);
    try std.testing.expectEqual(@intFromPtr(cached.section_storage[12].ptr), @intFromPtr(fresh.section_storage[12].ptr));
    for ([_]usize{ 0, 1, 2, 15 }) |index| try std.testing.expect(!std.mem.eql(u32, cached.section_storage[index], fresh.section_storage[index]));
    request.lifting_log_size = 7;
    var changed = try E.prepareRequestWithCache(a, request, channel, &cache);
    defer changed.deinit(a);
    try std.testing.expectEqual(@as(u64, 2), cache.misses);
    try std.testing.expect(@intFromPtr(changed.section_storage[14].ptr) != @intFromPtr(fresh.section_storage[14].ptr));
    try std.testing.expect(cache.retained_bytes <= cache.limit);
    var pins_before: usize = 0;
    for (cache.entries) |slot| if (slot) |entry| {
        pins_before += entry.pins;
    };
    const extension = D.O.fromM31Array(.{ D.M.zero(), D.M.one(), D.M.zero(), D.M.zero(), D.M.zero(), D.M.zero(), D.M.zero(), D.M.zero() });
    var invalid_points = [_]D.Point{ points[0], .{ .x = extension, .y = D.O.zero() } };
    columns_points[0] = &invalid_points;
    try std.testing.expectError(error.UnsupportedDevicePcsPointOffset, E.prepareRequestWithCache(a, request, channel, &cache));
    var pins_after: usize = 0;
    for (cache.entries) |slot| if (slot) |entry| {
        pins_after += entry.pins;
    };
    try std.testing.expectEqual(pins_before, pins_after);
}
test "PCS geometry cache pins borrowed tables and evicts only after release" {
    const a = std.testing.allocator;
    var cache = E.GeometryCache.init(a, 1 << 20);
    defer cache.deinit();
    const p = try F.Plan.init(5, config(4).fri_config);
    const q = try F.Plan.init(5, config(3).fri_config);
    const first = (try cache.acquire(6, p)).?;
    const expected = first.forward()[0];
    cache.limit = cache.retained_bytes;
    try std.testing.expect((try cache.acquire(6, q)) == null);
    try std.testing.expectEqual(expected, first.forward()[0]);
    first.release();
    const second = (try cache.acquire(6, q)).?;
    defer second.release();
    try std.testing.expectEqual(@as(u64, 1), cache.evictions);
    try std.testing.expect(cache.retained_bytes <= cache.limit);
    try std.testing.expect((try cache.acquire(6, p)) == null);
}
fn allocationFailures(a: std.mem.Allocator) !void {
    var cache = E.GeometryCache.init(a, 1 << 20);
    defer cache.deinit();
    const p = try F.Plan.init(5, config(4).fri_config);
    const q = try F.Plan.init(5, config(3).fri_config);
    const first = (try cache.acquire(6, p)).?;
    first.release();
    cache.limit = cache.retained_bytes;
    const old_bytes = cache.retained_bytes;
    const second = cache.acquire(6, q) catch |err| {
        try std.testing.expectEqual(old_bytes, cache.retained_bytes);
        try std.testing.expectEqual(@as(u64, 0), cache.evictions);
        const old = (try cache.acquire(6, p)).?;
        old.release();
        return err;
    };
    second.?.release();
}
test "PCS geometry cache cold allocation failures preserve admitted entries and ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailures, .{});
}
