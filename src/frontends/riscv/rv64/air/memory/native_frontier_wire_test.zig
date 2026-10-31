const std = @import("std");
const N = @import("native_frontier.zig");
const W = @import("native_frontier_wire.zig");
const V = @import("values.zig");
const O = @import("openings.zig");
const a = std.testing.allocator;
fn fixture(g: V.Geometry) !N.Prepared {
    var cache = try V.Cache.empty(a, g);
    defer cache.deinit();
    const before: [512]u64 = @splat(0);
    var after = before;
    after[0] = std.math.maxInt(u64);
    var clocks: [512]u32 = @splat(0);
    clocks[0] = (1 << 24) - 4;
    const rights: [512]u2 = @splat(3);
    const cells = g.cells();
    var owned = try O.Owned.copy(a, g, &.{.{ .index = (@as(u64, 1) << g.depth()) - 1, .before = before[0..cells], .after = after[0..cells], .terminal_clocks = clocks[0..cells], .rights = rights[0..cells] }});
    defer owned.deinit();
    return N.Prepared.init(a, &cache, &owned);
}
test "native frontier wire roundtrips both geometries and leaves following packet sections untouched" {
    for ([_]V.Geometry{ .chunk512, .page4096 }) |g| {
        var original = try fixture(g);
        defer original.deinit();
        var temp = std.testing.tmpDir(.{});
        defer temp.cleanup();
        const file = try temp.dir.createFile("graph", .{ .read = true });
        defer file.close();
        try W.write(file, &original);
        try std.testing.expectEqual(try W.encodedBytes(&original), try file.getEndPos());
        try std.testing.expect(try file.getEndPos() > 65536);
        try file.writeAll("NEXTTAPE");
        try file.seekTo(0);
        var loaded = try W.read(a, file, .{});
        defer loaded.deinit();
        try std.testing.expectEqual(N.Phase.prepared, loaded.phase);
        try std.testing.expectEqual(g, loaded.witness.geometry);
        try std.testing.expectEqualDeep(original.counts, loaded.counts);
        try std.testing.expectEqualDeep(original.witness.before, loaded.witness.before);
        try std.testing.expectEqualDeep(original.witness.after, loaded.witness.after);
        try std.testing.expectEqualDeep(original.witness.leaves, loaded.witness.leaves);
        try std.testing.expectEqualDeep(original.witness.before_nodes, loaded.witness.before_nodes);
        try std.testing.expectEqualDeep(original.witness.after_nodes, loaded.witness.after_nodes);
        try std.testing.expectEqualDeep(original.witness.sides, loaded.witness.sides);
        try std.testing.expectEqualDeep(original.witness.patches, loaded.witness.patches);
        try std.testing.expectEqualDeep(original.io, loaded.io);
        var next: [8]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 8), try file.readAll(&next));
        try std.testing.expectEqualSlices(u8, "NEXTTAPE", &next);
    }
}
test "native frontier wire rejects capped headers before allocating and malformed canonical advice" {
    var original = try fixture(.chunk512);
    defer original.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("graph", .{ .read = true });
    defer file.close();
    try W.write(file, &original);
    const bytes = try temp.dir.readFileAlloc(a, "graph", 1 << 20);
    defer a.free(bytes);
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try file.seekTo(0);
    try std.testing.expectError(error.FrontierWireResourceLimit, W.read(fail.allocator(), file, .{ .bytes = bytes.len - 1 }));
    try std.testing.expect(!fail.has_induced_failure);
    const changed = try a.dupe(u8, bytes);
    defer a.free(changed);
    changed[108] = 1;
    try replace(file, changed);
    try std.testing.expectError(error.InvalidFrontierWireHeader, W.read(fail.allocator(), file, .{}));
    try std.testing.expect(!fail.has_induced_failure);
    @memcpy(changed, bytes);
    changed[W.HEADER_BYTES + 80] = 4;
    try replace(file, changed);
    try std.testing.expectError(error.InvalidFrontierWireFlags, W.read(a, file, .{}));
    @memcpy(changed, bytes);
    changed[W.HEADER_BYTES + 97 * original.counts.leaves] = 64;
    try replace(file, changed);
    try std.testing.expectError(error.InvalidFrontierWireHeight, W.read(a, file, .{}));
    @memcpy(changed, bytes);
    const io_start = W.HEADER_BYTES + 97 * original.counts.leaves + 122 * (original.counts.before_nodes + original.counts.after_nodes) + 46 * original.counts.sides + 81 * original.witness.patches.len;
    std.mem.writeInt(u32, changed[io_start..][0..4], 0x7fffffff, .little);
    try replace(file, changed);
    try std.testing.expectError(error.NoncanonicalNativeFrontierIO, W.read(a, file, .{}));
    for ([_]usize{ 0, W.HEADER_BYTES - 1, W.HEADER_BYTES, bytes.len - 1 }) |length| {
        try replace(file, bytes[0..length]);
        try std.testing.expectError(error.TruncatedFrontierWire, W.read(a, file, .{}));
    }
}
test "native frontier wire allocation failures release partial frames without consuming producer ownership" {
    var original = try fixture(.chunk512);
    defer original.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("graph", .{ .read = true });
    defer file.close();
    try W.write(file, &original);
    try std.testing.checkAllAllocationFailures(a, decode, .{file});
    try original.validate();
    var taken = try original.take();
    defer {
        taken.witness.deinit();
        a.free(taken.io);
    }
    try std.testing.expectError(error.InvalidNativeFrontierPhase, W.write(file, &original));
}
fn decode(allocator: std.mem.Allocator, file: std.fs.File) !void {
    try file.seekTo(0);
    var native = try W.read(allocator, file, .{});
    defer native.deinit();
}
fn replace(file: std.fs.File, bytes: []const u8) !void {
    try file.setEndPos(0);
    try file.seekTo(0);
    try file.writeAll(bytes);
    try file.seekTo(0);
}
