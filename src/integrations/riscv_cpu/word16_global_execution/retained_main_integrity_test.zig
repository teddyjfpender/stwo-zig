const std = @import("std");
const engine = @import("stwo_prover_engine");
const I = @import("retained_main_integrity.zig");
const a = std.testing.allocator;
fn hashAllocationGate(allocator: std.mem.Allocator, data: []const u8) !void {
    _ = try I.digest(allocator, null, &.{.{ .offset = 0, .bytes = data }}, data.len);
}
test "v3 parking framed chunks have pool parity across segment boundaries and detect byte or chunk mutations" {
    const bytes = try a.alloc(u8, 4 * I.CHUNK_BYTES + 31);
    defer a.free(bytes);
    for (bytes, 0..) |*v, i| v.* = @truncate((i / I.CHUNK_BYTES) * 19 + i % 251);
    const split = I.CHUNK_BYTES - 17;
    const segments = [_]I.Segment{
        .{ .offset = 0, .bytes = bytes[0..128] },
        .{ .offset = 128, .bytes = bytes[128..split] },
        .{ .offset = split, .bytes = bytes[split .. split + 33] },
        .{ .offset = split + 33, .bytes = bytes[split + 33 ..] },
    };
    const serial = try I.digestWithOptions(a, null, &segments, bytes.len, .{ .max_shards = 1 });
    try std.testing.expectEqualDeep(serial, try I.digest(a, null, &.{.{ .offset = 0, .bytes = bytes }}, bytes.len));
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile("chunks", .{ .read = true });
    defer file.close();
    const read_only = try tmp.dir.openFile("chunks", .{});
    defer read_only.close();
    for ([_]usize{ 1, 2, 4 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        try std.testing.expectEqualDeep(serial, try I.digest(a, file, &segments, bytes.len));
        const reread = try file.readToEndAlloc(a, bytes.len);
        defer a.free(reread);
        try std.testing.expectEqualSlices(u8, bytes, reread);
        try file.seekTo(0);
        // Every helper must join and the leaf buffer must be freed even when
        // several positioned writes fail concurrently. A subsequent retry works.
        try std.testing.expectError(error.NotOpenForWriting, I.digest(a, read_only, &segments, bytes.len));
        try std.testing.expectEqualDeep(serial, try I.digest(a, null, &segments, bytes.len));
    }
    bytes[128] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &serial, &try I.digest(a, null, &segments, bytes.len)));
    bytes[128] ^= 1;
    std.mem.swap(u8, &bytes[17], &bytes[I.CHUNK_BYTES + 17]);
    try std.testing.expect(!std.mem.eql(u8, &serial, &try I.digest(a, null, &segments, bytes.len)));
}
test "v3 parking shape admission rejects gaps overlaps truncation and oversized metadata before allocation" {
    var none = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    const data = [_]u8{ 1, 2, 3, 4 };
    try std.testing.expectError(error.RetainedMainIntegrityShape, I.digest(none.allocator(), null, &.{ .{ .offset = 0, .bytes = data[0..2] }, .{ .offset = 1, .bytes = data[2..] } }, 4));
    try std.testing.expectError(error.RetainedMainIntegrityShape, I.digest(none.allocator(), null, &.{ .{ .offset = 0, .bytes = data[0..2] }, .{ .offset = 3, .bytes = data[2..] } }, 5));
    try std.testing.expectError(error.RetainedMainIntegrityShape, I.digest(none.allocator(), null, &.{.{ .offset = 0, .bytes = &data }}, 5));
    try std.testing.expectError(error.RetainedMainIntegrityLimit, I.scratchBytes((I.MAX_CHUNKS + 1) * I.CHUNK_BYTES, 1));
    try std.testing.checkAllAllocationFailures(a, hashAllocationGate, .{&data});
}
