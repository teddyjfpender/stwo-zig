const std = @import("std");
const memory = @import("../memory.zig");
const bulk = @import("../services/bulk_packets.zig");
const execute = bulk.execute;
const executeRecording = bulk.executeRecording;
const bitmapWords = bulk.bitmapWords;

test "admitted jumpdest writes the canonical bitmap and refuses unprovable calls" {
    const t = std.testing;
    const ref = @import("../ethereum_services/candidate_jumpdest.zig");
    var mem = memory.Memory.init(t.allocator, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 0x1000, .permissions = .{ .read = true, .write = true } });
    try mem.map(.{ .start = 0x3000, .size = 0x1000, .permissions = .{ .read = true } });
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    var bytes: [200]u8 = undefined;
    for (&bytes) |*b| b.* = switch (r.uintLessThan(u8, 3)) {
        0 => 0x5b,
        1 => r.intRangeAtMost(u8, 0x60, 0x7f),
        else => r.int(u8),
    };
    for (bytes, 0..) |b, i| try mem.store(0x1400 + i, 1, b);
    for ([_]u64{ 8, 64, 72, 200 }) |len| {
        try mem.storeWords(0x1000, &.{ 0x1400, len, 0x1800 });
        try mem.storeWords(0x1800, &.{ 0xdead, 0xdead, 0xdead, 0xdead });
        var before: std.ArrayList(u64) = .empty;
        defer before.deinit(t.allocator);
        _ = try executeRecording(t.allocator, &mem, .jumpdest, 0x1000, &before);
        var want: [4]u64 = @splat(0xdead);
        ref.bitmap(bytes[0..@intCast(len)], want[0..@intCast(bitmapWords(len))]);
        for (0..4) |j| try t.expectEqual(want[j], try mem.load(0x1800 + 8 * j, 8));
        try t.expectEqual(@as(usize, @intCast(bitmapWords(len))), before.items.len);
        for (before.items) |w| try t.expectEqual(@as(u64, 0xdead), w);
    }
    // Code may be read-only; the bitmap may not. Every refusal changes nothing.
    try mem.storeWords(0x1000, &.{ 0x3000, 64, 0x1800 });
    _ = try execute(t.allocator, &mem, .jumpdest, 0x1000);
    const bad = [_]struct { packet: [3]u64, err: anyerror }{
        .{ .packet = .{ 0x1400, 0, 0x1800 }, .err = error.BulkMemoryLength },
        .{ .packet = .{ 0x1400, 60, 0x1800 }, .err = error.BulkMemoryLength },
        .{ .packet = .{ 0x1400, (1 << 20) + 8, 0x1800 }, .err = error.BulkMemoryLength },
        .{ .packet = .{ 0x1408, 64, 0x1800 }, .err = error.MisalignedAddress },
        .{ .packet = .{ 0x1400, 64, 0x1804 }, .err = error.MisalignedAddress },
        .{ .packet = .{ 0x1400, 128, 0x1440 }, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1400, 64, 0x1010 }, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1000, 64, 0x1800 }, .err = error.BulkMemoryOverlap },
        .{ .packet = .{ 0x1400, 64, 0x3000 }, .err = error.AccessDenied },
        .{ .packet = .{ 0x1FC0, 128, 0x1800 }, .err = error.UnmappedAddress },
    };
    for (bad) |c| {
        try mem.storeWords(0x1000, &c.packet);
        var snapshot: [512]u64 = undefined;
        for (&snapshot, 0..) |*w, i| w.* = try mem.load(0x1000 + 8 * i, 8);
        try t.expectError(c.err, execute(t.allocator, &mem, .jumpdest, 0x1000));
        for (snapshot, 0..) |w, i| try t.expectEqual(w, try mem.load(0x1000 + 8 * i, 8));
    }
}
