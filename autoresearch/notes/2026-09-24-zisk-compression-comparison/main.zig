const std = @import("std");
const c = @import("compression.zig");
extern fn peer_compress(cv: *const [8]u32, block: *const [16]u32, counter: u64, len: u8, flags: u8, out: *[16]u32) void;
extern fn peer_batch(n: u64, out: *[16]u32) void;
fn localBatch(comptime native_hash: bool, n: u64) ![16]u32 {
    var block: [16]u32 = undefined;
    for (&block, 0..) |*word, j| word.* = @as(u32, @intCast(j)) *% 0x1234567;
    var sum: [16]u32 = @splat(0);
    for (0..n) |i| {
        block[0] = @truncate(i);
        const out = if (native_hash) blk: {
            var bytes: [64]u8 = undefined;
            for (block, 0..) |word, j| std.mem.writeInt(u32, bytes[j * 4 ..][0..4], word, .little);
            var digest: [64]u8 = undefined;
            std.crypto.hash.Blake3.hash(&bytes, &digest, .{});
            var words: [16]u32 = undefined;
            for (&words, 0..) |*word, j| word.* = std.mem.readInt(u32, digest[j * 4 ..][0..4], .little);
            break :blk words;
        } else try c.compress(c.IV, block, 0, 64, 11);
        for (&sum, out) |*word, value| word.* ^= value;
    }
    return sum;
}
pub fn main() !void {
    var rng = std.Random.DefaultPrng.init(0x12345678);
    const random = rng.random();
    for (0..1024) |i| {
        var cv: [8]u32 = undefined;
        var block: [16]u32 = undefined;
        for (&cv) |*word| word.* = random.int(u32);
        for (&block) |*word| word.* = random.int(u32);
        const counter = random.int(u64);
        const len: u8 = @intCast(i % 65);
        const flags: u8 = @intCast(i % 128);
        var peer: [16]u32 = undefined;
        peer_compress(&cv, &block, counter, len, flags, &peer);
        if (!std.meta.eql(peer, try c.compress(cv, block, counter, len, flags))) return error.CompressionMismatch;
    }
    const n: u64 = 5_000_000;
    var warm: [16]u32 = undefined;
    peer_batch(500_000, &warm);
    if (!std.meta.eql(warm, try localBatch(false, 500_000))) return error.BatchMismatch;
    if (!std.meta.eql(warm, try localBatch(true, 500_000))) return error.NativeHashMismatch;
    var expected: ?[16]u32 = null;
    for ([_]u8{ 0, 1, 2, 2, 1, 0, 0, 1, 2, 2, 1, 0 }, 0..) |arm, i| {
        var timer = try std.time.Timer.start();
        var sum: [16]u32 = undefined;
        switch (arm) {
            0 => peer_batch(n, &sum),
            1 => sum = try localBatch(false, n),
            2 => sum = try localBatch(true, n),
            else => unreachable,
        }
        const ns = timer.read();
        if (expected) |e| {
            if (!std.meta.eql(e, sum)) return error.BatchMismatch;
        } else expected = sum;
        std.debug.print("COMPRESSION arm={s} index={d} calls={d} ns={d} checksum={x}\n", .{ switch (arm) {
            0 => "zisk_scalar",
            1 => "stwo_author",
            2 => "zig_native_xof",
            else => unreachable,
        }, i, n, ns, sum[0] });
    }
    std.debug.print("PARITY cases=1024 passed=true batch_outputs_equal=true\n", .{});
}
