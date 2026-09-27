//! Bounded deterministic BLAKE3 nonce search using the existing prover pool.
const std = @import("std");
const core = @import("stwo_core");
const protocol = core.channel.blake3;
const Channel = protocol.Channel;
const pool_mod = @import("../work_pool.zig");
const batch = @import("blake3_pow_batch.zig");
const Work = struct {
    prefix: [8]u32,
    bits: u32,
    start: u64,
    stride: u64,
    best: *std.atomic.Value(u64),
    fn run(self: *const Work) void {
        var nonce = self.start;
        while (nonce < self.best.load(.monotonic)) {
            var candidates: [batch.LANES]u64 = @splat(std.math.maxInt(u64));
            candidates[0] = nonce;
            var count: usize = 1;
            while (count < candidates.len) : (count += 1) {
                candidates[count] = std.math.add(u64, candidates[count - 1], self.stride) catch break;
            }
            const words = batch.firstWords(self.prefix, candidates);
            for (candidates[0..count], words[0..count]) |candidate, word| {
                if (candidate >= self.best.load(.monotonic)) return;
                if (@ctz(word) >= self.bits) {
                    _ = self.best.fetchMin(candidate, .release);
                    return;
                }
            }
            nonce = std.math.add(u64, candidates[count - 1], self.stride) catch return;
        }
    }
};

pub fn grindInPool(channel: Channel, bits: u32, pool: *pool_mod.WorkPool) u64 {
    if (bits > protocol.MAX_POW_BITS) @panic("unsupported BLAKE3 PoW difficulty");
    if (bits == 0) return 0;
    const count = pool.workerCount();
    std.debug.assert(count >= 1 and count <= pool_mod.MAX_WORKERS);
    const prefix = channel.powChainingValue(bits) catch @panic("unsupported BLAKE3 PoW difficulty");
    var best = std.atomic.Value(u64).init(std.math.maxInt(u64));
    var jobs: [pool_mod.MAX_WORKERS]Work = undefined;
    for (jobs[0..count], 0..) |*job, i| job.* = .{
        .prefix = prefix,
        .bits = bits,
        .start = @intCast(i),
        .stride = @intCast(count),
        .best = &best,
    };
    var group: std.Thread.WaitGroup = .{};
    for (jobs[1..count]) |*job| pool.spawnWg(&group, Work.run, .{@as(*const Work, job)});
    Work.run(&jobs[0]);
    group.wait();
    const nonce = best.load(.acquire);
    // The sentinel is itself a valid candidate. Every smaller nonce has been
    // searched if no lane lowered it; never silently return an invalid result.
    if (!channel.verifyPowNonce(bits, nonce)) @panic("BLAKE3 nonce space exhausted");
    return nonce;
}

test "BLAKE3 PoW batch pool retains lowest nonce across worker counts" {
    var channel = Channel{};
    channel.mixU32s(&.{ 0x1234, 0xfedcba98 });
    const expected = channel.grind(12);
    for ([_]usize{ 2, 4, 16 }) |workers| {
        var pool: pool_mod.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = std.testing.allocator });
        defer pool.deinit();
        try std.testing.expectEqual(expected, grindInPool(channel, 12, &pool));
        try std.testing.expectEqual(@as(u64, 0), grindInPool(channel, 0, &pool));
    }
}

test "BLAKE3 PoW batch handles a partial batch at nonce exhaustion" {
    var channel = Channel{};
    channel.mixU32s(&.{0x98765432});
    const bits: u32 = 12;
    const first: u64 = std.math.maxInt(u64) - 5;
    var expected: u64 = std.math.maxInt(u64);
    var nonce = first;
    while (nonce < std.math.maxInt(u64)) : (nonce += 1) {
        if (channel.verifyPowNonce(bits, nonce)) {
            expected = nonce;
            break;
        }
    }
    var best = std.atomic.Value(u64).init(std.math.maxInt(u64));
    const work = Work{ .prefix = try channel.powChainingValue(bits), .bits = bits, .start = first, .stride = 1, .best = &best };
    work.run();
    try std.testing.expectEqual(expected, best.load(.acquire));
}
