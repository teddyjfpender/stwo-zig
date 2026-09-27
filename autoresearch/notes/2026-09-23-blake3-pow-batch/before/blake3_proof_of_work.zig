//! Bounded deterministic BLAKE3 nonce search using the existing prover pool.
const std = @import("std");
const core = @import("stwo_core");
const protocol = core.channel.blake3;
const Channel = protocol.Channel;
const pool_mod = @import("../work_pool.zig");
const Work = struct {
    prefix: core.vcs.blake3_hash.Blake3Hasher,
    bits: u32,
    start: u64,
    stride: u64,
    best: *std.atomic.Value(u64),
    fn run(self: *const Work) void {
        var nonce = self.start;
        while (nonce < self.best.load(.monotonic)) {
            if (Channel.validNonce(self.prefix, self.bits, nonce)) {
                _ = self.best.fetchMin(nonce, .release);
                return;
            }
            nonce = std.math.add(u64, nonce, self.stride) catch return;
        }
    }
};

pub fn grindInPool(channel: Channel, bits: u32, pool: *pool_mod.WorkPool) u64 {
    if (bits > protocol.MAX_POW_BITS) @panic("unsupported BLAKE3 PoW difficulty");
    if (bits == 0) return 0;
    const count = pool.workerCount();
    std.debug.assert(count >= 1 and count <= pool_mod.MAX_WORKERS);
    const prefix = channel.powPrefix(bits);
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
