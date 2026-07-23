//! Prover-side proof-of-work nonce search policy.

const std = @import("std");
const stwo_core = @import("stwo_core");
const work_pool_mod = @import("../work_pool.zig");

const Blake2sChannel = stwo_core.channel.blake2s.Blake2sChannel;
const Blake2sHasher = stwo_core.crypto.blake2s_backend.Blake2sHasher;

pub fn grind(channel: anytype, pow_bits: u32) u64 {
    if (pow_bits == 0) return 0;

    if (comptime @TypeOf(channel.*) == Blake2sChannel) {
        // Preserve the dedicated PoW worker override. The default path reuses
        // the prover pool instead of creating and joining OS threads here.
        if (!std.process.hasEnvVarConstant("STWO_ZIG_POW_WORKERS")) {
            if (work_pool_mod.getGlobalPool()) |pool| {
                return grindBlake2sInPool(channel.*, pow_bits, pool);
            }
        }
    }

    // Prefer a channel's cached or parallel implementation when it provides one.
    if (@hasDecl(@TypeOf(channel.*), "grind")) {
        return channel.grind(pow_bits);
    }

    var nonce: u64 = 0;
    while (true) : (nonce += 1) {
        if (channel.verifyPowNonce(pow_bits, nonce)) return nonce;
    }
}

const PowWork = struct {
    prefix: [32]u8,
    pow_bits: u32,
    start: u64,
    stride: u64,
    found: *std.atomic.Value(u64),

    fn run(self: *const PowWork) void {
        var nonce = self.start;
        while (nonce < self.found.load(.monotonic)) {
            if (verifyNonceWithPrefix(self.prefix, nonce, self.pow_bits)) {
                _ = self.found.fetchMin(nonce, .release);
                return;
            }
            nonce = std.math.add(u64, nonce, self.stride) catch return;
        }
    }
};

fn grindBlake2sInPool(
    channel: Blake2sChannel,
    pow_bits: u32,
    pool: *work_pool_mod.WorkPool,
) u64 {
    const worker_count = pool.workerCount();
    std.debug.assert(worker_count >= 2);
    std.debug.assert(worker_count <= work_pool_mod.MAX_WORKERS);

    const prefix = computePowPrefix(channel, pow_bits);
    var found = std.atomic.Value(u64).init(std.math.maxInt(u64));
    var jobs: [work_pool_mod.MAX_WORKERS]PowWork = undefined;
    for (jobs[0..worker_count], 0..) |*job, worker_index| {
        job.* = .{
            .prefix = prefix,
            .pow_bits = pow_bits,
            .start = @intCast(worker_index),
            .stride = @intCast(worker_count),
            .found = &found,
        };
    }

    var wait_group: std.Thread.WaitGroup = .{};
    for (jobs[1..worker_count]) |*job| {
        pool.spawnWg(&wait_group, PowWork.run, .{@as(*const PowWork, job)});
    }
    PowWork.run(&jobs[0]);
    wait_group.wait();
    return found.load(.acquire);
}

fn computePowPrefix(channel: Blake2sChannel, pow_bits: u32) [32]u8 {
    var input: [52]u8 = [_]u8{0} ** 52;
    std.mem.writeInt(u32, input[0..4], Blake2sChannel.POW_PREFIX, .little);
    @memcpy(input[16..48], channel.digestBytes()[0..]);
    std.mem.writeInt(u32, input[48..52], pow_bits, .little);
    return Blake2sHasher.hashFixedSingleBlock(input.len, &input);
}

fn verifyNonceWithPrefix(prefix: [32]u8, nonce: u64, pow_bits: u32) bool {
    var input: [40]u8 = undefined;
    @memcpy(input[0..32], prefix[0..]);
    std.mem.writeInt(u64, input[32..40], nonce, .little);
    const digest = Blake2sHasher.hashFixedSingleBlock(input.len, &input);
    return trailingZeroBits(digest[0..16]) >= pow_bits;
}

fn trailingZeroBits(bytes: []const u8) u32 {
    var total: u32 = 0;
    for (bytes) |byte| {
        if (byte == 0) {
            total += 8;
        } else {
            total += @ctz(byte);
            break;
        }
    }
    return total;
}

fn grindBlake2sResiduesForTest(
    channel: Blake2sChannel,
    pow_bits: u32,
    worker_count: usize,
) u64 {
    const prefix = computePowPrefix(channel, pow_bits);
    var found = std.atomic.Value(u64).init(std.math.maxInt(u64));
    for (0..worker_count) |worker_index| {
        const job = PowWork{
            .prefix = prefix,
            .pow_bits = pow_bits,
            .start = @intCast(worker_index),
            .stride = @intCast(worker_count),
            .found = &found,
        };
        job.run();
    }
    return found.load(.acquire);
}

test "proof of work: pooled residue search preserves the lowest nonce" {
    var channel = Blake2sChannel{};
    channel.mixU32s(&.{ 0x1234_5678, 0x9abc_def0 });

    for ([_]u32{ 1, 4, 8, 10 }) |pow_bits| {
        const expected = channel.grind(pow_bits);
        for ([_]usize{ 1, 2, 5, 16 }) |worker_count| {
            const actual = grindBlake2sResiduesForTest(
                channel,
                pow_bits,
                worker_count,
            );
            try std.testing.expectEqual(expected, actual);
            try std.testing.expect(channel.verifyPowNonce(pow_bits, actual));
        }
    }
}

test "proof of work: pooled residue search binds the transcript" {
    var first = Blake2sChannel{};
    first.mixU32s(&.{1});
    var second = Blake2sChannel{};
    second.mixU32s(&.{2});

    const first_nonce = grindBlake2sResiduesForTest(first, 8, 7);
    const second_nonce = grindBlake2sResiduesForTest(second, 8, 7);
    try std.testing.expectEqual(first.grind(8), first_nonce);
    try std.testing.expectEqual(second.grind(8), second_nonce);
}
