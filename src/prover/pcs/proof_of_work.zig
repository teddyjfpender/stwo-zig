//! Prover-side proof-of-work nonce search policy.
//!
//! BLAKE2s channels grind in the canonical Stwo `SimdBackend` order (smallest
//! valid `(hi << 32) | lo`, `lo < 2^20`, hi-major); see
//! `stwo_core.channel.blake2s.pow_order` for the design note. The pooled
//! search here, the channel's own thread search, and the Metal and CUDA
//! kernels all walk the same dense index space, so they agree with Rust and
//! with each other for every worker count. BLAKE3 keeps its stwo-zig-only
//! natural order.

const std = @import("std");
const stwo_core = @import("stwo_core");
const work_pool_mod = @import("../work_pool.zig");

const Blake2sChannel = stwo_core.channel.blake2s.Blake2sChannel;
const Blake2sM31Channel = stwo_core.channel.blake2s.Blake2sM31Channel;
const Blake2sHasher = stwo_core.crypto.blake2s_backend.Blake2sHasher;
const pow_order = stwo_core.channel.blake2s.pow_order;

pub const grindBlake3InPool = @import("blake3_proof_of_work.zig").grindInPool;

pub fn grind(channel: anytype, pow_bits: u32) u64 {
    if (comptime @TypeOf(channel.*) == Blake2sChannel) {
        if (pow_bits == 0) return 0;

        // Preserve the dedicated PoW worker override. The default path reuses
        // the prover pool instead of creating and joining OS threads here.
        if (!std.process.hasEnvVarConstant("STWO_ZIG_POW_WORKERS")) {
            if (work_pool_mod.getGlobalPool()) |pool| {
                return grindBlake2sInPool(channel.*, pow_bits, pool);
            }
        }
    }

    if (comptime @TypeOf(channel.*) == stwo_core.channel.blake3.Channel) {
        if (pow_bits == 0) return 0;
        if (!std.process.hasEnvVarConstant("STWO_ZIG_POW_WORKERS")) {
            if (work_pool_mod.getGlobalPool()) |pool| {
                return grindBlake3InPool(channel.*, pow_bits, pool);
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

/// Uses a backend-owned deterministic search when one is available. The
/// returned nonce is always revalidated through the channel's protocol
/// implementation before it can enter the transcript.
pub fn grindForBackend(comptime Backend: type, channel: anytype, pow_bits: u32) !u64 {
    if (pow_bits == 0) return 0;
    if (comptime @TypeOf(channel.*) == Blake2sChannel) {
        if (pow_bits > pow_order.MAX_POW_BITS) return error.UnsupportedProofOfWorkBits;
        const prefix = computePowPrefix(channel.*, pow_bits);
        const nonce = if (comptime @hasDecl(Backend, "grindBlake2sProofOfWork"))
            try Backend.grindBlake2sProofOfWork(prefix, pow_bits)
        else
            try grindOnHost(Backend, channel, pow_bits);
        // Minimality cannot be rechecked cheaply, but a nonce outside the
        // canonical lattice proves the backend searched the wrong order.
        if (pow_order.indexFromNonce(nonce) == null or !channel.verifyPowNonce(pow_bits, nonce))
            return error.InvalidBackendProofOfWorkNonce;
        return nonce;
    }
    if (comptime @TypeOf(channel.*) == Blake2sM31Channel and
        Backend != void and @hasDecl(Backend, "grindBlake2sM31ProofOfWork"))
    {
        // Same lattice as the plain channel; the device reduces the first
        // output word mod P before counting zeros (`Blake2sM31Channel`).
        if (pow_bits > pow_order.MAX_POW_BITS) return error.UnsupportedProofOfWorkBits;
        const nonce = try Backend.grindBlake2sM31ProofOfWork(channel.computePowPrefix(pow_bits), pow_bits);
        if (pow_order.indexFromNonce(nonce) == null or !channel.verifyPowNonce(pow_bits, nonce))
            return error.InvalidBackendProofOfWorkNonce;
        return nonce;
    }
    if (comptime @TypeOf(channel.*) == stwo_core.channel.blake3.Channel and
        Backend != void and @hasDecl(Backend, "grindBlake3ProofOfWork"))
    {
        const nonce = try Backend.grindBlake3ProofOfWork(try channel.powChainingValue(pow_bits), pow_bits);
        if (!channel.verifyPowNonce(pow_bits, nonce)) return error.InvalidBackendProofOfWorkNonce;
        return nonce;
    }
    if (comptime Backend != void and
        @hasDecl(@TypeOf(channel.*), "powPrefixState") and
        @hasDecl(Backend, "grindPoseidon2ChannelProofOfWork"))
    {
        const nonce = try Backend.grindPoseidon2ChannelProofOfWork(
            channel.powPrefixState(),
            pow_bits,
        );
        if (!channel.verifyPowNonce(pow_bits, nonce))
            return error.InvalidBackendProofOfWorkNonce;
        return nonce;
    }
    return grindOnHost(Backend, channel, pow_bits);
}

fn grindOnHost(comptime Backend: type, channel: anytype, pow_bits: u32) !u64 {
    if (comptime Backend != void and @hasDecl(Backend, "admitHostProving"))
        try Backend.admitHostProving(.proof_of_work);
    return grind(channel, pow_bits);
}

test "proof of work backend rejects forbidden host search before channel work" {
    const Backend = struct {
        pub fn admitHostProving(_: enum { proof_of_work }) !void {
            return error.MetalHostProofOfWorkForbidden;
        }
    };
    const Channel = struct {
        calls: usize = 0,
        pub fn grind(self: *@This(), _: u32) u64 {
            self.calls += 1;
            return 0;
        }
    };
    var channel = Channel{};
    try std.testing.expectError(error.MetalHostProofOfWorkForbidden, grindForBackend(Backend, &channel, 10));
    try std.testing.expectEqual(@as(usize, 0), channel.calls);
    try std.testing.expectEqual(@as(u64, 0), try grindForBackend(Backend, &channel, 0));
    try std.testing.expectEqual(@as(usize, 0), channel.calls);
}

/// First-word PoW predicate over eight candidates with the nonce-independent
/// part of the terminal compression prepared once per proof. Valid for
/// `pow_bits <= 32`, which the canonical search requires.
const PowChecker = struct {
    prepared_prefix: Blake2sHasher.Fixed40NoncePrefix,
    mask: u32,

    fn init(prefix: *const [32]u8, pow_bits: u32) PowChecker {
        std.debug.assert(pow_bits >= 1 and pow_bits <= pow_order.MAX_POW_BITS);
        return .{
            .prepared_prefix = Blake2sHasher.prepareFixed40NoncePrefix(prefix),
            .mask = if (pow_bits == 32)
                std.math.maxInt(u32)
            else
                (@as(u32, 1) << @intCast(pow_bits)) - 1,
        };
    }

    pub fn validMask8(self: *const PowChecker, nonces: [pow_order.BATCH]u64) u8 {
        const first_words = Blake2sHasher.hashFixed40NonceFirstWords8(
            &self.prepared_prefix,
            &nonces,
        );
        const Words = @Vector(pow_order.BATCH, u32);
        const vector: Words = first_words;
        const matches = (vector & @as(Words, @splat(self.mask))) == @as(Words, @splat(0));
        return @bitCast(matches);
    }
};

const PowWork = struct {
    checker: PowChecker,
    start: u64,
    stride: u64,
    best_index: *std.atomic.Value(u64),

    fn run(self: *const PowWork) void {
        pow_order.searchResidueClass(&self.checker, self.start, self.stride, self.best_index);
    }
};

fn grindBlake2sInPool(
    channel: Blake2sChannel,
    pow_bits: u32,
    pool: *work_pool_mod.WorkPool,
) u64 {
    // Grinding is a synchronous phase: no other prover work can use the pool
    // until the nonce is known and mixed into the transcript. Use every pool
    // lane here instead of leaving most Apple Max cores idle. Each lane scans
    // one residue class of the canonical search index space and atomically
    // lowers a shared best index, so the returned nonce (and therefore the
    // proof bytes) is independent of this worker count.
    pow_order.requireSupportedBits(pow_bits);
    const worker_count = pool.workerCount();
    std.debug.assert(worker_count >= 2);
    std.debug.assert(worker_count <= work_pool_mod.MAX_WORKERS);

    const prefix = computePowPrefix(channel, pow_bits);
    const checker = PowChecker.init(&prefix, pow_bits);
    var best_index = std.atomic.Value(u64).init(std.math.maxInt(u64));
    var jobs: [work_pool_mod.MAX_WORKERS]PowWork = undefined;
    for (jobs[0..worker_count], 0..) |*job, worker_index| {
        job.* = .{
            .checker = checker,
            .start = @intCast(worker_index),
            .stride = @intCast(worker_count),
            .best_index = &best_index,
        };
    }

    var wait_group: std.Thread.WaitGroup = .{};
    for (jobs[1..worker_count]) |*job| {
        pool.spawnWg(&wait_group, PowWork.run, .{@as(*const PowWork, job)});
    }
    PowWork.run(&jobs[0]);
    wait_group.wait();
    return pow_order.finish(best_index.load(.acquire));
}

fn computePowPrefix(channel: Blake2sChannel, pow_bits: u32) [32]u8 {
    var input: [52]u8 = [_]u8{0} ** 52;
    std.mem.writeInt(u32, input[0..4], Blake2sChannel.POW_PREFIX, .little);
    @memcpy(input[16..48], channel.digestBytes()[0..]);
    std.mem.writeInt(u32, input[48..52], pow_bits, .little);
    return Blake2sHasher.hashFixedSingleBlock(input.len, &input);
}

fn grindBlake2sResiduesForTest(
    channel: Blake2sChannel,
    pow_bits: u32,
    worker_count: usize,
) u64 {
    const prefix = computePowPrefix(channel, pow_bits);
    const checker = PowChecker.init(&prefix, pow_bits);
    var best_index = std.atomic.Value(u64).init(std.math.maxInt(u64));
    for (0..worker_count) |worker_index| {
        const job = PowWork{
            .checker = checker,
            .start = @intCast(worker_index),
            .stride = @intCast(worker_count),
            .best_index = &best_index,
        };
        job.run();
    }
    return pow_order.finish(best_index.load(.acquire));
}

test "proof of work: pooled batched residue search preserves the canonical nonce" {
    var channel = Blake2sChannel{};
    channel.mixU32s(&.{ 0x1234_5678, 0x9abc_def0 });

    for ([_]u32{ 1, 4, 8, 10, 20 }) |pow_bits| {
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

test "proof of work: pooled batched residue search binds the transcript" {
    var first = Blake2sChannel{};
    first.mixU32s(&.{1});
    var second = Blake2sChannel{};
    second.mixU32s(&.{2});

    const first_nonce = grindBlake2sResiduesForTest(first, 8, 7);
    const second_nonce = grindBlake2sResiduesForTest(second, 8, 7);
    try std.testing.expectEqual(first.grind(8), first_nonce);
    try std.testing.expectEqual(second.grind(8), second_nonce);
}

test "proof of work: prover pool grind matches Rust Stwo SimdBackend known answers" {
    // Rust Stwo 7b211ed `SimdBackend::grind` (features `prover,parallel`) on
    // `Blake2sChannel::default().mix_u64(seed)`. Natural-order grinding
    // returns 2279942, 3005205 and 25492719 for these transcripts.
    const vectors = [_]struct { seed: u64, bits: u32, nonce: u64 }{
        .{ .seed = 1, .bits = 20, .nonce = 12885063745 }, // hi 3, lo 161857
        .{ .seed = 0, .bits = 24, .nonce = 77309505868 }, // hi 18, lo 94540
        .{ .seed = 0, .bits = 26, .nonce = 34360584583 }, // hi 8, lo 846215
    };
    for ([_]usize{ 2, 7 }) |worker_count| {
        var pool: work_pool_mod.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = worker_count });
        defer pool.deinit();
        for (vectors) |vector| {
            var channel = Blake2sChannel{};
            channel.mixU64(vector.seed);
            try std.testing.expectEqual(vector.nonce, grindBlake2sInPool(channel, vector.bits, &pool));
        }
    }
}

test "proof of work: backend grind fails closed outside the canonical search" {
    const channel = Blake2sChannel{};
    const Unsupported = struct {
        pub fn grindBlake2sProofOfWork(_: [32]u8, _: u32) !u64 {
            return error.TestUnexpectedBackendCall;
        }
    };
    var mutable = channel;
    try std.testing.expectError(
        error.UnsupportedProofOfWorkBits,
        grindForBackend(Unsupported, &mutable, pow_order.MAX_POW_BITS + 1),
    );

    // A valid nonce outside the lattice (lo >= 2^20) is rejected even though
    // verification alone would accept it.
    const bits = 4;
    const natural = blk: {
        var nonce: u64 = pow_order.LOW_MASK + 1;
        while (!channel.verifyPowNonce(bits, nonce)) nonce += 1;
        break :blk nonce;
    };
    const OffLattice = struct {
        var nonce: u64 = 0;
        pub fn grindBlake2sProofOfWork(_: [32]u8, _: u32) !u64 {
            return nonce;
        }
    };
    OffLattice.nonce = natural;
    try std.testing.expectError(
        error.InvalidBackendProofOfWorkNonce,
        grindForBackend(OffLattice, &mutable, bits),
    );
    OffLattice.nonce = channel.grind(bits);
    try std.testing.expectEqual(OffLattice.nonce, try grindForBackend(OffLattice, &mutable, bits));
}
