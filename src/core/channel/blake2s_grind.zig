//! Blake2s proof-of-work nonce search orders.
//!
//! Every valid nonce verifies, but only one of them is the nonce a given lane
//! puts in its proof, so byte parity needs the search order of the prover it
//! reproduces. Two orders exist:
//!
//! - `lowest_nonce`: the smallest valid `u64`. This is what the Native and
//!   Cairo lanes have always produced (`Blake2sChannelGeneric.grind`) and it
//!   remains their default.
//! - `rust_simd_hi_major`: the order of `SimdBackend`'s Blake2s grind in
//!   `crates/stwo/src/prover/backend/simd/grind.rs` of
//!   https://github.com/starkware-libs/proving at
//!   5a7c5ede4299c91a61df19a07cba4f7502c14230. Nonces are `(hi << 32) | lo`
//!   with `lo < 2^low_bits`; chunks `hi = 0, 1, ...` are scanned in order and
//!   the first chunk holding a solution returns its smallest `lo`. Nonces with
//!   `lo >= 2^low_bits` are never tried, so whenever chunk 0 has no solution
//!   the result is at least `2^32` and differs from `lowest_nonce`. Chunk 0
//!   misses with probability about `exp(-2^(20 - n_bits))`: roughly 37% at 20
//!   bits (the circuit interaction PoW) and 94% at 24 bits.
//!
//! Both orders test the same predicate as `verifyPowNonce`: the first output
//! word of `H(prefix || nonce_le)`, reduced modulo P for the M31 channel, has
//! at least `n_bits` trailing zeros. For `n_bits <= 32` this equals upstream's
//! 128-bit trailing-zero check.

const std = @import("std");
const blake2s_backend = @import("../crypto/blake2s_backend.zig");
const m31 = @import("../fields/m31.zig");

const RawBlake2s = blake2s_backend.Blake2sHasher;
const PreparedPrefix = RawBlake2s.Fixed40NoncePrefix;

pub const GrindOrder = enum {
    lowest_nonce,
    rust_simd_hi_major,
};

/// `GRIND_LOW_BITS` of the upstream SIMD grind.
pub const low_bits: u32 = 20;
/// Upstream supports at most 32 bits for this order (`pow_bits <= 32` assert).
pub const max_hi_major_bits: u32 = 32;

pub const Error = error{PowBitsUnsupported};

/// Runs the hi-major search over `prefix = H(POW_PREFIX, [0; 12], digest, n_bits)`
/// on `n_workers` threads (at least one). Chunks are claimed from one atomic
/// counter in ascending order, so a failed spawn only removes parallelism and
/// the result does not depend on the worker count or on scheduling.
pub fn grindHiMajor(
    comptime is_m31_output: bool,
    prefix: [32]u8,
    n_bits: u32,
    n_workers: usize,
) Error!u64 {
    if (n_bits > max_hi_major_bits) return Error.PowBitsUnsupported;
    var search = Search(is_m31_output){
        .prepared = RawBlake2s.prepareFixed40NoncePrefix(&prefix),
        .mask = lowBitMask(n_bits),
    };

    var threads: [64]std.Thread = undefined;
    var spawned: usize = 0;
    for (1..@min(@max(n_workers, 1), threads.len)) |_| {
        threads[spawned] = std.Thread.spawn(.{}, Search(is_m31_output).work, .{&search}) catch break;
        spawned += 1;
    }
    search.work();
    for (threads[0..spawned]) |thread| thread.join();

    const nonce = search.best_nonce.load(.acquire);
    // Upstream asserts both halves are below P. A missing solution would need
    // every chunk below 2^31 - 1 (2^51 hashes) to fail, which the predicate
    // makes impossible in practice; `work` stops there rather than wrap.
    if (nonce == std.math.maxInt(u64)) @panic("Blake2s grind exhausted the M31 high-word range");
    return nonce;
}

fn Search(comptime is_m31_output: bool) type {
    return struct {
        prepared: PreparedPrefix,
        mask: u32,
        next_chunk: std.atomic.Value(u32) = .init(0),
        /// Smallest chunk known to hold a solution; chunks at or above it are
        /// never claimed afterwards.
        best_chunk: std.atomic.Value(u32) = .init(std.math.maxInt(u32)),
        best_nonce: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),

        const Self = @This();

        fn work(self: *Self) void {
            while (true) {
                const hi = self.next_chunk.fetchAdd(1, .monotonic);
                if (hi >= m31.Modulus or hi >= self.best_chunk.load(.monotonic)) return;
                if (self.scanChunk(hi)) |nonce| {
                    _ = self.best_chunk.fetchMin(hi, .monotonic);
                    _ = self.best_nonce.fetchMin(nonce, .release);
                    return;
                }
            }
        }

        /// The smallest `lo < 2^low_bits` whose nonce `(hi << 32) | lo` passes.
        fn scanChunk(self: *const Self, hi: u32) ?u64 {
            const Lanes = @Vector(8, u32);
            const zero: Lanes = @splat(0);
            const mask: Lanes = @splat(self.mask);
            const base = @as(u64, hi) << 32;
            var lo: u64 = 0;
            while (lo < (@as(u64, 1) << low_bits)) : (lo += 8) {
                var nonces: [8]u64 = undefined;
                for (&nonces, 0..) |*nonce, lane| nonce.* = base | (lo + lane);
                const first: Lanes = RawBlake2s.hashFixed40NonceFirstWords8(&self.prepared, &nonces);
                const words = if (is_m31_output) reduceModP(first) else first;
                const hits = (words & mask) == zero;
                if (!@reduce(.Or, hits)) continue;
                const hit_lanes: [8]bool = hits;
                for (hit_lanes, nonces) |hit, nonce| if (hit) return nonce;
            }
            return null;
        }
    };
}

/// `reduce_to_m31` on eight first words: `x mod P` for any `u32`.
fn reduceModP(words: @Vector(8, u32)) @Vector(8, u32) {
    const p: @Vector(8, u32) = @splat(m31.Modulus);
    const folded = (words & p) +% (words >> @splat(31));
    return @select(u32, folded >= p, folded -% p, folded);
}

fn lowBitMask(n_bits: u32) u32 {
    if (n_bits >= 32) return std.math.maxInt(u32);
    return (@as(u32, 1) << @intCast(n_bits)) - 1;
}

test "blake2s grind: M31 first-word reduction covers the u32 range" {
    const input: @Vector(8, u32) = .{ 0, 1, m31.Modulus - 1, m31.Modulus, m31.Modulus + 1, std.math.maxInt(u32) - 1, std.math.maxInt(u32), 0x8000_0000 };
    const expected = [8]u32{ 0, 1, m31.Modulus - 1, 0, 1, 0, 1, 1 };
    try std.testing.expectEqualSlices(u32, &expected, &@as([8]u32, reduceModP(input)));
}

test "blake2s grind: hi-major rejects more than 32 bits" {
    try std.testing.expectError(Error.PowBitsUnsupported, grindHiMajor(false, [_]u8{0} ** 32, 33, 1));
}

const channel_blake2s = @import("blake2s.zig");

/// Oracle nonces from proving@5a7c5ed: `<SimdBackend as GrindOps<C>>::grind(&c, bits)`
/// (crates/stwo, feature `prover`) after `c.mix_u64(0x1111222233334344)`, the
/// channel state of upstream's `test_parallel_grind_with_high_pow_bits`.
const OracleGrind = struct { bits: u32, blake2s: u64, blake2s_m31: u64 };
const oracle_grinds = [_]OracleGrind{
    .{ .bits = 1, .blake2s = 0, .blake2s_m31 = 0 },
    .{ .bits = 10, .blake2s = 0x413, .blake2s_m31 = 0x415 },
    .{ .bits = 20, .blake2s = 0xede9, .blake2s_m31 = 0x1_0005_a700 },
    .{ .bits = 24, .blake2s = 0x9_000e_1aa1, .blake2s_m31 = 0xf_0001_6fbd },
};

fn oracleChannel(comptime Channel: type) Channel {
    var channel = Channel{};
    channel.mixU64(0x1111_2222_3333_4344);
    return channel;
}

test "blake2s grind: hi-major order reproduces the proving@5a7c5ed SIMD nonces" {
    const plain = oracleChannel(channel_blake2s.Blake2sChannel);
    const reduced = oracleChannel(channel_blake2s.Blake2sM31Channel);
    for (oracle_grinds) |oracle| {
        const plain_nonce = try grindHiMajor(false, plain.computePowPrefix(oracle.bits), oracle.bits, 4);
        const reduced_nonce = try grindHiMajor(true, reduced.computePowPrefix(oracle.bits), oracle.bits, 4);
        try std.testing.expectEqual(oracle.blake2s, plain_nonce);
        try std.testing.expectEqual(oracle.blake2s_m31, reduced_nonce);
        try std.testing.expect(plain.verifyPowNonce(oracle.bits, plain_nonce));
        try std.testing.expect(reduced.verifyPowNonce(oracle.bits, reduced_nonce));
    }
    try std.testing.expectEqual(@as(u64, 0x415), try reduced.grindInOrder(.rust_simd_hi_major, 10));
}

test "blake2s grind: hi-major result is independent of the worker count" {
    const reduced = oracleChannel(channel_blake2s.Blake2sM31Channel);
    const prefix = reduced.computePowPrefix(20);
    for ([_]usize{ 1, 2, 3, 8 }) |workers| {
        try std.testing.expectEqual(@as(u64, 0x1_0005_a700), try grindHiMajor(true, prefix, 20, workers));
    }
}

test "blake2s grind: lowest-nonce order is the existing grind and differs past chunk 0" {
    const reduced = oracleChannel(channel_blake2s.Blake2sM31Channel);
    try std.testing.expectEqual(reduced.grind(10), try reduced.grindInOrder(.lowest_nonce, 10));
    // At 20 bits chunk 0 of the M31 channel has no solution, so upstream moves
    // to hi = 1 while the lowest valid nonce lies in [2^20, 2^32).
    const lowest = try reduced.grindInOrder(.lowest_nonce, 20);
    try std.testing.expect(reduced.verifyPowNonce(20, lowest));
    try std.testing.expect(lowest >= (@as(u64, 1) << low_bits) and lowest < (@as(u64, 1) << 32));
}
