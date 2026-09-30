//! Canonical proof-of-work nonce order for the BLAKE2s channels.
//!
//! Verification accepts any valid nonce, so the nonce a prover *chooses* is
//! not a soundness question. It is a proof-bytes question: the nonce is mixed
//! into the transcript, so every later challenge, and therefore the proof,
//! depends on which valid nonce the prover picked.
//!
//! The official Stwo prover grinds with `SimdBackend` (Stwo `7b211ed`,
//! `crates/stwo/src/prover/backend/simd/grind.rs`, used by stwo-cairo and by
//! StarkWare's `proving` crate). For `Blake2sChannelGeneric` (both
//! `Blake2sChannel` and `Blake2sM31Channel`) it returns the smallest nonce of
//! the form `(hi << 32) | lo`, `lo < 2^GRIND_LOW_BITS`, `hi < 2^31 - 1`,
//! searched hi-major: every `lo` for `hi = 0`, then every `lo` for `hi = 1`,
//! and so on. That is not the smallest natural nonce whenever no valid nonce
//! exists below `2^20` (about 94% of Cairo interaction PoW-24 and 98% of
//! query PoW-26 transcripts). Rust `CpuBackend` counts `0, 1, 2, ...`, but
//! it is not what the official prover runs.
//!
//! Design. Every stwo-zig BLAKE2s grinder (host single-thread, host threads,
//! the prover pool, Metal, and CUDA's `search.cu`) walks one dense *search
//! index* space `0, 1, 2, ...` and maps each index to a nonce with
//! `nonceFromIndex`. The map is strictly increasing, so the smallest valid
//! index maps to exactly the smallest valid lattice nonce that Rust returns.
//! Parallel searches split the index space into residue classes (CPU) or
//! ordered windows (GPU), scan each ascending, and lower a shared best index
//! with an atomic min. The result is the global minimum valid index no matter
//! how many workers ran or how they were scheduled.
//!
//! Limits. Rust asserts `pow_bits <= 32` and a reduced high word; stwo-zig
//! fails closed on the same conditions instead of inventing an order Rust
//! does not define.
//!
//! Non-Rust channels. The BLAKE3 and Poseidon2-M31 recursion channels exist
//! only in stwo-zig and keep their natural `0, 1, 2, ...` order: there is no
//! upstream ordering to match, their CPU/Metal grinders already agree, and
//! changing them would churn stwo-zig-only proof receipts for no parity gain.

const std = @import("std");
const m31 = @import("../fields/m31.zig");

/// Stwo `simd/grind.rs` `GRIND_LOW_BITS` for `Blake2sChannelGeneric`.
pub const GRIND_LOW_BITS: u6 = 20;
pub const LOW_MASK: u64 = (@as(u64, 1) << GRIND_LOW_BITS) - 1;
/// Largest PoW difficulty the canonical search is defined for (Rust asserts it).
pub const MAX_POW_BITS: u32 = 32;
/// Exclusive bound on search indices: the high nonce word stays below the
/// M31 prime, matching Rust's post-search assertion.
pub const INDEX_LIMIT: u64 = @as(u64, m31.Modulus) << GRIND_LOW_BITS;
/// Candidates hashed per batch by the CPU residue search.
pub const BATCH: usize = 8;

/// Maps a dense search index to its canonical nonce `(hi << 32) | lo`.
pub inline fn nonceFromIndex(index: u64) u64 {
    std.debug.assert(index < INDEX_LIMIT);
    return ((index >> GRIND_LOW_BITS) << 32) | (index & LOW_MASK);
}

/// Inverse of `nonceFromIndex`; null for nonces outside the canonical lattice.
pub fn indexFromNonce(nonce: u64) ?u64 {
    const lo = nonce & 0xffff_ffff;
    const hi = nonce >> 32;
    if (lo > LOW_MASK or hi >= m31.Modulus) return null;
    return (hi << GRIND_LOW_BITS) | lo;
}

/// Scans the residue class `start + k * stride` of the search index space in
/// ascending order and lowers `best_index` to the first valid index it finds.
/// `checker.validMask8(nonces)` returns bit `i` set when `nonces[i]` passes the
/// PoW predicate. Stops once every remaining index in the class is at least
/// `best_index`, so concurrent classes cooperate without affecting the result.
pub fn searchResidueClass(
    checker: anytype,
    start: u64,
    stride: u64,
    best_index: *std.atomic.Value(u64),
) void {
    std.debug.assert(stride > 0);
    var index = start;
    while (index < INDEX_LIMIT and index < best_index.load(.monotonic)) {
        var nonces: [BATCH]u64 = undefined;
        var live: u8 = 0xff;
        if (index + (BATCH - 1) * stride < INDEX_LIMIT) {
            for (&nonces, 0..) |*nonce, lane| nonce.* = nonceFromIndex(index + lane * stride);
        } else for (&nonces, 0..) |*nonce, lane| {
            const candidate = index + lane * stride;
            if (candidate < INDEX_LIMIT) {
                nonce.* = nonceFromIndex(candidate);
            } else {
                // Hashed but masked out: never reported.
                nonce.* = nonceFromIndex(INDEX_LIMIT - 1);
                live &= ~(@as(u8, 1) << @intCast(lane));
            }
        }
        const hits: u8 = checker.validMask8(nonces) & live;
        if (hits != 0) {
            const lane: u64 = @ctz(hits);
            _ = best_index.fetchMin(index + lane * stride, .release);
            return;
        }
        index = std.math.add(u64, index, BATCH * stride) catch return;
    }
}

/// Converts a finished search's best index to a nonce, failing closed when
/// the whole canonical space was exhausted (Rust panics likewise).
pub fn finish(best_index: u64) u64 {
    if (best_index >= INDEX_LIMIT) @panic("BLAKE2s proof-of-work nonce space exhausted");
    return nonceFromIndex(best_index);
}

/// Fails closed on difficulties the canonical Stwo search does not define.
pub fn requireSupportedBits(pow_bits: u32) void {
    if (pow_bits > MAX_POW_BITS) @panic("BLAKE2s proof-of-work above 32 bits is unsupported");
}

test "blake2s pow order: index map is the Stwo SIMD lattice and strictly increasing" {
    try std.testing.expectEqual(@as(u64, 0), nonceFromIndex(0));
    try std.testing.expectEqual(@as(u64, LOW_MASK), nonceFromIndex(LOW_MASK));
    try std.testing.expectEqual(@as(u64, 1) << 32, nonceFromIndex(LOW_MASK + 1));
    try std.testing.expectEqual((@as(u64, 47) << 32) | 207343, nonceFromIndex((47 << 20) | 207343));
    const last = nonceFromIndex(INDEX_LIMIT - 1);
    try std.testing.expectEqual(@as(u64, m31.Modulus - 1), last >> 32);
    try std.testing.expectEqual(LOW_MASK, last & 0xffff_ffff);
    var previous = nonceFromIndex(0);
    for (1..3 << GRIND_LOW_BITS) |index| {
        const nonce = nonceFromIndex(index);
        try std.testing.expect(nonce > previous);
        try std.testing.expectEqual(@as(?u64, index), indexFromNonce(nonce));
        previous = nonce;
    }
    try std.testing.expectEqual(@as(?u64, null), indexFromNonce(1 << 20));
    try std.testing.expectEqual(@as(?u64, null), indexFromNonce(@as(u64, m31.Modulus) << 32));
}

test "blake2s pow order: residue search returns the minimum for every stride" {
    // Synthetic predicate: a few isolated winners, the smallest in hi = 2,
    // plus every nonce from hi = 4 on so each residue class terminates even
    // when scanned alone before the others lower the bound.
    const Checker = struct {
        pub fn validMask8(_: @This(), nonces: [BATCH]u64) u8 {
            var mask: u8 = 0;
            for (nonces, 0..) |nonce, lane| {
                const valid = nonce == ((2 << 32) | 5) or nonce == ((3 << 32) | 1) or
                    nonce == ((2 << 32) | 900_000) or nonce >> 32 >= 4;
                if (valid) mask |= @as(u8, 1) << @intCast(lane);
            }
            return mask;
        }
    };
    const expected = (@as(u64, 2) << 32) | 5;
    for ([_]u64{ 1, 2, 3, 7, 16, 61 }) |stride| {
        var best = std.atomic.Value(u64).init(std.math.maxInt(u64));
        for (0..stride) |start| searchResidueClass(Checker{}, start, stride, &best);
        try std.testing.expectEqual(expected, finish(best.load(.acquire)));
    }
}
