const std = @import("std");
const hash256 = @import("crypto/hash256.zig");

pub const Digest32 = hash256.Digest32;

/// Proof-of-work helper.
///
/// This is a simple hash-based PoW:
///   digest = H(challenge || nonce_le)
///
/// A nonce is valid if the digest has at least `difficulty_bits`
/// leading zero bits.
pub const Pow = struct {
    pub fn verify(challenge: []const u8, nonce: u64, difficulty_bits: u16) bool {
        const digest = hash(challenge, nonce);
        return leadingZeroBits(digest[0..]) >= difficulty_bits;
    }

    /// Attempts to find a nonce satisfying the difficulty.
    /// Returns `null` if not found within `max_iters`.
    pub fn solve(challenge: []const u8, difficulty_bits: u16, max_iters: u64) ?u64 {
        var nonce: u64 = 0;
        while (nonce < max_iters) : (nonce += 1) {
            if (verify(challenge, nonce, difficulty_bits)) return nonce;
        }
        return null;
    }

    pub fn hash(challenge: []const u8, nonce: u64) Digest32 {
        var h = hash256.Hasher256.init();
        h.update(challenge);
        const nbytes = u64ToBytesLe(nonce);
        h.update(nbytes[0..]);
        var out: Digest32 = undefined;
        h.final(&out);
        return out;
    }
};

fn u64ToBytesLe(x: u64) [8]u8 {
    return .{
        @intCast(x & 0xff),
        @intCast((x >> 8) & 0xff),
        @intCast((x >> 16) & 0xff),
        @intCast((x >> 24) & 0xff),
        @intCast((x >> 32) & 0xff),
        @intCast((x >> 40) & 0xff),
        @intCast((x >> 48) & 0xff),
        @intCast((x >> 56) & 0xff),
    };
}

fn leadingZeroBits(bytes: []const u8) u16 {
    var count: u16 = 0;
    for (bytes) |b| {
        if (b == 0) {
            count += 8;
            continue;
        }
        count += @intCast(@clz(@as(u8, b)));
        break;
    }
    return count;
}

test "pow: solve+verify" {
    const challenge = "pow-challenge";
    const difficulty: u16 = 12; // small for unit tests
    const max_iters: u64 = 1_000_000;

    const nonce = Pow.solve(challenge, difficulty, max_iters) orelse return error.TestUnexpectedResult;
    try std.testing.expect(Pow.verify(challenge, nonce, difficulty));

    // Wrong nonce should not verify (extremely likely).
    try std.testing.expect(!Pow.verify(challenge, nonce + 1, difficulty));
}
