//! Exact native reference for the Blake2s secure-felt draw used by the
//! production transcript. It draws both secure felts from one accepted
//! eight-word block.

const std = @import("std");
const hash = @import("hash.zig");
const types = @import("types.zig");

pub const ChallengeContextV1 = struct {
    session_digest: hash.Digest,
    challenge_context_digest: hash.Digest,
    z: types.SecureFelt,
    alpha: types.SecureFelt,

    pub fn validate(self: ChallengeContextV1) !void {
        const expected = derive(self.session_digest);
        if (!hash.eql(self.challenge_context_digest, expected.challenge_context_digest) or
            !types.SecureFelt.eql(self.z, expected.z) or
            !types.SecureFelt.eql(self.alpha, expected.alpha))
        {
            return error.ChallengeContextMismatch;
        }
    }
};

pub fn derive(session_digest: hash.Digest) ChallengeContextV1 {
    const seed = hash.hashDomain(hash.CHALLENGE_DOMAIN, &session_digest);
    const felts = drawTwoSecureFelts(seed);
    return .{
        .session_digest = session_digest,
        .challenge_context_digest = seed,
        .z = felts[0],
        .alpha = felts[1],
    };
}

pub fn drawTwoSecureFelts(seed: hash.Digest) [2]types.SecureFelt {
    const rejection_bound: u32 = 2 * types.M31_MODULUS;
    var counter: u32 = 0;
    while (true) : (counter +%= 1) {
        var hasher = hash.Blake2s256.init(.{});
        hasher.update(&seed);
        var counter_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &counter_bytes, counter, .little);
        hasher.update(&counter_bytes);
        hasher.update(&.{0});

        var digest: hash.Digest = undefined;
        hasher.final(&digest);
        var words: [8]u32 = undefined;
        var accepted = true;
        for (&words, 0..) |*word, index| {
            const begin = index * 4;
            word.* = std.mem.readInt(
                u32,
                digest[begin..][0..4],
                .little,
            );
            if (word.* >= rejection_bound) accepted = false;
        }
        if (!accepted) continue;

        var limbs: [8]u32 = undefined;
        for (&limbs, words) |*limb, word| {
            limb.* = if (word >= types.M31_MODULUS)
                word - types.M31_MODULUS
            else
                word;
        }
        return .{
            .{ .limbs = limbs[0..4].* },
            .{ .limbs = limbs[4..8].* },
        };
    }
}
