//! Merkle channel profiles: one comptime value per upstream `MerkleChannel`.
//!
//! A profile fixes together everything a prover must agree on to reproduce an
//! upstream transcript: the Fiat-Shamir channel, the lifted Merkle hasher that
//! commits trees, the hash `mixRoot` absorbs (upstream `mix_hash`), and the
//! proof-of-work search order. Choosing them separately is how a lane ends up
//! with a verifying proof and different bytes, so recursion code names a
//! profile instead of its parts.
//!
//! Profiles are the `MC` parameter of `pcs.verifier.CommitmentSchemeVerifier`
//! (they provide `mixRoot`); `MerkleHasher` is its `H`.

const std = @import("std");
const blake2_hash = @import("../vcs/blake2_hash.zig");
const blake2_merkle = @import("blake2_merkle.zig");
const channel_blake2s = @import("../channel/blake2s.zig");
const blake2s_grind = @import("../channel/blake2s_grind.zig");
const revision_mod = @import("../protocol_revision.zig");

pub const Spec = struct {
    /// Fiat-Shamir channel output reduced modulo P (`Blake2sM31Channel`).
    m31_channel: bool,
    grind_order: blake2s_grind.GrindOrder,
    /// PCS laws a prover committing under this profile follows
    /// (`protocol_revision.Revision.of`).
    revision: revision_mod.Revision,
};

pub fn Blake2sMerkleChannelProfile(comptime spec: Spec) type {
    return struct {
        pub const Channel = channel_blake2s.Blake2sChannelGeneric(spec.m31_channel);
        /// Commitments always use the plain, unreduced Blake2s Merkle hasher,
        /// whichever channel runs Fiat-Shamir.
        pub const MerkleHasher = blake2_merkle.Blake2sPlainMerkleHasher;
        /// `MerkleHasher`'s word hash (`Hasher::hash_u32s*`), e.g. for the
        /// circuit hash.
        pub const Hasher = blake2_hash.Blake2sHasher;
        pub const grind_order = spec.grind_order;
        pub const protocol_revision = spec.revision;

        /// `mix_hash`: `digest = H_channel(digest || hash)`, with the channel's
        /// own (possibly M31-reduced) Blake2s.
        pub fn mixRoot(channel: *Channel, hash: MerkleHasher.Hash) void {
            blake2_merkle.Blake2sMerkleChannelGeneric(spec.m31_channel).mixRoot(channel, hash);
        }

        pub fn grind(channel: Channel, pow_bits: u32) blake2s_grind.Error!u64 {
            return channel.grindInOrder(grind_order, pow_bits);
        }
    };
}

/// The two Merkle channels of https://github.com/starkware-libs/proving at
/// 5a7c5ede4299c91a61df19a07cba4f7502c14230
/// (`crates/stwo/src/core/vcs_lifted/blake2_merkle.rs`), with the SIMD
/// backend's grind order (`prover/backend/simd/grind.rs`).
pub const proving_5a7c5ed = struct {
    /// `Blake2sMerkleChannel`: the recursion root fold.
    pub const Blake2sMerkleChannel = Blake2sMerkleChannelProfile(.{
        .m31_channel = false,
        .grind_order = .rust_simd_hi_major,
        .revision = .proving_5a7c5ed,
    });
    /// `Blake2sM31MerkleChannel`: Cairo leaf proofs, leaf wraps and internal folds.
    pub const Blake2sM31MerkleChannel = Blake2sMerkleChannelProfile(.{
        .m31_channel = true,
        .grind_order = .rust_simd_hi_major,
        .revision = .proving_5a7c5ed,
    });
};

const hasher_test_words = [_]u32{ 0, 1, 2, 3, 0x1234_5678, std.math.maxInt(u32), 7, 8, 9 };

fn expectDigestHex(expected: *const [64]u8, digest: [32]u8) !void {
    try std.testing.expectEqualStrings(expected, &std.fmt.bytesToHex(digest, .lower));
}

test "channel profile: mixRoot matches proving@5a7c5ed mix_hash" {
    // Oracle: `C::default()`, `mix_u64(1)`, then
    // `MC::mix_hash(&mut c, Blake2sMerkleHasher::hash_u32s(&WORDS))` with the
    // `hasher_test.rs` words, for both upstream Merkle channels.
    const hash = blake2_hash.Blake2sHasher.hashU32s(&hasher_test_words);
    inline for (.{
        .{ proving_5a7c5ed.Blake2sM31MerkleChannel, "45181730c0e0720f5e2ac400a8308300e579947dd429b721a55b8d103d43f066" },
        .{ proving_5a7c5ed.Blake2sMerkleChannel, "b9511af5d89a9f57095bf95edb9cb1725516152d2628266824c2e4766b620f78" },
    }) |case| {
        var channel = case[0].Channel{};
        channel.mixU64(1);
        case[0].mixRoot(&channel, hash);
        try expectDigestHex(case[1], channel.digestBytes());
    }
}

test "channel profile: both profiles commit with the plain Blake2s hasher" {
    // Oracle: the empty-tree root `MerkleProverLifted::<CpuBackend,
    // Blake2sMerkleHasher>::commit(vec![], 0, 0)` is Blake2s of no data
    // (`empty_root` in `testdata/lifted_height_vectors.zig`), the hasher both
    // upstream Merkle channels name; compare with the standard BLAKE2s-256.
    var empty_root: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash("", &empty_root, .{});
    inline for (.{ proving_5a7c5ed.Blake2sMerkleChannel, proving_5a7c5ed.Blake2sM31MerkleChannel }) |Profile| {
        var leaf = Profile.MerkleHasher.defaultWithInitialState();
        try std.testing.expectEqualSlices(u8, &empty_root, &leaf.finalize());
        try std.testing.expectEqual(@as(u32, 0), Profile.MerkleHasher.domainPrefixBytes());
    }
}

test "channel profile: grinding follows the profile's search order" {
    // Oracle nonce: `blake2s_grind` tests, M31 channel at 20 bits.
    var channel = proving_5a7c5ed.Blake2sM31MerkleChannel.Channel{};
    channel.mixU64(0x1111_2222_3333_4344);
    try std.testing.expectEqual(@as(u64, 0x1_0005_a700), try proving_5a7c5ed.Blake2sM31MerkleChannel.grind(channel, 20));
}

test "channel profile: profiles are the Merkle channel of the PCS verifier" {
    const pcs_verifier = @import("../pcs/verifier.zig");
    const config_v2 = @import("../pcs/config_v2.zig");
    const alloc = std.testing.allocator;
    const root = [_]u8{7} ** 32;
    inline for (.{ proving_5a7c5ed.Blake2sMerkleChannel, proving_5a7c5ed.Blake2sM31MerkleChannel }) |Profile| {
        const Scheme = pcs_verifier.CommitmentSchemeVerifier(Profile.MerkleHasher, Profile);
        var scheme = try Scheme.init(alloc, config_v2.PcsConfigV2.fromFriAndTraceSize(try config_v2.FriConfigV2.init(10, 0, 1, 3, 1), 4));
        defer scheme.deinit(alloc);
        var channel = Profile.Channel{};
        try scheme.commit(alloc, root, &.{ 3, 4 }, &channel);
        var expected = Profile.Channel{};
        Profile.mixRoot(&expected, root);
        try std.testing.expectEqualSlices(u8, &expected.digestBytes(), &channel.digestBytes());
    }
}
