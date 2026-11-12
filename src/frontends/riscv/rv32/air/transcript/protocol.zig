//! Shared Stark-V RISC-V claim-phase Fiat-Shamir protocol.
//!
//! This module deliberately stops at the generic Stwo composition phase. It
//! owns the protocol prefix through the interaction commitment, so prover and
//! verifier integrations cannot silently reorder claim-phase events.

const std = @import("std");
const claims = @import("claims.zig");
const public_data = @import("../public_data.zig");
const relation_challenges = @import("stwo_riscv_air_lang").evaluation.relation_challenges;

/// RV32IM interaction security parameter. Changing this value requires a proof
/// protocol version bump and renewed pinned-oracle evidence.
pub const INTERACTION_POW_BITS: u32 = 10;

pub const PrefixError = error{InvalidInteractionProofOfWork};

pub const ProverRelations = struct {
    interaction_pow: u64,
    relations: relation_challenges.Relations,
};

test "claim phase: interaction PoW difficulty is build-mode invariant" {
    try std.testing.expectEqual(@as(u32, 10), INTERACTION_POW_BITS);
}

/// Mix public data, preprocessed and main roots, then the canonical main claim.
/// Stark-V does not mix PCS configuration into this protocol prefix.
pub fn mixCommittedPrefix(
    comptime MerkleChannel: type,
    channel: anytype,
    data: *const public_data.PublicData,
    preprocessed_root: anytype,
    main_root: anytype,
    main_claim: *const claims.MainClaim,
) void {
    data.mixInto(channel);
    MerkleChannel.mixRoot(channel, preprocessed_root);
    MerkleChannel.mixRoot(channel, main_root);
    main_claim.mixInto(channel);
}

/// Prover-side prefix: committed data, interaction PoW, then all twelve
/// independent relation challenge pairs.
pub fn proveToRelations(
    comptime MerkleChannel: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    data: *const public_data.PublicData,
    preprocessed_root: anytype,
    main_root: anytype,
    main_claim: *const claims.MainClaim,
) !ProverRelations {
    mixCommittedPrefix(
        MerkleChannel,
        channel,
        data,
        preprocessed_root,
        main_root,
        main_claim,
    );
    const nonce = channel.grind(INTERACTION_POW_BITS);
    channel.mixU64(nonce);
    return .{
        .interaction_pow = nonce,
        .relations = try relation_challenges.Relations.draw(allocator, channel),
    };
}

/// Verifier-side replay of exactly the same prefix. Invalid PoW fails before
/// the nonce is mixed or any relation challenge is drawn.
pub fn verifyToRelations(
    comptime MerkleChannel: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    data: *const public_data.PublicData,
    preprocessed_root: anytype,
    main_root: anytype,
    main_claim: *const claims.MainClaim,
    interaction_pow: u64,
) !relation_challenges.Relations {
    mixCommittedPrefix(
        MerkleChannel,
        channel,
        data,
        preprocessed_root,
        main_root,
        main_claim,
    );
    if (!channel.verifyPowNonce(INTERACTION_POW_BITS, interaction_pow)) {
        return PrefixError.InvalidInteractionProofOfWork;
    }
    channel.mixU64(interaction_pow);
    return relation_challenges.Relations.draw(allocator, channel);
}

/// Mix the interaction claim before its non-empty tree root, matching pinned
/// Stark-V. This ordering is intentionally unavailable as separate public
/// operations.
pub fn finishWithInteractionRoot(
    comptime MerkleChannel: type,
    channel: anytype,
    interaction_claim: *const claims.InteractionClaim,
    interaction_root: anytype,
) void {
    interaction_claim.mixInto(channel);
    MerkleChannel.mixRoot(channel, interaction_root);
}

/// Finish a claim phase with no interaction columns. Stark-V still mixes the
/// canonical interaction claim but does not commit an empty tree.
pub fn finishWithoutInteractionRoot(
    channel: anytype,
    interaction_claim: *const claims.InteractionClaim,
) error{UnexpectedInteractionColumns}!void {
    if (interaction_claim.log_sizes.len != 0) return error.UnexpectedInteractionColumns;
    interaction_claim.mixInto(channel);
}
