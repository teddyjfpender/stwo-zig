//! Recursion-targeted proving-engine protocol types.
//!
//! Backend selection remains at the integration boundary.  This module fixes
//! only the cryptographic suite, so CPU and future device engines cannot
//! accidentally pair a Poseidon channel with Blake Merkle roots (or vice
//! versa).

const std = @import("std");
const stwo_core = @import("stwo_core");
const prover_engine = @import("stwo_prover_engine").engine;
const poseidon2 = @import("poseidon2_channel.zig");
const native_scheduled = @import("native_scheduled_channel.zig");

pub const Hasher = poseidon2.MerkleHasher;
pub const MerkleChannel = poseidon2.MerkleChannel;
pub const Channel = poseidon2.Channel;
pub const Proof = stwo_core.proof.StarkProof(Hasher);
pub const ExtendedProof = stwo_core.proof.ExtendedStarkProof(Hasher);

pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(
        Backend,
        Hasher,
        MerkleChannel,
        Channel,
    );
}

/// Production engine whose native Fiat--Shamir calls are framed by the exact
/// authenticated recursive-verifier schedule.  The Merkle hash and field are
/// unchanged; this is a transcript-authority selection, not a second suite.
pub fn ScheduledProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(
        Backend,
        Hasher,
        native_scheduled.MerkleChannel,
        native_scheduled.Channel,
    );
}

test "recursion engine: protocol types are one coherent Poseidon2 suite" {
    comptime stwo_core.vcs_lifted.merkle_hasher.assertMerkleHasherLifted(Hasher);
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(Hasher.Hash));
    try std.testing.expect(Hasher.Hash == poseidon2.Digest);
    try std.testing.expect(Channel == poseidon2.Channel);
}
