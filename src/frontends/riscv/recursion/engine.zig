//! Recursion-targeted proving-engine protocol types.
//!
//! Backend selection remains at the integration boundary.  This module fixes
//! only the cryptographic suite, so CPU and future device engines cannot
//! accidentally pair a Poseidon channel with Blake Merkle roots (or vice
//! versa).

const std = @import("std");
const stwo_core = @import("stwo_core");
const prover_engine = @import("stwo_prover_engine").engine;
const poseidon2 = @import("stwo_riscv_memory").primitives_recursion_poseidon2_channel;
const native_scheduled = @import("native_scheduled_channel.zig");

pub const Hasher = @import("stwo_riscv_recursion_air").protocol_recursion_engine_protocol.Hasher;
pub const MerkleChannel = @import("stwo_riscv_recursion_air").protocol_recursion_engine_protocol.MerkleChannel;
pub const Channel = @import("stwo_riscv_recursion_air").protocol_recursion_engine_protocol.Channel;
pub const Proof = @import("stwo_riscv_recursion_air").protocol_recursion_engine_protocol.Proof;
pub const ExtendedProof = @import("stwo_riscv_recursion_air").protocol_recursion_engine_protocol.ExtendedProof;

pub fn ProverEngineForBackend(comptime Backend: type) type {
    return prover_engine.ProverEngine(
        Backend,
        Hasher,
        MerkleChannel,
        Channel,
    );
}

/// Explicit experimental suite selection. Production defaults and scheduled
/// Poseidon identities are unchanged; the normal engine pipeline is reused.
pub fn Blake3ProverEngineForBackend(comptime Backend: type) type {
    const suite = @import("stwo_riscv_recursion_air").protocol_recursion_blake3_engine_protocol;
    return prover_engine.ProverEngine(Backend, suite.Hasher, suite.MerkleChannel, suite.Channel);
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
