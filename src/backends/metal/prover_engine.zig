const std = @import("std");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const prover_engine = @import("stwo_prover_engine").engine;
const MetalCommitBackend = @import("commit_backend.zig").MetalCommitBackend;

const Hasher = blake2_merkle.Blake2sPrefixedMerkleHasher;
const MerkleChannel = blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = channel_blake2s.Blake2sChannel;

/// Raw-Stwo prover composition pinned to the domain-prefixed lifted protocol.
pub const MetalProverEngine = prover_engine.ProverEngine(
    MetalCommitBackend,
    Hasher,
    MerkleChannel,
    Channel,
);

/// Explicit plain-hash composition for newer protocols such as Stwo-Cairo.
pub const PlainMetalProverEngine = prover_engine.ProverEngine(
    MetalCommitBackend,
    blake2_merkle.Blake2sPlainMerkleHasher,
    blake2_merkle.Blake2sPlainMerkleChannel,
    Channel,
);

comptime {
    @import("stwo_prover_api").assertProverEngine(MetalProverEngine);
    @import("stwo_prover_api").assertProverEngine(PlainMetalProverEngine);
}

test "Metal prover engine satisfies the shared transaction contract" {
    comptime @import("stwo_prover_api").assertProverEngine(MetalProverEngine);
    std.testing.refAllDecls(MetalProverEngine);
    _ = MetalProverEngine.TelemetrySnapshot;
    _ = &MetalProverEngine.telemetrySnapshot;
}
