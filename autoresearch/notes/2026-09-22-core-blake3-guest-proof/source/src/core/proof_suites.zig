//! Canonical commitment/transcript type bundles. Product admission selects a suite.
const proof = @import("proof.zig");
pub const Blake2s = struct {
    pub const Hasher = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    pub const MerkleChannel = @import("vcs_lifted/blake2_merkle.zig").Blake2sMerkleChannel;
    pub const Channel = @import("channel/blake2s.zig").Blake2sChannel;
    pub const Proof = proof.StarkProof(Hasher);
    pub const ExtendedProof = proof.ExtendedStarkProof(Hasher);
};
pub const Blake3 = struct {
    pub const Hasher = @import("vcs_lifted/blake3_merkle.zig").MerkleHasher;
    pub const MerkleChannel = @import("vcs_lifted/blake3_merkle.zig").MerkleChannel;
    pub const Channel = @import("channel/blake3.zig").Channel;
    pub const Proof = proof.StarkProof(Hasher);
    pub const ExtendedProof = proof.ExtendedStarkProof(Hasher);
};
