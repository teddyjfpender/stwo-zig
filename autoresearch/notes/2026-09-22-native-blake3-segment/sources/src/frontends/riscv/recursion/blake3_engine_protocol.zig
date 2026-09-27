//! Experimental BLAKE3 proof suite. This does not select production keys or
//! change guest-visible Poseidon/program/state commitment semantics.
const core = @import("stwo_core");
pub const Hasher = core.vcs_lifted.blake3_merkle.MerkleHasher;
pub const MerkleChannel = core.vcs_lifted.blake3_merkle.MerkleChannel;
pub const Channel = core.channel.blake3.Channel;
pub const Proof = core.proof.StarkProof(Hasher);
pub const ExtendedProof = core.proof.ExtendedStarkProof(Hasher);
