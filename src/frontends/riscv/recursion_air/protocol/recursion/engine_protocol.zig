//! Verifier-safe recursion suite types; backend selection belongs to engine.zig.
const stwo_core = @import("stwo_core");
const poseidon2 = @import("stwo_riscv_memory").recursion.poseidon2_channel;

pub const Hasher = poseidon2.MerkleHasher;
pub const MerkleChannel = poseidon2.MerkleChannel;
pub const Channel = poseidon2.Channel;
pub const Proof = stwo_core.proof.StarkProof(Hasher);
pub const ExtendedProof = stwo_core.proof.ExtendedStarkProof(Hasher);
