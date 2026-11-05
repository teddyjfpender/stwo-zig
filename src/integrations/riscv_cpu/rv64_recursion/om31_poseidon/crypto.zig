//! New-suite hash and captured-proof family; no producer-selected fallback.
const core = @import("stwo_core");
const B = @import("stwo_circuit_frontend").builder;
const Q = core.fields.qm31.QM31;
pub const Profile = core.vcs_lifted.poseidon2_profile.Om31V2;
pub const H = Profile.MerkleHasher;
pub const CircuitHash = @import("../../poseidon2_outer/sponge.zig").Hash;
pub const ProofFamily = @import("../om31_native/proof.zig").ForCrypto(@This());
pub fn guessHash(ctx: *B.Context(Q), digest: H.Hash) !CircuitHash {
    const words = try core.crypto.poseidon2_m31_sponge.decode(digest);
    var out: CircuitHash = undefined;
    // Dedicated permutation port lookups constrain these scalar digest words
    // to M31 in the full verifier; no byte truncation or modulo-u32 decoding.
    for (&out, words) |*wire, value| wire.* = try ctx.guess(Q.fromBase(value));
    return out;
}
