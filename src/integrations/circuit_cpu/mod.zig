//! The circuit prover on the CPU backend (design §4): the
//! circuit AIR's recorded constraint programs bound to a proof's geometry,
//! and the proving transcript of `crates/circuit_prover/src/prover.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) on both channel profiles.

pub const om31 = @import("om31/mod.zig");
pub const air = @import("air.zig");
pub const prove = @import("prove.zig");
pub const verifier_proof = @import("verifier_proof.zig");
pub const cairo_verifier_proof = @import("cairo_verifier_proof.zig");
/// `verify_circuit` on a `CircuitSerialize` proof.
pub const verify = @import("verify.zig");
pub const recursion = @import("recursion/mod.zig");

pub const Internal = prove.Internal;
pub const Root = prove.Root;

test "api signature: both channel profiles bind the CPU engine" {
    comptime @import("stwo_prover_api").assertProverEngine(prove.Internal.Engine);
    comptime @import("stwo_prover_api").assertProverEngine(prove.Root.Engine);
}

test "invariant: both profiles commit with the plain Blake2s Merkle hasher" {
    const std = @import("std");
    try std.testing.expect(prove.Internal.Hasher == prove.Root.Hasher);
    try std.testing.expect(prove.Internal.Channel != prove.Root.Channel);
}

test "api signature: OM31 CPU proof and wire preserve field authority" {
    const P = om31.protocol;
    comptime @import("stwo_prover_api").assertProverEngine(P.Engine);
    try @import("std").testing.expect(P.Proof == @import("stwo_core").proof.ForField(P.O).StarkProof(P.H));
    try @import("std").testing.expect(@TypeOf(@as(om31.wire.Owned, undefined).proof) == P.Proof);
    const verify_fn = @typeInfo(@TypeOf(om31.prove.verify)).@"fn";
    try @import("std").testing.expect(verify_fn.params[4].type.? == *const P.Proof);
}

test "invariant: OM31 retains its concrete transcript and rejects unknown profiles" {
    const core = @import("stwo_core");
    const P = om31.protocol;
    try @import("std").testing.expect(P.O == core.fields.om31.OM31);
    try @import("std").testing.expect(P.H == core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher);
    try @import("std").testing.expect(P.Channel == core.channel.raw_mod_m31.Om31Channel);
    try @import("std").testing.expectError(error.UnknownOm31OuterProfile, P.Profile.parse("unregistered-outer-profile"));
}

test {
    _ = air;
    _ = prove;
    _ = verifier_proof;
    _ = cairo_verifier_proof;
    _ = verify;
    _ = recursion;
}
