//! The in-circuit verifier of this repository's NATIVE protocol
//! (`stwo_7b211ed`: `core.pcs.PcsConfig`, `Blake2sChannel`, the
//! domain-prefixed lifted Blake2s Merkle hasher, `core.proof.StarkProof(H)`),
//! built with the circuit builder (`../builder`). It reuses the builder
//! gadgets and the circle/FRI arithmetic of `../stark_verifier` (which
//! verifies a different protocol) and ports the native verifier's own
//! transcript, hashing, Merkle, DEEP-quotient and FRI rules.
//!
//! Map (native source each file ports):
//! - `blake_chain.zig`: `core/vcs_lifted/blake2_merkle.zig` prefixed hashes
//!   (Blake2s from a constant chaining state);
//! - `channel.zig`: `core/channel/blake2s.zig` and `mixRoot`;
//! - `merkle.zig`: `core/vcs_lifted/verifier.zig` leaf/node hashing, column
//!   order and the per-tree query positions of `core/pcs/utils.zig`;
//! - `fri.zig`: `core/fri.zig` commit and decommit, `core/queries.zig`
//!   positions as circle points;
//! - `deep.zig`: `core/pcs/quotients/*` (the DEEP quotient per query);
//! - `shape.zig`: the static proof shape (`core/verifier.zig` geometry,
//!   `core/air/components.zig` mask points);
//! - `proof.zig`: the fixed-width witness, its guess order and the
//!   conversion from a natively verified proof capture;
//! - `verify.zig`: `core/verifier.zig` `verifyImpl` and
//!   `core/pcs/verifier.zig` `verifyValuesImpl`, statement parts delegated
//!   to a duck-typed `statement`.

pub const blake_chain = @import("blake_chain.zig");
pub const channel = @import("channel.zig");
pub const merkle = @import("merkle.zig");
pub const fri = @import("fri.zig");
pub const deep = @import("deep.zig");
pub const shape = @import("shape.zig");
pub const proof = @import("proof.zig");
pub const verify = @import("verify.zig");

pub const NativeChannel = channel.NativeChannel;
pub const Shape = shape.Shape;
pub const Proof = proof.Proof;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("test_fixture.zig");
    _ = @import("e2e_test.zig");
}
