//! The circuit prover on the CPU backend (design §4, milestone M7): the
//! circuit AIR's recorded constraint programs bound to a proof's geometry,
//! and the proving transcript of `crates/circuit_prover/src/prover.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) on both channel profiles.

pub const air = @import("air.zig");
pub const prove = @import("prove.zig");
pub const verifier_proof = @import("verifier_proof.zig");
pub const cairo_verifier_proof = @import("cairo_verifier_proof.zig");
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

test {
    _ = air;
    _ = prove;
    _ = verifier_proof;
    _ = cairo_verifier_proof;
    _ = recursion;
}
