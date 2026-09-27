//! One genuine PCS proof for an already assembled exact composite AIR. Claims
//! and admission stay with its versioned protocol; no proof byte concatenation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
pub fn prove(comptime Backend: type, a: std.mem.Allocator, first: anytype, interactions: []const engine.pcs.ColumnEvaluation, handles: []const engine.air.component_prover.ComponentProver, channel: *suite.Channel) !suite.Proof {
    if (!first.owns_scheme or first.scheme.trees.items.len != 3 or handles.len == 0) return error.InvalidV5CompositeFirstRound;
    try first.scheme.commitBorrowedStreaming(a, interactions, 8, channel);
    first.owns_scheme = false;
    return engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, channel, first.scheme);
}
pub const Captured = struct {
    proof: core.verifier.ProofCapture(suite.Hasher),
    final_channel: suite.Channel,
    pub fn deinit(self: *Captured, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.* = undefined;
    }
};
/// STARK ownership transfers on every path, including commit/shape failures.
pub fn verifyOwned(a: std.mem.Allocator, received: suite.Proof, roots: [3][32]u8, config: core.pcs.PcsConfig, fixed: []const u32, main: []const u32, witness: []const u32, interactions: []const u32, handles: []const core.air.components.Component, first_channel: suite.Channel, proof_channel: *suite.Channel) !void {
    _ = try verifyInternal(false, true, a, &received, roots, config, fixed, main, witness, interactions, handles, first_channel, proof_channel);
}
pub fn verifyCaptureOwned(a: std.mem.Allocator, received: suite.Proof, roots: [3][32]u8, config: core.pcs.PcsConfig, fixed: []const u32, main: []const u32, witness: []const u32, interactions: []const u32, handles: []const core.air.components.Component, first_channel: suite.Channel, proof_channel: *suite.Channel) !Captured {
    return verifyInternal(true, true, a, &received, roots, config, fixed, main, witness, interactions, handles, first_channel, proof_channel);
}
/// Full immutable proof verification; no source ownership or byte clone.
pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const suite.Proof, roots: [3][32]u8, config: core.pcs.PcsConfig, fixed: []const u32, main: []const u32, witness: []const u32, interactions: []const u32, handles: []const core.air.components.Component, first_channel: suite.Channel, proof_channel: *suite.Channel) !Captured {
    return verifyInternal(true, false, a, received, roots, config, fixed, main, witness, interactions, handles, first_channel, proof_channel);
}
fn verifyInternal(comptime capture: bool, comptime take: bool, a: std.mem.Allocator, received: *const suite.Proof, roots: [3][32]u8, config: core.pcs.PcsConfig, fixed: []const u32, main: []const u32, witness: []const u32, interactions: []const u32, handles: []const core.air.components.Component, first_channel: suite.Channel, proof_channel: *suite.Channel) !(if (capture) Captured else void) {
    var proof = received.*;
    var owns = take;
    defer if (owns) proof.deinit(a);
    const actual = proof.commitment_scheme_proof.commitments.items;
    if (handles.len == 0 or actual.len != 5 or !std.meta.eql(actual[0..3].*, roots) or !std.meta.eql(proof.commitment_scheme_proof.config, config)) return error.UntrustedV5CompositeRoots;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel).init(a, config);
    defer verifier.deinit(a);
    var channel = first_channel;
    try verifier.commit(a, roots[0], fixed, &channel);
    try verifier.commit(a, roots[1], main, &channel);
    try verifier.commit(a, roots[2], witness, &channel);
    try verifier.commit(a, actual[3], interactions, proof_channel);
    if (capture) {
        var captured: core.verifier.ProofCapture(suite.Hasher) = undefined;
        if (take) {
            owns = false;
            try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, handles, proof_channel, &verifier, proof, &captured);
        } else {
            try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, handles, proof_channel, &verifier, &proof, &captured);
        }
        return .{ .proof = captured, .final_channel = proof_channel.* };
    } else {
        owns = false;
        try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, proof_channel, &verifier, proof);
    }
}
