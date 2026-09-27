//! Witness-independent native-child BLAKE3 parent verification and capture.
const std = @import("std");
const core = @import("stwo_core");
const suite = @import("blake3_engine_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const universal = @import("air/universal_challenges.zig");
pub const Verified = struct {
    allocator: std.mem.Allocator,
    allocation_budget: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget = null,
    key_id: [32]u8,
    claims: artifact.Claims,
    relations: universal.UniversalRelations,
    seal: [32]u8,
    channel: suite.Channel,
    capture: core.verifier.ProofCapture(suite.Hasher),
    /// Transport mutation guard, never a substitute for proof verification.
    pub fn identity(self: *const Verified) ![32]u8 {
        try self.relations.validate();
        var channel = suite.Channel{};
        const mix = @import("../prover/blake3_execution_protocol.zig").mixDigest;
        channel.mixU32s(&.{ 0x42335052, 1 });
        mix(&channel, self.key_id);
        mix(&channel, @import("../prover/proof_capture_sha256.zig").compute(&self.capture));
        channel.mixFelts(&self.claims);
        for (self.relations.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        mix(&channel, self.channel.digestBytes());
        channel.mixU64(self.channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const Verified, admission: anytype, expected: [32]u8) !void {
        try admission.validate();
        if (!std.mem.eql(u8, &admission.expected_id, &expected) or !std.mem.eql(u8, &self.key_id, &expected)) return error.UntrustedBlake3ParentKey;
        if (self.capture.commitments.len != 4) return error.InvalidBlake3ParentCapture;
        try admission.admitRoot(self.capture.commitments[0]);
        try artifact.validateClaims(self.claims);
        if (!std.mem.eql(u8, &try self.identity(), &self.seal)) return error.InvalidBlake3ParentCapture;
    }
    pub fn deinit(self: *Verified) void {
        self.capture.deinit(self.allocator);
        if (self.allocation_budget) |budget| budget.destroy();
        self.* = undefined;
    }
};
/// Consumes the artifact proof on every path. Successful output owns its capture.
pub fn verify(owned: *artifact.Owned, admission: anytype) !Verified {
    defer owned.deinit();
    try owned.validate(admission);
    const a = owned.allocator;
    const components = try @import("blake3_native_parent_components.zig").Owned.init(a, admission);
    defer components.deinit();
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel).init(a, try admission.config());
    defer scheme.deinit(a);
    var channel = suite.Channel{};
    try admission.mix(&channel);
    const commitments = owned.proof.?.commitment_scheme_proof.commitments.items;
    try scheme.commit(a, commitments[0], components.columns[0].items, &channel);
    try scheme.commit(a, commitments[1], components.columns[1].items, &channel);
    const relations = try universal.UniversalRelations.draw(components.arena.allocator(), &channel);
    try admission.mixClaims(&channel, &owned.claims);
    try scheme.commit(a, commitments[2], components.columns[2].items, &channel);
    try components.bind(relations, owned.claims);
    const proof = owned.proof.?;
    owned.proof = null; // Core verification consumes proof even on failure.
    var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
    try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &components.verifiers, &channel, &scheme, proof, &capture);
    const budget = owned.allocation_budget;
    owned.allocation_budget = null; // Transfer allocator custody to the capture.
    var result = Verified{ .allocation_budget = budget, .allocator = a, .key_id = admission.expected_id, .claims = owned.claims, .channel = channel, .capture = capture, .relations = relations, .seal = undefined };
    errdefer result.deinit();
    result.seal = try result.identity();
    return result;
}
