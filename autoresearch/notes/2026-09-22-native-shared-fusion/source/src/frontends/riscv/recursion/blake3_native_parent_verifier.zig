//! Witness-independent native-child BLAKE3 parent verification and capture.
const std = @import("std");
const core = @import("stwo_core");
const suite = @import("blake3_engine_protocol.zig");
const protocol = @import("blake3_native_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const universal = @import("air/universal_challenges.zig");
pub const Verified = struct {
    allocator: std.mem.Allocator,
    allocation_budget: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget = null,
    key_id: [32]u8,
    claims: artifact.Claims,
    channel: suite.Channel,
    capture: core.verifier.ProofCapture(suite.Hasher),
    pub fn deinit(self: *Verified) void {
        self.capture.deinit(self.allocator);
        if (self.allocation_budget) |budget| budget.destroy();
        self.* = undefined;
    }
};
/// Consumes the artifact proof on every path. Successful output owns its capture.
pub fn verify(owned: *artifact.Owned, admission: *const protocol.Admission) !Verified {
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
    return .{ .allocation_budget = budget, .allocator = a, .key_id = admission.expected_id, .claims = owned.claims, .channel = channel, .capture = capture };
}
