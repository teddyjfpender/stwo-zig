//! Owned, unverified parent proof. The key identifier never selects its own key.
const std = @import("std");
const core = @import("stwo_core");
const suite = @import("blake3_engine_protocol.zig");
const protocol = @import("blake3_native_parent_protocol.zig");
pub const CLAIM_COUNT = @import("air/blake3_native_parent_rows.zig").Airs.len + 2;
pub const Claims = [CLAIM_COUNT]core.fields.qm31.QM31;
pub const Owned = struct {
    allocator: std.mem.Allocator,
    allocation_budget: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget = null,
    proof: ?suite.Proof,
    key_id: [32]u8,
    claims: Claims,
    /// Takes ownership, including responsibility for rejected artifacts.
    pub fn init(allocator: std.mem.Allocator, proof: suite.Proof, key_id: [32]u8, claims: Claims) Owned {
        return .{ .allocator = allocator, .proof = proof, .key_id = key_id, .claims = claims };
    }
    pub fn deinit(self: *Owned) void {
        if (self.proof) |*proof| proof.deinit(self.allocator);
        self.proof = null;
        if (self.allocation_budget) |budget| budget.destroy();
        self.allocation_budget = null;
    }
    pub fn validate(self: *const Owned, admission: *const protocol.Admission) !void {
        try admission.validate();
        if (!std.mem.eql(u8, &self.key_id, &admission.expected_id)) return error.UntrustedBlake3ParentKey;
        const proof = self.proof orelse return error.ConsumedBlake3ParentArtifact;
        if (proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidBlake3ParentCommitments;
        try admission.admitRoot(proof.commitment_scheme_proof.commitments.items[0]);
        try validateClaims(self.claims);
    }
};

pub fn validateClaims(claims: Claims) !void {
    var total = core.fields.qm31.QM31.zero();
    for (claims) |claim| {
        for (claim.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
        total = total.add(claim);
    }
    if (!total.isZero()) return error.InvalidBlake3ParentClaims;
}
