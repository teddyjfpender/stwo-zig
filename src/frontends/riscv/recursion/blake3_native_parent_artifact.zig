//! Owned, unverified parent proof. The key identifier never selects its own key.
const std = @import("std");
const core = @import("stwo_core");
const suite = @import("blake3_engine_protocol.zig");
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
    pub fn validate(self: *const Owned, admission: anytype) !void {
        try admission.validate();
        if (!std.mem.eql(u8, &self.key_id, &admission.expected_id)) return error.UntrustedBlake3ParentKey;
        const proof = self.proof orelse return error.ConsumedBlake3ParentArtifact;
        if (!std.meta.eql(proof.commitment_scheme_proof.config, try admission.config())) return error.InvalidBlake3ParentProfile;
        if (proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidBlake3ParentCommitments;
        try admission.admitRoot(proof.commitment_scheme_proof.commitments.items[0]);
        try validateClaimsForAdmission(self.claims, admission);
    }
};

pub fn validateClaimsForAdmission(claims: Claims, admission: anytype) !void {
    if (comptime @hasDecl(@TypeOf(admission.*), "validateClaimsForRelations")) {
        for (claims) |claim| for (claim.toM31Array()) |value|
            if (value.v >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
    } else try validateClaims(claims);
}
pub fn validateClosure(claims: Claims, admission: anytype, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
    if (comptime @hasDecl(@TypeOf(admission.*), "validateClaimsForRelations"))
        try admission.validateClaimsForRelations(claims, relations)
    else
        try validateClaims(claims);
}

pub fn validateClaims(claims: Claims) !void {
    var total = core.fields.qm31.QM31.zero();
    for (claims) |claim| {
        for (claim.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidBlake3ParentClaims;
        total = total.add(claim);
    }
    if (!total.isZero()) {
        if (std.process.hasEnvVarConstant("STWO_RISCV_PARENT_CLAIM_DIAGNOSTIC")) {
            for (claims, 0..) |claim, i| std.debug.print("BLAKE3_PARENT_CLAIM index={d} coordinates={any}\n", .{ i, claim.toM31Array() });
            std.debug.print("BLAKE3_PARENT_CLAIM_SUM coordinates={any}\n", .{total.toM31Array()});
        }
        return error.InvalidBlake3ParentClaims;
    }
}
