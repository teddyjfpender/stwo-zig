//! Structural 50-row adapter gate for the direct V5 leaf wrapper.
//!
//! The gate checks exact roster placement, typed component constraint counts,
//! and one claim per row. It cannot expose components to a prover or verifier:
//! the V5 relation closure, independent Tree0 key, and native child authority
//! are not yet qualified as one proof transaction.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const plan_mod = @import("segment_leaf_wrapper_roster_direct_v5.zig");
const closure = @import("../segment_leaf_wrapper_cohort_closure_v5.zig");
const adapter = @import("universal_adapter_manifest.zig");

const QM31 = core.fields.qm31.QM31;
pub const COMPONENT_COUNT = plan_mod.COMPONENT_COUNT;
pub const ALL_COMPONENT_MASK: u64 = (@as(u64, 1) << COMPONENT_COUNT) - 1;
pub const CLAIM_DOMAIN = "stwo-zig/riscv-direct-v5-50-row-claims/v1\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_PROOF_AVAILABLE = false;

/// Adapter responsibility map. Tags are build-time wiring, never a source of
/// witness, claim, or child-proof authority. Rows not listed as replacements
/// reuse the same typed native V2 adapter under V5's rechecked placement.
pub const AdapterOwner = enum {
    native_v2,
    frame_provider_v4,
    poseidon_provider_v5,
    range_provider_v4,
    statement_v5,
    direct_v4,
    program_bridge_v5,
    local_v5,
};

pub fn ownerForRow(row: usize) !AdapterOwner {
    if (row >= COMPONENT_COUNT) return error.InvalidV5ProofGateRow;
    return switch (row) {
        4 => .frame_provider_v4,
        34 => .poseidon_provider_v5,
        35 => .range_provider_v4,
        36 => .statement_v5,
        42 => .program_bridge_v5,
        47...49 => .local_v5,
        39...41, 43...46 => .direct_v4,
        else => .native_v2,
    };
}

comptime {
    if (COMPONENT_COUNT != 50 or plan_mod.TREE_COUNT != 3 or
        closure.ROW_COUNT != COMPONENT_COUNT or closure.DOMAIN_COUNT != 47)
        @compileError("V5 proof gate requires exactly 50 rows and 47 relation domains");
}

/// Metadata-only preflight. Passing it never authorizes a proof.
pub const BindingAudit = struct {
    plan_seal: [32]u8,
    count: u8 = 0,
    bound_mask: u64 = 0,
    claimed_sums: [COMPONENT_COUNT]QM31 = @splat(QM31.zero()),
    claim_seal: [32]u8 = .{0} ** 32,
    structurally_sealed: bool = false,

    pub fn init(plan: *const plan_mod.Plan) !BindingAudit {
        try plan.validate();
        return .{ .plan_seal = plan.seal };
    }

    pub fn bind(
        self: *BindingAudit,
        plan: *const plan_mod.Plan,
        placement: plan_mod.Placement,
        claim: QM31,
        verifier_constraints: usize,
        prover_constraints: usize,
    ) !void {
        try self.validatePlan(plan);
        if (self.structurally_sealed or self.count >= COMPONENT_COUNT)
            return error.IncompleteV5ProofGate;
        const row = self.count;
        const expected = plan.placements[row] orelse return error.InvalidV5ProofGatePlacement;
        if (placement.geometry.roster_row != row or
            !placement.eql(expected) or
            placement.claimed_sum_index != row)
            return error.InvalidV5ProofGatePlacement;
        const constraints = @as(usize, expected.geometry.direct_constraints) + expected.geometry.interaction_batches;
        if (verifier_constraints != constraints or prover_constraints != constraints)
            return error.InvalidV5ProofGateComponent;
        for (claim.toM31Array()) |limb| if (limb.toU32() >= core.fields.m31.Modulus)
            return error.NonCanonicalV5ProofGateClaim;
        const bit = @as(u64, 1) << @intCast(row);
        if (self.bound_mask & bit != 0) return error.DuplicateV5ProofGateRow;
        self.claimed_sums[row] = claim;
        self.bound_mask |= bit;
        self.count += 1;
    }

    pub fn sealStructural(self: *BindingAudit, plan: *const plan_mod.Plan, claims: *const closure.Claims50) !void {
        try self.validatePlan(plan);
        try claims.validateRows();
        if (self.structurally_sealed or self.count != COMPONENT_COUNT or self.bound_mask != ALL_COMPONENT_MASK)
            return error.IncompleteV5ProofGate;
        for (self.claimed_sums, claims.claims) |actual, expected|
            if (!actual.eql(expected)) return error.V5ProofGateClaimMismatch;
        self.claim_seal = claimSeal(self);
        self.structurally_sealed = true;
    }

    pub fn validateStructural(self: *const BindingAudit, plan: *const plan_mod.Plan) !void {
        try self.validatePlan(plan);
        if (!self.structurally_sealed or self.count != COMPONENT_COUNT or
            self.bound_mask != ALL_COMPONENT_MASK or
            !std.mem.eql(u8, &self.claim_seal, &claimSeal(self)))
            return error.IncompleteV5ProofGate;
    }

    fn validatePlan(self: *const BindingAudit, plan: *const plan_mod.Plan) !void {
        try plan.validate();
        if (!std.mem.eql(u8, &self.plan_seal, &plan.seal))
            return error.V5ProofGatePlanMismatch;
    }
};

/// Owns typed component handles only after each adapter passes `BindingAudit`.
/// No slice accessor is active until a fully verified V5 transaction exists.
pub const ProofGate = struct {
    audit: BindingAudit,
    verifier_components: [COMPONENT_COUNT]core.air.components.Component = undefined,
    prover_components: [COMPONENT_COUNT]prover.air.component_prover.ComponentProver = undefined,

    pub fn init(plan: *const plan_mod.Plan) !ProofGate {
        return .{ .audit = try BindingAudit.init(plan) };
    }

    pub fn append(self: *ProofGate, plan: *const plan_mod.Plan, binding: adapter.AdapterBinding) !void {
        if (!std.mem.eql(u8, &binding.manifest_seal, &plan.seal))
            return error.V5ProofGatePlanMismatch;
        const row = self.audit.count;
        try self.audit.bind(plan, binding.placement, binding.claimed_sum, binding.verifier.nConstraints(), binding.prover.nConstraints());
        self.verifier_components[row] = binding.verifier;
        self.prover_components[row] = binding.prover;
    }

    pub fn sealStructural(self: *ProofGate, plan: *const plan_mod.Plan, claims: *const closure.Claims50) !void {
        try self.audit.sealStructural(plan, claims);
    }

    pub fn verifierSlice(_: *const ProofGate) error{V5WrapperProofUnavailable}![]const core.air.components.Component {
        return error.V5WrapperProofUnavailable;
    }

    pub fn proverSlice(_: *const ProofGate) error{V5WrapperProofUnavailable}![]const prover.air.component_prover.ComponentProver {
        return error.V5WrapperProofUnavailable;
    }
};

fn claimSeal(audit: *const BindingAudit) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLAIM_DOMAIN);
    hash.update(&audit.plan_seal);
    var count: [1]u8 = .{audit.count};
    hash.update(&count);
    var mask: [8]u8 = undefined;
    std.mem.writeInt(u64, &mask, audit.bound_mask, .little);
    hash.update(&mask);
    for (audit.claimed_sums, 0..) |claim, row| {
        const row_byte: [1]u8 = .{@intCast(row)};
        hash.update(&row_byte);
        for (claim.toM31Array()) |limb| {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, limb.toU32(), .little);
            hash.update(&encoded);
        }
    }
    return hash.finalResult();
}
