//! Unrouteable pre-final Stage103 q193 transaction.
//!
//! This sibling is the execution-policy-aware bridge between a live campaign
//! PaddingTarget and the role-1 cold geometry used to mint FinalRemint. It
//! publishes no node/StageManifest because those require the final registry;
//! callers may retain the canonical proof bytes, then promote the live lease
//! or cold-open them again after FinalRemint is available.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const source_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const proof_mod =
    @import("recursive_common_canonical_empty_campaign_universal_proof_v2.zig");
const child_mod =
    @import("recursive_common_canonical_empty_campaign_prefinal_fold_child_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const Q193_GENUINE_GATE_GREEN = false;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const NODE_PUBLICATION_REQUIRES_FINAL_REMINT = true;

pub const ProvedV2 = struct {
    allocator: std.mem.Allocator,
    lease: child_mod.OwnedPreFinalLeaseV2,
    proof_bytes: []u8,
    receipt: @import("recursive_temporal_secure_parent_native_engine_v1.zig").ReceiptV1,

    pub fn deinit(self: *ProvedV2) void {
        self.allocator.free(self.proof_bytes);
        self.lease.deinit();
        self.* = undefined;
    }

    pub fn validate(
        self: *const ProvedV2,
        target: *const target_mod.CampaignPaddingTargetV2,
        source: *const source_mod.ColdInputV2,
    ) !void {
        try self.receipt.validate();
        try self.lease.validateForPaddingTarget(target);
        if (!std.meta.eql(self.lease.cold.source_input, source.*) or
            self.proof_bytes.len == 0)
        {
            return error.CampaignCanonicalEmptyPreFinalOutputMismatch;
        }
        const encoded = try self.lease.cold.encodeArtifactAlloc(self.allocator);
        defer self.allocator.free(encoded);
        if (!std.mem.eql(u8, encoded, self.proof_bytes))
            return error.CampaignCanonicalEmptyPreFinalOutputMismatch;
    }

    pub fn finalGeometrySource(
        self: *const ProvedV2,
    ) *const proof_mod.OwnedColdProofV2 {
        return &self.lease.cold;
    }
};

pub fn proveAndColdVerify(
    allocator: std.mem.Allocator,
    target: *const target_mod.CampaignPaddingTargetV2,
    active_sources: anytype,
    source: *const source_mod.ColdInputV2,
    execution: artifact_store.ExecutionKeyV1,
    policy: *const policy_mod.PolicyV2,
) !ProvedV2 {
    try policy.validateAgainstExecution(execution);
    try target.validateAgainstActive(active_sources);
    if (!std.meta.eql(source.shape, target.shape))
        return error.CampaignCanonicalEmptyPreFinalOutputMismatch;
    const source_bytes = try source.source.encodeCanonical(&source.shape);
    var proved = try proof_mod.proveAndColdVerifyPreFinal(
        allocator,
        target,
        active_sources,
        &source_bytes,
        .{ .worker_count = try policy.engineWorkerCount() },
    );
    var proved_owned = true;
    defer if (proved_owned) proved.deinit();
    const proof_bytes = try proved.proof.encodeArtifactAlloc(allocator);
    errdefer allocator.free(proof_bytes);
    const receipt = proved.receipt;
    const cold = proved.proof;
    proved.proof = undefined;
    proved_owned = false;
    var lease = try child_mod.OwnedPreFinalLeaseV2.initOwned(target, cold);
    errdefer lease.deinit();
    var result = ProvedV2{
        .allocator = allocator,
        .lease = lease,
        .proof_bytes = proof_bytes,
        .receipt = receipt,
    };
    try result.validate(target, source);
    return result;
}

pub fn coldOpen(
    allocator: std.mem.Allocator,
    target: *const target_mod.CampaignPaddingTargetV2,
    active_sources: anytype,
    source: *const source_mod.ColdInputV2,
    proof_bytes: []const u8,
) !child_mod.OwnedPreFinalLeaseV2 {
    try target.validateAgainstActive(active_sources);
    if (!std.meta.eql(source.shape, target.shape))
        return error.CampaignCanonicalEmptyPreFinalOutputMismatch;
    const source_bytes = try source.source.encodeCanonical(&source.shape);
    const cold = try proof_mod.coldOpenPreFinal(
        allocator,
        target,
        active_sources,
        &source_bytes,
        proof_bytes,
    );
    return child_mod.OwnedPreFinalLeaseV2.initOwned(target, cold);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        Q193_GENUINE_GATE_GREEN or PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !NODE_PUBLICATION_REQUIRES_FINAL_REMINT)
    {
        @compileError("campaign canonical-empty pre-final worker drifted");
    }
}
