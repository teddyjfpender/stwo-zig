//! Pre-final campaign role-1 child owned by one q193 cold proof.
//!
//! This capability is usable by a role-2 proof before FinalRemint exists. It
//! binds the exact PaddingTarget and verifier-owned query/composition capture,
//! but exposes no registry-backed wrapper artifact. Promotion consumes this
//! owner only after all three final geometries mint FinalRemint.

const std = @import("std");

const proof_mod =
    @import("recursive_common_canonical_empty_campaign_universal_proof_v2.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_campaign_universal_manifest_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const final_child =
    @import("recursive_common_canonical_empty_campaign_fold_child_v2.zig");
const prefinal_union =
    @import("recursive_pipeline_campaign_prefinal_fold_lease_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROLE = registry_mod.CircuitRoleV1.canonical_empty_field_v2;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const ProjectionV2 = prefinal_union.ProjectionV2;

pub const FreshPreFinalFoldChildV2 = struct {
    owner: *const OwnedPreFinalLeaseV2,
    projection_value: ProjectionV2,

    pub fn validateBorrowed(self: FreshPreFinalFoldChildV2) !void {
        try self.owner.validateForPaddingTarget(self.owner.padding_target);
        const expected = try projectionFromOwner(self.owner);
        if (!std.meta.eql(self.projection_value, expected))
            return error.CampaignCanonicalEmptyPreFinalChildMismatch;
    }

    pub fn projection(self: FreshPreFinalFoldChildV2) !ProjectionV2 {
        try self.validateBorrowed();
        return self.projection_value;
    }
};

pub const OwnedPreFinalLeaseV2 = struct {
    pub const ROLE = registry_mod.CircuitRoleV1.canonical_empty_field_v2;

    padding_target: *const target_mod.CampaignPaddingTargetV2,
    cold: proof_mod.OwnedColdProofV2,

    pub fn initOwned(
        target: *const target_mod.CampaignPaddingTargetV2,
        cold: proof_mod.OwnedColdProofV2,
    ) !OwnedPreFinalLeaseV2 {
        var owned = cold;
        var owned_live = true;
        errdefer if (owned_live) owned.deinit();
        var result = OwnedPreFinalLeaseV2{
            .padding_target = target,
            .cold = owned,
        };
        owned = undefined;
        owned_live = false;
        errdefer result.cold.deinit();
        try result.validateForPaddingTarget(target);
        return result;
    }

    pub fn deinit(self: *OwnedPreFinalLeaseV2) void {
        self.cold.deinit();
        self.* = undefined;
    }

    pub fn validateForPaddingTarget(
        self: *const OwnedPreFinalLeaseV2,
        target: *const target_mod.CampaignPaddingTargetV2,
    ) !void {
        if (self.padding_target != target or
            !std.meta.eql(self.cold.padding_target, target.*))
        {
            return error.CampaignCanonicalEmptyPreFinalChildMismatch;
        }
        try self.cold.validateToken();
        try target.validateRemintedGeometry(
            OwnedPreFinalLeaseV2.ROLE,
            &self.cold.geometry_value,
        );
        try validateRoleSpecificOwner(self, target);
        const projection = try projectionFromOwner(self);
        try projection.validateAgainstPaddingTarget(target);
    }

    pub fn validateColdGeometry(self: *const OwnedPreFinalLeaseV2) !void {
        try self.validateForPaddingTarget(self.padding_target);
    }

    pub fn geometryForPaddingTarget(
        self: *const OwnedPreFinalLeaseV2,
    ) *const registry_mod.AuthenticatedGeometryV1 {
        return &self.cold.geometry_value;
    }

    pub fn preFinalFoldProjection(
        self: *const OwnedPreFinalLeaseV2,
        target: *const target_mod.CampaignPaddingTargetV2,
    ) !ProjectionV2 {
        try self.validateForPaddingTarget(target);
        return projectionFromOwner(self);
    }

    pub fn requireFoldChild(
        self: *const OwnedPreFinalLeaseV2,
    ) !FreshPreFinalFoldChildV2 {
        try self.validateForPaddingTarget(self.padding_target);
        var result = FreshPreFinalFoldChildV2{
            .owner = self,
            .projection_value = try projectionFromOwner(self),
        };
        try result.validateBorrowed();
        return result;
    }

    /// Consumes this pre-final owner. On success the same cold verifier owner
    /// is retained by the registry-backed role-1 lease; no proof is reopened.
    pub fn promoteOwned(
        self: *OwnedPreFinalLeaseV2,
        final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
    ) !final_child.OwnedLeaseV2 {
        try self.validateForPaddingTarget(self.padding_target);
        try self.padding_target.validateAgainstFinal(final_remint);
        try self.cold.validateAgainstFinal(final_remint);
        const cold = self.cold;
        self.* = undefined;
        return final_child.OwnedLeaseV2.initOwned(final_remint, cold);
    }
};

fn projectionFromOwner(owner: *const OwnedPreFinalLeaseV2) !ProjectionV2 {
    const graph = try owner.cold.foldGraphView();
    return .{
        .role = ROLE,
        .padding_target = owner.padding_target,
        .geometry = &owner.cold.geometry_value,
        .node_public = &owner.cold.node_public,
        .claimed_sums = &owner.cold.claims.values,
        .claims_seal = &owner.cold.claims.seal,
        .session = &owner.cold.session,
        .statement = &owner.cold.fresh.statement,
        .capture = &owner.cold.fresh.capture,
        .query_words = &owner.cold.query_authority.query_words,
        .query_log_size = owner.cold.query_authority.query_log_size,
        .final_transcript_digest = &owner.cold.query_authority.final_transcript_digest,
        .final_transcript_draw_count = owner.cold.query_authority.final_transcript_draw_count,
        .query_words_identity_sha256 = &owner.cold.query_authority.query_words_identity_sha256,
        .graph = .{
            .capture_identity_sha256 = graph.capture_identity_sha256,
            .layout_identity_sha256 = graph.layout_identity_sha256,
            .query_words = graph.query_words,
            .query_log_size = graph.query_log_size,
            .final_transcript_digest = graph.final_transcript_digest,
            .final_transcript_draw_count = graph.final_transcript_draw_count,
            .query_words_identity_sha256 = graph.query_words_identity_sha256,
            .lane = graph.lane,
            .evaluation = graph.evaluation,
        },
    };
}

fn validateRoleSpecificOwner(
    owner: *const OwnedPreFinalLeaseV2,
    target: *const target_mod.CampaignPaddingTargetV2,
) !void {
    if (!std.meta.eql(owner.cold.source_input.shape, target.shape))
        return error.CampaignCanonicalEmptyPreFinalChildMismatch;
    try campaign_public.validate(&target.shape, &owner.cold.node_public);
    var logs: manifest_mod.LogSizes = undefined;
    const padded = try target.paddedLogs();
    for (&logs, padded[0..manifest_mod.COMPONENT_COUNT]) |
        *destination,
        source,
    | destination.* = source;
    const manifest = try manifest_mod.buildForLogSizes(logs);
    try owner.cold.claims.validate(&manifest);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("campaign canonical-empty pre-final child drifted");
    }
}
