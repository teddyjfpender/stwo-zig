//! Pre-final role-0 fold child for one independently cold-opened V4 proof.
//!
//! The current role-0 prover is not a padding adapter.  Consequently this
//! owner succeeds only when the verifier-derived role-0 geometry already
//! matches the authenticated campaign padding target point-for-point.  A
//! target with any larger row remains unavailable until a genuinely padded
//! role-0 proof exists.  No registry, FinalRemint, durable node, or digest can
//! substitute for the borrowed cold verifier owner.

const std = @import("std");

const proof_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const prefinal =
    @import("recursive_pipeline_campaign_prefinal_fold_lease_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROLE = registry_mod.CircuitRoleV1
    .ethereum_incremental_leaf_wrapper_v4;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const HOST_PADDING_ADMITTED = false;

pub const ProjectionV2 = prefinal.ProjectionV2;

pub fn Types(comptime Engine: type) type {
    const Proof = proof_mod.Types(Engine);
    return TypesForColdProof(Proof.OwnedColdProofV4);
}

/// Generic only so structural tests can instantiate the custody boundary.
/// Production callers use `Types(Engine)` and therefore the exact verifier
/// owner from the role-0 q193 transaction.
pub fn TypesForColdProof(comptime ColdProof: type) type {
    assertColdProofContract(ColdProof);
    return struct {
        pub const OwnedPreFinalLeaseV4 = struct {
            pub const ROLE = registry_mod.CircuitRoleV1
                .ethereum_incremental_leaf_wrapper_v4;

            padding_target: *const target_mod.CampaignPaddingTargetV2,
            cold: ColdProof,

            pub fn initOwned(
                target: *const target_mod.CampaignPaddingTargetV2,
                cold: ColdProof,
            ) !OwnedPreFinalLeaseV4 {
                var owned = cold;
                var owned_live = true;
                errdefer if (owned_live) owned.deinit();
                var result = OwnedPreFinalLeaseV4{
                    .padding_target = target,
                    .cold = owned,
                };
                owned = undefined;
                owned_live = false;
                errdefer result.cold.deinit();
                try result.validateForPaddingTarget(target);
                return result;
            }

            pub fn deinit(self: *OwnedPreFinalLeaseV4) void {
                self.cold.deinit();
                self.* = undefined;
            }

            pub fn validateForPaddingTarget(
                self: *const OwnedPreFinalLeaseV4,
                target: *const target_mod.CampaignPaddingTargetV2,
            ) !void {
                if (self.padding_target != target)
                    return error.EthereumIncrementalPreFinalChildMismatchV4;
                try target.validateSelf();
                try self.cold.validateForPaddingTarget(target);
                // This is the fail-closed target-native gate.  In particular,
                // it rejects a valid active proof whose padded logs or table
                // layout do not equal the common target.
                try target.validateRemintedGeometry(
                    OwnedPreFinalLeaseV4.ROLE,
                    &self.cold.geometry_value,
                );
                try validateCampaignCustody(&self.cold, target);
                const projection = try projectionFromCold(
                    &self.cold,
                    target,
                );
                try projection.validateAgainstPaddingTarget(target);
            }

            pub fn validateColdGeometry(
                self: *const OwnedPreFinalLeaseV4,
            ) !void {
                try self.validateForPaddingTarget(self.padding_target);
            }

            pub fn geometryForPaddingTarget(
                self: *const OwnedPreFinalLeaseV4,
            ) *const registry_mod.AuthenticatedGeometryV1 {
                return &self.cold.geometry_value;
            }

            pub fn preFinalFoldProjection(
                self: *const OwnedPreFinalLeaseV4,
                target: *const target_mod.CampaignPaddingTargetV2,
            ) !ProjectionV2 {
                try self.validateForPaddingTarget(target);
                return projectionFromCold(&self.cold, target);
            }
        };
    };
}

fn projectionFromCold(
    cold: anytype,
    target: *const target_mod.CampaignPaddingTargetV2,
) !ProjectionV2 {
    const ingress = try cold.ingressView();
    const graph = try cold.foldGraphView();
    return .{
        .role = ROLE,
        .padding_target = target,
        .geometry = &cold.geometry_value,
        .node_public = ingress.node_public,
        .claimed_sums = &cold.claims.values,
        .claims_seal = &cold.claims.seal,
        .session = ingress.session,
        .statement = ingress.statement,
        .capture = ingress.capture,
        .query_words = ingress.query_words,
        .query_log_size = ingress.query_log_size,
        .final_transcript_digest = ingress.final_transcript_digest,
        .final_transcript_draw_count = ingress.final_transcript_draw_count,
        .query_words_identity_sha256 = ingress.query_words_identity_sha256,
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

fn validateCampaignCustody(
    cold: anytype,
    target: *const target_mod.CampaignPaddingTargetV2,
) !void {
    try campaign_public.validate(&target.shape, &cold.node_public);
    if (cold.materialized.campaign_authority.leaf_count !=
        target.shape.real_leaf_count or
        cold.cohort.padding_target != target or
        !std.mem.eql(
            u8,
            &cold.materialized.campaign_authority.campaign_inventory
                .table_identity_sha256,
            &target.shape.inventory_identity_sha256,
        ))
    {
        return error.EthereumIncrementalPreFinalChildMismatchV4;
    }
    const ingress = try cold.ingressView();
    try ingress.validate();
    if (ingress.geometry != &cold.geometry_value or
        ingress.node_public != &cold.node_public or
        ingress.claims != &cold.claims)
    {
        return error.EthereumIncrementalPreFinalChildMismatchV4;
    }
}

fn assertColdProofContract(comptime ColdProof: type) void {
    if (!@hasDecl(ColdProof, "ROLE") or ColdProof.ROLE != ROLE)
        @compileError("role-0 pre-final owner requires the genuine role-0 cold proof");
    inline for (.{
        "deinit",
        "validateBorrowed",
        "validateForPaddingTarget",
        "ingressView",
        "foldGraphView",
    }) |name| if (!@hasDecl(ColdProof, name))
        @compileError("role-0 pre-final cold proof missing " ++ name);
    inline for (.{
        "materialized",
        "claims",
        "geometry_value",
        "node_public",
    }) |name| if (!@hasField(ColdProof, name))
        @compileError("role-0 pre-final cold proof missing field " ++ name);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        @intFromEnum(ROLE) != 0 or PRODUCTION_ACTIVATION or
        ROUTER_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        HOST_PADDING_ADMITTED)
    {
        @compileError("role-0 campaign pre-final child contract drifted");
    }
}
