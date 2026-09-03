//! Verifier-owned campaign role-1 fold child.
//!
//! The durable source/proof/node remain transport. This owner exists only
//! after campaign-native q193 cold verification and binds every borrowed view
//! to one runtime FinalRemint authority. No pointer or freshness token has a
//! codec.

const std = @import("std");

const proof_mod =
    @import("recursive_common_canonical_empty_campaign_universal_proof_v2.zig");
const source_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const neutral_projection =
    @import("recursive_pipeline_campaign_fold_projection_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const ROLE = registry_mod.CircuitRoleV1.canonical_empty_field_v2;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const PRODUCTION_ACTIVATION = false;

pub const Authority = final_mod.CampaignFinalRemintAuthorityV2;
pub const Registry = registry_mod.RecursiveCircuitRegistryV1;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const Ingress = proof_mod.FreshRecursiveIngressV2;
pub const Graph = proof_mod.FreshCompositionGraphV2;

pub const CampaignWrapperViewV2 = struct {
    artifact: *const campaign_artifact.Artifact,
    source_input: *const source_mod.ColdInputV2,
    authority: *const Authority,
    geometry: *const Geometry,
    capture: *const common_authority.ProofCapture,

    pub fn validateAgainst(
        self: CampaignWrapperViewV2,
        registry: *const Registry,
    ) !void {
        try self.authority.validateAgainstCampaign(
            self.source_input.shape.campaign_namespace_sha256,
        );
        const expected_registry = try self.authority.registryAuthority();
        const expected_geometry = try self.authority.geometryForRole(ROLE);
        if (registry != expected_registry or self.geometry != expected_geometry)
            return error.CampaignCanonicalEmptyFoldChildMismatch;
        try campaign_artifact.validate(
            &self.source_input.shape,
            self.artifact,
        );
        try campaign_artifact.admitRegistry(
            registry,
            &self.source_input.shape,
            self.artifact,
            self.geometry,
        );
        const derived = try registry_mod.sealProofShapeFromCapture(
            self.capture,
            self.geometry.component_count,
            self.geometry.proof_shape.column_log_degree,
            self.geometry.proof_shape.table_layout_identity_sha256,
        );
        if (!std.meta.eql(derived, self.geometry.proof_shape))
            return error.CampaignCanonicalEmptyFoldChildMismatch;
    }

    pub fn role(_: CampaignWrapperViewV2) registry_mod.CircuitRoleV1 {
        return ROLE;
    }
};

pub const ProjectionV2 = struct {
    role: registry_mod.CircuitRoleV1,
    wrapper: CampaignWrapperViewV2,
    ingress: Ingress,
    graph: Graph,

    pub fn validateAgainst(
        self: ProjectionV2,
        registry: *const Registry,
    ) !void {
        try self.wrapper.validateAgainst(registry);
        try self.ingress.validate();
        try self.graph.lane.graph.validate();
        if (self.role != ROLE or
            self.wrapper.source_input != self.ingress.source_input or
            self.wrapper.authority != self.ingress.final_remint or
            self.wrapper.geometry != self.ingress.geometry or
            self.wrapper.capture != self.ingress.capture or
            self.ingress.query_words != self.graph.query_words or
            self.ingress.query_log_size != self.graph.query_log_size or
            self.ingress.final_transcript_digest !=
                self.graph.final_transcript_digest or
            self.ingress.final_transcript_draw_count !=
                self.graph.final_transcript_draw_count or
            self.ingress.query_words_identity_sha256 !=
                self.graph.query_words_identity_sha256 or
            self.graph.evaluation.values.len != self.graph.lane.graph.nodes.len)
        {
            return error.CampaignCanonicalEmptyFoldChildMismatch;
        }
    }
};

pub const FreshFoldChildV2 = struct {
    owner: *const proof_mod.EvidenceV2,
    projection_value: ProjectionV2,

    pub fn validateBorrowed(self: FreshFoldChildV2) !void {
        try self.owner.validateFresh();
        const expected = try projectionFromEvidence(self.owner);
        if (!std.meta.eql(self.projection_value, expected))
            return error.CampaignCanonicalEmptyFoldChildMismatch;
        const registry = try self.owner.final_remint.registryAuthority();
        try self.projection_value.validateAgainst(registry);
    }

    pub fn projection(self: FreshFoldChildV2) !ProjectionV2 {
        try self.validateBorrowed();
        return self.projection_value;
    }
};

pub const OwnedLeaseV2 = struct {
    pub const ROLE = registry_mod.CircuitRoleV1.canonical_empty_field_v2;

    authority: *const Authority,
    evidence: proof_mod.EvidenceV2,

    pub fn initOwned(
        authority: *const Authority,
        cold: proof_mod.OwnedColdProofV2,
    ) !OwnedLeaseV2 {
        var evidence = try proof_mod.EvidenceV2.initOwned(authority, cold);
        errdefer evidence.deinit();
        var result = OwnedLeaseV2{
            .authority = authority,
            .evidence = evidence,
        };
        try result.validateForCampaign(authority);
        return result;
    }

    pub fn deinit(self: *OwnedLeaseV2) void {
        self.evidence.deinit();
        self.* = undefined;
    }

    pub fn validateForCampaign(
        self: *const OwnedLeaseV2,
        authority: *const Authority,
    ) !void {
        if (self.authority != authority or
            self.evidence.final_remint != authority)
        {
            return error.CampaignCanonicalEmptyFoldChildMismatch;
        }
        try authority.validateAgainstCampaign(
            self.evidence.cold.source_input.shape.campaign_namespace_sha256,
        );
        try self.evidence.validateFresh();
        const child = try self.requireFoldChild();
        try child.validateBorrowed();
    }

    pub fn requireFoldChild(self: *const OwnedLeaseV2) !FreshFoldChildV2 {
        try self.evidence.validateFresh();
        var result = FreshFoldChildV2{
            .owner = &self.evidence,
            .projection_value = try projectionFromEvidence(&self.evidence),
        };
        try result.validateBorrowed();
        return result;
    }

    pub fn nodeArtifact(
        self: *const OwnedLeaseV2,
    ) *const campaign_artifact.Artifact {
        return self.evidence.artifact();
    }

    pub fn foldProjection(
        self: *const OwnedLeaseV2,
        registry: *const Registry,
    ) !ProjectionV2 {
        const expected_registry = try self.authority.registryAuthority();
        if (registry != expected_registry)
            return error.CampaignCanonicalEmptyFoldChildMismatch;
        return (try self.requireFoldChild()).projection();
    }

    /// Role-neutral campaign projection used by the final Stage104 child
    /// union. The nominal role-1 projection above remains available to direct
    /// consumers; no cast or digest substitutes for this field-wise copy.
    pub fn campaignFoldProjection(
        self: *const OwnedLeaseV2,
        authority: *const Authority,
    ) !neutral_projection.ProjectionV2 {
        try self.validateForCampaign(authority);
        const ingress = try self.evidence.ingressView();
        const graph = try self.evidence.foldGraphView();
        const geometry = try self.evidence.geometry();
        const result = neutral_projection.ProjectionV2{
            .role = OwnedLeaseV2.ROLE,
            .authority = authority,
            .geometry = geometry,
            .node_artifact = self.evidence.artifact(),
            .node_public = ingress.node_public,
            .claimed_sums = &ingress.claims.values,
            .claims_seal = &ingress.claims.seal,
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
        try result.validateAgainstFinal(authority);
        return result;
    }
};

fn projectionFromEvidence(
    evidence: *const proof_mod.EvidenceV2,
) !ProjectionV2 {
    const ingress = try evidence.ingressView();
    const graph = try evidence.foldGraphView();
    const geometry = try evidence.geometry();
    const result = ProjectionV2{
        .role = ROLE,
        .wrapper = .{
            .artifact = evidence.artifact(),
            .source_input = &evidence.cold.source_input,
            .authority = evidence.final_remint,
            .geometry = geometry,
            .capture = evidence.proofCapture(),
        },
        .ingress = ingress,
        .graph = graph,
    };
    try result.validateAgainst(
        try evidence.final_remint.registryAuthority(),
    );
    return result;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        SERIALIZABLE_FRESH_CAPABILITY or PRODUCTION_ACTIVATION)
    {
        @compileError("campaign canonical-empty fold child drifted");
    }
}
