//! Role-neutral campaign fold projection from one verifier-owned cold lease.
//!
//! This is a borrowed process-local view, not a nominal cast and not a proof
//! codec. Role-specific leases fill its fields only after rerunning their own
//! cold-owner validation. This validator then closes every pointer against
//! the same FinalRemint, campaign node, capture, q193 query authority, and
//! rerecorded composition graph.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");

const recursion = frontend.recursion;
const composition = recursion.air.composition_circuit;
const lowering = recursion.air.verifier_arithmetic_lowering;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const QUERY_WORD_COUNT: usize = 193;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Authority = final_mod.CampaignFinalRemintAuthorityV2;
pub const Role = registry_mod.CircuitRoleV1;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const Artifact = campaign_artifact.Artifact;
pub const NodePublic = campaign_artifact.NodePublic;
pub const ProofCapture = common_authority.ProofCapture;
pub const TranscriptDigestV2 = recursion.poseidon2_channel.Digest;

pub const Error = error{
    CampaignFoldProjectionMismatch,
};

pub const ProjectionGraphV2 = struct {
    capture_identity_sha256: *const [32]u8,
    layout_identity_sha256: *const [32]u8,
    query_words: *const [QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_transcript_digest: *const TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,
    lane: composition.RecursionLane,
    evaluation: lowering.Evaluation,
};

pub const ProjectionV2 = struct {
    role: Role,
    authority: *const Authority,
    geometry: *const Geometry,
    node_artifact: *const Artifact,
    node_public: *const NodePublic,
    claimed_sums: []const QM31,
    claims_seal: *const [32]u8,
    session: *const secure_artifact.SessionV1,
    statement: *const secure_artifact.StatementV1,
    capture: *const ProofCapture,
    query_words: *const [QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_transcript_digest: *const TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,
    graph: ProjectionGraphV2,

    pub fn validateAgainstFinal(
        self: ProjectionV2,
        authority: *const Authority,
    ) !void {
        if (self.authority != authority)
            return error.CampaignFoldProjectionMismatch;
        try authority.validateAgainstCampaign(
            self.node_artifact.campaign_namespace_sha256,
        );
        const registry = try authority.registryAuthority();
        const expected_geometry = try authority.geometryForRole(self.role);
        if (self.geometry != expected_geometry or
            self.geometry.role != self.role or
            self.node_public != &self.node_artifact.node_public or
            self.claimed_sums.len != self.geometry.component_count or
            self.claimed_sums.len != 36 or
            self.capture.commitments.len !=
                common_authority.COMMITMENT_TREE_COUNT or
            self.capture.queries.raw.len != QUERY_WORD_COUNT or
            self.query_words != self.graph.query_words or
            self.query_log_size != self.graph.query_log_size or
            self.final_transcript_digest !=
                self.graph.final_transcript_digest or
            self.final_transcript_draw_count !=
                self.graph.final_transcript_draw_count or
            self.query_words_identity_sha256 !=
                self.graph.query_words_identity_sha256 or
            self.graph.evaluation.values.len != self.graph.lane.graph.nodes.len or
            !std.mem.eql(
                u8,
                self.claims_seal,
                &self.statement.claims_sha256,
            ) or !std.meta.eql(
            self.statement.transcript_id,
            recursion.protocol.transcriptId(
                self.final_transcript_digest.*,
                self.final_transcript_draw_count,
            ),
        ) or !std.meta.eql(
            self.geometry.preprocessed_root,
            self.capture.commitments[0],
        ) or !std.mem.eql(
            u8,
            &self.graph.evaluation.circuit_identity,
            &self.graph.lane.graph.identity_digest,
        ) or std.mem.allEqual(u8, self.query_words_identity_sha256, 0) or
            std.mem.allEqual(u8, self.graph.capture_identity_sha256, 0) or
            std.mem.allEqual(u8, self.graph.layout_identity_sha256, 0) or
            try roleForArtifact(self.node_artifact) != self.role)
        {
            return error.CampaignFoldProjectionMismatch;
        }
        try self.session.validate();
        try self.statement.validateAgainstSession(self.session);
        try self.geometry.validate();
        try self.graph.lane.graph.validate();
        try campaign_artifact.validate(authority.shape, self.node_artifact);
        try campaign_artifact.admitRegistry(
            registry,
            authority.shape,
            self.node_artifact,
            self.geometry,
        );
        const captured_shape = try registry_mod.sealProofShapeFromCapture(
            self.capture,
            self.geometry.component_count,
            self.geometry.proof_shape.column_log_degree,
            self.geometry.proof_shape.table_layout_identity_sha256,
        );
        if (!std.meta.eql(captured_shape, self.geometry.proof_shape) or
            try queryLogSizeFromCapture(self.capture) != self.query_log_size)
        {
            return error.CampaignFoldProjectionMismatch;
        }
        const mask = (@as(u32, 1) << @intCast(self.query_log_size)) - 1;
        for (self.query_words.*, self.capture.queries.raw) |full, projected| {
            const projected_u32 = std.math.cast(u32, projected) orelse
                return error.CampaignFoldProjectionMismatch;
            if ((full.toU32() & mask) != projected_u32)
                return error.CampaignFoldProjectionMismatch;
        }
    }
};

fn roleForArtifact(value: *const Artifact) !Role {
    return switch (value.stage_kind) {
        .leaf_wrapper => switch (value.node_kind) {
            .real => .ethereum_incremental_leaf_wrapper_v4,
            .empty => .canonical_empty_field_v2,
            .mixed => error.CampaignFoldProjectionMismatch,
        },
        .fold, .root => .common_fold_field_v2,
    };
}

fn queryLogSizeFromCapture(capture: *const ProofCapture) !u32 {
    if (capture.column_log_sizes.len !=
        common_authority.COMMITMENT_TREE_COUNT or
        capture.trace_paths.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.CampaignFoldProjectionMismatch;
    }
    const composition_index = common_authority.COMMITMENT_TREE_COUNT - 1;
    const logs = capture.column_log_sizes[composition_index];
    if (logs.len == 0) return error.CampaignFoldProjectionMismatch;
    var query_log_size: u32 = 0;
    for (logs) |log_size| {
        if (log_size == 0 or log_size >= 31)
            return error.CampaignFoldProjectionMismatch;
        query_log_size = @max(query_log_size, log_size);
    }
    if (capture.trace_paths[composition_index].path_depth != query_log_size)
        return error.CampaignFoldProjectionMismatch;
    return query_log_size;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        QUERY_WORD_COUNT != 193 or SERIALIZABLE_FRESH_CAPABILITY or
        @hasDecl(ProjectionV2, "encode") or
        @hasDecl(ProjectionV2, "decode"))
    {
        @compileError("campaign fold projection drifted");
    }
}
