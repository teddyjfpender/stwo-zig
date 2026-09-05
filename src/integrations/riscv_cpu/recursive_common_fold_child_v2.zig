//! Role-specific live child capability minted by a cold common-fold verifier.
//!
//! The value is deliberately process-local. Every pointer borrows one
//! `OwnedColdProof`, and no encoder exists for verifier freshness, replayed
//! query words, or the authenticated composition graph.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const capture_mod = @import("recursive_common_fold_composition_capture_v2.zig");
const child_capability =
    @import("recursive_common_fold_child_capability_v2.zig");
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const artifact_mod = @import("recursive_node_artifact_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");

const recursion = frontend.recursion;
const M31 = stwo_core.fields.m31.M31;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const QUERY_WORD_COUNT: usize = 193;
pub const QueryWordV2 = M31;
pub const TranscriptDigestV2 = capture_mod.TranscriptDigestV2;
pub const COMMON_FOLD_ROLE = registry_mod.CircuitRoleV1.common_fold_field_v2;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const FreshRecursiveIngressV2 = struct {
    node_public: *const artifact_mod.NodePublicV2,
    claims: *const manifest_mod.ClaimVector,
    session: *const secure_artifact.SessionV1,
    statement: *const secure_artifact.StatementV1,
    geometry_authority: *const manifest_mod.AuthorityV2,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
    capture: *const common_authority.ProofCapture,
    query_words: *const [QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_transcript_digest: *const TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,

    pub fn validate(self: FreshRecursiveIngressV2) !void {
        try self.node_public.validate();
        try self.geometry_authority.validate();
        try self.claims.validate(self.geometry_authority.manifest());
        try self.session.validate();
        try self.statement.validateAgainstSession(self.session);
        try self.geometry.validate();
        const capture_query_log_size = child_capability
            .queryLogSizeFromCapture(self.capture) catch
            return error.CommonFoldFreshIngressMismatch;
        if (self.geometry != self.geometry_authority.commonFoldGeometry() or
            self.geometry.role != COMMON_FOLD_ROLE or
            self.capture.commitments.len !=
                common_authority.COMMITMENT_TREE_COUNT or
            self.capture.queries.raw.len != self.query_words.len or
            self.query_log_size == 0 or self.query_log_size >= 31 or
            capture_query_log_size != self.query_log_size or
            !std.mem.eql(
                u8,
                &self.claims.seal,
                &self.statement.claims_sha256,
            ) or !std.meta.eql(
            self.geometry.preprocessed_root,
            self.capture.commitments[0],
        ) or !std.meta.eql(
            self.statement.transcript_id,
            recursion.protocol.transcriptId(
                self.final_transcript_digest.*,
                self.final_transcript_draw_count,
            ),
        ) or std.mem.allEqual(
            u8,
            self.query_words_identity_sha256,
            0,
        )) return error.CommonFoldFreshIngressMismatch;
        const mask = (@as(u32, 1) << @intCast(self.query_log_size)) - 1;
        for (self.query_words.*, self.capture.queries.raw) |full, projected| {
            const projected_u32 = std.math.cast(u32, projected) orelse
                return error.CommonFoldFreshIngressMismatch;
            if ((full.toU32() & mask) != projected_u32)
                return error.CommonFoldFreshIngressMismatch;
        }
        const shape = try registry_mod.sealProofShapeFromCapture(
            self.capture,
            self.geometry.component_count,
            self.geometry.proof_shape.column_log_degree,
            self.geometry.proof_shape.table_layout_identity_sha256,
        );
        if (!std.meta.eql(shape, self.geometry.proof_shape))
            return error.CommonFoldFreshIngressMismatch;
    }
};

pub const FreshFoldChildV2 = struct {
    wrapper: common_authority.FreshWrapperViewV2,
    ingress: FreshRecursiveIngressV2,
    graph: capture_mod.FreshGraphViewV2,
    query_words: *const [QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_transcript_digest: *const TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,

    pub fn validateBorrowed(self: FreshFoldChildV2) !void {
        try self.wrapper.validateAgainst(self.ingress.geometry_authority.registry);
        try self.ingress.validate();
        if (try self.wrapper.role() != COMMON_FOLD_ROLE or
            self.wrapper.geometry != self.ingress.geometry or
            self.wrapper.capture != self.ingress.capture or
            self.ingress.node_public != self.wrapper.nodePublic() or
            self.query_words != self.ingress.query_words or
            self.query_words != self.graph.query_words or
            self.query_log_size != self.ingress.query_log_size or
            self.query_log_size != self.graph.query_log_size or
            self.final_transcript_digest !=
                self.ingress.final_transcript_digest or
            self.final_transcript_digest !=
                self.graph.final_transcript_digest or
            self.final_transcript_draw_count !=
                self.ingress.final_transcript_draw_count or
            self.final_transcript_draw_count !=
                self.graph.final_transcript_draw_count or
            self.query_words_identity_sha256 !=
                self.ingress.query_words_identity_sha256 or
            self.query_words_identity_sha256 !=
                self.graph.query_words_identity_sha256 or
            self.graph.evaluation.values.len != self.graph.lane.graph.nodes.len or
            !std.mem.eql(
                u8,
                &self.graph.evaluation.circuit_identity,
                &self.graph.lane.graph.identity_digest,
            ) or std.mem.allEqual(
            u8,
            self.graph.capture_identity_sha256,
            0,
        ) or std.mem.allEqual(
            u8,
            self.graph.layout_identity_sha256,
            0,
        )) return error.CommonFoldColdGraphMismatch;
        try self.graph.lane.graph.validate();
    }
};

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        QUERY_WORD_COUNT != 193 or SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("common-fold role-specific child contract drifted");
    }
}
