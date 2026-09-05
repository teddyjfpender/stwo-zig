//! Role-neutral pre-final child union for campaign padding proofs.
//!
//! Unlike the post-final fold lease, this capability is bound only to one
//! authenticated `CampaignPaddingTargetV2`.  It lets the role-2 proof consume
//! two independently cold-opened role-0/role-1 children before a registry can
//! exist.  Role nominality is retained in the tagged union, and promotion to
//! the final registry remains a separate role-specific operation.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const artifact_mod = @import("recursive_node_artifact_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");

const recursion = frontend.recursion;
const composition = recursion.air.composition_circuit;
const lowering = recursion.air.verifier_arithmetic_lowering;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Authority = target_mod.CampaignPaddingTargetV2;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const Role = target_mod.Role;
pub const QUERY_WORD_COUNT: usize = 193;
pub const TranscriptDigestV2 = recursion.poseidon2_channel.Digest;

pub const Error = target_mod.Error || error{
    CampaignPreFinalFoldLeaseAuthorityMismatch,
    CampaignPreFinalFoldLeaseProjectionMismatch,
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

/// Role-neutral projection of one role-specific cold owner. Claimed sums are
/// a borrowed slice so no nominal claim-vector cast is needed; the seal and
/// every backing pointer remain owned and revalidated by the role lease.
pub const ProjectionV2 = struct {
    role: Role,
    padding_target: *const Authority,
    geometry: *const Geometry,
    node_public: *const artifact_mod.NodePublicV2,
    claimed_sums: []const QM31,
    claims_seal: *const [32]u8,
    session: *const secure_artifact.SessionV1,
    statement: *const secure_artifact.StatementV1,
    capture: *const common_authority.ProofCapture,
    query_words: *const [QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_transcript_digest: *const TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,
    graph: ProjectionGraphV2,

    pub fn validateAgainstPaddingTarget(
        self: ProjectionV2,
        target: *const Authority,
    ) !void {
        if (self.padding_target != target or self.geometry.role != self.role or
            self.claimed_sums.len != 36 or
            self.capture.commitments.len != common_authority.COMMITMENT_TREE_COUNT or
            self.capture.queries.raw.len != QUERY_WORD_COUNT or
            self.query_words != self.graph.query_words or
            self.query_log_size != self.graph.query_log_size or
            self.final_transcript_digest != self.graph.final_transcript_digest or
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
        ) or std.mem.allEqual(u8, self.query_words_identity_sha256, 0) or
            std.mem.allEqual(u8, self.graph.capture_identity_sha256, 0) or
            std.mem.allEqual(u8, self.graph.layout_identity_sha256, 0))
        {
            return error.CampaignPreFinalFoldLeaseProjectionMismatch;
        }
        try target.validateRemintedGeometry(self.role, self.geometry);
        try self.session.validate();
        try self.statement.validateAgainstSession(self.session);
        try self.graph.lane.graph.validate();
        const captured_shape = try registry_mod.sealProofShapeFromCapture(
            self.capture,
            self.geometry.component_count,
            self.geometry.proof_shape.column_log_degree,
            self.geometry.proof_shape.table_layout_identity_sha256,
        );
        if (!std.meta.eql(captured_shape, self.geometry.proof_shape) or
            !std.meta.eql(self.geometry.preprocessed_root, self.capture.commitments[0]))
        {
            return error.CampaignPreFinalFoldLeaseProjectionMismatch;
        }
        const query_log = try queryLogSizeFromCapture(self.capture);
        if (query_log != self.query_log_size)
            return error.CampaignPreFinalFoldLeaseProjectionMismatch;
        const mask = (@as(u32, 1) << @intCast(query_log)) - 1;
        for (self.query_words.*, self.capture.queries.raw) |full, projected| {
            const projected_u32 = std.math.cast(u32, projected) orelse
                return error.CampaignPreFinalFoldLeaseProjectionMismatch;
            if ((full.toU32() & mask) != projected_u32)
                return error.CampaignPreFinalFoldLeaseProjectionMismatch;
        }
    }
};

fn queryLogSizeFromCapture(
    capture: *const common_authority.ProofCapture,
) !u32 {
    if (capture.column_log_sizes.len != common_authority.COMMITMENT_TREE_COUNT or
        capture.trace_paths.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.CampaignPreFinalFoldLeaseProjectionMismatch;
    }
    const composition_index = common_authority.COMMITMENT_TREE_COUNT - 1;
    const logs = capture.column_log_sizes[composition_index];
    if (logs.len == 0) return error.CampaignPreFinalFoldLeaseProjectionMismatch;
    var result: u32 = 0;
    for (logs) |log_size| {
        if (log_size == 0 or log_size >= 31)
            return error.CampaignPreFinalFoldLeaseProjectionMismatch;
        result = @max(result, log_size);
    }
    if (capture.trace_paths[composition_index].path_depth != result)
        return error.CampaignPreFinalFoldLeaseProjectionMismatch;
    return result;
}

/// Role lease contract:
/// - exact `ROLE: Role`;
/// - `validateForPaddingTarget(*const Authority) !void`;
/// - `preFinalFoldProjection(*const Authority) !Projection`.
///
/// Projection exposes `role`, `padding_target`, `geometry`, and
/// `validateAgainstPaddingTarget`. No final registry is accepted here.
pub fn TypedCampaignPreFinalFoldLeaseV2(
    comptime RealLease: type,
    comptime EmptyLease: type,
    comptime CommonLease: type,
) type {
    assertRoleLeaseContract(
        RealLease,
        .ethereum_incremental_leaf_wrapper_v4,
    );
    assertRoleLeaseContract(EmptyLease, .canonical_empty_field_v2);
    assertRoleLeaseContract(CommonLease, .common_fold_field_v2);

    return struct {
        const Self = @This();

        pub const PayloadV2 = union(Role) {
            ethereum_incremental_leaf_wrapper_v4: *const RealLease,
            canonical_empty_field_v2: *const EmptyLease,
            common_fold_field_v2: *const CommonLease,
        };

        padding_target: *const Authority,
        payload: PayloadV2,

        pub fn fromReal(
            target: *const Authority,
            lease: *const RealLease,
        ) !Self {
            return init(target, .{
                .ethereum_incremental_leaf_wrapper_v4 = lease,
            });
        }

        pub fn fromEmpty(
            target: *const Authority,
            lease: *const EmptyLease,
        ) !Self {
            return init(target, .{ .canonical_empty_field_v2 = lease });
        }

        pub fn fromCommon(
            target: *const Authority,
            lease: *const CommonLease,
        ) !Self {
            return init(target, .{ .common_fold_field_v2 = lease });
        }

        pub fn role(self: *const Self) Role {
            return std.meta.activeTag(self.payload);
        }

        pub fn validateAgainstPaddingTarget(
            self: *const Self,
            target: *const Authority,
        ) !void {
            _ = try self.projectAgainst(target);
        }

        pub fn preFinalFoldProjection(
            self: *const Self,
            target: *const Authority,
        ) !ProjectionV2 {
            return self.projectAgainst(target);
        }

        fn init(target: *const Authority, payload: PayloadV2) !Self {
            const result = Self{
                .padding_target = target,
                .payload = payload,
            };
            try result.validateAgainstPaddingTarget(target);
            return result;
        }

        fn projectAgainst(
            self: *const Self,
            target: *const Authority,
        ) !ProjectionV2 {
            if (self.padding_target != target)
                return error.CampaignPreFinalFoldLeaseAuthorityMismatch;
            try target.validateSelf();
            const projection = switch (self.payload) {
                .ethereum_incremental_leaf_wrapper_v4 => |lease| blk: {
                    try lease.validateForPaddingTarget(target);
                    break :blk try lease.preFinalFoldProjection(target);
                },
                .canonical_empty_field_v2 => |lease| blk: {
                    try lease.validateForPaddingTarget(target);
                    break :blk try lease.preFinalFoldProjection(target);
                },
                .common_fold_field_v2 => |lease| blk: {
                    try lease.validateForPaddingTarget(target);
                    break :blk try lease.preFinalFoldProjection(target);
                },
            };
            try projection.validateAgainstPaddingTarget(target);
            const active_role = self.role();
            if (projection.role != active_role or
                projection.padding_target != target or
                projection.geometry.role != active_role)
            {
                return error.CampaignPreFinalFoldLeaseProjectionMismatch;
            }
            try target.validateRemintedGeometry(
                active_role,
                projection.geometry,
            );
            return projection;
        }
    };
}

fn assertRoleLeaseContract(comptime Lease: type, comptime role: Role) void {
    if (!@hasDecl(Lease, "ROLE") or Lease.ROLE != role)
        @compileError("campaign pre-final fold lease has wrong role");
    inline for (.{
        "validateForPaddingTarget",
        "preFinalFoldProjection",
    }) |name| if (!@hasDecl(Lease, name))
        @compileError("campaign pre-final fold lease missing " ++ name);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        QUERY_WORD_COUNT != 193)
    {
        @compileError("campaign pre-final fold lease contract drifted");
    }
}
