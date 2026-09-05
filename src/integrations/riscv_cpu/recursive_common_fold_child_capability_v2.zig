//! Tagged role-neutral child capability for the schema-4 common fold.
//!
//! Every payload is a typed pointer to a role-specific cold-verifier view.
//! Accessors rerun that role's validator before constructing the common
//! projection. There is no `anyopaque`, nominal cast, digest promotion, or
//! serializable freshness token.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const artifact_mod = @import("recursive_node_artifact_v2.zig");
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

pub const Role = registry_mod.CircuitRoleV1;
pub const TranscriptDigestV2 = recursion.poseidon2_channel.Digest;

/// Neutral borrowed graph projection. Role-specific graph view types are
/// copied field-wise into this value only after their own cold validators run.
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

/// Placeholder used only to keep the role-0 branch explicit in the type while
/// its genuine cold wrapper is unavailable. No value of this type can pass
/// admission, and generic projection code never treats it as a child.
pub const UnavailableRealLeafChildV2 = struct {
    pub fn validateBorrowed(_: UnavailableRealLeafChildV2) !void {
        return error.CommonFoldRealLeafCapabilityUnavailable;
    }
};

pub const ProjectionV2 = struct {
    role: Role,
    wrapper: common_authority.FreshWrapperViewV2,
    node_public: *const artifact_mod.NodePublicV2,
    claimed_sums: []const QM31,
    claims_seal: *const [32]u8,
    session: *const secure_artifact.SessionV1,
    statement: *const secure_artifact.StatementV1,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
    capture: *const common_authority.ProofCapture,
    query_words: *const [QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_transcript_digest: *const TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,
    graph: ProjectionGraphV2,

    pub fn validateAgainst(
        self: ProjectionV2,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
    ) !void {
        try registry.validate();
        try self.wrapper.validateAgainst(registry);
        try self.node_public.validate();
        try self.session.validate();
        try self.statement.validateAgainstSession(self.session);
        try self.geometry.validate();
        try self.graph.lane.graph.validate();
        if (self.role != try self.wrapper.role() or
            self.wrapper.nodePublic() != self.node_public or
            self.wrapper.geometry != self.geometry or
            self.wrapper.capture != self.capture or
            self.geometry.role != self.role or
            self.claimed_sums.len != self.geometry.component_count or
            self.claimed_sums.len != 36 or
            self.capture.commitments.len !=
                common_authority.COMMITMENT_TREE_COUNT or
            self.capture.queries.raw.len != QUERY_WORD_COUNT or
            self.query_log_size == 0 or self.query_log_size >= 31 or
            try queryLogSizeFromCapture(self.capture) != self.query_log_size or
            self.query_words != self.graph.query_words or
            self.query_log_size != self.graph.query_log_size or
            self.final_transcript_digest !=
                self.graph.final_transcript_digest or
            self.final_transcript_draw_count !=
                self.graph.final_transcript_draw_count or
            self.query_words_identity_sha256 !=
                self.graph.query_words_identity_sha256 or
            self.graph.evaluation.values.len != self.graph.lane.graph.nodes.len or
            !std.meta.eql(
                self.geometry.preprocessed_root,
                self.capture.commitments[0],
            ) or !std.mem.eql(
            u8,
            self.claims_seal,
            &self.statement.claims_sha256,
        ) or !std.meta.eql(
            self.statement.transcript_id,
            recursion.protocol.transcriptId(
                self.final_transcript_digest.*,
                self.final_transcript_draw_count,
            ),
        ) or !std.mem.eql(
            u8,
            &self.graph.evaluation.circuit_identity,
            &self.graph.lane.graph.identity_digest,
        ) or std.mem.allEqual(
            u8,
            self.query_words_identity_sha256,
            0,
        ) or std.mem.allEqual(
            u8,
            self.graph.capture_identity_sha256,
            0,
        ) or std.mem.allEqual(
            u8,
            self.graph.layout_identity_sha256,
            0,
        )) return error.InvalidRoleNeutralFoldChild;

        const mask = (@as(u32, 1) << @intCast(self.query_log_size)) - 1;
        for (self.query_words.*, self.capture.queries.raw) |full, projected| {
            const projected_u32 = std.math.cast(u32, projected) orelse
                return error.InvalidRoleNeutralFoldChild;
            if ((full.toU32() & mask) != projected_u32)
                return error.InvalidRoleNeutralFoldChild;
        }
    }
};

/// Reconstructs the native query mask from the verifier capture itself. The
/// composition-tree column logs and authenticated trace-path depth must agree;
/// no stale circuit/profile field or inferred maximum is accepted.
pub fn queryLogSizeFromCapture(
    capture: *const common_authority.ProofCapture,
) !u32 {
    if (capture.column_log_sizes.len !=
        common_authority.COMMITMENT_TREE_COUNT or
        capture.trace_paths.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.InvalidRoleNeutralFoldChild;
    }
    const composition_index = common_authority.COMMITMENT_TREE_COUNT - 1;
    const logs = capture.column_log_sizes[composition_index];
    if (logs.len == 0) return error.InvalidRoleNeutralFoldChild;
    var query_log_size: u32 = 0;
    for (logs) |log_size| {
        if (log_size == 0 or log_size >= 31)
            return error.InvalidRoleNeutralFoldChild;
        query_log_size = @max(query_log_size, log_size);
    }
    if (capture.trace_paths[composition_index].path_depth != query_log_size)
        return error.InvalidRoleNeutralFoldChild;
    return query_log_size;
}

pub fn TaggedFoldChildV2(
    comptime RealChild: type,
    comptime EmptyChild: type,
    comptime CommonChild: type,
) type {
    assertChildContract(EmptyChild);
    assertChildContract(CommonChild);
    if (RealChild != UnavailableRealLeafChildV2)
        assertChildContract(RealChild);

    return struct {
        const Self = @This();

        pub const PayloadV2 = union(Role) {
            ethereum_incremental_leaf_wrapper_v4: *const RealChild,
            canonical_empty_field_v2: *const EmptyChild,
            common_fold_field_v2: *const CommonChild,
        };

        payload: PayloadV2,

        pub fn fromReal(
            child: *const RealChild,
            registry: *const registry_mod.RecursiveCircuitRegistryV1,
        ) !Self {
            if (comptime RealChild == UnavailableRealLeafChildV2) {
                return error.CommonFoldRealLeafCapabilityUnavailable;
            } else {
                const result = Self{ .payload = .{
                    .ethereum_incremental_leaf_wrapper_v4 = child,
                } };
                try result.validateAgainst(registry);
                return result;
            }
        }

        pub fn fromCanonical(
            child: *const EmptyChild,
            registry: *const registry_mod.RecursiveCircuitRegistryV1,
        ) !Self {
            const result = Self{ .payload = .{
                .canonical_empty_field_v2 = child,
            } };
            try result.validateAgainst(registry);
            return result;
        }

        pub fn fromCommon(
            child: *const CommonChild,
            registry: *const registry_mod.RecursiveCircuitRegistryV1,
        ) !Self {
            const result = Self{ .payload = .{
                .common_fold_field_v2 = child,
            } };
            try result.validateAgainst(registry);
            return result;
        }

        pub fn role(self: Self) Role {
            return std.meta.activeTag(self.payload);
        }

        pub fn validateAgainst(
            self: Self,
            registry: *const registry_mod.RecursiveCircuitRegistryV1,
        ) !void {
            const common_projection = try self.projectValidated();
            if (common_projection.role != self.role())
                return error.InvalidRoleNeutralFoldChild;
            try common_projection.validateAgainst(registry);
        }

        pub fn projection(
            self: Self,
            registry: *const registry_mod.RecursiveCircuitRegistryV1,
        ) !ProjectionV2 {
            try self.validateAgainst(registry);
            return self.projectValidated();
        }

        fn projectValidated(self: Self) !ProjectionV2 {
            return switch (self.payload) {
                .ethereum_incremental_leaf_wrapper_v4 => |child| blk: {
                    if (comptime RealChild == UnavailableRealLeafChildV2) {
                        return error.CommonFoldRealLeafCapabilityUnavailable;
                    } else {
                        try child.validateBorrowed();
                        break :blk try projectChild(
                            child,
                            .ethereum_incremental_leaf_wrapper_v4,
                        );
                    }
                },
                .canonical_empty_field_v2 => |child| blk: {
                    try child.validateBorrowed();
                    break :blk try projectChild(
                        child,
                        .canonical_empty_field_v2,
                    );
                },
                .common_fold_field_v2 => |child| blk: {
                    try child.validateBorrowed();
                    break :blk try projectChild(
                        child,
                        .common_fold_field_v2,
                    );
                },
            };
        }
    };
}

fn projectChild(child: anytype, expected_role: Role) !ProjectionV2 {
    if (try child.wrapper.role() != expected_role or
        child.query_words != child.ingress.query_words or
        child.query_words != child.graph.query_words or
        child.query_log_size != child.ingress.query_log_size or
        child.query_log_size != child.graph.query_log_size or
        child.final_transcript_digest !=
            child.ingress.final_transcript_digest or
        child.final_transcript_digest !=
            child.graph.final_transcript_digest or
        child.final_transcript_draw_count !=
            child.ingress.final_transcript_draw_count or
        child.final_transcript_draw_count !=
            child.graph.final_transcript_draw_count or
        child.query_words_identity_sha256 !=
            child.ingress.query_words_identity_sha256 or
        child.query_words_identity_sha256 !=
            child.graph.query_words_identity_sha256)
    {
        return error.InvalidRoleNeutralFoldChild;
    }
    return .{
        .role = expected_role,
        .wrapper = child.wrapper,
        .node_public = child.ingress.node_public,
        .claimed_sums = &child.ingress.claims.values,
        .claims_seal = &child.ingress.claims.seal,
        .session = child.ingress.session,
        .statement = child.ingress.statement,
        .geometry = child.ingress.geometry,
        .capture = child.ingress.capture,
        .query_words = child.query_words,
        .query_log_size = child.query_log_size,
        .final_transcript_digest = child.final_transcript_digest,
        .final_transcript_draw_count = child.final_transcript_draw_count,
        .query_words_identity_sha256 = child.query_words_identity_sha256,
        .graph = .{
            .capture_identity_sha256 = child.graph.capture_identity_sha256,
            .layout_identity_sha256 = child.graph.layout_identity_sha256,
            .query_words = child.graph.query_words,
            .query_log_size = child.graph.query_log_size,
            .final_transcript_digest = child.graph.final_transcript_digest,
            .final_transcript_draw_count = child.graph.final_transcript_draw_count,
            .query_words_identity_sha256 = child.graph.query_words_identity_sha256,
            .lane = child.graph.lane,
            .evaluation = child.graph.evaluation,
        },
    };
}

fn assertChildContract(comptime Child: type) void {
    const fields = .{
        "wrapper",
        "ingress",
        "graph",
        "query_words",
        "query_log_size",
        "final_transcript_digest",
        "final_transcript_draw_count",
        "query_words_identity_sha256",
    };
    inline for (fields) |name| if (!@hasField(Child, name))
        @compileError("fold child is missing required field: " ++ name);
    if (!@hasDecl(Child, "validateBorrowed"))
        @compileError("fold child is missing validateBorrowed");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        QUERY_WORD_COUNT != 193 or SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("role-neutral fold-child contract drifted");
    }
}
