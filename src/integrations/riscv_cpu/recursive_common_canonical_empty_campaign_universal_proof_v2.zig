//! Genuine q193 campaign canonical-empty wrapper proof and cold admission.
//!
//! The durable source is the already-canonical empty-leaf transport. The
//! field-native NodePublicV2 and all 173 Poseidon calls are reconstructed from
//! that source by both prover and cold verifier. Fixed proof geometry is
//! minted only from the verifier-owned expanded PCS capture; no producer
//! header, host width, or freshness bit is serialized as authority.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const input_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_campaign_universal_manifest_v2.zig");
const cohort_mod =
    @import("recursive_common_canonical_empty_campaign_universal_cohort_v2.zig");
const composition_capture =
    @import("recursive_common_canonical_empty_campaign_composition_capture_v2.zig");
const process_validation =
    @import("recursive_process_local_validation_token_v1.zig");
const cold_token =
    @import("recursive_common_canonical_empty_campaign_cold_token_v2.zig");
const evidence_support =
    @import("recursive_common_canonical_empty_campaign_evidence_support_v2.zig");
const geometry_mod =
    @import("recursive_common_canonical_empty_campaign_geometry_v2.zig");
const field_public =
    @import("recursive_common_canonical_empty_campaign_field_public_v2.zig");
const common_authority =
    @import("recursive_common_wrapper_authority_v2.zig");
const artifact_mod = @import("recursive_node_artifact_v2.zig");
const artifact_ref_mod = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const final_remint_mod =
    @import("recursive_pipeline_campaign_final_remint_v2.zig");
const padding_target_mod =
    @import("recursive_pipeline_campaign_padding_target_v2.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const PRODUCTION_ACTIVATION = false;
pub const PROOF_REQUIRES_PADDING_TARGET = true;
pub const PROOF_REQUIRES_FINAL_REMINT = false;
pub const FOLD_CHILD_REQUIRES_FINAL_REMINT = true;
pub const PROOF_ARTIFACT_KIND = common_authority.PROOF_ARTIFACT_KIND;
pub const PROOF_ARTIFACT_SCHEMA_VERSION: u16 = 1;
pub const SOURCE_ARTIFACT_KIND = input_mod.SOURCE_ARTIFACT_KIND;
pub const SOURCE_ARTIFACT_SCHEMA_VERSION = input_mod.SCHEMA_VERSION;

pub const Kernel = secure_engine.EngineKernelForManifest(
    cohort_mod.CohortV2,
    manifest_mod,
    .canonical_empty_campaign_v2,
);
pub const FreshCompositionGraphV2 = composition_capture.FreshGraphViewV2;
pub const QUERY_WORD_COUNT = composition_capture.QUERY_WORD_COUNT;
pub const QueryWordV2 = stwo_core.fields.m31.M31;
pub const TranscriptDigestV2 = composition_capture.TranscriptDigestV2;

pub const FIXED_WIRE_IS_COLD_CAPTURE_DERIVED = true;
pub const geometryFromFresh = geometry_mod.geometryFromFresh;

pub const Error = input_mod.Error || registry_mod.Error || error{
    CanonicalEmptyUniversalEvidenceMismatch,
    CanonicalEmptyUniversalProofMismatch,
    CanonicalEmptyUniversalProofShapeMismatch,
};

/// Projects an already cold-minted proof-shape authority into the comptime
/// fixed-wire selector. This projection is never proof admission by itself.
pub fn fixedWireDimensionsFromColdShape(
    shape: *const registry_mod.FixedProofShapeV3,
) !frontend.recursion.fixed_wire.Dimensions {
    try shape.validate();
    return .{
        .commitment_count = shape.tree_count,
        .claimed_sum_count = shape.claimed_sum_count,
        .sampled_value_count = shape.sampled_value_count,
        .queried_value_count = shape.queried_value_count,
        .trace_path_count = shape.trace_path_count,
        .fri_layer_count = shape.fri_layer_count,
        .query_count = shape.query_count,
        .maximum_fold_width = shape.maximum_fold_width,
        .last_layer_coefficient_count = shape.last_layer_coefficient_count,
        .maximum_merkle_depth = shape.maximum_merkle_depth,
    };
}

pub const ProveResultV2 = struct {
    proof: OwnedColdProofV2,
    receipt: secure_engine.ReceiptV1,

    pub fn deinit(self: *ProveResultV2) void {
        self.proof.deinit();
        self.* = undefined;
    }
};

/// Current-process verifier capability. `fresh.capture` and `claims` are
/// never encoded. Claims are reconstructed from the same cold transcript and
/// checked against the verifier-minted statement seal.
pub const OwnedColdProofV2 = struct {
    pub const ROLE = registry_mod.CircuitRoleV1.canonical_empty_field_v2;

    allocator: std.mem.Allocator,
    source_bytes: [input_mod.SOURCE_ENCODED_BYTE_COUNT]u8,
    source_input: input_mod.ColdInputV2,
    padding_target: padding_target_mod.CampaignPaddingTargetV2,
    session: secure_artifact.SessionV1,
    artifact_value: secure_artifact.OwnedArtifactV1,
    fresh: secure_engine.FreshVerificationV1,
    composition_capture: composition_capture.CaptureV2,
    query_authority: composition_capture.VerifierQueryAuthorityV2,
    claims: manifest_mod.ClaimVector,
    geometry_value: registry_mod.AuthenticatedGeometryV1,
    node_public: artifact_mod.NodePublicV2,
    validation: *process_validation.ValidatedOwnerV1,

    pub fn deinit(self: *OwnedColdProofV2) void {
        self.allocator.destroy(self.validation);
        self.composition_capture.deinit();
        self.fresh.deinit();
        self.artifact_value.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const OwnedColdProofV2) !void {
        var full_timer = startTimer();
        defer self.validation.counters.recordTimed(
            .full_audit,
            readTimer(&full_timer),
        );
        const inputs = try authorityInputsFromSource(
            &self.padding_target,
            &self.source_bytes,
        );
        var cohort = try cohort_mod.CohortV2.init(self.allocator, inputs);
        defer cohort.deinit();
        const expected_session = try cohort.session();
        try self.artifact_value.validateCustody();
        try self.artifact_value.statement.validateAgainstSession(
            &self.session,
        );
        var replay_timer = startTimer();
        const replay = try Kernel.reconstructVerifiedReplay(
            self.allocator,
            inputs,
            &self.session,
            &self.fresh,
        );
        self.validation.counters.recordTimed(
            .transcript_replay,
            readTimer(&replay_timer),
        );
        try self.query_authority.validateAgainst(&replay, &self.fresh);
        try self.composition_capture.validateAgainst(
            &cohort,
            &self.session,
            &self.fresh.statement,
            &self.fresh.capture,
            &replay,
            false,
        );
        const rebuilt_geometry = try geometryFromFresh(
            &self.padding_target,
            &self.fresh,
        );
        const schedule = try field_public.PoseidonScheduleV2.build(
            &inputs.cold,
        );
        if (!std.meta.eql(self.session, expected_session) or
            !std.meta.eql(self.source_input, inputs.cold) or
            !std.meta.eql(inputs.padding_target, self.padding_target) or
            !std.meta.eql(
                self.fresh.statement,
                self.artifact_value.statement,
            ) or !std.meta.eql(self.claims, replay.claims) or
            !std.meta.eql(self.geometry_value, rebuilt_geometry) or
            !std.meta.eql(self.node_public, schedule.node_public))
        {
            return error.CanonicalEmptyUniversalProofMismatch;
        }
        try self.validateToken();
    }

    /// Cheap in-process revalidation. The token was minted only after this
    /// owner completed q193 cold verification, transcript replay, and graph
    /// construction. It closes immutable identities and exact allocations;
    /// a new process must call `coldOpen` and cannot deserialize this token.
    pub fn validateToken(self: *const OwnedColdProofV2) !void {
        var timer = startTimer();
        defer self.validation.counters.recordTimed(
            .token_check,
            readTimer(&timer),
        );
        try self.composition_capture.validateProcessLocalClosure(
            &self.validation.token,
        );
        try self.validation.token.validateAgainst(try cold_token.snapshot(self));
        var cohort = try cohort_mod.CohortV2.init(
            self.allocator,
            .{
                .cold = self.source_input,
                .padding_target = self.padding_target,
            },
        );
        defer cohort.deinit();
        const manifest = cohort.manifest();
        try self.session.validate();
        try self.artifact_value.statement.validateAgainstSession(&self.session);
        try self.claims.validate(manifest);
        try self.geometry_value.validate();
        try campaign_public.validate(
            &self.source_input.shape,
            &self.node_public,
        );
        const expected_geometry = try geometryFromFresh(
            &self.padding_target,
            &self.fresh,
        );
        if (!std.meta.eql(
            self.fresh.statement,
            self.artifact_value.statement,
        ) or !std.meta.eql(
            self.geometry_value.preprocessed_root,
            self.fresh.capture.commitments[0],
        ) or !std.meta.eql(
            self.geometry_value,
            expected_geometry,
        )) return error.CanonicalEmptyUniversalProofMismatch;
    }

    pub fn performanceSnapshot(
        self: *const OwnedColdProofV2,
    ) process_validation.CounterSnapshotV1 {
        return self.validation.counters.snapshot();
    }

    pub fn validateColdGeometry(self: *const OwnedColdProofV2) !void {
        try self.validateToken();
        if (self.geometry_value.role != ROLE)
            return error.CanonicalEmptyUniversalProofShapeMismatch;
    }

    /// Uniform final-transaction boundary shared by all three target-native
    /// cold owners. The target is compared as a complete authenticated value;
    /// its digest alone never promotes this proof or its process-local token.
    pub fn validateForPaddingTarget(
        self: *const OwnedColdProofV2,
        target: *const padding_target_mod.CampaignPaddingTargetV2,
    ) !void {
        try target.validateSelf();
        try self.validateColdGeometry();
        if (!std.meta.eql(self.padding_target, target.*))
            return error.CanonicalEmptyUniversalProofShapeMismatch;
        try target.validateRemintedGeometry(ROLE, &self.geometry_value);
    }

    pub fn geometryForPaddingTarget(
        self: *const OwnedColdProofV2,
    ) *const registry_mod.AuthenticatedGeometryV1 {
        return &self.geometry_value;
    }

    /// Reborrows the already verifier-rerecorded graph after the process-local
    /// token closes every retained identity and allocation. No transcript or
    /// graph execution is repeated here.
    pub fn foldGraphView(
        self: *const OwnedColdProofV2,
    ) !composition_capture.FreshGraphViewV2 {
        try self.validateToken();
        var timer = startTimer();
        const result = try self.composition_capture.borrowProcessLocalView(
            &self.query_authority,
            &self.validation.token,
        );
        self.validation.counters.recordTimed(
            .graph_view_borrow,
            readTimer(&timer),
        );
        return result;
    }

    pub fn encodeArtifactAlloc(
        self: *const OwnedColdProofV2,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try self.validateToken();
        return self.artifact_value.encodeCanonicalAlloc(allocator);
    }

    pub fn proofArtifactRef(
        self: *const OwnedColdProofV2,
    ) !artifact_mod.ArtifactRefV1 {
        try self.validateToken();
        const bytes = try self.artifact_value.encodeCanonicalAlloc(
            self.allocator,
        );
        defer self.allocator.free(bytes);
        var sha: [32]u8 = undefined;
        Sha256.hash(bytes, &sha, .{});
        const result = artifact_mod.ArtifactRefV1{
            .kind = PROOF_ARTIFACT_KIND,
            .format_version = artifact_ref_mod.ARTIFACT_REF_FORMAT_VERSION,
            .schema_version = PROOF_ARTIFACT_SCHEMA_VERSION,
            .byte_count = @intCast(bytes.len),
            .sha256 = sha,
        };
        try result.validate();
        return result;
    }

    /// Verifier-owned recursive ingress. Every pointer is backed by this
    /// live cold-proof owner; no portion is a durable freshness capability.
    pub fn ingressView(
        self: *const OwnedColdProofV2,
        final_remint: *const final_remint_mod.CampaignFinalRemintAuthorityV2,
    ) !FreshRecursiveIngressV2 {
        try self.validateToken();
        try self.validateAgainstFinal(final_remint);
        const geometry = try final_remint.geometryForRole(
            .canonical_empty_field_v2,
        );
        return .{
            .source_input = &self.source_input,
            .final_remint = final_remint,
            .node_public = &self.node_public,
            .claims = &self.claims,
            .session = &self.session,
            .statement = &self.fresh.statement,
            .geometry = geometry,
            .capture = &self.fresh.capture,
            .query_words = &self.query_authority.query_words,
            .query_log_size = self.query_authority.query_log_size,
            .final_transcript_digest = &self.query_authority.final_transcript_digest,
            .final_transcript_draw_count = self.query_authority.final_transcript_draw_count,
            .query_words_identity_sha256 = &self.query_authority.query_words_identity_sha256,
        };
    }

    /// Final promotion is a separate process-local admission. The proof is
    /// already q193-verified at the common target; this check requires its
    /// independently cold-derived role geometry to be the exact role-1 entry
    /// of the subsequently minted FinalRemint.
    pub fn validateAgainstFinal(
        self: *const OwnedColdProofV2,
        final_remint: *const final_remint_mod.CampaignFinalRemintAuthorityV2,
    ) !void {
        try self.padding_target.validateAgainstFinal(final_remint);
        const expected = try final_remint.geometryForRole(
            .canonical_empty_field_v2,
        );
        if (!std.meta.eql(self.geometry_value, expected.*))
            return error.CanonicalEmptyUniversalProofShapeMismatch;
    }
};

/// Complete fixed-wire input retained for a future common-fold verifier.
/// The interaction nonce and transcript checkpoint live in `statement`; the
/// exact q193/PCS/program/profile/root authorities live in session/geometry.
pub const FreshRecursiveIngressV2 = struct {
    source_input: *const input_mod.ColdInputV2,
    final_remint: *const final_remint_mod.CampaignFinalRemintAuthorityV2,
    node_public: *const artifact_mod.NodePublicV2,
    claims: *const manifest_mod.ClaimVector,
    session: *const secure_artifact.SessionV1,
    statement: *const secure_artifact.StatementV1,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
    capture: *const common_authority.ProofCapture,
    query_words: *const [composition_capture.QUERY_WORD_COUNT]stwo_core.fields.m31.M31,
    query_log_size: u32,
    final_transcript_digest: *const composition_capture.TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,

    pub fn validate(self: FreshRecursiveIngressV2) !void {
        try self.final_remint.validateAgainstCampaign(
            self.source_input.shape.campaign_namespace_sha256,
        );
        const expected_geometry = try self.final_remint.geometryForRole(
            .canonical_empty_field_v2,
        );
        var logs: manifest_mod.LogSizes = undefined;
        for (&logs, expected_geometry.padded_component_log_sizes[0..manifest_mod.COMPONENT_COUNT]) |
            *destination,
            source,
        | destination.* = source;
        const manifest = try manifest_mod.buildForLogSizes(logs);
        try campaign_public.validate(
            &self.source_input.shape,
            self.node_public,
        );
        try self.claims.validate(&manifest);
        try self.session.validate();
        try self.statement.validateAgainstSession(self.session);
        try self.geometry.validate();
        if (self.capture.commitments.len !=
            common_authority.COMMITMENT_TREE_COUNT or
            self.capture.queries.raw.len != self.query_words.len or
            self.query_log_size == 0 or self.query_log_size >= 31 or
            try queryLogSizeFromCapture(self.capture) != self.query_log_size or
            self.geometry.role != .canonical_empty_field_v2 or
            self.geometry != expected_geometry or
            !std.meta.eql(self.node_public.*, self.source_input.node_public) or
            !std.mem.eql(
                u8,
                &self.claims.seal,
                &self.statement.claims_sha256,
            ) or !std.meta.eql(
            self.geometry.preprocessed_root,
            self.capture.commitments[0],
        ) or !std.meta.eql(
            self.statement.transcript_id,
            @import("stwo_riscv_frontend").recursion.protocol.transcriptId(
                self.final_transcript_digest.*,
                self.final_transcript_draw_count,
            ),
        ) or std.mem.allEqual(
            u8,
            self.query_words_identity_sha256,
            0,
        )) return error.CanonicalEmptyUniversalEvidenceMismatch;
        const mask = (@as(u32, 1) << @intCast(self.query_log_size)) - 1;
        for (self.query_words.*, self.capture.queries.raw) |full, projected| {
            const projected_u32 = std.math.cast(u32, projected) orelse
                return error.CanonicalEmptyUniversalEvidenceMismatch;
            if ((full.toU32() & mask) != projected_u32)
                return error.CanonicalEmptyUniversalEvidenceMismatch;
        }
        const shape = try registry_mod.sealProofShapeFromCapture(
            self.capture,
            self.geometry.component_count,
            self.geometry.proof_shape.column_log_degree,
            self.geometry.proof_shape.table_layout_identity_sha256,
        );
        if (!std.meta.eql(shape, self.geometry.proof_shape))
            return error.CanonicalEmptyUniversalProofShapeMismatch;
    }
};

pub fn queryLogSizeFromCapture(
    capture: *const common_authority.ProofCapture,
) !u32 {
    if (capture.column_log_sizes.len !=
        common_authority.COMMITMENT_TREE_COUNT or
        capture.trace_paths.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.CanonicalEmptyUniversalEvidenceMismatch;
    }
    const composition_index = common_authority.COMMITMENT_TREE_COUNT - 1;
    const logs = capture.column_log_sizes[composition_index];
    if (logs.len == 0)
        return error.CanonicalEmptyUniversalEvidenceMismatch;
    var query_log_size: u32 = 0;
    for (logs) |log_size| {
        if (log_size == 0 or log_size >= 31)
            return error.CanonicalEmptyUniversalEvidenceMismatch;
        query_log_size = @max(query_log_size, log_size);
    }
    if (capture.trace_paths[composition_index].path_depth != query_log_size)
        return error.CanonicalEmptyUniversalEvidenceMismatch;
    return query_log_size;
}

pub fn proveAndColdVerify(
    allocator: std.mem.Allocator,
    final_remint: *const final_remint_mod.CampaignFinalRemintAuthorityV2,
    source_bytes: []const u8,
    execution: secure_engine.ExecutionOptions,
) !ProveResultV2 {
    const padding_target = try padding_target_mod.CampaignPaddingTargetV2
        .fromFinal(final_remint);
    return proveAtTarget(
        allocator,
        &padding_target,
        source_bytes,
        execution,
    );
}

/// Pre-final proving validates the target against the three ordered live
/// active geometry owners before the engine sees it. The returned cold owner
/// is itself the role-1 final geometry source; it grants no FoldChild until a
/// later FinalRemint includes that exact geometry.
pub fn proveAndColdVerifyPreFinal(
    allocator: std.mem.Allocator,
    padding_target: *const padding_target_mod.CampaignPaddingTargetV2,
    active_sources: anytype,
    source_bytes: []const u8,
    execution: secure_engine.ExecutionOptions,
) !ProveResultV2 {
    try padding_target.validateAgainstActive(active_sources);
    return proveAtTarget(
        allocator,
        padding_target,
        source_bytes,
        execution,
    );
}

fn proveAtTarget(
    allocator: std.mem.Allocator,
    padding_target: *const padding_target_mod.CampaignPaddingTargetV2,
    source_bytes: []const u8,
    execution: secure_engine.ExecutionOptions,
) !ProveResultV2 {
    const inputs = authorityInputsFromSource(padding_target, source_bytes) catch |err|
        return stageFailure("wrapper.source-open", err);
    const session = sessionForInputs(allocator, inputs) catch |err|
        return stageFailure("wrapper.session-build", err);
    var result = Kernel.proveAndColdVerify(
        allocator,
        inputs,
        session,
        execution,
    ) catch |err| return stageFailure("wrapper.engine-transaction", err);
    errdefer result.deinit();
    var proof = ownResult(
        allocator,
        padding_target,
        source_bytes,
        session,
        result.artifact,
        result.fresh,
        result.receipt.cold_verify_ns,
    ) catch |err| return stageFailure("wrapper.capture-own", err);
    result.artifact = undefined;
    result.fresh = undefined;
    errdefer proof.deinit();
    return .{ .proof = proof, .receipt = result.receipt };
}

/// Canonically decodes retained bytes and runs a new independent q193
/// verifier before any geometry, claims, or wrapper artifact can be minted.
pub fn coldOpen(
    allocator: std.mem.Allocator,
    final_remint: *const final_remint_mod.CampaignFinalRemintAuthorityV2,
    source_bytes: []const u8,
    retained_artifact_bytes: []const u8,
) !OwnedColdProofV2 {
    const padding_target = try padding_target_mod.CampaignPaddingTargetV2
        .fromFinal(final_remint);
    return coldOpenAtTarget(
        allocator,
        &padding_target,
        source_bytes,
        retained_artifact_bytes,
    );
}

pub fn coldOpenPreFinal(
    allocator: std.mem.Allocator,
    padding_target: *const padding_target_mod.CampaignPaddingTargetV2,
    active_sources: anytype,
    source_bytes: []const u8,
    retained_artifact_bytes: []const u8,
) !OwnedColdProofV2 {
    try padding_target.validateAgainstActive(active_sources);
    return coldOpenAtTarget(
        allocator,
        padding_target,
        source_bytes,
        retained_artifact_bytes,
    );
}

fn coldOpenAtTarget(
    allocator: std.mem.Allocator,
    padding_target: *const padding_target_mod.CampaignPaddingTargetV2,
    source_bytes: []const u8,
    retained_artifact_bytes: []const u8,
) !OwnedColdProofV2 {
    const inputs = authorityInputsFromSource(padding_target, source_bytes) catch |err|
        return stageFailure("wrapper.cold-source", err);
    const session = sessionForInputs(allocator, inputs) catch |err|
        return stageFailure("wrapper.cold-session", err);
    var artifact_value = secure_artifact.OwnedArtifactV1.decodeCanonical(
        allocator,
        retained_artifact_bytes,
    ) catch |err| return stageFailure("wrapper.cold-decode", err);
    errdefer artifact_value.deinit();
    var cold_timer = startTimer();
    var fresh = Kernel.verifyCold(
        allocator,
        inputs,
        &session,
        &artifact_value,
    ) catch |err| return stageFailure("wrapper.cold-verify", err);
    const cold_verify_ns = readTimer(&cold_timer);
    errdefer fresh.deinit();
    return ownResult(
        allocator,
        padding_target,
        source_bytes,
        session,
        artifact_value,
        fresh,
        cold_verify_ns,
    ) catch |err| return stageFailure("wrapper.cold-capture-own", err);
}

fn ownResult(
    allocator: std.mem.Allocator,
    padding_target: *const padding_target_mod.CampaignPaddingTargetV2,
    source_bytes: []const u8,
    session: secure_artifact.SessionV1,
    artifact_value: secure_artifact.OwnedArtifactV1,
    fresh: secure_engine.FreshVerificationV1,
    cold_verify_ns: u64,
) !OwnedColdProofV2 {
    if (source_bytes.len != input_mod.SOURCE_ENCODED_BYTE_COUNT)
        return error.CanonicalEmptyUniversalProofMismatch;
    var source_copy: [input_mod.SOURCE_ENCODED_BYTE_COUNT]u8 = undefined;
    @memcpy(&source_copy, source_bytes);
    const inputs = authorityInputsFromSource(padding_target, &source_copy) catch |err|
        return stageFailure("wrapper.own-source", err);
    var cohort = cohort_mod.CohortV2.init(allocator, inputs) catch |err|
        return stageFailure("wrapper.own-cohort", err);
    defer cohort.deinit();
    var replay_timer = startTimer();
    const replay = Kernel.reconstructVerifiedReplay(
        allocator,
        inputs,
        &session,
        &fresh,
    ) catch |err| return stageFailure("wrapper.verified-replay", err);
    const replay_ns = readTimer(&replay_timer);
    const query_authority = composition_capture.VerifierQueryAuthorityV2.init(
        &replay,
    ) catch |err| return stageFailure("wrapper.query-authority", err);
    var graph_timer = startTimer();
    var graph_capture = composition_capture.CaptureV2.init(
        allocator,
        &cohort,
        &session,
        &fresh.statement,
        &fresh.capture,
        &replay,
    ) catch |err| return stageFailure("wrapper.composition-capture", err);
    const graph_record_ns = readTimer(&graph_timer);
    errdefer graph_capture.deinit();
    const geometry = geometryFromFresh(padding_target, &fresh) catch |err|
        return stageFailure("wrapper.geometry", err);
    const schedule = field_public.PoseidonScheduleV2.build(
        &inputs.cold,
    ) catch |err| return stageFailure("wrapper.node-public", err);
    const validation = allocator.create(
        process_validation.ValidatedOwnerV1,
    ) catch |err| return stageFailure("wrapper.validation-owner", err);
    errdefer allocator.destroy(validation);
    validation.* = undefined;
    var result = OwnedColdProofV2{
        .allocator = allocator,
        .source_bytes = source_copy,
        .source_input = inputs.cold,
        .padding_target = padding_target.*,
        .session = session,
        .artifact_value = artifact_value,
        .fresh = fresh,
        .composition_capture = graph_capture,
        .query_authority = query_authority,
        .claims = replay.claims,
        .geometry_value = geometry,
        .node_public = schedule.node_public,
        .validation = validation,
    };
    cold_token.validateConstructed(&result, &cohort, &replay) catch |err|
        return stageFailure("wrapper.owned-validate", err);
    validation.* = process_validation.ValidatedOwnerV1.init(
        try cold_token.snapshot(&result),
    ) catch |err| return stageFailure("wrapper.validation-token", err);
    validation.counters.recordTimed(
        .q193_cold_verification,
        cold_verify_ns,
    );
    validation.counters.recordTimed(.transcript_replay, replay_ns);
    validation.counters.recordTimed(.graph_record, graph_record_ns);
    result.validateToken() catch |err|
        return stageFailure("wrapper.validation-token-check", err);
    return result;
}

/// Exact schema-2 Evidence surface consumed by the common wrapper authority.
pub const EvidenceV2 = struct {
    allocator: std.mem.Allocator,
    cold: *OwnedColdProofV2,
    final_remint: *const final_remint_mod.CampaignFinalRemintAuthorityV2,
    node_artifact: artifact_mod.RecursiveNodeArtifactV2,
    cached_graph: composition_capture.FreshGraphViewV2,

    pub fn initOwned(
        final_remint: *const final_remint_mod.CampaignFinalRemintAuthorityV2,
        cold: OwnedColdProofV2,
    ) !EvidenceV2 {
        var owned = cold;
        var owned_live = true;
        errdefer if (owned_live) owned.deinit();
        try owned.validateToken();
        try owned.validateAgainstFinal(final_remint);
        const allocator = owned.allocator;
        const cold_owner = try allocator.create(OwnedColdProofV2);
        cold_owner.* = owned;
        owned = undefined;
        owned_live = false;
        errdefer {
            cold_owner.deinit();
            allocator.destroy(cold_owner);
        }
        const node_artifact = try evidence_support.buildNodeArtifact(
            cold_owner,
            final_remint,
        );
        const cached_graph = try cold_owner.foldGraphView();
        var result = EvidenceV2{
            .allocator = allocator,
            .cold = cold_owner,
            .final_remint = final_remint,
            .node_artifact = node_artifact,
            .cached_graph = cached_graph,
        };
        try result.validateFresh();
        return result;
    }

    pub fn deinit(self: *EvidenceV2) void {
        self.cold.deinit();
        self.allocator.destroy(self.cold);
        self.* = undefined;
    }

    pub fn validateFresh(self: *const EvidenceV2) !void {
        try evidence_support.validateFresh(
            self.cold,
            self.final_remint,
            &self.node_artifact,
            self.cached_graph,
        );
    }

    pub fn artifact(
        self: *const EvidenceV2,
    ) *const artifact_mod.RecursiveNodeArtifactV2 {
        return &self.node_artifact;
    }

    pub fn geometry(
        self: *const EvidenceV2,
    ) !*const registry_mod.AuthenticatedGeometryV1 {
        try self.cold.validateAgainstFinal(self.final_remint);
        return self.final_remint.geometryForRole(
            .canonical_empty_field_v2,
        );
    }

    pub fn proofCapture(
        self: *const EvidenceV2,
    ) *const common_authority.ProofCapture {
        return &self.cold.fresh.capture;
    }

    pub fn ingressView(self: *const EvidenceV2) !FreshRecursiveIngressV2 {
        return evidence_support.rebaseIngressToArtifact(
            &self.node_artifact,
            try self.cold.ingressView(self.final_remint),
        );
    }

    pub fn foldGraphView(
        self: *const EvidenceV2,
    ) !composition_capture.FreshGraphViewV2 {
        try evidence_support.validateCachedGraph(
            self.cold,
            self.cached_graph,
        );
        return self.cached_graph;
    }

    pub fn queryAuthority(
        self: *const EvidenceV2,
    ) !*const composition_capture.VerifierQueryAuthorityV2 {
        try self.cold.validateToken();
        return &self.cold.query_authority;
    }
};

fn authorityInputsFromSource(
    padding_target: *const padding_target_mod.CampaignPaddingTargetV2,
    source_bytes: []const u8,
) !cohort_mod.AuthorityInputs {
    try padding_target.validateSelf();
    const cold = try input_mod.ColdInputV2.open(
        &padding_target.shape,
        source_bytes,
    );
    return .{ .cold = cold, .padding_target = padding_target.* };
}

fn sessionForInputs(
    allocator: std.mem.Allocator,
    inputs: cohort_mod.AuthorityInputs,
) !secure_artifact.SessionV1 {
    var cohort = try cohort_mod.CohortV2.init(allocator, inputs);
    defer cohort.deinit();
    return cohort.session();
}

fn startTimer() ?std.time.Timer {
    return std.time.Timer.start() catch null;
}

fn readTimer(timer: *?std.time.Timer) u64 {
    if (timer.*) |*active| return active.read();
    return 0;
}

/// Failure-only gate breadcrumb. Product builds return the original error
/// without retaining a logging branch or changing any durable bytes.
fn stageFailure(comptime stage: []const u8, err: anyerror) anyerror {
    if (builtin.is_test) std.debug.print(
        "CANONICAL_EMPTY_Q193_STAGE={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    return err;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 2 or
        PRODUCTION_ACTIVATION or !PROOF_REQUIRES_PADDING_TARGET or
        PROOF_REQUIRES_FINAL_REMINT or !FOLD_CHILD_REQUIRES_FINAL_REMINT or
        PROOF_ARTIFACT_KIND != 8 or SOURCE_ARTIFACT_KIND != 14 or
        manifest_mod.COMPONENT_COUNT != 36 or
        field_public.POSEIDON_CALL_COUNT != 173)
    {
        @compileError("campaign canonical-empty universal proof V2 drifted");
    }
}
