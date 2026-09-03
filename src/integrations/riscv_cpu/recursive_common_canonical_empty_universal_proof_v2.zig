//! Genuine q193 canonical-empty wrapper proof and cold admission.
//!
//! The durable source is the already-canonical empty-leaf transport. The
//! field-native NodePublicV2 and all 113 Poseidon calls are reconstructed from
//! that source by both prover and cold verifier. Fixed proof geometry is
//! minted only from the verifier-owned expanded PCS capture; no producer
//! header, host width, or freshness bit is serialized as authority.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const input_mod =
    @import("recursive_common_canonical_empty_wrapper_input_v1.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_universal_manifest_v2.zig");
const cohort_mod =
    @import("recursive_common_canonical_empty_universal_cohort_v2.zig");
const composition_capture =
    @import("recursive_common_canonical_empty_composition_capture_v2.zig");
const process_validation =
    @import("recursive_process_local_validation_token_v1.zig");
const cold_token =
    @import("recursive_common_canonical_empty_cold_token_v2.zig");
const evidence_support =
    @import("recursive_common_canonical_empty_evidence_support_v2.zig");
const field_public =
    @import("recursive_common_canonical_empty_field_public_v2.zig");
const common_authority =
    @import("recursive_common_wrapper_authority_v2.zig");
const artifact_mod = @import("recursive_node_artifact_v2.zig");
const artifact_ref_mod = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const REGISTRY_PARITY_AVAILABLE = false;
pub const PROOF_ARTIFACT_KIND = common_authority.PROOF_ARTIFACT_KIND;
pub const PROOF_ARTIFACT_SCHEMA_VERSION: u16 = 1;
pub const SOURCE_ARTIFACT_KIND = input_mod.SOURCE_ARTIFACT_KIND;
pub const SOURCE_ARTIFACT_SCHEMA_VERSION = input_mod.SCHEMA_VERSION;

pub const Kernel = secure_engine.EngineKernelForManifest(
    cohort_mod.CohortV2,
    manifest_mod,
    .canonical_empty_field_v2,
);
pub const FreshCompositionGraphV2 = composition_capture.FreshGraphViewV2;
pub const QUERY_WORD_COUNT = composition_capture.QUERY_WORD_COUNT;
pub const QueryWordV2 = stwo_core.fields.m31.M31;
pub const TranscriptDigestV2 = composition_capture.TranscriptDigestV2;

/// Exact fixed-wire dimensions observed from, and continuously checked
/// against, a genuine canonical-empty q193 cold verifier capture. These are
/// comptime type parameters only; the runtime shape remains independently
/// reminted from every successful cold verification before admission.
pub const CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2: frontend.recursion.fixed_wire.Dimensions = .{
    .commitment_count = common_authority.COMMITMENT_TREE_COUNT,
    .claimed_sum_count = manifest_mod.COMPONENT_COUNT,
    .sampled_value_count = 2_330,
    .queried_value_count = 421_126,
    .trace_path_count = 772,
    .fri_layer_count = 4,
    .query_count = QUERY_WORD_COUNT,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 17,
};
pub const CAPTURE_DERIVED_FRI_FOLD_WIDTHS_V2 = [_]u8{ 16, 16, 16, 16 };
pub const CAPTURE_DERIVED_FRI_PATH_DEPTHS_V2 = [_]u8{ 13, 9, 5, 1 };

comptime {
    CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2.validate();
}

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
    allocator: std.mem.Allocator,
    source_bytes: [input_mod.SOURCE_ENCODED_BYTE_COUNT]u8,
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
        const inputs = try authorityInputsFromSource(&self.source_bytes);
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
        const rebuilt_geometry = try geometryFromFresh(&self.fresh);
        const schedule = try field_public.PoseidonScheduleV2.build(
            inputs.statement_words,
            inputs.coordinate,
        );
        if (!std.meta.eql(self.session, expected_session) or
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
        const manifest = try manifest_mod.build();
        try self.session.validate();
        try self.artifact_value.statement.validateAgainstSession(&self.session);
        try self.claims.validate(&manifest);
        try self.geometry_value.validate();
        try self.node_public.validate();
        if (!std.meta.eql(
            self.fresh.statement,
            self.artifact_value.statement,
        ) or !std.meta.eql(
            self.geometry_value.preprocessed_root,
            self.fresh.capture.commitments[0],
        )) return error.CanonicalEmptyUniversalProofMismatch;
    }

    pub fn performanceSnapshot(
        self: *const OwnedColdProofV2,
    ) process_validation.CounterSnapshotV1 {
        return self.validation.counters.snapshot();
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
    ) !FreshRecursiveIngressV2 {
        try self.validateToken();
        return .{
            .node_public = &self.node_public,
            .claims = &self.claims,
            .session = &self.session,
            .statement = &self.fresh.statement,
            .geometry = &self.geometry_value,
            .capture = &self.fresh.capture,
            .query_words = &self.query_authority.query_words,
            .query_log_size = self.query_authority.query_log_size,
            .final_transcript_digest = &self.query_authority.final_transcript_digest,
            .final_transcript_draw_count = self.query_authority.final_transcript_draw_count,
            .query_words_identity_sha256 = &self.query_authority.query_words_identity_sha256,
        };
    }
};

/// Complete fixed-wire input retained for a future common-fold verifier.
/// The interaction nonce and transcript checkpoint live in `statement`; the
/// exact q193/PCS/program/profile/root authorities live in session/geometry.
pub const FreshRecursiveIngressV2 = struct {
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
        const manifest = try manifest_mod.build();
        try self.node_public.validate();
        try self.claims.validate(&manifest);
        try self.session.validate();
        try self.statement.validateAgainstSession(self.session);
        try self.geometry.validate();
        if (self.capture.commitments.len !=
            common_authority.COMMITMENT_TREE_COUNT or
            self.capture.queries.raw.len != self.query_words.len or
            self.query_log_size == 0 or self.query_log_size >= 31 or
            try captureQueryLogSize(self.capture) != self.query_log_size or
            self.geometry.role != .canonical_empty_field_v2 or
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

fn captureQueryLogSize(
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
    source_bytes: []const u8,
    execution: secure_engine.ExecutionOptions,
) !ProveResultV2 {
    const inputs = authorityInputsFromSource(source_bytes) catch |err|
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
    source_bytes: []const u8,
    retained_artifact_bytes: []const u8,
) !OwnedColdProofV2 {
    const inputs = authorityInputsFromSource(source_bytes) catch |err|
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
        source_bytes,
        session,
        artifact_value,
        fresh,
        cold_verify_ns,
    ) catch |err| return stageFailure("wrapper.cold-capture-own", err);
}

fn ownResult(
    allocator: std.mem.Allocator,
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
    const inputs = authorityInputsFromSource(&source_copy) catch |err|
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
    const geometry = geometryFromFresh(&fresh) catch |err|
        return stageFailure("wrapper.geometry", err);
    const schedule = field_public.PoseidonScheduleV2.build(
        inputs.statement_words,
        inputs.coordinate,
    ) catch |err| return stageFailure("wrapper.node-public", err);
    const validation = allocator.create(
        process_validation.ValidatedOwnerV1,
    ) catch |err| return stageFailure("wrapper.validation-owner", err);
    errdefer allocator.destroy(validation);
    validation.* = undefined;
    var result = OwnedColdProofV2{
        .allocator = allocator,
        .source_bytes = source_copy,
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
    node_artifact: artifact_mod.RecursiveNodeArtifactV2,
    cached_graph: composition_capture.FreshGraphViewV2,

    pub fn initOwned(
        cold: OwnedColdProofV2,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
        campaign_namespace_sha256: [32]u8,
    ) !EvidenceV2 {
        var owned = cold;
        var owned_live = true;
        errdefer if (owned_live) owned.deinit();
        try owned.validateToken();
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
            registry,
            campaign_namespace_sha256,
        );
        const cached_graph = try cold_owner.foldGraphView();
        var result = EvidenceV2{
            .allocator = allocator,
            .cold = cold_owner,
            .node_artifact = node_artifact,
            .cached_graph = cached_graph,
        };
        try result.validateFresh(registry);
        return result;
    }

    pub fn deinit(self: *EvidenceV2) void {
        self.cold.deinit();
        self.allocator.destroy(self.cold);
        self.* = undefined;
    }

    pub fn validateFresh(
        self: *const EvidenceV2,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
    ) !void {
        try evidence_support.validateFresh(
            self.cold,
            &self.node_artifact,
            self.cached_graph,
            registry,
        );
    }

    pub fn artifact(
        self: *const EvidenceV2,
    ) *const artifact_mod.RecursiveNodeArtifactV2 {
        return &self.node_artifact;
    }

    pub fn geometry(
        self: *const EvidenceV2,
    ) *const registry_mod.AuthenticatedGeometryV1 {
        return &self.cold.geometry_value;
    }

    pub fn proofCapture(
        self: *const EvidenceV2,
    ) *const common_authority.ProofCapture {
        return &self.cold.fresh.capture;
    }

    pub fn ingressView(self: *const EvidenceV2) !FreshRecursiveIngressV2 {
        return evidence_support.rebaseIngressToArtifact(
            &self.node_artifact,
            try self.cold.ingressView(),
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

pub const FreshAdmissionV2 =
    common_authority.OwnedFreshWrapperAdmissionV2(EvidenceV2);

pub fn geometryFromFresh(
    fresh: *const secure_engine.FreshVerificationV1,
) !registry_mod.AuthenticatedGeometryV1 {
    const manifest = try manifest_mod.build();
    const pcs = registry_mod.PcsConfigV1.secureTemporalParent();
    const capture = &fresh.capture;
    if (capture.commitments.len != common_authority.COMMITMENT_TREE_COUNT or
        capture.column_log_sizes.len != common_authority.COMMITMENT_TREE_COUNT)
    {
        return error.CanonicalEmptyUniversalProofShapeMismatch;
    }
    try validateTraceTree(
        &manifest,
        capture.column_log_sizes[0],
        .preprocessed,
        pcs.fri_log_blowup_factor,
    );
    try validateTraceTree(
        &manifest,
        capture.column_log_sizes[1],
        .main,
        pcs.fri_log_blowup_factor,
    );
    try validateTraceTree(
        &manifest,
        capture.column_log_sizes[2],
        .interaction,
        pcs.fri_log_blowup_factor,
    );
    const column_log_degree = try columnDegreeFromCapture(
        capture.column_log_sizes[3],
        pcs.fri_log_blowup_factor,
    );
    const composition_columns = stwo_core.verifier_types
        .compositionColumnCount(
        stwo_core.verifier_types.COMPOSITION_LOG_SPLIT,
        stwo_core.fields.qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.CanonicalEmptyUniversalProofShapeMismatch;
    if (capture.column_log_sizes[3].len != composition_columns)
        return error.CanonicalEmptyUniversalProofShapeMismatch;

    const proof_shape = try registry_mod.sealProofShapeFromCapture(
        capture,
        manifest_mod.COMPONENT_COUNT,
        column_log_degree,
        try manifest_mod.tableLayoutIdentity(),
    );
    var active = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    var padded = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    for (manifest_mod.exactLogSizes(), 0..) |log_size, index| {
        active[index] = std.math.cast(u8, log_size) orelse
            return error.CanonicalEmptyUniversalProofShapeMismatch;
        padded[index] = active[index];
    }
    var preprocessed = [_]u8{0} **
        registry_mod.MAX_PREPROCESSED_COLUMN_COUNT;
    try fillBaseColumnLogs(&manifest, .preprocessed, &preprocessed);
    return registry_mod.AuthenticatedGeometryV1.seal(.{
        .role = .canonical_empty_field_v2,
        .authenticated_padding = true,
        .component_count = manifest_mod.COMPONENT_COUNT,
        .preprocessed_column_count = @intCast(
            manifest.total_preprocessed_columns,
        ),
        .trace_log_size = @intCast(manifest_mod.RANGE_LOG_SIZE),
        .active_component_log_sizes = active,
        .padded_component_log_sizes = padded,
        .preprocessed_column_log_sizes = preprocessed,
        .circuit_identity_sha256 = try manifest_mod.contractIdentity(),
        .program_identity_sha256 = try manifest_mod.programIdentity(),
        .profile_identity_sha256 = try manifest_mod.profileIdentity(),
        .padding_layout_identity_sha256 = try manifest_mod.paddingLayoutIdentity(),
        .preprocessed_root = capture.commitments[0],
        .pcs = pcs,
        .output_abi = registry_mod.OutputAbiV1.fieldNodePublicV2(),
        .proof_shape = proof_shape,
        .authority_identity_sha256 = undefined,
    });
}

const TraceTreeV2 = enum { preprocessed, main, interaction };

fn validateTraceTree(
    manifest: *const manifest_mod.Manifest,
    captured_logs: anytype,
    tree: TraceTreeV2,
    blowup: u32,
) !void {
    const expected_count = switch (tree) {
        .preprocessed => manifest.total_preprocessed_columns,
        .main => manifest.total_main_columns,
        .interaction => manifest.total_interaction_columns,
    };
    if (captured_logs.len != @as(usize, expected_count))
        return error.CanonicalEmptyUniversalProofShapeMismatch;
    inline for (manifest_mod.COMPONENT_KEYS) |key| {
        const placement = try manifest.placement(key);
        const offset = switch (tree) {
            .preprocessed => placement.preprocessed_offset,
            .main => placement.main_offset,
            .interaction => placement.interaction_offset,
        };
        const count = switch (tree) {
            .preprocessed => placement.geometry.preprocessed_columns,
            .main => placement.geometry.main_columns,
            .interaction => placement.geometry.interaction_columns,
        };
        const expected = std.math.add(
            u32,
            placement.geometry.log_size,
            blowup,
        ) catch return error.CanonicalEmptyUniversalProofShapeMismatch;
        const start: usize = @intCast(offset);
        const column_count: usize = @intCast(count);
        for (captured_logs[start..][0..column_count]) |actual|
            if (actual != expected)
                return error.CanonicalEmptyUniversalProofShapeMismatch;
    }
}

fn fillBaseColumnLogs(
    manifest: *const manifest_mod.Manifest,
    tree: TraceTreeV2,
    destination: *[registry_mod.MAX_PREPROCESSED_COLUMN_COUNT]u8,
) !void {
    inline for (manifest_mod.COMPONENT_KEYS) |key| {
        const placement = try manifest.placement(key);
        const offset = switch (tree) {
            .preprocessed => placement.preprocessed_offset,
            .main => placement.main_offset,
            .interaction => placement.interaction_offset,
        };
        const count = switch (tree) {
            .preprocessed => placement.geometry.preprocessed_columns,
            .main => placement.geometry.main_columns,
            .interaction => placement.geometry.interaction_columns,
        };
        const log_size = std.math.cast(
            u8,
            placement.geometry.log_size,
        ) orelse return error.CanonicalEmptyUniversalProofShapeMismatch;
        const start: usize = @intCast(offset);
        const column_count: usize = @intCast(count);
        @memset(destination[start..][0..column_count], log_size);
    }
}

fn columnDegreeFromCapture(
    composition_logs: anytype,
    blowup: u32,
) !u8 {
    if (composition_logs.len == 0)
        return error.CanonicalEmptyUniversalProofShapeMismatch;
    const extended = composition_logs[0];
    for (composition_logs[1..]) |log_size|
        if (log_size != extended)
            return error.CanonicalEmptyUniversalProofShapeMismatch;
    const base = std.math.sub(u32, extended, blowup) catch
        return error.CanonicalEmptyUniversalProofShapeMismatch;
    return std.math.cast(u8, base) orelse
        error.CanonicalEmptyUniversalProofShapeMismatch;
}

fn authorityInputsFromSource(
    source_bytes: []const u8,
) !cohort_mod.AuthorityInputs {
    const cold = try input_mod.ColdInputV1.open(source_bytes);
    return .{
        .statement_words = cold.source.statement_words,
        .coordinate = try cold.coordinate(),
    };
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
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or REGISTRY_PARITY_AVAILABLE or
        PROOF_ARTIFACT_KIND != 8 or SOURCE_ARTIFACT_KIND != 14 or
        manifest_mod.COMPONENT_COUNT != 36 or
        field_public.POSEIDON_CALL_COUNT != 113)
    {
        @compileError("canonical-empty universal proof V2 drifted");
    }
}
