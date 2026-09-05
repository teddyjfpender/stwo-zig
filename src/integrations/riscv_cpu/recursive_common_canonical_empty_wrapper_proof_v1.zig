//! Retained q193 proof and cold-verifier boundary for canonical-empty wrappers.
//!
//! A live result owns the decoded proof capture minted by a current cold
//! verification. Durable bytes retain only the canonical source and secure
//! proof artifact. Registry admission is a separate, fail-closed step and is
//! impossible until the other common-wrapper circuit entries also exist.

const std = @import("std");

const input_mod =
    @import("recursive_common_canonical_empty_wrapper_input_v1.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_wrapper_manifest_v1.zig");
const cohort_mod =
    @import("recursive_common_canonical_empty_wrapper_cohort_v1.zig");
const common_authority =
    @import("recursive_common_wrapper_authority_v1.zig");
const artifact_mod = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const REGISTRY_PARITY_AVAILABLE = false;
/// The diagnostic manifest has 252 preprocessed columns, while the admitted
/// universal common-fold geometry has 570.  No proof over this source may be
/// promoted or even executed as a prospective common-wrapper child.
pub const COMMON_GEOMETRY_COMPATIBLE = false;
pub const PROOF_ROUTE_AVAILABLE = false;
pub const PROOF_ARTIFACT_KIND = common_authority.PROOF_ARTIFACT_KIND;
pub const PROOF_ARTIFACT_SCHEMA_VERSION: u16 = 1;

pub const Kernel = secure_engine.EngineKernelForManifest(
    cohort_mod.CohortV1,
    manifest_mod,
    .canonical_empty_wrapper_v1,
);

pub const Error = input_mod.Error || registry_mod.Error || error{
    CanonicalEmptyWrapperEvidenceMismatch,
    CanonicalEmptyWrapperProofMismatch,
    CanonicalEmptyWrapperRegistryUnavailable,
    CanonicalEmptyWrapperCommonGeometryUnavailable,
};

pub const ProveResultV1 = struct {
    proof: OwnedColdProofV1,
    receipt: secure_engine.ReceiptV1,

    pub fn deinit(self: *ProveResultV1) void {
        self.proof.deinit();
        self.* = undefined;
    }
};

/// Current-process proof capability. The fresh capture is never encoded.
pub const OwnedColdProofV1 = struct {
    allocator: std.mem.Allocator,
    source_bytes: [input_mod.SOURCE_ENCODED_BYTE_COUNT]u8,
    session: secure_artifact.SessionV1,
    artifact_value: secure_artifact.OwnedArtifactV1,
    fresh: secure_engine.FreshVerificationV1,
    geometry_value: registry_mod.AuthenticatedGeometryV1,

    pub fn deinit(self: *OwnedColdProofV1) void {
        self.fresh.deinit();
        self.artifact_value.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const OwnedColdProofV1) !void {
        const expected_session = try sessionForSource(&self.source_bytes);
        try self.artifact_value.validateCustody();
        try self.artifact_value.statement.validateAgainstSession(
            &self.session,
        );
        try self.geometry_value.validate();
        if (!std.meta.eql(self.session, expected_session) or
            !std.meta.eql(
                self.fresh.statement,
                self.artifact_value.statement,
            ) or !std.meta.eql(
            self.geometry_value,
            try geometryFromFresh(&self.fresh),
        )) return error.CanonicalEmptyWrapperProofMismatch;
    }

    pub fn encodeArtifactAlloc(
        self: *const OwnedColdProofV1,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try self.validate();
        return self.artifact_value.encodeCanonicalAlloc(allocator);
    }

    pub fn proofArtifactRef(
        self: *const OwnedColdProofV1,
    ) !artifact_mod.ArtifactRefV1 {
        const bytes = try self.artifact_value.encodeCanonicalAlloc(
            self.allocator,
        );
        defer self.allocator.free(bytes);
        var sha: [32]u8 = undefined;
        Sha256.hash(bytes, &sha, .{});
        const result = artifact_mod.ArtifactRefV1{
            .kind = PROOF_ARTIFACT_KIND,
            .format_version = artifact_mod.ARTIFACT_REF_FORMAT_VERSION,
            .schema_version = PROOF_ARTIFACT_SCHEMA_VERSION,
            .byte_count = @intCast(bytes.len),
            .sha256 = sha,
        };
        try result.validate();
        return result;
    }
};

pub fn proveAndColdVerify(
    allocator: std.mem.Allocator,
    source_bytes: []const u8,
    execution: secure_engine.ExecutionOptions,
) !ProveResultV1 {
    if (!PROOF_ROUTE_AVAILABLE)
        return error.CanonicalEmptyWrapperCommonGeometryUnavailable;
    const session = try sessionForSource(source_bytes);
    var result = try Kernel.proveAndColdVerify(
        allocator,
        .{ .source_bytes = source_bytes },
        session,
        execution,
    );
    errdefer result.deinit();
    var proof = try ownResult(
        allocator,
        source_bytes,
        session,
        result.artifact,
        result.fresh,
    );
    result.artifact = undefined;
    result.fresh = undefined;
    errdefer proof.deinit();
    return .{ .proof = proof, .receipt = result.receipt };
}

/// Canonically decodes retained bytes and runs a new independent q193 verifier.
pub fn coldOpen(
    allocator: std.mem.Allocator,
    source_bytes: []const u8,
    retained_artifact_bytes: []const u8,
) !OwnedColdProofV1 {
    if (!PROOF_ROUTE_AVAILABLE)
        return error.CanonicalEmptyWrapperCommonGeometryUnavailable;
    const session = try sessionForSource(source_bytes);
    var artifact_value = try secure_artifact.OwnedArtifactV1.decodeCanonical(
        allocator,
        retained_artifact_bytes,
    );
    errdefer artifact_value.deinit();
    var fresh = try Kernel.verifyCold(
        allocator,
        .{ .source_bytes = source_bytes },
        &session,
        &artifact_value,
    );
    errdefer fresh.deinit();
    return ownResult(
        allocator,
        source_bytes,
        session,
        artifact_value,
        fresh,
    );
}

fn ownResult(
    allocator: std.mem.Allocator,
    source_bytes: []const u8,
    session: secure_artifact.SessionV1,
    artifact_value: secure_artifact.OwnedArtifactV1,
    fresh: secure_engine.FreshVerificationV1,
) !OwnedColdProofV1 {
    if (source_bytes.len != input_mod.SOURCE_ENCODED_BYTE_COUNT)
        return error.CanonicalEmptyWrapperProofMismatch;
    var source_copy: [input_mod.SOURCE_ENCODED_BYTE_COUNT]u8 = undefined;
    @memcpy(&source_copy, source_bytes);
    var result = OwnedColdProofV1{
        .allocator = allocator,
        .source_bytes = source_copy,
        .session = session,
        .artifact_value = artifact_value,
        .fresh = fresh,
        .geometry_value = try geometryFromFresh(&fresh),
    };
    try result.validate();
    return result;
}

/// Exact Evidence surface consumed by `OwnedFreshWrapperAdmissionV1`.
pub const EvidenceV1 = struct {
    cold: OwnedColdProofV1,
    node_artifact: artifact_mod.RecursiveNodeArtifactV1,

    pub fn initOwned(
        cold: OwnedColdProofV1,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
        campaign_namespace_sha256: [32]u8,
    ) !EvidenceV1 {
        var owned = cold;
        errdefer owned.deinit();
        const node_artifact = try buildNodeArtifact(
            &owned,
            registry,
            campaign_namespace_sha256,
        );
        var result = EvidenceV1{
            .cold = owned,
            .node_artifact = node_artifact,
        };
        try result.validateFresh(registry);
        return result;
    }

    pub fn deinit(self: *EvidenceV1) void {
        self.cold.deinit();
        self.* = undefined;
    }

    pub fn validateFresh(
        self: *const EvidenceV1,
        registry: *const registry_mod.RecursiveCircuitRegistryV1,
    ) !void {
        try self.cold.validate();
        const expected = try buildNodeArtifact(
            &self.cold,
            registry,
            self.node_artifact.campaign_namespace_sha256,
        );
        if (!std.meta.eql(self.node_artifact, expected))
            return error.CanonicalEmptyWrapperEvidenceMismatch;
        try registry.admit(&self.node_artifact, &self.cold.geometry_value);
    }

    pub fn artifact(
        self: *const EvidenceV1,
    ) *const artifact_mod.RecursiveNodeArtifactV1 {
        return &self.node_artifact;
    }

    pub fn geometry(
        self: *const EvidenceV1,
    ) *const registry_mod.AuthenticatedGeometryV1 {
        return &self.cold.geometry_value;
    }

    pub fn proofCapture(
        self: *const EvidenceV1,
    ) *const common_authority.ProofCapture {
        return &self.cold.fresh.capture;
    }
};

pub const FreshAdmissionV1 =
    common_authority.OwnedFreshWrapperAdmissionV1(EvidenceV1);

fn sessionForSource(
    source_bytes: []const u8,
) !secure_artifact.SessionV1 {
    const cold = try input_mod.ColdInputV1.open(source_bytes);
    return secure_artifact.SessionV1.initCanonicalEmptyWrapper(.{
        .ingress_identity_sha256 = cold.identity_sha256,
        .parent_statement_words = cold.leaf.child().statement_words,
        .profile_identity_sha256 = try manifest_mod.profileIdentity(),
        .child_composition_manifest_sha256 = try manifest_mod.contractIdentity(),
        .parent_outer_manifest_sha256 = try manifest_mod.contractIdentity(),
        .verification_key_id = try manifest_mod.verificationKeyId(),
        .next_parent_vk_id = try manifest_mod.nextParentVkId(),
        .air_program_id = try manifest_mod.airProgramId(),
    });
}

fn geometryFromFresh(
    fresh: *const secure_engine.FreshVerificationV1,
) !registry_mod.AuthenticatedGeometryV1 {
    const manifest = try manifest_mod.build();
    if (fresh.capture.commitments.len != common_authority.COMMITMENT_TREE_COUNT)
        return error.CanonicalEmptyWrapperProofMismatch;
    var active = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    var padded = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    // All 36 typed statement adapters are physically committed at log 11.
    // Logical zero rows in lanes 1..35 do not authorize a host-declared
    // smaller active circuit: the authenticated geometry describes the proof
    // actually verified, not an unproved pre-padding shape.
    @memset(
        active[0..manifest_mod.COMPONENT_COUNT],
        manifest_mod.LOG_SIZE,
    );
    @memset(
        padded[0..manifest_mod.COMPONENT_COUNT],
        manifest_mod.LOG_SIZE,
    );
    var preprocessed = [_]u8{0} **
        registry_mod.MAX_PREPROCESSED_COLUMN_COUNT;
    @memset(
        preprocessed[0..manifest.total_preprocessed_columns],
        manifest_mod.LOG_SIZE,
    );
    return registry_mod.AuthenticatedGeometryV1.seal(.{
        .role = .canonical_empty_field_v2,
        .authenticated_padding = true,
        .component_count = manifest_mod.COMPONENT_COUNT,
        .preprocessed_column_count = @intCast(
            manifest.total_preprocessed_columns,
        ),
        .trace_log_size = manifest_mod.LOG_SIZE,
        .active_component_log_sizes = active,
        .padded_component_log_sizes = padded,
        .preprocessed_column_log_sizes = preprocessed,
        .circuit_identity_sha256 = try manifest_mod.contractIdentity(),
        .program_identity_sha256 = try manifest_mod.programIdentity(),
        .profile_identity_sha256 = try manifest_mod.profileIdentity(),
        .padding_layout_identity_sha256 = try manifest_mod.paddingLayoutIdentity(),
        .preprocessed_root = fresh.capture.commitments[0],
        .pcs = registry_mod.PcsConfigV1.secureTemporalParent(),
        .output_abi = registry_mod.OutputAbiV1.nodePublic(),
        .authority_identity_sha256 = undefined,
    });
}

fn buildNodeArtifact(
    cold_proof: *const OwnedColdProofV1,
    registry: *const registry_mod.RecursiveCircuitRegistryV1,
    campaign_namespace_sha256: [32]u8,
) !artifact_mod.RecursiveNodeArtifactV1 {
    try cold_proof.validate();
    try registry.validate();
    if (std.mem.allEqual(u8, &campaign_namespace_sha256, 0))
        return error.CanonicalEmptyWrapperEvidenceMismatch;
    const entry = try registry.entry(.canonical_empty_field_v2);
    const source_ref = try cold_proofSourceRef(cold_proof);
    const proof_ref = try cold_proof.proofArtifactRef();
    const node_public = (try input_mod.ColdInputV1.open(
        &cold_proof.source_bytes,
    )).node_public;
    return artifact_mod.RecursiveNodeArtifactV1.seal(.{
        .stage_kind = .leaf_wrapper,
        .node_kind = .empty,
        .child_count = 1,
        .coordinate = try (try input_mod.ColdInputV1.open(
            &cold_proof.source_bytes,
        )).coordinate(),
        .node_public = node_public,
        .campaign_namespace_sha256 = campaign_namespace_sha256,
        .circuit_identity_sha256 = entry.circuit_identity_sha256,
        .program_identity_sha256 = entry.program_identity_sha256,
        .profile_identity_sha256 = entry.profile_identity_sha256,
        .pcs_identity_sha256 = entry.pcs_identity_sha256,
        .padding_layout_identity_sha256 = entry.padding_layout_identity_sha256,
        .registry_identity_sha256 = registry.identity_sha256,
        .node_public_abi_sha256 = artifact_mod.nodePublicAbiIdentity(),
        .statement_identity_sha256 = node_public.statement_identity_sha256,
        .output_identity_sha256 = node_public.output_identity_sha256,
        .ordered_children = .{ source_ref, artifact_mod.ArtifactRefV1.zero() },
        .proof_ref = proof_ref,
        .preprocessed_root = cold_proof.geometry_value.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
}

fn cold_proofSourceRef(
    cold_proof: *const OwnedColdProofV1,
) !artifact_mod.ArtifactRefV1 {
    const cold = try input_mod.ColdInputV1.open(&cold_proof.source_bytes);
    return cold.sourceRef();
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or REGISTRY_PARITY_AVAILABLE or
        COMMON_GEOMETRY_COMPATIBLE or PROOF_ROUTE_AVAILABLE or
        PROOF_ARTIFACT_KIND != 8)
    {
        @compileError("canonical-empty wrapper proof contract drifted");
    }
}
