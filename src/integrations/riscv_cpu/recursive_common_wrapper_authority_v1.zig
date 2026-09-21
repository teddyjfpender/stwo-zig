//! Process-local admission shared by the three common recursive wrappers.
//!
//! Durable recursive-node bytes and authenticated geometry remain inert until
//! a kind-specific cold verifier supplies an exact `Evidence` implementation.
//! The generic owner below retains that verifier-owned evidence and exposes a
//! uniform borrowed view over the actual PCS capture.  No capture, pointer, or
//! freshness bit is serializable through this module.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const artifact_mod = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const node_public_mod =
    @import("recursive_temporal_node_public_authority_v2.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const COMMITMENT_TREE_COUNT: usize = 4;
pub const PROOF_ARTIFACT_KIND: u32 = 8;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const ProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);
pub const Registry = registry_mod.RecursiveCircuitRegistryV1;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const RecursiveNodeArtifact = artifact_mod.RecursiveNodeArtifactV1;
pub const NodePublic = artifact_mod.NodePublicV1;

pub const Error = registry_mod.Error || error{
    ChildCoordinateMismatch,
    EvidenceContractIncomplete,
    FreshWrapperCaptureMismatch,
    FreshWrapperEvidenceMismatch,
    FreshWrapperRoleMismatch,
    InvalidCommonFoldOutput,
    InvalidRecursiveProofReference,
    NonCanonicalStatementWord,
};

/// Uniform borrowed capability consumed by the one common fold.  The owner of
/// `evidence` must outlive this value.  A view cannot be constructed from a
/// digest because the actual verifier-expanded PCS capture is mandatory.
pub const FreshWrapperViewV1 = struct {
    artifact: *const RecursiveNodeArtifact,
    geometry: *const Geometry,
    capture: *const ProofCapture,

    pub fn validateAgainst(
        self: FreshWrapperViewV1,
        registry: *const Registry,
    ) !void {
        try registry.admit(self.artifact, self.geometry);
        if (self.artifact.proof_ref.kind != PROOF_ARTIFACT_KIND) {
            return error.InvalidRecursiveProofReference;
        }
        const artifact_role = try registry_mod.roleForArtifact(self.artifact);
        if (artifact_role != self.geometry.role)
            return error.FreshWrapperRoleMismatch;
        try validateCaptureShape(self.capture, self.geometry);
    }

    pub fn role(self: FreshWrapperViewV1) !registry_mod.CircuitRoleV1 {
        return registry_mod.roleForArtifact(self.artifact);
    }

    pub fn reference(self: FreshWrapperViewV1) !artifact_mod.ArtifactRefV1 {
        return self.artifact.artifactRef();
    }

    pub fn nodePublic(self: FreshWrapperViewV1) *const NodePublic {
        return &self.artifact.node_public;
    }
};

/// Owns one exact kind-specific cold-verifier result.  `Evidence` is selected
/// at compile time by a production stage adapter and must provide:
///
/// * `deinit(*Evidence)`;
/// * `validateFresh(*const Evidence, *const Registry)`;
/// * `artifact(*const Evidence) *const RecursiveNodeArtifact`;
/// * `geometry(*const Evidence) *const Geometry`;
/// * `proofCapture(*const Evidence) *const ProofCapture`.
///
/// Consequently a generic controller cannot substitute a digest-shaped mock
/// for the production evidence type.  Test adapters may use their own exact
/// evidence type, but production registry selection is Zig-owned.
pub fn OwnedFreshWrapperAdmissionV1(comptime Evidence: type) type {
    assertEvidenceContract(Evidence);
    return struct {
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        evidence: Evidence,
        registry: Registry,

        const Self = @This();

        pub fn initOwned(
            evidence: Evidence,
            registry: Registry,
        ) !Self {
            var owned_evidence = evidence;
            errdefer owned_evidence.deinit();
            var result = Self{
                .evidence = owned_evidence,
                .registry = registry,
            };
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.evidence.deinit();
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION)
            {
                return error.FreshWrapperEvidenceMismatch;
            }
            try self.registry.validate();
            try self.evidence.validateFresh(&self.registry);
            try self.view().validateAgainst(&self.registry);
        }

        pub fn view(self: *const Self) FreshWrapperViewV1 {
            return .{
                .artifact = self.evidence.artifact(),
                .geometry = self.evidence.geometry(),
                .capture = self.evidence.proofCapture(),
            };
        }
    };
}

/// Proof-independent parent public derivation.  The common-fold AIR must
/// record the same equations; this host result is only the expected output
/// supplied to that circuit and later compared with its public values.
pub const ParentNodePublicDerivationV1 = struct {
    compiler: node_public_mod.ParentCompilerAuthorityV2,
    node_public: NodePublic,

    pub fn validateAgainst(
        self: *const ParentNodePublicDerivationV1,
        left: FreshWrapperViewV1,
        right: FreshWrapperViewV1,
        parent: artifact_mod.TaskCoordinateV1,
        registry: *const Registry,
    ) !void {
        const expected = try deriveParentNodePublic(left, right, parent, registry);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidCommonFoldOutput;
    }
};

pub fn deriveParentNodePublic(
    left: FreshWrapperViewV1,
    right: FreshWrapperViewV1,
    parent: artifact_mod.TaskCoordinateV1,
    registry: *const Registry,
) !ParentNodePublicDerivationV1 {
    try left.validateAgainst(registry);
    try right.validateAgainst(registry);
    try parent.validate();
    if (parent.height == 0 or
        left.artifact.coordinate.height + 1 != parent.height or
        right.artifact.coordinate.height != left.artifact.coordinate.height or
        left.artifact.coordinate.index != parent.index * 2 or
        right.artifact.coordinate.index != left.artifact.coordinate.index + 1 or
        !std.mem.eql(
            u8,
            &left.artifact.campaign_namespace_sha256,
            &right.artifact.campaign_namespace_sha256,
        )) return error.ChildCoordinateMismatch;

    const common_entry = try registry.entry(.common_fold_field_v2);
    const left_reference = try nodeReference(left.artifact);
    const right_reference = try nodeReference(right.artifact);
    const compiler_input = node_public_mod.ParentCompilerInputV2{
        .left = left_reference,
        .right = right_reference,
        .air_program_identity = common_entry.program_identity_sha256,
        .verifier_program_authority = common_entry.circuit_identity_sha256,
        .protocol_profile_sha256 = common_entry.profile_identity_sha256,
        .preprocessed_commitment_root = common_entry.preprocessed_root,
    };
    const compiler = try node_public_mod.ParentCompilerAuthorityV2.compile(
        compiler_input,
    );
    if (compiler.height != parent.height)
        return error.ChildCoordinateMismatch;
    const reference = try compiler.reference();
    var statement_words: [artifact_mod.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&statement_words, reference.statement_words) |*destination, word|
        destination.* = word.toU32();
    const node_public = try NodePublic.seal(.{
        .statement_words = statement_words,
        .statement_identity_sha256 = compiler.statement_sha256,
        .node_authority_sha256 = reference.authority_sha256,
        .subtree_sha256 = reference.subtree_sha256,
        .subtree_digest = reference.subtree_digest,
        .output_identity_sha256 = undefined,
    });
    return .{ .compiler = compiler, .node_public = node_public };
}

fn nodeReference(
    artifact: *const RecursiveNodeArtifact,
) !node_public_mod.NodeReferenceV2 {
    try artifact.validate();
    var words: recursion.span_statement.StatementWords = undefined;
    for (&words, artifact.node_public.statement_words) |*destination, word| {
        if (word >= m31.Modulus) return error.NonCanonicalStatementWord;
        destination.* = M31.fromCanonical(word);
    }
    const result = node_public_mod.NodeReferenceV2{
        .height = artifact.coordinate.height,
        .statement_words = words,
        .authority_sha256 = artifact.node_public.node_authority_sha256,
        .subtree_sha256 = artifact.node_public.subtree_sha256,
        .subtree_digest = artifact.node_public.subtree_digest,
    };
    try result.validate();
    const statement = try recursion.span_statement.SpanStatement
        .fromCanonicalWords(&words);
    if (statement.slots.height != artifact.coordinate.height or
        statement.slots.nodeIndex() != artifact.coordinate.index or
        !std.mem.eql(
            u8,
            &artifact.node_public.statement_identity_sha256,
            &statement_plan.statementSha256(&words),
        ))
    {
        return error.ChildCoordinateMismatch;
    }
    switch (statement.body) {
        .empty => if (artifact.node_kind != .empty)
            return error.ChildCoordinateMismatch,
        .executed => if (artifact.node_kind == .empty)
            return error.ChildCoordinateMismatch,
    }
    return result;
}

fn validateCaptureShape(
    capture: *const ProofCapture,
    geometry: *const Geometry,
) !void {
    if (capture.commitments.len != COMMITMENT_TREE_COUNT or
        capture.column_log_sizes.len != COMMITMENT_TREE_COUNT or
        capture.sampled_points.len != COMMITMENT_TREE_COUNT or
        capture.trace_paths.len != COMMITMENT_TREE_COUNT or
        capture.queries.raw.len != geometry.pcs.fri_query_count or
        capture.deep_answers.len != geometry.pcs.fri_query_count or
        capture.column_log_sizes[0].len !=
            geometry.preprocessed_column_count)
    {
        return error.FreshWrapperCaptureMismatch;
    }
    for (
        capture.column_log_sizes[0],
        geometry.preprocessed_column_log_sizes[0..geometry.preprocessed_column_count],
    ) |captured, base| {
        const expected = std.math.add(
            u32,
            base,
            geometry.pcs.fri_log_blowup_factor,
        ) catch return error.FreshWrapperCaptureMismatch;
        if (captured != expected)
            return error.FreshWrapperCaptureMismatch;
    }
    for (capture.column_log_sizes[1..]) |logs|
        if (logs.len == 0) return error.FreshWrapperCaptureMismatch;
}

fn assertEvidenceContract(comptime Evidence: type) void {
    inline for (.{
        "deinit",
        "validateFresh",
        "artifact",
        "geometry",
        "proofCapture",
    }) |name| if (!@hasDecl(Evidence, name))
        @compileError("common wrapper Evidence missing declaration: " ++ name);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        COMMITMENT_TREE_COUNT != 4 or PRODUCTION_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        artifact_mod.STATEMENT_WORD_COUNT != 412 or PROOF_ARTIFACT_KIND != 8)
    {
        @compileError("common wrapper authority V1 contract drifted");
    }
}
