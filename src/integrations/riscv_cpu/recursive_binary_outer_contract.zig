const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const binary_composition_authority = @import("recursive_binary_composition_authority.zig");
const verified_publication = @import("recursive_binary_verified_publication.zig");
const verified_artifact_v3 = @import("recursive_binary_v3_verified_artifact.zig");
const segment_publication = @import("recursive_segment_v2_verified_publication.zig");
const segment_artifact = @import("recursive_segment_v2_verified_artifact.zig");
const temporal_relation_profile = @import("recursive_temporal_child_relation_profile.zig");
const temporal_child_authority = @import("recursive_segment_v2_temporal_child_authority.zig");
const temporal_pair_authority = @import("recursive_temporal_pair_authority_v2.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const air = recursion.air;
const roster = air.universal_roster;
const universal = air.universal_challenges;
const segment_manifest_mod = air.segment_outer_adapter_manifest_v2;
const poseidon2_channel = recursion.poseidon2_channel;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);

pub const VerifiedBinaryClosurePublicationV2 =
    verified_publication.VerifiedBinaryClosurePublicationV2;
pub const VerifiedBinaryArtifactV3 =
    verified_artifact_v3.VerifiedBinaryArtifactV3;
pub const BinaryProgramDescriptorV3 = composition_v3.ProgramDescriptorV3;

fn nativeDigestCanonicalNonzero(value: poseidon2_channel.Digest) bool {
    var any = false;
    for (value) |word| {
        if (word >= m31.Modulus) return false;
        any = any or word != 0;
    }
    return any;
}

pub const FORMAT_VERSION: u16 = 1;
pub const CAPABILITY_FORMAT_VERSION: u16 = 1;
pub const COMPLETE_ROW_COUNT: usize = roster.COMPONENT_COUNT;
pub const NON_FRI_FIRST_ROW: usize = 0;
pub const NON_FRI_LAST_ROW: usize = 17;
pub const FRI_FIRST_ROW: usize = 18;
pub const FRI_LAST_DATA_ROW: usize = 33;
pub const POSEIDON_PROVIDER_ROW: usize = 34;
pub const RANGE_PROVIDER_ROW: usize = 35;

pub const PROTOCOL_SUBSTRATE_ONLY = true;
pub const WHOLE_FRONTEND_VERIFIED = false;
pub const PRODUCTION_ACTIVATION = false;
pub const CANONICAL_PROOF_SERIALIZATION_PASSES: u8 = 2;
pub const RETAINED_CANONICAL_PROOF_BYTES: usize = 0;
pub const TEMPORAL_PARENT_CAPABILITY_FORMAT_VERSION: u16 = 1;
pub const TEMPORAL_VERIFIER_EVIDENCE_FORMAT_VERSION: u16 = 1;
pub const TEMPORAL_VERIFIER_PUBLIC_MINT_AVAILABLE = false;
pub const TEMPORAL_VERIFIER_EVIDENCE_HEAP_ALLOCATIONS: usize = 0;
pub const TEMPORAL_ARTIFACT_PREFLIGHT_FORMAT_VERSION: u16 = 1;
pub const HEAP_ALLOCATIONS_PER_TEMPORAL_ARTIFACT_PREFLIGHT: usize = 0;
pub const PROOF_DECODING_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT: usize = 0;
pub const CAPTURE_IDENTITY_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT: usize = 2;
pub const SEGMENT_PUBLICATION_VALIDATION_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT: usize = 2;
pub const TEMPORAL_PAIR_VALIDATION_PASSES_PER_ARTIFACT_PREFLIGHT: usize = 1;
pub const SEGMENT_MANIFEST_VALIDATION_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT: usize = 1;
pub const SEGMENT_WITNESS_PREFLIGHT_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT: usize = 2;
pub const TEMPORAL_CHILD_CLAIM_PROFILE_FORMAT_VERSION: u16 = 1;
pub const TEMPORAL_CHILD_CLAIM_PROFILE_AVAILABLE = true;
pub const TEMPORAL_CHILD_RELATION_REPLAY_AVAILABLE = true;
pub const TEMPORAL_SEGMENT_CLAIM_ABI_AVAILABLE = true;
pub const TEMPORAL_SEGMENT_V2_COMPOSITION_PROFILE_AVAILABLE = true;
pub const TEMPORAL_ROWS_0_THROUGH_17_AVAILABLE = true;
pub const VERIFIED_TEMPORAL_PARENT_PUBLICATION_AVAILABLE = true;
pub const TEMPORAL_PARENT_PROVER_AND_VERIFIER_AVAILABLE = true;
pub const TEMPORAL_RELATION_RECONSTRUCTIONS_PER_ARTIFACT_PREFLIGHT: usize =
    temporal_pair_authority.CHILD_COUNT;
pub const TEMPORAL_RELATION_DRAW_REHASHES_PER_ARTIFACT_PREFLIGHT: usize = 0;
pub const TEMPORAL_SEGMENT_CLAIM_INPUT_WRITES_PER_PARENT: usize =
    temporal_pair_authority.CHILD_COUNT;

pub const Error = error{
    ArithmeticOverflow,
    BinaryFriInteractionAuthorityUnavailable,
    CohortContractViolation,
    InvalidProofShape,
    PreprocessedRootMismatch,
    ProofAlreadyConsumed,
    DuplicateTemporalChildArtifact,
    TemporalChildArtifactMismatch,
    TemporalChildCaptureMismatch,
    TemporalChildClaimProfileMismatch,
    TemporalChildRelationProfileMismatch,
    TemporalSegmentClaimAbiMismatch,
    TemporalChildRelationReplayUnavailable,
    TemporalNonFriAirUnavailable,
    TemporalParentPublicationUnavailable,
    TemporalParentProofUnavailable,
    TemporalSegmentCompositionProfileUnavailable,
    TransactionOutputAlias,
    TemporalVerifierEvidenceMismatch,
    WorkerPoolMismatch,
};

/// Value-only statement sealed into the transaction-local successful-verifier
/// capability below.  It binds the exact proof/capture pair to the complete
/// temporal cohort, manifest, claims, independently replayed audit, and global
/// closure which the native verifier accepted.
pub const TemporalVerifierSuccessBindingV1 = struct {
    canonical_proof_byte_count: u32,
    proof_id: poseidon2_channel.Digest,
    canonical_proof_sha_id: [32]u8,
    capture_id: poseidon2_channel.Digest,
    transcript_id: poseidon2_channel.Digest,
    cohort_authority_sha_id: [32]u8,
    manifest_sha_id: [32]u8,
    claims_sha_id: [32]u8,
    generated_interactions_sha_id: [32]u8,
    audit_sha_id: [32]u8,
    closure_receipt_sha_id: [32]u8,

    pub fn validate(self: *const TemporalVerifierSuccessBindingV1) !void {
        if (self.canonical_proof_byte_count == 0 or
            !nativeDigestCanonicalNonzero(self.proof_id) or
            !nativeDigestCanonicalNonzero(self.capture_id) or
            !nativeDigestCanonicalNonzero(self.transcript_id))
        {
            return error.TemporalVerifierEvidenceMismatch;
        }
        inline for (.{
            self.canonical_proof_sha_id,
            self.cohort_authority_sha_id,
            self.manifest_sha_id,
            self.claims_sha_id,
            self.generated_interactions_sha_id,
            self.audit_sha_id,
            self.closure_receipt_sha_id,
        }) |value| if (std.mem.allEqual(u8, &value, 0))
            return error.TemporalVerifierEvidenceMismatch;
    }
};

/// Opaque, borrowed capability.  Production code exposes validation but no
/// constructor: the only mint is lexically inside this verifier module and is
/// called after `verifyWithProofCapture` succeeds.  The backing storage lives
/// on that verifier stack and is consumed synchronously by publication.
pub const TemporalVerifierSuccessEvidenceV1 = opaque {};

pub const TemporalVerifierSuccessEvidenceStorageV1 = struct {
    format_version: u16 = TEMPORAL_VERIFIER_EVIDENCE_FORMAT_VERSION,
    verified: bool = true,
    padding: [5]u8 = [_]u8{0} ** 5,
    binding: TemporalVerifierSuccessBindingV1,
    identity: [32]u8,
};

pub fn mintTemporalVerifierSuccessEvidence(
    storage: *TemporalVerifierSuccessEvidenceStorageV1,
    binding: TemporalVerifierSuccessBindingV1,
) !*const TemporalVerifierSuccessEvidenceV1 {
    try binding.validate();
    storage.* = .{
        .binding = binding,
        .identity = undefined,
    };
    storage.identity = temporalVerifierEvidenceIdentity(storage);
    return @ptrCast(storage);
}

fn temporalVerifierEvidenceIdentity(
    evidence: *const TemporalVerifierSuccessEvidenceStorageV1,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/temporal-verifier-success-evidence/v1\x00");
    evidenceHashInt(&hash, u16, evidence.format_version);
    evidenceHashInt(&hash, u8, @intFromBool(evidence.verified));
    hash.update(&evidence.padding);
    const binding = evidence.binding;
    evidenceHashInt(&hash, u32, binding.canonical_proof_byte_count);
    for (binding.proof_id) |word| evidenceHashInt(&hash, u32, word);
    hash.update(&binding.canonical_proof_sha_id);
    for (binding.capture_id) |word| evidenceHashInt(&hash, u32, word);
    for (binding.transcript_id) |word| evidenceHashInt(&hash, u32, word);
    hash.update(&binding.cohort_authority_sha_id);
    hash.update(&binding.manifest_sha_id);
    hash.update(&binding.claims_sha_id);
    hash.update(&binding.generated_interactions_sha_id);
    hash.update(&binding.audit_sha_id);
    hash.update(&binding.closure_receipt_sha_id);
    return hash.finalResult();
}

fn evidenceHashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

/// Opens a capability without extending its lifetime.  Revalidation includes
/// the complete binding and mutation-detecting storage identity.
pub fn openTemporalVerifierSuccessEvidence(
    evidence: *const TemporalVerifierSuccessEvidenceV1,
) !TemporalVerifierSuccessBindingV1 {
    const storage: *const TemporalVerifierSuccessEvidenceStorageV1 =
        @ptrCast(@alignCast(evidence));
    if (storage.format_version != TEMPORAL_VERIFIER_EVIDENCE_FORMAT_VERSION or
        !storage.verified or !std.mem.allEqual(u8, &storage.padding, 0) or
        !std.mem.eql(
            u8,
            &storage.identity,
            &temporalVerifierEvidenceIdentity(storage),
        ))
    {
        return error.TemporalVerifierEvidenceMismatch;
    }
    try storage.binding.validate();
    return storage.binding;
}

/// Value-only CPU resource request for one binary outer proof. Worker count is
/// an execution concern only: authority, commitments, transcript, claims, and
/// proof bytes must remain identical across valid worker counts.
pub const ExecutionOptions = struct {
    worker_count: usize = 1,
};

/// Ordered view of one successful SegmentV2 verifier transaction. The fixed
/// witness is copied only by the successful child verifier; the dynamic
/// capture remains separately owned. This view borrows all three values only
/// during parent construction and retains no allocation.
pub const TemporalChildArtifactV1 = struct {
    publication: *const segment_publication.VerifiedSegmentV2PublicationV1,
    capture: *const OuterProofCapture,
    recursive_witness: *const segment_artifact.RecursiveWitnessV1,

    pub fn validate(
        self: TemporalChildArtifactV1,
        manifest: *const segment_manifest_mod.Manifest,
    ) !void {
        segment_artifact.preflight(
            self.capture,
            self.publication,
            self.recursive_witness,
            manifest,
        ) catch |err| {
            if (err == error.CaptureIdentityMismatch)
                return error.TemporalChildCaptureMismatch;
            return err;
        };
    }
};

/// Exact fixed values consumed by the temporal composition frontend. It is a
/// derived profile, never a second claim authority: validation requires byte-
/// for-byte field equality with the verifier-minted recursive witness.
pub const TemporalChildClaimProfileV1 = struct {
    format_version: u16 = TEMPORAL_CHILD_CLAIM_PROFILE_FORMAT_VERSION,
    claim_count: u8 = segment_artifact.CLAIM_COUNT,
    poseidon2_partial_count: u8 = segment_artifact.POSEIDON2_PARTIAL_COUNT,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    publication_id: segment_publication.Digest,
    witness_id: segment_publication.Digest,
    claimed_sums: [segment_artifact.CLAIM_COUNT]QM31,
    poseidon2_partials: [segment_artifact.POSEIDON2_PARTIAL_COUNT]QM31,
    profile_id: segment_publication.Digest,

    pub fn validateAgainst(
        self: *const TemporalChildClaimProfileV1,
        child: TemporalChildArtifactV1,
    ) !void {
        if (self.format_version != TEMPORAL_CHILD_CLAIM_PROFILE_FORMAT_VERSION or
            self.claim_count != segment_artifact.CLAIM_COUNT or
            self.poseidon2_partial_count !=
                segment_artifact.POSEIDON2_PARTIAL_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0) or
            !std.meta.eql(self.publication_id, child.publication.publication_id) or
            !std.meta.eql(self.witness_id, child.recursive_witness.witness_id) or
            !std.meta.eql(self.claimed_sums, child.recursive_witness.claimed_sums) or
            !std.meta.eql(
                self.poseidon2_partials,
                child.recursive_witness.poseidon2_partials,
            ) or !std.meta.eql(self.profile_id, claimProfileId(self)))
        {
            return error.TemporalChildClaimProfileMismatch;
        }
    }
};

pub const TemporalChildRelationProfileV1 =
    temporal_relation_profile.TemporalChildRelationProfileV1;

const ValidatedTemporalProfilesV1 = struct {
    claim_profiles: [temporal_pair_authority.CHILD_COUNT]TemporalChildClaimProfileV1,
    relation_profiles: [temporal_pair_authority.CHILD_COUNT]TemporalChildRelationProfileV1,
    relations: [temporal_pair_authority.CHILD_COUNT]universal.UniversalRelations,
    segment_composition_profile: binary_composition_authority.SegmentV2CompositionProfileV1,
};

/// Cold, allocation-free chain of custody for the inputs to one temporal
/// parent.  `init` independently re-admits both verifier publications and
/// compares the resulting complete children against the prepared pair.  A
/// caller cannot splice a valid capture, publication, or pair from a different
/// transaction.  No proof bytes are parsed or retained here.
pub const TemporalParentArtifactViewV1 = struct {
    format_version: u16 = TEMPORAL_ARTIFACT_PREFLIGHT_FORMAT_VERSION,
    children: [temporal_pair_authority.CHILD_COUNT]TemporalChildArtifactV1,
    segment_manifests: [temporal_pair_authority.CHILD_COUNT]*const segment_manifest_mod.Manifest,
    pair: *const temporal_pair_authority.PreparedTemporalPairAuthorityV1,
    claim_profiles: [temporal_pair_authority.CHILD_COUNT]TemporalChildClaimProfileV1,
    relation_profiles: [temporal_pair_authority.CHILD_COUNT]TemporalChildRelationProfileV1,
    segment_composition_profile: binary_composition_authority.SegmentV2CompositionProfileV1,

    pub fn init(
        left: TemporalChildArtifactV1,
        right: TemporalChildArtifactV1,
        segment_manifests: [temporal_pair_authority.CHILD_COUNT]*const segment_manifest_mod.Manifest,
        pair: *const temporal_pair_authority.PreparedTemporalPairAuthorityV1,
    ) !TemporalParentArtifactViewV1 {
        if (left.publication == right.publication or
            left.capture == right.capture or
            left.recursive_witness == right.recursive_witness)
        {
            return error.DuplicateTemporalChildArtifact;
        }
        var result = TemporalParentArtifactViewV1{
            .children = .{ left, right },
            .segment_manifests = segment_manifests,
            .pair = pair,
            .claim_profiles = undefined,
            .relation_profiles = undefined,
            .segment_composition_profile = undefined,
        };
        const validated = try result.validateInputs();
        result.claim_profiles = validated.claim_profiles;
        result.relation_profiles = validated.relation_profiles;
        result.segment_composition_profile =
            validated.segment_composition_profile;
        return result;
    }

    pub fn validate(self: *const TemporalParentArtifactViewV1) !void {
        if (self.format_version != TEMPORAL_ARTIFACT_PREFLIGHT_FORMAT_VERSION)
            return error.TemporalChildArtifactMismatch;
        if (self.children[0].publication == self.children[1].publication or
            self.children[0].capture == self.children[1].capture or
            self.children[0].recursive_witness ==
                self.children[1].recursive_witness)
        {
            return error.DuplicateTemporalChildArtifact;
        }
        const expected = try self.validateInputs();
        if (!std.meta.eql(expected.claim_profiles, self.claim_profiles))
            return error.TemporalChildClaimProfileMismatch;
        if (!std.meta.eql(expected.relation_profiles, self.relation_profiles))
            return error.TemporalChildRelationProfileMismatch;
        if (!std.meta.eql(
            expected.segment_composition_profile,
            self.segment_composition_profile,
        )) return error.TemporalSegmentClaimAbiMismatch;
    }

    pub fn claimProfiles(
        self: *const TemporalParentArtifactViewV1,
    ) ![temporal_pair_authority.CHILD_COUNT]TemporalChildClaimProfileV1 {
        try self.validate();
        return self.claim_profiles;
    }

    pub fn relationProfiles(
        self: *const TemporalParentArtifactViewV1,
    ) ![temporal_pair_authority.CHILD_COUNT]TemporalChildRelationProfileV1 {
        try self.validate();
        return self.relation_profiles;
    }

    /// Reconstructs the exact per-child universal relation bundles once each
    /// while re-admitting all transitive publication, witness, manifest, and
    /// pair links. No proof bytes are decoded and the 94 raw draws are not
    /// rehashed at this boundary.
    pub fn reconstructChildRelations(
        self: *const TemporalParentArtifactViewV1,
    ) ![temporal_pair_authority.CHILD_COUNT]universal.UniversalRelations {
        const validated = try self.validateInputs();
        if (!std.meta.eql(validated.claim_profiles, self.claim_profiles))
            return error.TemporalChildClaimProfileMismatch;
        if (!std.meta.eql(validated.relation_profiles, self.relation_profiles))
            return error.TemporalChildRelationProfileMismatch;
        return validated.relations;
    }

    /// Publishes the two exact 39+2 composition input vectors consumed by the
    /// V3 heterogeneous recorder. The common profile is derived from the
    /// trusted SegmentV2 manifest and verifier-minted AIR program identity;
    /// no legacy 39-to-36 projection exists on this path.
    pub fn writeSegmentCompositionInputs(
        self: *const TemporalParentArtifactViewV1,
        destination: *[temporal_pair_authority.CHILD_COUNT][
            binary_composition_authority.SEGMENT_V2_COMPOSITION_CLAIM_COUNT
        ]QM31,
    ) !void {
        const validated = try self.validateInputs();
        if (!std.meta.eql(validated.claim_profiles, self.claim_profiles))
            return error.TemporalChildClaimProfileMismatch;
        if (!std.meta.eql(validated.relation_profiles, self.relation_profiles))
            return error.TemporalChildRelationProfileMismatch;
        if (!std.meta.eql(
            validated.segment_composition_profile,
            self.segment_composition_profile,
        )) return error.TemporalSegmentClaimAbiMismatch;

        var staged: @TypeOf(destination.*) = undefined;
        for (
            &staged,
            validated.claim_profiles,
            self.segment_manifests,
        ) |*child_inputs, child_profile, child_manifest| {
            try validated.segment_composition_profile.writeClaimInputs(
                child_manifest,
                &child_profile.claimed_sums,
                &child_profile.poseidon2_partials,
                child_inputs,
            );
        }
        destination.* = staged;
    }

    fn validateInputs(
        self: *const TemporalParentArtifactViewV1,
    ) !ValidatedTemporalProfilesV1 {
        for (self.segment_manifests) |manifest| try manifest.validate();
        try segment_manifest_mod.requireSameProgramGeometry(
            self.segment_manifests[0],
            self.segment_manifests[1],
        );
        try self.pair.validate();

        var admitted: [temporal_pair_authority.CHILD_COUNT]temporal_child_authority.PreparedTemporalChildV1 = undefined;
        var profiles: ValidatedTemporalProfilesV1 = undefined;
        for (
            &admitted,
            &profiles.claim_profiles,
            &profiles.relation_profiles,
            &profiles.relations,
            self.children,
            self.segment_manifests,
        ) |*destination, *claim_profile, *relation_profile, *relations, child, child_manifest| {
            try temporal_child_authority.admitInto(
                destination,
                child.publication,
            );
            segment_artifact.preflightAgainstValidatedPublicationAndManifest(
                child.capture,
                child.publication,
                child.recursive_witness,
                child_manifest,
            ) catch |err| {
                if (err == error.CaptureIdentityMismatch)
                    return error.TemporalChildCaptureMismatch;
                return err;
            };
            claim_profile.* = claimProfileFromValidatedChild(child);
            try claim_profile.validateAgainst(child);
            relation_profile.* = try TemporalChildRelationProfileV1
                .deriveFromValidatedWitness(
                child.publication,
                child.recursive_witness,
            );
            relations.* = try relation_profile
                .reconstructAgainstValidatedWitness(
                child.publication,
                child.recursive_witness,
            );
        }
        if (!std.meta.eql(
            self.children[0].recursive_witness.air_program_id,
            self.children[1].recursive_witness.air_program_id,
        )) return error.TemporalSegmentClaimAbiMismatch;
        profiles.segment_composition_profile =
            try binary_composition_authority.SegmentV2CompositionProfileV1
                .seal(
                self.segment_manifests[0],
                self.children[0].recursive_witness.air_program_id,
            );
        const pair_children =
            self.pair.prepared_root.authority_snapshot.children;
        for (
            admitted,
            self.pair.source_bindings,
            pair_children,
        ) |child, binding, pair_child| {
            if (!std.meta.eql(child.sourceBinding(), binding) or
                !std.meta.eql(child.child, pair_child))
            {
                return error.TemporalChildArtifactMismatch;
            }
        }
        return profiles;
    }
};

const TEMPORAL_CHILD_CLAIM_PROFILE_ID_DOMAIN: u32 = 0x5443_5031; // "TCP1"

fn claimProfileFromValidatedChild(
    child: TemporalChildArtifactV1,
) TemporalChildClaimProfileV1 {
    var result = TemporalChildClaimProfileV1{
        .publication_id = child.publication.publication_id,
        .witness_id = child.recursive_witness.witness_id,
        .claimed_sums = child.recursive_witness.claimed_sums,
        .poseidon2_partials = child.recursive_witness.poseidon2_partials,
        .profile_id = undefined,
    };
    result.profile_id = claimProfileId(&result);
    return result;
}

fn claimProfileId(
    profile: *const TemporalChildClaimProfileV1,
) segment_publication.Digest {
    var hash = ClaimProfileHasher.init();
    hash.addU32(profile.format_version);
    hash.addU32(profile.claim_count);
    hash.addU32(profile.poseidon2_partial_count);
    hash.digest(profile.publication_id);
    hash.digest(profile.witness_id);
    for (profile.claimed_sums) |value| hash.qm31(value);
    for (profile.poseidon2_partials) |value| hash.qm31(value);
    return hash.inner.finalize();
}

const ClaimProfileHasher = struct {
    inner: poseidon2_channel.CanonicalWordHasher,

    fn init() ClaimProfileHasher {
        return .{
            .inner = poseidon2_channel.CanonicalWordHasher.init(
                TEMPORAL_CHILD_CLAIM_PROFILE_ID_DOMAIN,
            ),
        };
    }

    fn addU32(self: *ClaimProfileHasher, value: anytype) void {
        const exact: u32 = @intCast(value);
        std.debug.assert(exact < m31.Modulus);
        self.inner.update(&.{M31.fromCanonical(exact)});
    }

    fn digest(
        self: *ClaimProfileHasher,
        value: segment_publication.Digest,
    ) void {
        for (value) |word| self.addU32(word);
    }

    fn qm31(self: *ClaimProfileHasher, value: QM31) void {
        self.inner.update(&value.toM31Array());
    }
};

/// Exact temporal-parent frontier, kept separate from the green V1 36-row
/// proof contract.  The role-neutral rows 18--35 and generic PCS engine can be
/// reused. Child claims, ordered Poseidon2 partials, and raw relation replay
/// now come only from verifier-minted sidecars. The temporal V3 cohort binds
/// the versioned SegmentV2 composition profile, rows 0--35, its successful
/// verifier publication, and the independent prover/verifier transaction.
pub const TemporalParentProofCapabilitiesV1 = struct {
    format_version: u16 = TEMPORAL_PARENT_CAPABILITY_FORMAT_VERSION,
    verified_segment_child_publications: bool,
    verifier_capture_identity_binding: bool,
    authenticated_temporal_pair: bool,
    role_neutral_rows_18_through_35: bool,
    verifier_child_claim_values: bool,
    verifier_child_relation_replay: bool,
    segment_v2_composition_profile: bool,
    temporal_rows_0_through_17: bool,
    verified_complete_parent_publication: bool,
    complete_parent_prover_and_verifier: bool,

    pub fn ready(self: TemporalParentProofCapabilitiesV1) bool {
        return self.format_version == TEMPORAL_PARENT_CAPABILITY_FORMAT_VERSION and
            self.verified_segment_child_publications and
            self.verifier_capture_identity_binding and
            self.authenticated_temporal_pair and
            self.role_neutral_rows_18_through_35 and
            self.verifier_child_claim_values and
            self.verifier_child_relation_replay and
            self.segment_v2_composition_profile and
            self.temporal_rows_0_through_17 and
            self.verified_complete_parent_publication and
            self.complete_parent_prover_and_verifier;
    }

    /// Returns the first missing production authority in witness-to-proof
    /// order.  This is intentionally executable so orchestration does not need
    /// to infer readiness from comments or the existence of a green V1 proof.
    pub fn requireProduction(
        self: TemporalParentProofCapabilitiesV1,
    ) !void {
        if (!self.verified_segment_child_publications or
            !self.verifier_capture_identity_binding or
            !self.authenticated_temporal_pair or
            !self.role_neutral_rows_18_through_35)
        {
            return error.TemporalChildArtifactMismatch;
        }
        if (!self.verifier_child_claim_values)
            return error.TemporalChildArtifactMismatch;
        if (!self.verifier_child_relation_replay)
            return error.TemporalChildRelationReplayUnavailable;
        if (!self.segment_v2_composition_profile)
            return error.TemporalSegmentCompositionProfileUnavailable;
        if (!self.temporal_rows_0_through_17)
            return error.TemporalNonFriAirUnavailable;
        if (!self.verified_complete_parent_publication)
            return error.TemporalParentPublicationUnavailable;
        if (!self.complete_parent_prover_and_verifier)
            return error.TemporalParentProofUnavailable;
    }
};

pub const CURRENT_TEMPORAL_PARENT_CAPABILITIES =
    TemporalParentProofCapabilitiesV1{
        .verified_segment_child_publications = segment_publication.COMPLETE_SEGMENT_CHILD_CAPABILITY,
        .verifier_capture_identity_binding = @hasDecl(segment_publication, "captureIdentity"),
        .authenticated_temporal_pair = temporal_pair_authority.AUTHENTICATED_PAIR_AVAILABLE,
        .role_neutral_rows_18_through_35 = true,
        .verifier_child_claim_values = TEMPORAL_CHILD_CLAIM_PROFILE_AVAILABLE,
        .verifier_child_relation_replay = TEMPORAL_CHILD_RELATION_REPLAY_AVAILABLE,
        .segment_v2_composition_profile = TEMPORAL_SEGMENT_V2_COMPOSITION_PROFILE_AVAILABLE,
        .temporal_rows_0_through_17 = TEMPORAL_ROWS_0_THROUGH_17_AVAILABLE,
        .verified_complete_parent_publication = VERIFIED_TEMPORAL_PARENT_PUBLICATION_AVAILABLE,
        .complete_parent_prover_and_verifier = TEMPORAL_PARENT_PROVER_AND_VERIFIER_AVAILABLE,
    };

/// Fixed from the independently versioned outer-child admission profile. No
/// proof byte or caller value can select these PCS parameters.
pub const OUTER_CONFIG = stwo_core.pcs.PcsConfig{
    .pow_bits = recursion.outer_parent_child_admission.PCS_POW_BITS,
    .fri_config = .{
        .log_blowup_factor = recursion.outer_parent_child_admission.LOG_BLOWUP_FACTOR,
        .log_last_layer_degree_bound = recursion.outer_parent_child_admission.LOG_LAST_LAYER_DEGREE_BOUND,
        .n_queries = recursion.outer_parent_child_admission.QUERY_COUNT,
        .fold_step = recursion.outer_parent_child_admission.FOLD_STEP,
    },
};

/// What the current rows-18--34 source already authenticates, independent of
/// the still-missing all-36 proof adapter.
pub const SourceCustodyCapabilitiesV1 = struct {
    format_version: u16 = CAPABILITY_FORMAT_VERSION,
    authenticated_child_custody: bool,
    full_composition_authority: bool,
    retained_relation_rows: bool,
    local_preprocessed_main_writers: bool,
    retained_row34_poseidon_calls: bool,

    pub fn inspect(comptime Source: type) SourceCustodyCapabilitiesV1 {
        return .{
            .authenticated_child_custody = @hasDecl(Source, "validate") and
                @hasDecl(Source, "wire"),
            .full_composition_authority = @hasDecl(Source, "requireFullBundleAuthority"),
            .retained_relation_rows = @hasDecl(Source, "RelationRows") and
                @hasDecl(Source, "merkleRelationRows"),
            .local_preprocessed_main_writers = @hasDecl(Source, "fillCompositionPreprocessedInto") and
                @hasDecl(Source, "fillCompositionMainInto") and
                @hasDecl(Source, "fillFriPreprocessedInto") and
                @hasDecl(Source, "fillFriMainInto") and
                @hasDecl(Source, "fillArithmeticPreprocessedInto") and
                @hasDecl(Source, "fillArithmeticMainInto") and
                @hasDecl(Source, "fillMerkleMainInto"),
            .retained_row34_poseidon_calls = @hasDecl(Source, "merklePoseidonCalls"),
        };
    }
};

/// Structural contract required between a source-owned all-36 adapter and the
/// generic Engine kernel. This records capabilities only; it never invokes a
/// method by a guessed signature.
///
/// The final two fields deliberately keep row 34 and row 35 distinct. The FRI
/// owner must append the authenticated Poseidon provider at row 34, then the
/// non-FRI owner appends its authenticated range provider at row 35.
pub const ProofContractCapabilitiesV1 = struct {
    format_version: u16 = CAPABILITY_FORMAT_VERSION,
    global_manifest_geometry: bool,
    global_tree_writers: bool,
    authenticated_interaction_receipt: bool,
    authenticated_domain_audit: bool,
    retained_v2_closure_receipt: bool,
    verified_publication_authority: bool,
    complete_claim_binding: bool,
    component_construction: bool,
    ordered_rows_0_through_33: bool,
    authenticated_row34_provider: bool,
    authenticated_row35_provider: bool,
    independent_verifier_rebuild: bool,

    pub fn inspect(comptime Contract: type) ProofContractCapabilitiesV1 {
        return .{
            .global_manifest_geometry = @hasDecl(Contract, "installLogSizes"),
            .global_tree_writers = @hasDecl(Contract, "fillPreprocessedInto") and
                @hasDecl(Contract, "fillMainInto"),
            .authenticated_interaction_receipt = @hasDecl(Contract, "GeneratedInteractionsV1") and
                @hasDecl(Contract, "fillInteractionInto"),
            .authenticated_domain_audit = @hasDecl(Contract, "AuditedInteractionsV1") and
                @hasDecl(Contract, "auditGeneratedInteractions"),
            .retained_v2_closure_receipt = @hasDecl(Contract, "AuditedInteractionsV2") and
                @hasDecl(Contract, "auditGlobalClosureV2"),
            .verified_publication_authority = @hasDecl(Contract, "PublicationAuthorityV1") and
                @hasDecl(Contract, "publicationAuthority"),
            .complete_claim_binding = @hasDecl(Contract, "bindClaimsInto"),
            .component_construction = @hasDecl(Contract, "initComponents"),
            .ordered_rows_0_through_33 = @hasDecl(Contract, "appendRows0Through33ToGate"),
            .authenticated_row34_provider = @hasDecl(Contract, "appendRow34ProviderToGate"),
            .authenticated_row35_provider = @hasDecl(Contract, "appendRow35ProviderToGate"),
            .independent_verifier_rebuild = @hasDecl(Contract, "AuthorityInputs") and
                @hasDecl(Contract, "init") and
                @hasDecl(Contract, "rebuildGeneratedInteractions"),
        };
    }

    pub fn ready(self: ProofContractCapabilitiesV1) bool {
        return self.format_version == CAPABILITY_FORMAT_VERSION and
            self.global_manifest_geometry and
            self.global_tree_writers and
            self.authenticated_interaction_receipt and
            self.authenticated_domain_audit and
            self.retained_v2_closure_receipt and
            self.verified_publication_authority and
            self.complete_claim_binding and
            self.component_construction and
            self.ordered_rows_0_through_33 and
            self.authenticated_row34_provider and
            self.authenticated_row35_provider and
            self.independent_verifier_rebuild;
    }

    pub fn unavailable() ProofContractCapabilitiesV1 {
        return .{
            .global_manifest_geometry = false,
            .global_tree_writers = false,
            .authenticated_interaction_receipt = false,
            .authenticated_domain_audit = false,
            .retained_v2_closure_receipt = false,
            .verified_publication_authority = false,
            .complete_claim_binding = false,
            .component_construction = false,
            .ordered_rows_0_through_33 = false,
            .authenticated_row34_provider = false,
            .authenticated_row35_provider = false,
            .independent_verifier_rebuild = false,
        };
    }
};

pub const CURRENT_PROOF_CAPABILITIES =
    ProofContractCapabilitiesV1.unavailable();

pub const Receipt = struct {
    proof_size_estimate: usize,
    canonical_proof_bytes: usize,
    canonical_proof_streamed_bytes: usize,
    canonical_proof_serialization_passes: u8,
    canonical_proof_retained_bytes: usize,
    canonical_proof_id: verified_publication.NativeDigest,
    canonical_proof_sha256: [32]u8,
    canonical_proof_id_poseidon_permutations: usize,
    proof_canonicalize_ns: u64,
    prove_ns: u64,
    verify_ns: u64,
    pair_authority_prepare_ns: u64,
    publication_ns: u64,
    pair_authentication_poseidon_permutations: usize,
    cohort_authority_sha256: [32]u8,
    closure_receipt_sha256: [32]u8,
    transcript_draws: usize,
    preprocessed_columns: u32,
    main_columns: u32,
    interaction_columns: u32,
    roster_count: u8,
    worker_count: usize,
};

comptime {
    @import("stwo_prover_api").assertProverEngine(Engine);
    if (COMPLETE_ROW_COUNT != 36 or NON_FRI_FIRST_ROW != 0 or
        NON_FRI_LAST_ROW != 17 or FRI_FIRST_ROW != 18 or
        FRI_LAST_DATA_ROW != 33 or POSEIDON_PROVIDER_ROW != 34 or
        RANGE_PROVIDER_ROW != 35)
    {
        @compileError("binary outer row ownership drifted");
    }
    if (CURRENT_PROOF_CAPABILITIES.ready() or
        !CURRENT_TEMPORAL_PARENT_CAPABILITIES.ready() or
        !PROTOCOL_SUBSTRATE_ONLY or WHOLE_FRONTEND_VERIFIED or
        PRODUCTION_ACTIVATION)
    {
        @compileError("binary outer production boundary changed");
    }
    if (CANONICAL_PROOF_SERIALIZATION_PASSES != 2 or
        RETAINED_CANONICAL_PROOF_BYTES != 0)
    {
        @compileError("binary outer canonical identity accounting drifted");
    }
    if (TEMPORAL_PARENT_CAPABILITY_FORMAT_VERSION != 1 or
        TEMPORAL_VERIFIER_EVIDENCE_FORMAT_VERSION != 1 or
        TEMPORAL_VERIFIER_PUBLIC_MINT_AVAILABLE or
        TEMPORAL_VERIFIER_EVIDENCE_HEAP_ALLOCATIONS != 0 or
        TEMPORAL_ARTIFACT_PREFLIGHT_FORMAT_VERSION != 1 or
        HEAP_ALLOCATIONS_PER_TEMPORAL_ARTIFACT_PREFLIGHT != 0 or
        PROOF_DECODING_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT != 0 or
        CAPTURE_IDENTITY_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT != 2 or
        SEGMENT_PUBLICATION_VALIDATION_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT != 2 or
        TEMPORAL_PAIR_VALIDATION_PASSES_PER_ARTIFACT_PREFLIGHT != 1)
    {
        @compileError("temporal parent artifact preflight accounting drifted");
    }
    if (!TEMPORAL_CHILD_RELATION_REPLAY_AVAILABLE or
        TEMPORAL_RELATION_RECONSTRUCTIONS_PER_ARTIFACT_PREFLIGHT !=
            temporal_pair_authority.CHILD_COUNT or
        TEMPORAL_RELATION_DRAW_REHASHES_PER_ARTIFACT_PREFLIGHT != 0 or
        temporal_relation_profile.UNIVERSAL_RECONSTRUCTIONS_PER_RECONSTRUCT != 1 or
        temporal_relation_profile.RAW_DRAW_REHASHES_PER_DERIVE != 0)
    {
        @compileError("temporal parent relation replay accounting drifted");
    }
    if (!TEMPORAL_SEGMENT_CLAIM_ABI_AVAILABLE or
        TEMPORAL_SEGMENT_CLAIM_INPUT_WRITES_PER_PARENT !=
            temporal_pair_authority.CHILD_COUNT or
        binary_composition_authority.SEGMENT_V2_PHYSICAL_CLAIM_COUNT !=
            segment_artifact.CLAIM_COUNT or
        binary_composition_authority.SEGMENT_V2_POSEIDON_PARTIAL_COUNT !=
            segment_artifact.POSEIDON2_PARTIAL_COUNT or
        binary_composition_authority.SEGMENT_V2_LEGACY_V1_PROJECTION_ALLOWED)
    {
        @compileError("temporal parent SegmentV2 claim ABI drifted");
    }
}
