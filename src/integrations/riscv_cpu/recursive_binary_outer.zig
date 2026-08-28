//! CPU proof transaction for an authenticated binary-parent outer cohort.
//!
//! The reusable `EngineKernel` below is the real three-tree STWO transaction:
//! it constructs prover and verifier cohorts independently from the same
//! authority inputs, commits preprocessed/main/interaction trees, draws the
//! universal challenges, binds all 36 claims, seals the exact component gate,
//! proves, and independently verifies with transactional proof capture.
//!
//! The concrete `recursive_binary_outer_cohort` now satisfies that engine
//! contract and proves all 36 V1 rows.  Its rows 0--17 intentionally retain
//! the frozen split-role authority, so that proof remains protocol substrate:
//! it is not an adjacent-span temporal parent.  The temporal ingress below
//! binds two independently verified SegmentV2 publications and their exact
//! verifier captures to the authenticated V2 pair without decoding either
//! proof again. The versioned temporal V3 cohort now completes that path and
//! independently verifies a real parent; product activation remains separate.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const prover_engine = @import("stwo_prover_engine");
const prover_pcs = prover_engine.pcs;
const prover_work_pool = prover_engine.work_pool;
const fri_outer_diagnostic = @import("recursive_fri_outer.zig");
const binary_composition_authority =
    @import("recursive_binary_composition_authority.zig");
const verified_publication = @import("recursive_binary_verified_publication.zig");
const verified_artifact_v3 =
    @import("recursive_binary_v3_verified_artifact.zig");
const segment_publication = @import("recursive_segment_v2_verified_publication.zig");
const segment_artifact = @import("recursive_segment_v2_verified_artifact.zig");
const temporal_relation_profile =
    @import("recursive_temporal_child_relation_profile.zig");
const temporal_child_authority = @import("recursive_segment_v2_temporal_child_authority.zig");
const temporal_pair_authority = @import("recursive_temporal_pair_authority_v2.zig");
const contract = @import("recursive_binary_outer_contract.zig");
const legacy_engine = @import("recursive_binary_outer_legacy_engine.zig");
const native_engine = @import("recursive_binary_outer_native_engine.zig");
const native_core_engine =
    @import("recursive_binary_outer_native_core_engine.zig");
const outer_support = @import("recursive_binary_outer_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const air = recursion.air;
const manifest_mod = air.universal_adapter_manifest;
const roster = air.universal_roster;
const shared_provider = air.universal_shared_provider;
const universal = air.universal_challenges;
const segment_manifest_mod = air.segment_outer_adapter_manifest_v2;
const poseidon2_channel = recursion.poseidon2_channel;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;

pub const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
pub const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion.engine.Hasher,
    recursion.engine.MerkleChannel,
);
pub const VerifiedBinaryClosurePublicationV2 =
    verified_publication.VerifiedBinaryClosurePublicationV2;
pub const VerifiedBinaryArtifactV3 =
    verified_artifact_v3.VerifiedBinaryArtifactV3;
pub const BinaryProgramDescriptorV3 = composition_v3.ProgramDescriptorV3;

pub const FORMAT_VERSION = contract.FORMAT_VERSION;
pub const CAPABILITY_FORMAT_VERSION = contract.CAPABILITY_FORMAT_VERSION;
pub const COMPLETE_ROW_COUNT = contract.COMPLETE_ROW_COUNT;
pub const NON_FRI_FIRST_ROW = contract.NON_FRI_FIRST_ROW;
pub const NON_FRI_LAST_ROW = contract.NON_FRI_LAST_ROW;
pub const FRI_FIRST_ROW = contract.FRI_FIRST_ROW;
pub const FRI_LAST_DATA_ROW = contract.FRI_LAST_DATA_ROW;
pub const POSEIDON_PROVIDER_ROW = contract.POSEIDON_PROVIDER_ROW;
pub const RANGE_PROVIDER_ROW = contract.RANGE_PROVIDER_ROW;
pub const PROTOCOL_SUBSTRATE_ONLY = contract.PROTOCOL_SUBSTRATE_ONLY;
pub const WHOLE_FRONTEND_VERIFIED = contract.WHOLE_FRONTEND_VERIFIED;
pub const PRODUCTION_ACTIVATION = contract.PRODUCTION_ACTIVATION;
pub const CANONICAL_PROOF_SERIALIZATION_PASSES = contract.CANONICAL_PROOF_SERIALIZATION_PASSES;
pub const RETAINED_CANONICAL_PROOF_BYTES = contract.RETAINED_CANONICAL_PROOF_BYTES;
pub const TEMPORAL_PARENT_CAPABILITY_FORMAT_VERSION = contract.TEMPORAL_PARENT_CAPABILITY_FORMAT_VERSION;
pub const TEMPORAL_VERIFIER_EVIDENCE_FORMAT_VERSION = contract.TEMPORAL_VERIFIER_EVIDENCE_FORMAT_VERSION;
pub const TEMPORAL_VERIFIER_PUBLIC_MINT_AVAILABLE = contract.TEMPORAL_VERIFIER_PUBLIC_MINT_AVAILABLE;
pub const TEMPORAL_VERIFIER_EVIDENCE_HEAP_ALLOCATIONS = contract.TEMPORAL_VERIFIER_EVIDENCE_HEAP_ALLOCATIONS;
pub const TEMPORAL_ARTIFACT_PREFLIGHT_FORMAT_VERSION = contract.TEMPORAL_ARTIFACT_PREFLIGHT_FORMAT_VERSION;
pub const HEAP_ALLOCATIONS_PER_TEMPORAL_ARTIFACT_PREFLIGHT = contract.HEAP_ALLOCATIONS_PER_TEMPORAL_ARTIFACT_PREFLIGHT;
pub const PROOF_DECODING_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT = contract.PROOF_DECODING_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT;
pub const CAPTURE_IDENTITY_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT = contract.CAPTURE_IDENTITY_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT;
pub const SEGMENT_PUBLICATION_VALIDATION_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT = contract.SEGMENT_PUBLICATION_VALIDATION_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT;
pub const TEMPORAL_PAIR_VALIDATION_PASSES_PER_ARTIFACT_PREFLIGHT = contract.TEMPORAL_PAIR_VALIDATION_PASSES_PER_ARTIFACT_PREFLIGHT;
pub const SEGMENT_MANIFEST_VALIDATION_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT = contract.SEGMENT_MANIFEST_VALIDATION_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT;
pub const SEGMENT_WITNESS_PREFLIGHT_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT = contract.SEGMENT_WITNESS_PREFLIGHT_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT;
pub const TEMPORAL_CHILD_CLAIM_PROFILE_FORMAT_VERSION = contract.TEMPORAL_CHILD_CLAIM_PROFILE_FORMAT_VERSION;
pub const TEMPORAL_CHILD_CLAIM_PROFILE_AVAILABLE = contract.TEMPORAL_CHILD_CLAIM_PROFILE_AVAILABLE;
pub const TEMPORAL_CHILD_RELATION_REPLAY_AVAILABLE = contract.TEMPORAL_CHILD_RELATION_REPLAY_AVAILABLE;
pub const TEMPORAL_SEGMENT_CLAIM_ABI_AVAILABLE = contract.TEMPORAL_SEGMENT_CLAIM_ABI_AVAILABLE;
pub const TEMPORAL_SEGMENT_V2_COMPOSITION_PROFILE_AVAILABLE = contract.TEMPORAL_SEGMENT_V2_COMPOSITION_PROFILE_AVAILABLE;
pub const TEMPORAL_ROWS_0_THROUGH_17_AVAILABLE = contract.TEMPORAL_ROWS_0_THROUGH_17_AVAILABLE;
pub const VERIFIED_TEMPORAL_PARENT_PUBLICATION_AVAILABLE = contract.VERIFIED_TEMPORAL_PARENT_PUBLICATION_AVAILABLE;
pub const TEMPORAL_PARENT_PROVER_AND_VERIFIER_AVAILABLE = contract.TEMPORAL_PARENT_PROVER_AND_VERIFIER_AVAILABLE;
pub const TEMPORAL_RELATION_RECONSTRUCTIONS_PER_ARTIFACT_PREFLIGHT = contract.TEMPORAL_RELATION_RECONSTRUCTIONS_PER_ARTIFACT_PREFLIGHT;
pub const TEMPORAL_RELATION_DRAW_REHASHES_PER_ARTIFACT_PREFLIGHT = contract.TEMPORAL_RELATION_DRAW_REHASHES_PER_ARTIFACT_PREFLIGHT;
pub const TEMPORAL_SEGMENT_CLAIM_INPUT_WRITES_PER_PARENT = contract.TEMPORAL_SEGMENT_CLAIM_INPUT_WRITES_PER_PARENT;
pub const Error = contract.Error;
pub const TemporalVerifierSuccessBindingV1 = contract.TemporalVerifierSuccessBindingV1;
pub const TemporalVerifierSuccessEvidenceV1 = contract.TemporalVerifierSuccessEvidenceV1;
pub const openTemporalVerifierSuccessEvidence = contract.openTemporalVerifierSuccessEvidence;
pub const ExecutionOptions = contract.ExecutionOptions;
pub const TemporalChildArtifactV1 = contract.TemporalChildArtifactV1;
pub const TemporalChildClaimProfileV1 = contract.TemporalChildClaimProfileV1;
pub const TemporalChildRelationProfileV1 = contract.TemporalChildRelationProfileV1;
pub const TemporalParentArtifactViewV1 = contract.TemporalParentArtifactViewV1;
pub const TemporalParentProofCapabilitiesV1 = contract.TemporalParentProofCapabilitiesV1;
pub const CURRENT_TEMPORAL_PARENT_CAPABILITIES = contract.CURRENT_TEMPORAL_PARENT_CAPABILITIES;
pub const OUTER_CONFIG = contract.OUTER_CONFIG;
pub const SourceCustodyCapabilitiesV1 = contract.SourceCustodyCapabilitiesV1;
pub const ProofContractCapabilitiesV1 = contract.ProofContractCapabilitiesV1;
pub const CURRENT_PROOF_CAPABILITIES = contract.CURRENT_PROOF_CAPABILITIES;
pub const Receipt = contract.Receipt;
pub const proveAndVerifyCurrent = legacy_engine.proveAndVerifyCurrent;
pub const EngineKernel = legacy_engine.EngineKernel;
pub const EngineKernelForManifest = legacy_engine.EngineKernelForManifest;
pub const NativeEngineKernelForManifest = native_engine.NativeEngineKernelForManifest;
pub const NativeCoreEngineKernelForManifest =
    native_core_engine.NativeCoreEngineKernelForManifest;

const TemporalVerifierSuccessEvidenceStorageV1 =
    contract.TemporalVerifierSuccessEvidenceStorageV1;
const mintTemporalVerifierSuccessEvidence =
    contract.mintTemporalVerifierSuccessEvidence;
const ProofExecutionPool = outer_support.ProofExecutionPool;
const temporalVerifierEvidenceIdentity =
    outer_support.temporalVerifierEvidenceIdentity;

test "binary outer execution pool preserves an explicit serial control" {
    var execution_pool: ProofExecutionPool = .{};
    try execution_pool.initInPlace(std.testing.allocator, 1);
    defer execution_pool.deinit();

    try std.testing.expectEqual(@as(usize, 1), try execution_pool.visibleWorkerCount());
    try std.testing.expect(prover_work_pool.getGlobalPool() == null);
}

test "binary outer execution pool exposes the exact requested width" {
    var execution_pool: ProofExecutionPool = .{};
    try execution_pool.initInPlace(std.testing.allocator, 4);
    defer execution_pool.deinit();

    try std.testing.expectEqual(@as(usize, 4), try execution_pool.visibleWorkerCount());
    try std.testing.expect(prover_work_pool.getGlobalPool() == &execution_pool.pool);
}

test "binary outer execution pool rejects invalid widths before binding" {
    var execution_pool: ProofExecutionPool = .{};
    try std.testing.expectError(
        error.InvalidWorkerBudget,
        execution_pool.initInPlace(std.testing.allocator, 0),
    );
    try std.testing.expect(prover_work_pool.getGlobalPool() == null);
}

test "temporal verifier success capability rejects mutation and forged storage" {
    const binding = TemporalVerifierSuccessBindingV1{
        .canonical_proof_byte_count = 97,
        .proof_id = @splat(1),
        .canonical_proof_sha_id = @splat(2),
        .capture_id = @splat(3),
        .transcript_id = @splat(10),
        .cohort_authority_sha_id = @splat(4),
        .manifest_sha_id = @splat(5),
        .claims_sha_id = @splat(6),
        .generated_interactions_sha_id = @splat(7),
        .audit_sha_id = @splat(8),
        .closure_receipt_sha_id = @splat(9),
        .recursive_admission_sha_id = @splat(11),
    };
    var storage: TemporalVerifierSuccessEvidenceStorageV1 = undefined;
    const evidence = try mintTemporalVerifierSuccessEvidence(&storage, binding);
    try std.testing.expectEqualDeep(
        binding,
        try openTemporalVerifierSuccessEvidence(evidence),
    );

    var forged = storage;
    forged.binding.capture_id[0] +%= 1;
    try std.testing.expectError(
        error.TemporalVerifierEvidenceMismatch,
        openTemporalVerifierSuccessEvidence(@ptrCast(&forged)),
    );
    forged = storage;
    forged.binding.audit_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.TemporalVerifierEvidenceMismatch,
        openTemporalVerifierSuccessEvidence(@ptrCast(&forged)),
    );
    forged = storage;
    forged.binding.recursive_admission_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.TemporalVerifierEvidenceMismatch,
        openTemporalVerifierSuccessEvidence(@ptrCast(&forged)),
    );
    forged = storage;
    forged.verified = false;
    forged.identity = temporalVerifierEvidenceIdentity(&forged);
    try std.testing.expectError(
        error.TemporalVerifierEvidenceMismatch,
        openTemporalVerifierSuccessEvidence(@ptrCast(&forged)),
    );
    forged = storage;
    forged.identity[0] ^= 1;
    try std.testing.expectError(
        error.TemporalVerifierEvidenceMismatch,
        openTemporalVerifierSuccessEvidence(@ptrCast(&forged)),
    );
    try std.testing.expect(!TEMPORAL_VERIFIER_PUBLIC_MINT_AVAILABLE);
}
