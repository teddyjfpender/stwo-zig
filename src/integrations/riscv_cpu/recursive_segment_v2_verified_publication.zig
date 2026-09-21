//! Compatibility aliases for the shared recursion owner.
const implementation = @import("stwo_riscv_frontend").recursion.segment_verified_publication_v2;

pub const Digest = implementation.Digest;
pub const Sha256Digest = implementation.Sha256Digest;
pub const Qm31Words = implementation.Qm31Words;
pub const OuterProofCapture = implementation.OuterProofCapture;
pub const FORMAT_VERSION = implementation.FORMAT_VERSION;
pub const PUBLICATION_SCHEMA_VERSION = implementation.PUBLICATION_SCHEMA_VERSION;
pub const CLOSURE_SCHEMA_VERSION = implementation.CLOSURE_SCHEMA_VERSION;
pub const STATEMENT_VERSION = implementation.STATEMENT_VERSION;
pub const PROVED_COMPONENT_COUNT = implementation.PROVED_COMPONENT_COUNT;
pub const UNIVERSAL_ROSTER_COUNT = implementation.UNIVERSAL_ROSTER_COUNT;
pub const RELATION_DOMAIN_COUNT = implementation.RELATION_DOMAIN_COUNT;
pub const COMPLETE_COMPONENT_MASK = implementation.COMPLETE_COMPONENT_MASK;
pub const COMPLETE_DOMAIN_MASK = implementation.COMPLETE_DOMAIN_MASK;
pub const MANIFEST_ID_DOMAIN = implementation.MANIFEST_ID_DOMAIN;
pub const AIR_PROGRAM_ID_DOMAIN = implementation.AIR_PROGRAM_ID_DOMAIN;
pub const PROFILE_ID_DOMAIN = implementation.PROFILE_ID_DOMAIN;
pub const CLAIMED_SUMS_ID_DOMAIN = implementation.CLAIMED_SUMS_ID_DOMAIN;
pub const RELATION_REPLAY_ID_DOMAIN = implementation.RELATION_REPLAY_ID_DOMAIN;
pub const AUXILIARY_CLAIM_ID_DOMAIN = implementation.AUXILIARY_CLAIM_ID_DOMAIN;
pub const VERIFIER_RECEIPT_ID_DOMAIN = implementation.VERIFIER_RECEIPT_ID_DOMAIN;
pub const CONTEXT_ID_DOMAIN = implementation.CONTEXT_ID_DOMAIN;
pub const PUBLICATION_ID_DOMAIN = implementation.PUBLICATION_ID_DOMAIN;
pub const HEAP_ALLOCATIONS_PER_VALIDATE = implementation.HEAP_ALLOCATIONS_PER_VALIDATE;
pub const HEAP_ALLOCATIONS_PER_PUBLICATION = implementation.HEAP_ALLOCATIONS_PER_PUBLICATION;
pub const BORROWED_STORAGE_AFTER_PUBLICATION = implementation.BORROWED_STORAGE_AFTER_PUBLICATION;
pub const POINTER_FREE_PUBLICATION = implementation.POINTER_FREE_PUBLICATION;
pub const SUCCESSFUL_VERIFIER_TRANSACTION_REQUIRED = implementation.SUCCESSFUL_VERIFIER_TRANSACTION_REQUIRED;
pub const PUBLIC_MINT_CONSTRUCTOR_AVAILABLE = implementation.PUBLIC_MINT_CONSTRUCTOR_AVAILABLE;
pub const COMPLETE_SEGMENT_CHILD_CAPABILITY = implementation.COMPLETE_SEGMENT_CHILD_CAPABILITY;
pub const COMPLETE_PARENT_CAPABILITY = implementation.COMPLETE_PARENT_CAPABILITY;
pub const RECURSIVE_WITNESS_REQUIRED = implementation.RECURSIVE_WITNESS_REQUIRED;
pub const Error = implementation.Error;
pub const ProofScopeV1 = implementation.ProofScopeV1;
pub const ProofEncodingV1 = implementation.ProofEncodingV1;
pub const VerifiedClosureReceiptV1 = implementation.VerifiedClosureReceiptV1;
pub const VerifiedSegmentV2PublicationV1 = implementation.VerifiedSegmentV2PublicationV1;
pub const expectedManifestId = implementation.expectedManifestId;
pub const captureIdentity = implementation.captureIdentity;
pub const expectedAirProgramId = implementation.expectedAirProgramId;
pub const expectedProfileId = implementation.expectedProfileId;
pub const expectedClaimedSumsId = implementation.expectedClaimedSumsId;
pub const expectedRelationReplayId = implementation.expectedRelationReplayId;
pub const expectedAuxiliaryClaimSealId = implementation.expectedAuxiliaryClaimSealId;
pub const expectedVerifierContextId = implementation.expectedVerifierContextId;
pub const expectedVerifierReceiptId = implementation.expectedVerifierReceiptId;
pub const expectedTemporalClosureId = implementation.expectedTemporalClosureId;
pub const expectedPublicationId = implementation.expectedPublicationId;

test "SegmentV2 verified publication exposes no public mint constructor" {
    try implementation.testNoPublicMint();
}
