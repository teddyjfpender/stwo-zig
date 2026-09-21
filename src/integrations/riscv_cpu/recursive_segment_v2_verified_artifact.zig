//! Compatibility aliases for the shared recursion owner.
const implementation = @import("stwo_riscv_frontend").recursion.segment_verified_artifact_v2;

pub const Digest = implementation.Digest;
pub const Publication = implementation.Publication;
pub const OuterProofCapture = implementation.OuterProofCapture;
pub const FORMAT_VERSION = implementation.FORMAT_VERSION;
pub const SCHEMA_VERSION = implementation.SCHEMA_VERSION;
pub const TRANSCRIPT_PREFIX_FORMAT_VERSION = implementation.TRANSCRIPT_PREFIX_FORMAT_VERSION;
pub const OUTER_ADMISSION_FORMAT_VERSION = implementation.OUTER_ADMISSION_FORMAT_VERSION;
pub const OUTER_ADMISSION_SCHEMA_VERSION = implementation.OUTER_ADMISSION_SCHEMA_VERSION;
pub const CLAIM_COUNT = implementation.CLAIM_COUNT;
pub const RELATION_DRAW_COUNT = implementation.RELATION_DRAW_COUNT;
pub const POSEIDON2_PARTIAL_COUNT = implementation.POSEIDON2_PARTIAL_COUNT;
pub const POSEIDON2_ROSTER_ROW = implementation.POSEIDON2_ROSTER_ROW;
pub const RELATION_DRAWS_ID_DOMAIN = implementation.RELATION_DRAWS_ID_DOMAIN;
pub const POSEIDON2_PARTIALS_ID_DOMAIN = implementation.POSEIDON2_PARTIALS_ID_DOMAIN;
pub const WITNESS_ID_DOMAIN = implementation.WITNESS_ID_DOMAIN;
pub const TRANSCRIPT_PREFIX_ID_DOMAIN = implementation.TRANSCRIPT_PREFIX_ID_DOMAIN;
pub const OUTER_ADMISSION_ID_DOMAIN = implementation.OUTER_ADMISSION_ID_DOMAIN;
pub const POINTER_FREE = implementation.POINTER_FREE;
pub const HEAP_ALLOCATIONS_PER_VALIDATE = implementation.HEAP_ALLOCATIONS_PER_VALIDATE;
pub const RETAINED_PROOF_BYTES = implementation.RETAINED_PROOF_BYTES;
pub const PUBLIC_MINT_CONSTRUCTOR_AVAILABLE = implementation.PUBLIC_MINT_CONSTRUCTOR_AVAILABLE;
pub const CAPTURE_ID_HASHES_PER_PREFLIGHT = implementation.CAPTURE_ID_HASHES_PER_PREFLIGHT;
pub const Error = implementation.Error;
pub const OuterAdmissionReceiptV2 = implementation.OuterAdmissionReceiptV2;
pub const TranscriptPrefixV1 = implementation.TranscriptPrefixV1;
pub const preflight = implementation.preflight;
pub const preflightAgainstValidatedPublication = implementation.preflightAgainstValidatedPublication;
pub const preflightAgainstValidatedPublicationAndManifest = implementation.preflightAgainstValidatedPublicationAndManifest;
pub const RecursiveWitnessV1 = implementation.RecursiveWitnessV1;
pub const relationDrawsId = implementation.relationDrawsId;
pub const poseidon2PartialsId = implementation.poseidon2PartialsId;
pub const witnessId = implementation.witnessId;
pub const outerAdmissionReceiptId = implementation.outerAdmissionReceiptId;
pub const transcriptPrefixId = implementation.transcriptPrefixId;

test "segment V2 recursive witness exposes no detached mint constructor" {
    try implementation.testNoDetachedMint();
}
