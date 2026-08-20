//! Versioned segment-leaf source for resumed-execution recursion.
//!
//! The frozen V1 leaf row publishes exactly 412 statement words at a fixed
//! log size.  A resumed segment has a variable authenticated V2 wire whose
//! retained sparse value and predecessor-clock sections are part of the
//! statement.  This module therefore defines a new row/manifest schema; it
//! never truncates the wire, aliases it to the V1 row geometry, or changes any
//! V1 type.
//!
//! The source consumes only `PublicDataV2`, which re-authenticates the complete
//! `segment_statement_v2` wire, and `public_logup_v2`, which derives exact
//! verifier compensation from that same retained boundary.  Two existing
//! universal relation ABIs are reused without changing their registry order:
//!
//! - every V2 wire/context word is emitted as a scoped
//!   `recursion_statement_word(scope,index,value)` tuple;
//! - challenge-dependent public LogUp words are consumed as canonical
//!   `recursion_verifier_input_word(verifier,kind,index,0,value)` tuples.
//!
//! The first relation requires a versioned V2 row manifest because its logical
//! length is variable.  `ManifestV2` says that explicitly and cannot be
//! admitted as frozen roster row 10 without an outer-driver V2 manifest.
//!
//! Native Poseidon2-M31 temporal identities and SHA-256 closure provenance are
//! published in distinct types.  No byte digest is reinterpreted as a native
//! temporal digest.  All hot writes are allocation-free, exact-size and
//! failure-atomic.
//!
//! This is a source/authority contract.  It does not add the V2 component to
//! the frozen 36-row proof and does not claim recursive proof activation.
const shard_0 = @import("segment_leaf_authority_v2_contract.zig");
const shard_1 = @import("segment_leaf_authority_v2_source_preflight_public_log_up_publication_v2.zig");
const shard_2 = @import("segment_leaf_authority_v2_authority_hash_poseidon_plan_v2.zig");
const shard_3 = @import("segment_leaf_authority_v2_publish_cohort_handoff_into.zig");

pub const Digest = shard_0.Digest;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const MANIFEST_VERSION = shard_0.MANIFEST_VERSION;
pub const KNOWN_FLAGS = shard_0.KNOWN_FLAGS;
pub const WIRE_SCOPE = shard_0.WIRE_SCOPE;
pub const CONTEXT_SCOPE = shard_0.CONTEXT_SCOPE;
pub const SEGMENT_V2_VERIFIER_ID = shard_0.SEGMENT_V2_VERIFIER_ID;
pub const PUBLIC_LOGUP_V2_KIND = shard_0.PUBLIC_LOGUP_V2_KIND;
/// Recursion-local custody bridge from source component 37 to rows 12--14.
pub const PUBLICATION_BRIDGE_CIRCUIT_ID = shard_0.PUBLICATION_BRIDGE_CIRCUIT_ID;
pub const CONTEXT_TAG = shard_0.CONTEXT_TAG;
pub const LOGUP_TAG = shard_0.LOGUP_TAG;
pub const VERIFIED_NATIVE_LOGUP_TAG = shard_0.VERIFIED_NATIVE_LOGUP_TAG;
pub const FORMAT_ID_DOMAIN = shard_0.FORMAT_ID_DOMAIN;
pub const MANIFEST_ID_DOMAIN = shard_0.MANIFEST_ID_DOMAIN;
pub const VK_AUTHORITY_ID_DOMAIN = shard_0.VK_AUTHORITY_ID_DOMAIN;
pub const CONTEXT_ID_DOMAIN = shard_0.CONTEXT_ID_DOMAIN;
pub const SOURCE_ID_DOMAIN = shard_0.SOURCE_ID_DOMAIN;
pub const LOGUP_RELATION_ID_DOMAIN = shard_0.LOGUP_RELATION_ID_DOMAIN;
pub const LOGUP_PUBLICATION_ID_DOMAIN = shard_0.LOGUP_PUBLICATION_ID_DOMAIN;
pub const VERIFIED_NATIVE_LOGUP_ID_DOMAIN = shard_0.VERIFIED_NATIVE_LOGUP_ID_DOMAIN;
pub const AUTHORITY_HASH_PLAN_ID_DOMAIN = shard_0.AUTHORITY_HASH_PLAN_ID_DOMAIN;
pub const NATIVE_PUBLICATION_ID_DOMAIN = shard_0.NATIVE_PUBLICATION_ID_DOMAIN;
pub const STATEMENT_RELATION_DOMAIN = shard_0.STATEMENT_RELATION_DOMAIN;
pub const VERIFIER_INPUT_RELATION_DOMAIN = shard_0.VERIFIER_INPUT_RELATION_DOMAIN;
pub const STATEMENT_RELATION_ARITY = shard_0.STATEMENT_RELATION_ARITY;
pub const VERIFIER_INPUT_RELATION_ARITY = shard_0.VERIFIER_INPUT_RELATION_ARITY;
pub const FROZEN_V1_ROSTER_ROW = shard_0.FROZEN_V1_ROSTER_ROW;
pub const CONTEXT_WORD_COUNT = shard_0.CONTEXT_WORD_COUNT;
pub const CONTEXT_PREFIX_WORD_COUNT = shard_0.CONTEXT_PREFIX_WORD_COUNT;
pub const CONTEXT_SEGMENT_WIRE_ID_DIGEST_ORDINAL = shard_0.CONTEXT_SEGMENT_WIRE_ID_DIGEST_ORDINAL;
pub const CONTEXT_SEGMENT_WIRE_ID_START = shard_0.CONTEXT_SEGMENT_WIRE_ID_START;
pub const LOGUP_PUBLICATION_WORD_COUNT = shard_0.LOGUP_PUBLICATION_WORD_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = shard_0.PREPROCESSED_COLUMN_COUNT;
pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const INTERACTION_COLUMN_COUNT = shard_0.INTERACTION_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = shard_0.DIRECT_CONSTRAINT_COUNT;
pub const INTERACTION_BATCH_COUNT = shard_0.INTERACTION_BATCH_COUNT;
pub const PROTOCOL_CONSTRAINT_DEGREE = shard_0.PROTOCOL_CONSTRAINT_DEGREE;
pub const HOT_HEAP_ALLOCATIONS = shard_0.HOT_HEAP_ALLOCATIONS;
pub const TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE = shard_0.TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE = shard_0.RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const FROZEN_V1_ROW_COMPATIBLE = shard_0.FROZEN_V1_ROW_COMPATIBLE;
pub const REQUIRES_VERSIONED_OUTER_MANIFEST = shard_0.REQUIRES_VERSIONED_OUTER_MANIFEST;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const AUTHORITY_HASH_SHARED_PROVIDER_REQUESTS_AVAILABLE = shard_0.AUTHORITY_HASH_SHARED_PROVIDER_REQUESTS_AVAILABLE;
pub const AUTHORITY_HASH_REQUEST_AIR_CLOSURE_AVAILABLE = shard_0.AUTHORITY_HASH_REQUEST_AIR_CLOSURE_AVAILABLE;
pub const AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT = shard_0.AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT;
pub const AUTHORITY_HASH_WORDS_PER_DESCRIPTOR = shard_0.AUTHORITY_HASH_WORDS_PER_DESCRIPTOR;
pub const Error = shard_0.Error;
pub const Activation = shard_0.Activation;
/// Cold verifier-key authority.  The outer driver constructs this from its
/// admitted leaf and recursive-parent verification keys; both native digests
/// become proof-visible context words.
pub const VerifierKeyAuthorityV2 = shard_0.VerifierKeyAuthorityV2;
/// Geometry for a new V2 statement-source row.  `frozen_v1_row_compatible` is
/// deliberately false even when a small wire happens to fit in 2^11 rows.
pub const ManifestV2 = shard_0.ManifestV2;
/// Native temporal preimage retained separately from every SHA closure ID.
pub const NativeTemporalContextV2 = shard_0.NativeTemporalContextV2;
pub const PerformanceV2 = shard_0.PerformanceV2;
/// SHA identities consumed by global-closure plumbing.  These byte values are
/// never accepted where a native temporal `Digest` is required.
pub const ShaTupleEvidenceV2 = shard_1.ShaTupleEvidenceV2;
/// Pointer-free source receipt.  The full wire is retained in the caller's
/// `PublicDataV2`; this receipt binds it transitively through `segment_wire_id`
/// and is re-derived before every hot write.
pub const PreparedV2 = shard_1.PreparedV2;
/// SoA trace destinations for the new V2 statement-source row.
pub const TraceColumnsV2 = shard_1.TraceColumnsV2;
pub const StatementRelationEventV2 = shard_1.StatementRelationEventV2;
/// Allocation geometry obtained only after authenticating the borrowed wire.
/// Drivers use this cold preflight before allocating reusable trace/event slabs;
/// hot publication remains allocation-free.
pub const PreflightV2 = shard_1.PreflightV2;
pub const preflight = shard_1.preflight;
/// Derive and publish one complete V2 source and its trace transactionally.
/// Every validation, alias check and size check completes before any output is
/// modified.  No allocation occurs.
pub const prepareInto = shard_1.prepareInto;
/// Revalidated trace refill for a reusable preallocated worker slab.
pub const writeTraceInto = shard_1.writeTraceInto;
/// Exact logical relation multiset for closure/audit consumers.  Padding rows
/// are inactive and intentionally absent from this compact publication.
pub const writeStatementRelationEventsInto = shard_1.writeStatementRelationEventsInto;
/// Allocation-free source preflight over the uncompensated public boundary.
///
/// This value is useful for typed-AIR authoring and trace-shape validation,
/// but it is not evidence that a native proof verified.  Production callers
/// must use the separately typed capture-backed publication below; retaining
/// this explicit name prevents a bare recomputation from acquiring verifier
/// custody by accident.
pub const SourcePreflightPublicLogUpPublicationV2 = shard_1.SourcePreflightPublicLogUpPublicationV2;
/// Compatibility spelling for existing source-preflight callers.  New code
/// should name the provenance explicitly and must not treat this alias as a
/// successful native-verifier receipt.
pub const PublicLogUpPublicationV2 = shard_1.PublicLogUpPublicationV2;
/// Exact native-verifier compensation admitted from a successful verifier
/// capture.  The full receipt and native-sum seals are retained as typed
/// fields, while their identities are folded into the final canonical word so
/// the 55-word verifier-input ABI remains fixed.
///
/// This is stronger than source preflight but still not an outer-proof
/// receipt: `productionReady` remains false until the authority hash program
/// and every other universal domain close inside a verified outer STARK.
pub const VerifiedNativePublicLogUpPublicationV2 = shard_2.VerifiedNativePublicLogUpPublicationV2;
/// Value-only plan for the exact Poseidon2-M31 program used by
/// `statement_v2.authorityIdentityFromGeometry`.  It does not retain borrowed
/// descriptor or wire storage.  Every append re-authenticates those sources,
/// replays the canonical encoder and checks the final digest before exposing
/// calls to the single shared row-34 provider.
pub const AuthorityHashPoseidonPlanV2 = shard_2.AuthorityHashPoseidonPlanV2;
pub const VerifierInputEventV2 = shard_2.VerifierInputEventV2;
pub const preparePublicLogUpInto = shard_2.preparePublicLogUpInto;
/// Allocation-free, fail-atomic construction from verifier-owned custody.
/// Callers at the integration boundary must invoke their capture-level
/// validation first; this function independently revalidates every value it
/// consumes and recomputes the statement authority from the authenticated
/// wire and verifier-owned component geometry.
pub const prepareVerifiedNativePublicLogUpInto = shard_2.prepareVerifiedNativePublicLogUpInto;
pub const writeVerifierInputEventsInto = shard_2.writeVerifierInputEventsInto;
pub const writeVerifiedNativeVerifierInputEventsInto = shard_2.writeVerifiedNativeVerifierInputEventsInto;
/// Native verifier handoff.  SHA tuple evidence is not embedded here.
pub const NativeTemporalPublicationV2 = shard_2.NativeTemporalPublicationV2;
/// Closure plumbing keeps byte identities in their native SHA representation.
pub const ShaClosurePublicationV2 = shard_2.ShaClosurePublicationV2;
pub const CohortHandoffV2 = shard_3.CohortHandoffV2;
/// Transactional preimage for the full outer driver.  The driver must bind the
/// two SHA tuple publications into its V2 global-closure receipt and publish
/// `native` only after independent proof verification succeeds.
pub const publishCohortHandoffInto = shard_3.publishCohortHandoffInto;
pub const formatId = shard_0.formatId;
pub const authorityIdentityPoseidonPermutationCount = shard_1.authorityIdentityPoseidonPermutationCount;
/// Exact one-pass identity cost after authenticated public LogUp calculation:
/// relation challenge context plus public LogUp publication identity.
pub const publicLogUpIdentityPoseidonPermutationCount = shard_3.publicLogUpIdentityPoseidonPermutationCount;
/// Exact one-pass identity cost for the self-contained native cohort receipt.
pub const cohortHandoffIdentityPoseidonPermutationCount = shard_3.cohortHandoffIdentityPoseidonPermutationCount;
