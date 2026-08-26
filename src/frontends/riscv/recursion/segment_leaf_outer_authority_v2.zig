//! V2 recursive leaf-outer authority and allocation-free focused driver.
//!
//! The frozen 36-row V1 manifest cannot represent a variable resumed-segment
//! wire. This module therefore owns a disjoint V2 manifest containing two
//! typed components:
//!
//! * every authenticated statement/context word emitted by
//!   `segment_leaf_authority_v2`;
//! * all 55 words of its public-LogUp publication consumed as verifier input
//!   and emitted onto the circuit-44 recursion-wire custody bridge.
//!
//! Cold setup owns typed definitions and reusable scratch. Hot preparation and
//! independent authority verification allocate nothing, authenticate every
//! event, evaluate every direct constraint, and generate framework-exact
//! interaction traces with one bulk inversion per component. Relation-domain
//! boundary claims remain distinct, so aggregate cross-domain cancellation is
//! never accepted as closure.
//!
//! Native V2 STARK prove/verify/capture APIs exist and feed the capture-backed
//! preparation path below. This two-source authority is nevertheless not an
//! outer-proof receipt or a complete temporal parent. Production activation
//! remains fail-closed until these sources and their routing consumers are
//! proved together by the complete recursive outer STARK.
const shard_0 = @import("segment_leaf_outer_authority_v2_contract.zig");
const shard_1 = @import("segment_leaf_outer_authority_v2_workspace_v2.zig");
const shard_2 = @import("segment_leaf_outer_authority_v2_verify_authority_into.zig");
const shard_3 = @import("segment_leaf_outer_authority_v2_prepare_native_verifier_into.zig");

pub const NativeDigest = shard_0.NativeDigest;
pub const Sha256Digest = shard_0.Sha256Digest;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const MANIFEST_VERSION = shard_0.MANIFEST_VERSION;
pub const COMPONENT_COUNT = shard_0.COMPONENT_COUNT;
pub const PUBLIC_LOGUP_LOGICAL_ROWS = shard_0.PUBLIC_LOGUP_LOGICAL_ROWS;
pub const PUBLIC_LOGUP_TRACE_LOG_SIZE = shard_0.PUBLIC_LOGUP_TRACE_LOG_SIZE;
pub const PUBLIC_LOGUP_TRACE_ROWS = shard_0.PUBLIC_LOGUP_TRACE_ROWS;
pub const STATEMENT_COMPONENT_TAG = shard_0.STATEMENT_COMPONENT_TAG;
pub const PUBLIC_LOGUP_COMPONENT_TAG = shard_0.PUBLIC_LOGUP_COMPONENT_TAG;
pub const MANIFEST_ID_DOMAIN = shard_0.MANIFEST_ID_DOMAIN;
pub const PREPARED_ID_DOMAIN = shard_0.PREPARED_ID_DOMAIN;
pub const NATIVE_CAPTURE_PREPARED_ID_DOMAIN = shard_0.NATIVE_CAPTURE_PREPARED_ID_DOMAIN;
pub const VERIFICATION_ID_DOMAIN = shard_0.VERIFICATION_ID_DOMAIN;
pub const PUBLICATION_ID_DOMAIN = shard_0.PUBLICATION_ID_DOMAIN;
pub const SHA256_ENCODING_TAG = shard_0.SHA256_ENCODING_TAG;
pub const HOT_PREPARE_HEAP_ALLOCATIONS = shard_0.HOT_PREPARE_HEAP_ALLOCATIONS;
pub const HOT_VERIFY_HEAP_ALLOCATIONS = shard_0.HOT_VERIFY_HEAP_ALLOCATIONS;
pub const HOT_PUBLISH_HEAP_ALLOCATIONS = shard_0.HOT_PUBLISH_HEAP_ALLOCATIONS;
pub const INTERACTION_BULK_INVERSIONS = shard_0.INTERACTION_BULK_INVERSIONS;
pub const ALL_AUTHORITY_EVENTS_CHECKED = shard_0.ALL_AUTHORITY_EVENTS_CHECKED;
pub const ALL_PUBLIC_LOGUP_WORDS_CHECKED = shard_0.ALL_PUBLIC_LOGUP_WORDS_CHECKED;
pub const NATIVE_V2_PROOF_API_AVAILABLE = shard_0.NATIVE_V2_PROOF_API_AVAILABLE;
pub const OUTER_STARK_VERIFICATION_AVAILABLE = shard_0.OUTER_STARK_VERIFICATION_AVAILABLE;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const COMPLETE_TEMPORAL_PARENT = shard_0.COMPLETE_TEMPORAL_PARENT;
pub const Error = shard_0.Error;
pub const ComponentKindV2 = shard_0.ComponentKindV2;
pub const ComponentGeometryV2 = shard_0.ComponentGeometryV2;
/// V2-only component manifest. Its native identity binds the SHA typed-AIR
/// authority through an explicit byte encoding; the two digest types remain
/// distinct fields and are never bit-cast or substituted.
pub const OuterManifestV2 = shard_0.OuterManifestV2;
pub const PreflightV2 = shard_0.PreflightV2;
pub const preflight = shard_0.preflight;
/// Cold typed-program owner. Hot paths revalidate the immutable programs but
/// never allocate; all digest and plan recomputation is stack-only.
pub const AuthorityV2 = shard_0.AuthorityV2;
pub const StatementTraceV2 = shard_0.StatementTraceV2;
pub const PublicLogUpTraceV2 = shard_0.PublicLogUpTraceV2;
pub const TracesV2 = shard_0.TracesV2;
/// Cold, worker-private reusable storage. All arrays are exact-capacity for
/// one authenticated manifest; no resize or fallback allocation exists.
pub const WorkspaceV2 = shard_1.WorkspaceV2;
/// The two V2 components expose open boundaries in three universal relation
/// domains. They may be closed only against same-domain counterpart claims;
/// aggregate cancellation across domains is never accepted as custody.
pub const BoundaryClosureV2 = shard_1.BoundaryClosureV2;
/// Pointer-free result of trace preparation. SHA trace/evidence identities and
/// native temporal identities remain in separately typed fields.
pub const PreparedOuterAuthorityV2 = shard_1.PreparedOuterAuthorityV2;
/// Same two typed authority rows, but populated exclusively from a successful
/// native V2 verifier capture.  Compensated public sums, the sealed receipt,
/// the independently recomputed statement authority and its exact row-34
/// provider request plan cross this boundary as one value.
///
/// This still is not a recursive-proof receipt.  The authority-hash request
/// AIR and whole 36-row closure must consume this plan before production can
/// be enabled.
pub const PreparedNativeVerifierOuterAuthorityV2 = shard_1.PreparedNativeVerifierOuterAuthorityV2;
/// Independent authority-trace verifier receipt. `outer_stark_verified` is
/// fixed false: this is the exact landing point a future native V2 verifier
/// must extend, never a substitute for its proof receipt.
pub const AuthorityVerificationV2 = shard_1.AuthorityVerificationV2;
/// Publication permitted only after `verifyAuthorityInto` has independently
/// rebuilt and compared every trace cell. It is useful integration substrate,
/// but its capability bits prevent reinterpretation as a native proof.
pub const VerifiedAuthorityPublicationV2 = shard_2.VerifiedAuthorityPublicationV2;
/// Generates both typed component traces and their framework interaction
/// columns into caller-owned final storage. All fallible work targets retained
/// workspace staging; destinations and receipt commit only after both
/// components and both exact-domain claims succeed.
pub const prepareInto = shard_2.prepareInto;
/// Capture-backed preparation.  Every mutable capture sidecar is expected to
/// have passed its capture-level verifier check at the integration boundary;
/// this authority independently revalidates the receipt, wire, compensated
/// sums and geometry-derived statement authority before committing any trace
/// cell or destination byte.
pub const prepareNativeVerifierInto = shard_3.prepareNativeVerifierInto;
/// Independent allocation-free verifier for an already prepared component
/// pair. The destination is untouched on every source, trace, claim, event,
/// relation-context, or identity failure.
pub const verifyAuthorityInto = shard_2.verifyAuthorityInto;
/// Publishes the source cohort only after the independent authority verifier
/// receipt above succeeds. This bare/source-preflight path remains
/// non-production because it does not accept successful native-verifier
/// custody; recursive ingestion uses `PreparedNativeVerifierOuterAuthorityV2`.
pub const publishVerifiedInto = shard_3.publishVerifiedInto;
/// Intentionally has no current success path. Constructing valid V2 traces or
/// a development authority receipt cannot manufacture native proof custody.
pub const publishProductionInto = shard_3.publishProductionInto;
