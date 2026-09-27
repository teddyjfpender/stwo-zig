//! Versioned rows 0--9 source for native resumed-segment transcripts.
//!
//! The frozen V1 rows assume one header-framed operation per verifier step and
//! a 412-word statement.  The native V2 transcript deliberately has neither
//! property: it replays ordinary channel calls and absorbs a variable,
//! authenticated segment wire.  This source therefore publishes a disjoint
//! V2 manifest while retaining the existing typed relation domains, tuple
//! arities, row ordering and shared Poseidon-provider call ABI.
//!
//! `PreparedV2` is value-only.  Hot publication accepts caller-owned exact-size
//! buffers, performs every authority/shape/alias check before the first store,
//! and then writes in canonical roster order without allocating.  Native
//! identities are custody seals, not MACs; the 36-row integration must still
//! constrain the authority words and close every emitted relation.  Until that
//! bundle independently proves and verifies, `productionReady` is false.
const shard_0 = @import("segment_transcript_outer_source_v2_contract.zig");
const shard_1 = @import("segment_transcript_outer_source_v2_prepared_v2.zig");
const shard_2 = @import("segment_transcript_outer_source_v2_write_rows_assume_valid.zig");
const shard_3 = @import("segment_transcript_outer_source_v2_write_into.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const MANIFEST_VERSION = shard_0.MANIFEST_VERSION;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const LAST_ROW = shard_0.LAST_ROW;
pub const VERIFIER_ID = shard_0.VERIFIER_ID;
pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const SOURCE_ID_DOMAIN = shard_0.SOURCE_ID_DOMAIN;
pub const MANIFEST_ID_DOMAIN = shard_0.MANIFEST_ID_DOMAIN;
pub const RANGE_ID_DOMAIN = shard_0.RANGE_ID_DOMAIN;
pub const AUTHORITY_INPUT_KIND = shard_0.AUTHORITY_INPUT_KIND;
pub const HOT_HEAP_ALLOCATIONS = shard_0.HOT_HEAP_ALLOCATIONS;
pub const TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE = shard_0.TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE = shard_0.RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const FROZEN_V1_ROW_COMPATIBLE = shard_0.FROZEN_V1_ROW_COMPATIBLE;
pub const REQUIRES_VERSIONED_OUTER_MANIFEST = shard_0.REQUIRES_VERSIONED_OUTER_MANIFEST;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const Digest = shard_0.Digest;
pub const ProviderCall = shard_0.ProviderCall;
pub const ControlRowV2 = shard_0.ControlRowV2;
pub const TranscriptAirRowV2 = shard_0.TranscriptAirRowV2;
pub const Error = shard_0.Error;
/// Exact dynamic geometry for V2 rows 0--9.  Counts are logical rows; each
/// `log_size` is the smallest admitted power-of-two trace with the universal
/// minimum of sixteen rows.
pub const ManifestV2 = shard_0.ManifestV2;
pub const CountsV2 = shard_0.CountsV2;
/// The three native identities that the V2 integration must make
/// proof-visible.  `canonicalWords` is deliberately allocation-free.
pub const AuthorityBindingV2 = shard_0.AuthorityBindingV2;
/// Pointer-free source receipt retained by the outer integration bundle.
pub const PreparedV2 = shard_1.PreparedV2;
/// Checked half-open ownership range in the single shared row-34 provider.
pub const PoseidonRequestRangeV2 = shard_1.PoseidonRequestRangeV2;
pub const TranscriptBindingRowV2 = shard_1.TranscriptBindingRowV2;
pub const TranscriptStateRowV2 = shard_1.TranscriptStateRowV2;
pub const TranscriptWordRowV2 = shard_1.TranscriptWordRowV2;
pub const PayloadSourceKindV2 = shard_1.PayloadSourceKindV2;
/// V2 replacement for frozen row 5's fixed statement-source metadata.
pub const TranscriptPayloadRowV2 = shard_1.TranscriptPayloadRowV2;
pub const PowCheckRowV2 = shard_1.PowCheckRowV2;
pub const PowFrameRowV2 = shard_1.PowFrameRowV2;
pub const RelationChallengeRowV2 = shard_1.RelationChallengeRowV2;
pub const VerifierRandomnessRowV2 = shard_1.VerifierRandomnessRowV2;
/// One exact universal relation event.  `arity` is checked against the pinned
/// registry; unused tuple lanes are canonical zero.  `multiplicity` retains
/// zero-weight AIR events so event ordinal/order stays identical to the typed
/// component definition.
pub const RelationEventV2 = shard_1.RelationEventV2;
pub const DestinationsV2 = shard_1.DestinationsV2;
pub const preflight = shard_1.preflight;
/// Fail-atomic pointer-free publication into caller storage.
pub const prepareInto = shard_1.prepareInto;
/// Revalidates every authority and destination before writing any row, event,
/// or provider request.  The post-preflight loops are allocation-free and
/// infallible over the admitted geometry.
pub const writeInto = shard_3.writeInto;
