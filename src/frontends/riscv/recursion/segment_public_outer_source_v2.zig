//! Versioned source authority for resumed-segment public-spine rows 12--17.
//!
//! V1's public spine starts from a fixed complete-execution claim.  A resumed
//! V2 segment instead carries an authenticated variable wire and exact entry /
//! exit transition.  Reinterpreting that boundary as the frozen V1 claim would
//! either discard continuation state or count it twice.  This source therefore
//! owns a disjoint manifest and derives every row only from verifier-captured
//! `OwnedPublicDataV2`, its checked native public sums, and the capture-backed
//! 55-word publication.
//!
//! The native base-domain events are deliberately not replayed into the outer
//! 47-domain registry. Source component 37 consumes the 55 native-publication
//! words once and emits a distinct recursion-wire bridge. Rows 12--14 consume
//! that bridge in canonical partitions: 27 authority/header words, sixteen
//! four-domain sum limbs, then four total limbs plus the eight-word seal. Row
//! 11 similarly emits a distinct bridge for the authenticated boundary; row
//! 15 consumes it. Row 16 consumes the 32 native `(z, alpha)` limbs exactly
//! once. Only boundary, native sum/total, and challenge values are forwarded
//! to the single arithmetic circuit owned by rows 30--32. Row 17 consumes the
//! final publication-seal control relay.
//!
//! `PreparedV2` is pointer-free. `writeInto` validates every source, length,
//! and alias before its first store and performs no heap allocation. This is a
//! source contract, not a proof receipt: the capability ledger names every
//! missing V2 AIR/tree/component/global-proof integration and production stays
//! false until an independent complete outer STARK consumes it.
const shard_0 = @import("segment_public_outer_source_v2_contract.zig");
const shard_1 = @import("segment_public_outer_source_v2_arithmetic_graph_binding_v2.zig");
const shard_2 = @import("segment_public_outer_source_v2_write_into_bound.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const MANIFEST_VERSION = shard_0.MANIFEST_VERSION;
pub const FIRST_ROW = shard_0.FIRST_ROW;
pub const ROW_COUNT = shard_0.ROW_COUNT;
pub const LAST_ROW = shard_0.LAST_ROW;
pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const NATIVE_SUM_CIRCUIT_ID = shard_0.NATIVE_SUM_CIRCUIT_ID;
pub const CONTROL_RELAY_CIRCUIT_ID = shard_0.CONTROL_RELAY_CIRCUIT_ID;
pub const PUBLICATION_BRIDGE_CIRCUIT_ID = shard_0.PUBLICATION_BRIDGE_CIRCUIT_ID;
pub const BOUNDARY_BRIDGE_CIRCUIT_ID = shard_0.BOUNDARY_BRIDGE_CIRCUIT_ID;
pub const CONTROL_TAG = shard_0.CONTROL_TAG;
pub const MANIFEST_ID_DOMAIN = shard_0.MANIFEST_ID_DOMAIN;
pub const SOURCE_ID_DOMAIN = shard_0.SOURCE_ID_DOMAIN;
pub const LOWERING_OBLIGATION_ID_DOMAIN = shard_0.LOWERING_OBLIGATION_ID_DOMAIN;
pub const ARITHMETIC_BINDING_FORMAT_VERSION = shard_0.ARITHMETIC_BINDING_FORMAT_VERSION;
pub const ARITHMETIC_BINDING_ID_DOMAIN = shard_0.ARITHMETIC_BINDING_ID_DOMAIN;
pub const TRANSCRIPT_VERIFIER_ID = shard_0.TRANSCRIPT_VERIFIER_ID;
pub const CHALLENGE_COUNT = shard_0.CHALLENGE_COUNT;
pub const CHALLENGE_WORDS_PER_RELATION = shard_0.CHALLENGE_WORDS_PER_RELATION;
pub const CHALLENGE_WORD_COUNT = shard_0.CHALLENGE_WORD_COUNT;
pub const PUBLICATION_WORD_COUNT = shard_0.PUBLICATION_WORD_COUNT;
pub const PUBLICATION_HEADER_WORD_COUNT = shard_0.PUBLICATION_HEADER_WORD_COUNT;
pub const NATIVE_PUBLIC_SUM_WORD_COUNT = shard_0.NATIVE_PUBLIC_SUM_WORD_COUNT;
pub const PUBLICATION_SEAL_WORD_COUNT = shard_0.PUBLICATION_SEAL_WORD_COUNT;
pub const PUBLICATION_SUM_START = shard_0.PUBLICATION_SUM_START;
pub const PUBLICATION_SEAL_START = shard_0.PUBLICATION_SEAL_START;
pub const CONTROL_PUBLICATION_INDEX = shard_0.CONTROL_PUBLICATION_INDEX;
pub const NATIVE_TOTAL_WORD_COUNT = shard_0.NATIVE_TOTAL_WORD_COUNT;
pub const ARITHMETIC_PUBLICATION_WORD_COUNT = shard_0.ARITHMETIC_PUBLICATION_WORD_COUNT;
pub const CONTROL_LOGICAL_ROW_COUNT = shard_0.CONTROL_LOGICAL_ROW_COUNT;
pub const CONTROL_RELATION_EVENT_COUNT = shard_0.CONTROL_RELATION_EVENT_COUNT;
pub const AUTHORITY_BIND_EVENT_COUNT = shard_0.AUTHORITY_BIND_EVENT_COUNT;
pub const HOT_HEAP_ALLOCATIONS = shard_0.HOT_HEAP_ALLOCATIONS;
pub const TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE = shard_0.TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE = shard_0.RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const NATIVE_PUBLIC_SUM_CAPTURE_PARITY_CHECKED = shard_0.NATIVE_PUBLIC_SUM_CAPTURE_PARITY_CHECKED;
pub const ALL_55_PUBLICATION_BRIDGE_WORDS_CONSUMED = shard_0.ALL_55_PUBLICATION_BRIDGE_WORDS_CONSUMED;
pub const SHARED_CHALLENGE_WORDS_CONSUMED = shard_0.SHARED_CHALLENGE_WORDS_CONSUMED;
pub const BASE_DOMAIN_OUTER_EVENTS_EMITTED = shard_0.BASE_DOMAIN_OUTER_EVENTS_EMITTED;
pub const SOURCE_36_BOUNDARY_BRIDGE_AVAILABLE = shard_0.SOURCE_36_BOUNDARY_BRIDGE_AVAILABLE;
pub const SOURCE_37_PUBLICATION_BRIDGE_REQUIRED = shard_0.SOURCE_37_PUBLICATION_BRIDGE_REQUIRED;
pub const SOURCE_37_PUBLICATION_BRIDGE_AVAILABLE = shard_0.SOURCE_37_PUBLICATION_BRIDGE_AVAILABLE;
pub const FROZEN_V1_ROW_COMPATIBLE = shard_0.FROZEN_V1_ROW_COMPATIBLE;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const Digest = shard_0.Digest;
pub const Sha256Digest = shard_0.Sha256Digest;
pub const ControlLogicalRowV2 = shard_0.ControlLogicalRowV2;
/// Exact capabilities intentionally absent from this source-only lane.
pub const MissingIntegrationCapability = shard_0.MissingIntegrationCapability;
pub const MISSING_INTEGRATION_CAPABILITIES = shard_0.MISSING_INTEGRATION_CAPABILITIES;
pub const CapabilityLedgerV2 = shard_0.CapabilityLedgerV2;
pub const CAPABILITY_LEDGER = shard_0.CAPABILITY_LEDGER;
pub const Error = shard_0.Error;
pub const CountsV2 = shard_0.CountsV2;
/// Auditable producer/consumer table for every recursion-local edge touched
/// by rows 12--17. Source components 36 and 37 now publish both custody
/// bridges; arithmetic consumers remain deliberately fail-closed until the
/// complete 38-row graph binds their use counts.
pub const ClosureLedgerV2 = shard_0.ClosureLedgerV2;
pub const ManifestV2 = shard_0.ManifestV2;
pub const LoweringObligationV2 = shard_0.LoweringObligationV2;
/// Exact graph-derived multiplicities for the rows 13--16 arithmetic relay.
///
/// This pointer-bearing view is issued by the owning native-sum graph.  Its
/// identity binds every count and all public-source custody identifiers; the
/// production integration must additionally compare `circuit_identity` and
/// `graph_identity` with that graph owner.  The public source deliberately
/// cannot import its consumer, which would create a module cycle.
pub const ArithmeticGraphBindingV2 = shard_1.ArithmeticGraphBindingV2;
pub const PreparedV2 = shard_1.PreparedV2;
/// All values are borrowed from one successful native-verifier capture.  The
/// owned public-data wrapper prevents this source from retaining or accepting
/// caller-owned proof-byte storage.
pub const InputsV2 = shard_1.InputsV2;
pub const RelaySourceKindV2 = shard_1.RelaySourceKindV2;
/// Physical row contract shared with `air/segment_public_outer_air_v2.zig`.
/// `source_fields` excludes `value`; its first `source_arity - 1` entries are
/// inserted around the value at the source ABI's fixed value coordinate.
pub const RelayRowV2 = shard_1.RelayRowV2;
pub const RelationEventV2 = shard_1.RelationEventV2;
pub const DestinationsV2 = shard_1.DestinationsV2;
pub const preflight = shard_1.preflight;
pub const prepareInto = shard_1.prepareInto;
/// Exact-size, failure-atomic and allocation-free hot materialization.
pub const writeInto = shard_2.writeInto;
/// Production row materialization with exact graph-derived input
/// multiplicities.  The binding and all of its backing storage are admitted
/// before the first destination write; zero-use graph inputs remain explicit
/// source rows but emit no arithmetic-wire multiplicity.
pub const writeIntoBound = shard_2.writeIntoBound;
pub const sealArithmeticGraphBinding = shard_2.sealArithmeticGraphBinding;
