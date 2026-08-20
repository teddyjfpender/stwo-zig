//! Versioned row-10 replacement and row-11 routing source for resumed leaves.
//!
//! V2 does not squeeze its variable statement back into frozen universal row
//! 10. `segment_leaf_outer_air_v2.Statement` is the committed boundary source;
//! this module keeps roster row 10 inactive and drives row 11 directly from
//! that source. Every source tuple is consumed once, and every ProgramV2
//! statement payload tuple is consumed once, without a duplicate statement
//! emission.
//!
//! The row-11 trace also proves the 16-bit decomposition of every structurally
//! encoded integer limb in the canonical wire and of the sixteen transcript
//! limbs carrying its eight-word identity. Those requests are the exact input
//! to the partial V2 row-35 range ledger. Full wire-hash, authority-hash, and
//! rows-12--17 closure remain explicit false capabilities; no partial receipt
//! can be published as a recursive proof.
const shard_0 = @import("segment_statement_outer_source_v2_contract.zig");
const shard_1 = @import("segment_statement_outer_source_v2_prepared_v2.zig");
const shard_2 = @import("segment_statement_outer_source_v2_prepare_into.zig");

pub const Digest = shard_0.Digest;
pub const Sha256Digest = shard_0.Sha256Digest;
pub const Air = shard_0.Air;
pub const Framework = shard_0.Framework;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const MANIFEST_VERSION = shard_0.MANIFEST_VERSION;
pub const FROZEN_ROW_10 = shard_0.FROZEN_ROW_10;
pub const ROUTING_ROW_11 = shard_0.ROUTING_ROW_11;
pub const RANGE_PROVIDER_ROW_35 = shard_0.RANGE_PROVIDER_ROW_35;
pub const STATEMENT_SOURCE_COMPONENT_36 = shard_0.STATEMENT_SOURCE_COMPONENT_36;
pub const PUBLIC_LOGUP_SOURCE_COMPONENT_37 = shard_0.PUBLIC_LOGUP_SOURCE_COMPONENT_37;
pub const VM_PUBLIC_LOGUP_ROW_16 = shard_0.VM_PUBLIC_LOGUP_ROW_16;
pub const HEADER_LIMB_COUNT = shard_0.HEADER_LIMB_COUNT;
pub const WIRE_ID_WORD_COUNT = shard_0.WIRE_ID_WORD_COUNT;
pub const WIRE_ID_LIMB_COUNT = shard_0.WIRE_ID_LIMB_COUNT;
pub const EVENT_COUNT_PER_ROW = shard_0.EVENT_COUNT_PER_ROW;
pub const MANIFEST_ID_DOMAIN = shard_0.MANIFEST_ID_DOMAIN;
pub const PREPARED_ID_DOMAIN = shard_0.PREPARED_ID_DOMAIN;
pub const TRACE_SHA_DOMAIN = shard_0.TRACE_SHA_DOMAIN;
pub const ROW_SHA_DOMAIN = shard_0.ROW_SHA_DOMAIN;
pub const HOT_PREPARE_HEAP_ALLOCATIONS = shard_0.HOT_PREPARE_HEAP_ALLOCATIONS;
pub const FROZEN_ROW_10_ACTIVE = shard_0.FROZEN_ROW_10_ACTIVE;
pub const FROZEN_ROW_10_CLAIM_IS_ZERO = shard_0.FROZEN_ROW_10_CLAIM_IS_ZERO;
pub const ROW_11_SOURCE_TUPLES_CLOSED = shard_0.ROW_11_SOURCE_TUPLES_CLOSED;
pub const ROW_11_TRANSCRIPT_STATEMENT_INPUTS_CLOSED = shard_0.ROW_11_TRANSCRIPT_STATEMENT_INPUTS_CLOSED;
pub const ROW_11_BOUNDARY_BRIDGE_CLOSED = shard_0.ROW_11_BOUNDARY_BRIDGE_CLOSED;
pub const ROW_35_REQUEST_SET_COMPLETE = shard_0.ROW_35_REQUEST_SET_COMPLETE;
pub const WIRE_HASH_AIR_VERIFIED = shard_0.WIRE_HASH_AIR_VERIFIED;
pub const AUTHORITY_HASH_AIR_VERIFIED = shard_0.AUTHORITY_HASH_AIR_VERIFIED;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const OverrideActivationV2 = shard_0.OverrideActivationV2;
/// Exact manifest handoff for the central 38-component V2 roster. Geometry is
/// exported from each authoritative AIR and is never transcribed by callers.
pub const ComponentOverrideV2 = shard_0.ComponentOverrideV2;
pub const COMPONENT_OVERRIDE_TABLE_V2 = shard_0.COMPONENT_OVERRIDE_TABLE_V2;
/// Auditable producer/consumer multiplicities for the V2 statement boundary.
/// Source 37 now publishes its exact circuit-44 bridge into rows 12--14. Its
/// custom verifier-input namespace remains disjoint from row 16's standard
/// claimed-sum input, so the two consumers cannot cancel or double-consume an
/// edge accidentally.
pub const ClosureLedgerV2 = shard_0.ClosureLedgerV2;
pub const Error = shard_0.Error;
pub const ManifestV2 = shard_0.ManifestV2;
pub const PreprocessedRowV2 = shard_0.PreprocessedRowV2;
pub const MainRowV2 = shard_0.MainRowV2;
pub const LogicalRowV2 = shard_0.LogicalRowV2;
pub const RelationEventV2 = shard_0.RelationEventV2;
pub const RangeRequestV2 = shard_0.RangeRequestV2;
pub const TraceColumnsV2 = shard_0.TraceColumnsV2;
pub const DestinationsV2 = shard_0.DestinationsV2;
pub const AuthorityV2 = shard_0.AuthorityV2;
/// Stack-only direct-constraint scratch. Interaction inversion storage is
/// separately retained by `Framework.Workspace` and shared across proofs.
pub const WorkspaceV2 = shard_0.WorkspaceV2;
pub const PreparedV2 = shard_1.PreparedV2;
pub const preflight = shard_1.preflight;
/// Fail-atomic, allocation-free row publication. Every authority, shape,
/// alias, and direct-constraint check completes in a dry pass before the first
/// caller-owned destination cell is changed.
pub const prepareInto = shard_2.prepareInto;
pub const generateInteractionInto = shard_2.generateInteractionInto;
/// Re-authenticates the immutable row array carried by `PreparedV2`. This is
/// the zero-allocation custody seam used by the partial shared-row-35 ledger.
pub const validateLogicalRows = shard_2.validateLogicalRows;
pub const closureLedger = shard_2.closureLedger;
