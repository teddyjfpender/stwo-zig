//! Versioned public boundary for resumed RISC-V execution segments.
//!
//! V1 remains the immutable 412-word Stark-V span statement.  This module
//! wraps that exact projection in a V2 frame which carries the state omitted
//! by V1: global segment position, predecessor clocks, full sparse memory
//! state, real final-only completion, and session/job/lineage identities.
//!
//! The variable tail is intentional.  It retains canonical sparse
//! `(address, value)` and `(address, predecessor_clock)` tuples for the outer
//! AIR instead of publishing a detached digest.  Digests and counts in the
//! fixed header seal those retained tuples.  Encoding performs a complete
//! preflight before touching the destination; decoding, authentication, and
//! adjacent-span validation allocate no memory.
//!
//! This is statement and custody substrate.  Constructing or authenticating a
//! V2 wire does not prove that a VM trace satisfies it.
const shard_0 = @import("segment_statement_v2_contract.zig");
const shard_1 = @import("segment_statement_v2_canonical_wire_view_v2.zig");
const shard_2 = @import("segment_statement_v2_source_v2.zig");
const shard_3 = @import("segment_statement_v2_authenticate_canonical_wire.zig");

pub const Digest = shard_0.Digest;
pub const BaseStatementWords = shard_0.BaseStatementWords;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SCHEMA_VERSION = shard_0.SCHEMA_VERSION;
pub const KNOWN_FLAGS = shard_0.KNOWN_FLAGS;
/// The native proof geometry admits at most 2^24 retired instructions and
/// 2^24 memory rows.  V2 uses the same ceiling for global ranges and each
/// sparse boundary.  A larger protocol requires a new schema, not a wider
/// attacker-controlled allocation.
pub const MAX_GLOBAL_CYCLES = shard_0.MAX_GLOBAL_CYCLES;
pub const MAX_SPARSE_BOUNDARY_ENTRIES = shard_0.MAX_SPARSE_BOUNDARY_ENTRIES;
pub const MAX_RW_ADDRESS_EXCLUSIVE = shard_0.MAX_RW_ADDRESS_EXCLUSIVE;
pub const FORMAT_ID_DOMAIN = shard_0.FORMAT_ID_DOMAIN;
/// Shared with `temporal_pair_node.JOB_ID_DOMAIN`: the V2 wrapper must publish
/// the exact job identity already consumed by the temporal parent.
pub const JOB_ID_DOMAIN = shard_0.JOB_ID_DOMAIN;
pub const POSITION_ID_DOMAIN = shard_0.POSITION_ID_DOMAIN;
pub const MEMORY_STATE_ID_DOMAIN = shard_0.MEMORY_STATE_ID_DOMAIN;
pub const MEMORY_CLOCK_ID_DOMAIN = shard_0.MEMORY_CLOCK_ID_DOMAIN;
pub const BOUNDARY_LINEAGE_ID_DOMAIN = shard_0.BOUNDARY_LINEAGE_ID_DOMAIN;
pub const SEGMENT_LINEAGE_ID_DOMAIN = shard_0.SEGMENT_LINEAGE_ID_DOMAIN;
pub const WIRE_ID_DOMAIN = shard_0.WIRE_ID_DOMAIN;
pub const ADJACENCY_ID_DOMAIN = shard_0.ADJACENCY_ID_DOMAIN;
pub const HOT_VALIDATION_HEAP_ALLOCATIONS = shard_0.HOT_VALIDATION_HEAP_ALLOCATIONS;
pub const ENCODING_FAILS_BEFORE_FIRST_WRITE = shard_0.ENCODING_FAILS_BEFORE_FIRST_WRITE;
pub const V1_PROJECTION_WORD_COUNT = shard_0.V1_PROJECTION_WORD_COUNT;
pub const Tag = shard_0.Tag;
/// Fixed header layout.  All unrestricted u32 values use two 16-bit limbs.
pub const fixed_layout = shard_0.fixed_layout;
pub const FIXED_CANONICAL_WORDS = shard_0.FIXED_CANONICAL_WORDS;
pub const SECTION_HEADER_WORDS = shard_0.SECTION_HEADER_WORDS;
pub const RETAINED_ENTRY_WORDS = shard_0.RETAINED_ENTRY_WORDS;
pub const MIN_CANONICAL_WORDS = shard_0.MIN_CANONICAL_WORDS;
pub const Error = shard_0.Error;
pub const CompletionKindV2 = shard_0.CompletionKindV2;
pub const CompletionV2 = shard_0.CompletionV2;
/// Shared boundary primitives used by later statement versions. Exporting
/// these through the facade keeps V3 from importing an internal V2 shard or
/// silently drifting the canonical sparse-state formulas.
pub const SnapshotIdentity = shard_0.SnapshotIdentity;
pub const SnapshotSide = shard_1.SnapshotSide;
pub const completionFromRunner = shard_1.completionFromRunner;
pub const validateMemoryWords = shard_1.validateMemoryWords;
pub const validateClockBoundary = shard_1.validateClockBoundary;
pub const snapshotIdentity = shard_1.snapshotIdentity;
pub const memoryClockIdentity = shard_1.memoryClockIdentity;
/// Borrowed, exact native source for one segment statement.  The slices stay
/// owned by the runner result.  `encodeCanonical` retains their canonical
/// sparse projections in the wire before that result may be released.
pub const SourceV2 = shard_2.SourceV2;
pub const StatementV2 = shard_0.StatementV2;
pub const RetainedSectionV2 = shard_0.RetainedSectionV2;
pub const SparseEntryV2 = shard_0.SparseEntryV2;
pub const ClockEntryV2 = shard_0.ClockEntryV2;
/// Allocation-free authenticated view over one canonical variable-length V2
/// wire.  Offsets refer to retained four-word `(u32,u32)` entries.
pub const CanonicalWireViewV2 = shard_1.CanonicalWireViewV2;
pub const AdjacentReceiptV2 = shard_2.AdjacentReceiptV2;
/// Authenticate an untrusted canonical wire without allocation.  All retained
/// tuples are checked for strict order, nonzero sparse normalization, bounds,
/// count/header agreement, and digest agreement before a view is returned.
pub const authenticateCanonicalWire = shard_3.authenticateCanonicalWire;
/// Exact adjacent-span authentication over the retained canonical wires.
/// This re-authenticates both inputs so a mutation after an earlier decode
/// cannot reuse a stale view.
pub const authenticateAdjacentCanonicalWires = shard_3.authenticateAdjacentCanonicalWires;
/// Exact source-side check used before encoding two adjacent runner results.
/// Sparse memory equality treats an omitted address as zero, matching the
/// sparse Merkle default.  Clock maps are cumulative and therefore compare as
/// exact retained slices.
pub const requireAdjacentSources = shard_3.requireAdjacentSources;
pub const formatId = shard_3.formatId;
