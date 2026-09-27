//! Allocation-free SegmentV2 program replay for the V3 recursion circuit.
//!
//! This is the heterogeneous recorder's Segment lane.  It consumes the exact
//! 39-row SegmentV2 manifest and the sampled-value layout derived from a
//! successful verifier capture.  Generic typed components replay their two
//! compiler products; rows 34 and 35 replay the shipped native provider
//! evaluators.  No concrete proof claim is read from an adapter: every LogUp
//! shift comes from the fixed 41-element V3 graph-input ABI.
//!
//! Construction is intentionally transactional.  A caller reserves and
//! activates one graph builder, records rows 0 through 38 in manifest order,
//! then publishes the builder only after `finishProgram` succeeds.  A failed
//! row may have extended that private builder, but can never partially publish
//! a circuit.

const shard_0 = @import("recursion_air_composition_segment_recorder_v3_error.zig");
const shard_1 = @import("recursion_air_composition_segment_recorder_v3_program_recorder_for_manifest.zig");
const shard_2 = @import("recursion_air_composition_segment_recorder_v3_empty_program_recorder_v3.zig");

pub const graph_recorder = shard_0.graph_recorder;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const SEGMENT_ROW_COUNT = shard_0.SEGMENT_ROW_COUNT;
pub const COMPOSITION_CLAIM_INPUT_COUNT = shard_0.COMPOSITION_CLAIM_INPUT_COUNT;
pub const POSEIDON_ROW = shard_0.POSEIDON_ROW;
pub const RANGE_ROW = shard_0.RANGE_ROW;
pub const POSEIDON_AUX_START = shard_0.POSEIDON_AUX_START;
pub const HOT_ROW_REPLAY_HEAP_ALLOCATIONS = shard_0.HOT_ROW_REPLAY_HEAP_ALLOCATIONS;
pub const HOT_PROGRAM_FINISH_HEAP_ALLOCATIONS = shard_0.HOT_PROGRAM_FINISH_HEAP_ALLOCATIONS;
pub const SEGMENT_39_ROW_ORDER_AUTHORITY_AVAILABLE = shard_0.SEGMENT_39_ROW_ORDER_AUTHORITY_AVAILABLE;
pub const GENERIC_TYPED_ROW_RECORDER_AVAILABLE = shard_0.GENERIC_TYPED_ROW_RECORDER_AVAILABLE;
pub const EXACT_SHARED_PROVIDER_RECORDERS_AVAILABLE = shard_0.EXACT_SHARED_PROVIDER_RECORDERS_AVAILABLE;
pub const UNIVERSAL_36_ROW_ORDER_AUTHORITY_AVAILABLE = shard_0.UNIVERSAL_36_ROW_ORDER_AUTHORITY_AVAILABLE;
pub const UNIVERSAL_CATALOG_RECORDER_AVAILABLE = shard_0.UNIVERSAL_CATALOG_RECORDER_AVAILABLE;
/// Set only by the complete V3 session once a real initialized 39-row cohort
/// is replayed into the same graph as the binary and empty programs.
pub const SHARED_HETEROGENEOUS_SESSION_AVAILABLE = shard_0.SHARED_HETEROGENEOUS_SESSION_AVAILABLE;
pub const PoseidonAdapterV2 = shard_0.PoseidonAdapterV2;
pub const RangeCheck8x8AdapterV2 = shard_0.RangeCheck8x8AdapterV2;
pub const Error = shard_0.Error;
pub const ProgramResultV3 = shard_0.ProgramResultV3;
/// Manifest-parametric borrowed view over one active graph-construction
/// transaction. Every slice and authority object must remain at a stable
/// address through `finishProgram`; the returned result itself owns no borrow.
pub const ProgramRecorderForManifest = shard_1.ProgramRecorderForManifest;
pub const SegmentProgramRecorderV3 = shard_2.SegmentProgramRecorderV3;
pub const UniversalProgramRecorderV3 = shard_2.UniversalProgramRecorderV3;
pub const EmptyProgramRecorderV3 = shard_2.EmptyProgramRecorderV3;
