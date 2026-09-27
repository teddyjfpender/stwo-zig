//! Internal shard of recursion_air_composition_segment_recorder_v3.zig; use the public facade.

pub const std = @import("std");

pub const stwo_core = @import("stwo_core");

pub const circle = stwo_core.circle;

pub const M31 = stwo_core.fields.m31.M31;

pub const qm31 = stwo_core.fields.qm31;

pub const relation = @import("../air/lang/relation.zig");

pub const poseidon_air = @import("../air/memory_commitment/poseidon2_air.zig");

pub const capture_layout = @import("recursion_air_composition_capture_layout_v3.zig");

pub const graph_recorder = @import("air/composition_graph_recorder.zig");

pub const recorder = graph_recorder;

pub const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");

pub const universal_manifest_mod = @import("air/universal_adapter_manifest.zig");

pub const universal_catalog = @import("air/universal_catalog.zig");

pub const universal_roster = @import("air/universal_roster.zig");

pub const shared_provider = @import("air/universal_shared_provider.zig");

pub const shared_provider_composition =
    @import("air/universal_shared_provider_composition.zig");

pub const complete_segment_cohort =
    @import("recursion_air_composition_segment_recorder_v3_complete_segment_cohort.zig");

pub const FORMAT_VERSION: u16 = 1;

pub const SEGMENT_ROW_COUNT: usize = manifest_mod.COMPONENT_COUNT;

pub const COMPOSITION_CLAIM_INPUT_COUNT: usize = SEGMENT_ROW_COUNT +
    shared_provider_composition.POSEIDON_AUXILIARY_CLAIM_COUNT;

pub const POSEIDON_ROW: u8 = @intFromEnum(manifest_mod.ComponentKey.poseidon2);

pub const RANGE_ROW: u8 =
    @intFromEnum(manifest_mod.ComponentKey.range_check_8_8);

pub const POSEIDON_AUX_START: usize = SEGMENT_ROW_COUNT;

pub const HOT_ROW_REPLAY_HEAP_ALLOCATIONS: usize = 0;

pub const HOT_PROGRAM_FINISH_HEAP_ALLOCATIONS: usize = 0;

pub const SEGMENT_39_ROW_ORDER_AUTHORITY_AVAILABLE = true;

pub const GENERIC_TYPED_ROW_RECORDER_AVAILABLE = true;

pub const EXACT_SHARED_PROVIDER_RECORDERS_AVAILABLE = true;

pub const UNIVERSAL_36_ROW_ORDER_AUTHORITY_AVAILABLE = true;

pub const UNIVERSAL_CATALOG_RECORDER_AVAILABLE = true;

/// Set only by the complete V3 session once a real initialized 39-row cohort
/// is replayed into the same graph as the binary and empty programs.
pub const SHARED_HETEROGENEOUS_SESSION_AVAILABLE = false;

pub const PoseidonAdapterV2 =
    shared_provider.Poseidon2AdapterForManifest(manifest_mod);

pub const RangeCheck8x8AdapterV2 =
    shared_provider.RangeCheck8x8AdapterForManifest(manifest_mod);

pub const Error = capture_layout.Error || recorder.Error || manifest_mod.Error ||
    universal_manifest_mod.Error || shared_provider.Error ||
    shared_provider_composition.Error || M31.Error || error{
    CircuitAlreadyFinished,
    CircuitTooLarge,
    ComponentGeometryMismatch,
    ComponentOrderMismatch,
    ComponentProgramSealMismatch,
    IncompleteProgram,
    IncompleteSegmentProgram,
    InvalidManifest,
    InvalidSampleInputCount,
    ProviderRequiresExactRecorder,
};

pub const ProgramResultV3 = struct {
    accumulation: recorder.Scalar,
    constraint_count: usize,
    row_count: u8,
};
