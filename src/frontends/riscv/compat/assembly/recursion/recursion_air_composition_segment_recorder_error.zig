//! Internal shard of recursion_air_composition_segment_recorder.zig; use the public facade.

pub const std = @import("std");

pub const stwo_core = @import("stwo_core");

pub const circle = stwo_core.circle;

pub const M31 = stwo_core.fields.m31.M31;

pub const qm31 = stwo_core.fields.qm31;

pub const relation = @import("stwo_riscv_air_lang").relation;

pub const poseidon_air = @import("stwo_riscv_memory").air.poseidon2_air;

pub const capture_layout = @import("recursion_air_composition_capture_layout.zig");

pub const graph_recorder = @import("stwo_riscv_rv32").recursion.air.composition_graph_recorder;

pub const recorder = graph_recorder;

pub const manifest_mod = @import("stwo_riscv_recursion").air.segment_outer_adapter_manifest;

pub const universal_manifest_mod = @import("stwo_riscv_air_lang").framework.universal_adapter_manifest;

pub const universal_catalog = @import("stwo_riscv_recursion_air").universal_catalog;

pub const universal_roster = @import("stwo_riscv_air_lang").framework.universal_roster;

pub const shared_provider = @import("stwo_riscv_rv32").recursion.air.universal_shared_provider;

pub const shared_provider_composition =
    @import("stwo_riscv_rv32").recursion.air.universal_shared_provider_composition;

pub const complete_segment_cohort =
    @import("stwo_riscv_recursion").recursion_air_composition_segment_recorder_complete_segment_cohort;

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
