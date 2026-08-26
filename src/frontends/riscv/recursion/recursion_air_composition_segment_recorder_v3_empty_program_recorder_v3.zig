//! Internal shard of recursion_air_composition_segment_recorder_v3.zig; use the public facade.

const dependency_0 = @import("recursion_air_composition_segment_recorder_v3_error.zig");
const dependency_1 = @import("recursion_air_composition_segment_recorder_v3_program_recorder_for_manifest.zig");

const capture_layout = dependency_0.capture_layout;
const recorder = dependency_0.recorder;
const manifest_mod = dependency_0.manifest_mod;
const universal_manifest_mod = dependency_0.universal_manifest_mod;
const universal_catalog = dependency_0.universal_catalog;
const universal_roster = dependency_0.universal_roster;
const shared_provider_composition = dependency_0.shared_provider_composition;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const SEGMENT_ROW_COUNT = dependency_0.SEGMENT_ROW_COUNT;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const POSEIDON_ROW = dependency_0.POSEIDON_ROW;
const RANGE_ROW = dependency_0.RANGE_ROW;
const POSEIDON_AUX_START = dependency_0.POSEIDON_AUX_START;
const UNIVERSAL_36_ROW_ORDER_AUTHORITY_AVAILABLE = dependency_0.UNIVERSAL_36_ROW_ORDER_AUTHORITY_AVAILABLE;
const UNIVERSAL_CATALOG_RECORDER_AVAILABLE = dependency_0.UNIVERSAL_CATALOG_RECORDER_AVAILABLE;
const ProgramRecorderForManifest = dependency_1.ProgramRecorderForManifest;

pub const SegmentProgramRecorderV3 = ProgramRecorderForManifest(
    manifest_mod,
    .segment_leaf,
    SEGMENT_ROW_COUNT,
);

pub const UniversalProgramRecorderV3 = ProgramRecorderForManifest(
    universal_manifest_mod,
    .binary_node,
    universal_roster.COMPONENT_COUNT,
);

pub const EmptyProgramRecorderV3 = ProgramRecorderForManifest(
    universal_manifest_mod,
    .empty_leaf,
    universal_roster.COMPONENT_COUNT,
);

comptime {
    if (FORMAT_VERSION != 1 or SEGMENT_ROW_COUNT != 39 or
        COMPOSITION_CLAIM_INPUT_COUNT != 41 or POSEIDON_ROW != 34 or
        RANGE_ROW != 35 or POSEIDON_AUX_START != 39 or
        universal_catalog.LOGICAL_COUNT != 34 or
        !UNIVERSAL_36_ROW_ORDER_AUTHORITY_AVAILABLE or
        !UNIVERSAL_CATALOG_RECORDER_AVAILABLE or
        capture_layout.TREE_COUNT != 4 or
        shared_provider_composition.POSEIDON_AUXILIARY_CLAIM_COUNT != 2)
    {
        @compileError("Segment V3 composition recorder ABI drifted");
    }
}
