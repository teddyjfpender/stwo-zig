//! Fixed column and OODS geometry of the canonical 39-row SegmentV2 roster.
//! Derive transport sizes from AIR owners, never from a candidate capture.
const core = @import("stwo_core");
const catalog = @import("air/segment_leaf_catalog_v2.zig");
const provider = @import("air/universal_shared_geometry.zig");
const EXTENSION_DEGREE = core.fields.qm31.SECURE_EXTENSION_DEGREE;

// Use the same default composition split as the component prover contract.
pub const TREE_COLUMN_COUNTS: [4]usize = counts: {
    var counts = [4]usize{
        provider.POSEIDON_PREPROCESSED_COLUMN_COUNT + provider.RANGE_PREPROCESSED_COLUMN_COUNT,
        provider.POSEIDON_MAIN_COLUMN_COUNT + provider.RANGE_MAIN_COLUMN_COUNT,
        provider.POSEIDON_INTERACTION_COLUMN_COUNT + provider.RANGE_INTERACTION_COLUMN_COUNT,
        core.verifier_types.compositionColumnCount(core.verifier_types.COMPOSITION_LOG_SPLIT, EXTENSION_DEGREE).?,
    };
    for (catalog.LOGICAL_ROWS) |entry| {
        counts[0] += entry.Air.PREPROCESSED_COLUMN_COUNT;
        counts[1] += entry.Air.PHYSICAL_MAIN_COLUMN_COUNT;
        counts[2] += entry.Air.INTERACTION_COLUMN_COUNT;
    }
    break :counts counts;
};

pub const QUERIED_VALUES_PER_QUERY = TREE_COLUMN_COUNTS[0] + TREE_COLUMN_COUNTS[1] + TREE_COLUMN_COUNTS[2] + TREE_COLUMN_COUNTS[3];
// Every column has a current sample. Typed and range rows also sample the
// preceding row for their final secure interaction column. Native Poseidon
// samples both positions for every interaction column.
pub const SAMPLED_VALUE_COUNT = QUERIED_VALUES_PER_QUERY +
    catalog.LOGICAL_ROWS.len * EXTENSION_DEGREE +
    EXTENSION_DEGREE + provider.POSEIDON_INTERACTION_COLUMN_COUNT;
