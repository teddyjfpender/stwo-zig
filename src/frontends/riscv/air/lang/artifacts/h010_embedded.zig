//! Checked H-010 deterministic vector bytes for tool/test-only consumers.

pub const poseidon_layout_vector_log10 =
    @embedFile("h010-poseidon-layout-v1/vector-log10.stwairb");
pub const poseidon_layout_vector_log14 =
    @embedFile("h010-poseidon-layout-v1/vector-log14.stwairb");
pub const poseidon_layout_vector_index =
    @embedFile("h010-poseidon-layout-v1/index-v1.tsv");
