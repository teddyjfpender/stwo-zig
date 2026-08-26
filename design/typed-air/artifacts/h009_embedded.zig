//! Test-only H-009 bridge, isolated from compatibility artifact consumers.

pub const h009_poseidon2_frontier =
    @embedFile("h009-poseidon2-cost-v1/frontier.stwairm");
pub const h009_poseidon2_frontier_tsv =
    @embedFile("h009-poseidon2-cost-v1/frontier-v1.tsv");
pub const h009_poseidon2_frontier_markdown =
    @embedFile("h009-poseidon2-cost-v1/frontier-v1.md");
