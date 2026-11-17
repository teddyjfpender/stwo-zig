//! This package's one focused test root.
//!
//! Focused suites live in `tests/focused/`. Zig confines a module's file
//! imports to the directory of its root file, so a suite cannot be its own
//! root without losing access to the package it exercises. Every focused
//! build step therefore roots here and names one suite through the
//! `focused_suite` build option. Only that suite is analysed; an unknown name
//! is a compile error rather than an empty, passing binary.

const suites = struct {
    pub const recursion_binary_closure = @import("tests/focused/recursion_binary_closure.zig");
    pub const recursion_fri_profile_measurements = @import("tests/focused/recursion_fri_profile_measurements.zig");
    pub const recursion_pair_node = @import("tests/focused/recursion_pair_node.zig");
    pub const recursion_parent_statement_source = @import("tests/focused/recursion_parent_statement_source.zig");
    pub const recursion_parent_transcript_source = @import("tests/focused/recursion_parent_transcript_source.zig");
    pub const recursion_segment_leaf_outer_v2_1 = @import("tests/focused/recursion_segment_leaf_outer_v2_1.zig");
    pub const recursion_segment_leaf_outer_v2_2 = @import("tests/focused/recursion_segment_leaf_outer_v2_2.zig");
    pub const recursion_segment_native_sum_v2 = @import("tests/focused/recursion_segment_native_sum_v2.zig");
    pub const recursion_segment_outer_cohort_v2 = @import("tests/focused/recursion_segment_outer_cohort_v2.zig");
    pub const recursion_segment_outer_noncore_audits_v2_1 = @import("tests/focused/recursion_segment_outer_noncore_audits_v2_1.zig");
    pub const recursion_segment_public_source_v2_1 = @import("tests/focused/recursion_segment_public_source_v2_1.zig");
    pub const recursion_segment_statement_source_v2 = @import("tests/focused/recursion_segment_statement_source_v2.zig");
    pub const recursion_segment_transcript_components_v2_1 = @import("tests/focused/recursion_segment_transcript_components_v2_1.zig");
    pub const recursion_segment_transcript_source_v2_1 = @import("tests/focused/recursion_segment_transcript_source_v2_1.zig");
    pub const recursion_temporal_pair = @import("tests/focused/recursion_temporal_pair.zig");
    pub const recursion_transcript_v2_1 = @import("tests/focused/recursion_transcript_v2_1.zig");
    pub const recursion_vm_composition = @import("tests/focused/recursion_vm_composition.zig");
    pub const retained_authority_contracts_3 = @import("tests/focused/retained_authority_contracts_3.zig");
    pub const retained_fri_frontier = @import("tests/focused/retained_fri_frontier.zig");
    pub const retained_transcript_contracts = @import("tests/focused/retained_transcript_contracts.zig");
};

comptime {
    _ = @field(suites, @import("focused_suite").name);
}
