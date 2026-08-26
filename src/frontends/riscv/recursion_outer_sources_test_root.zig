//! Fast integration gate for the three segment-leaf outer-proof sources.
//!
//! This root deliberately excludes the rest of the recursion inventory. It is
//! the edit loop for rows 0--17 and 35 while the full 36-row proof remains the
//! release-level acceptance test.

test {
    _ = @import("segment_transcript_outer_source_test_root.zig");
    _ = @import("recursion/segment_leaf_outer_bundle_test.zig");
    _ = @import("recursion/segment_statement_outer_source_test.zig");
    _ = @import("recursion/segment_public_outer_source_test.zig");
    _ = @import("recursion/outer_parent_child_admission_test.zig");
}
