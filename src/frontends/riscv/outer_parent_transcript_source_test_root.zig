//! Isolated test root for recursive-parent transcript custody.

test {
    _ = @import("recursion/outer_parent_transcript_source.zig");
    _ = @import("recursion/outer_parent_transcript_source_test.zig");
}
