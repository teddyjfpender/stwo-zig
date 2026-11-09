//! Isolated test root for recursive-parent transcript custody.

test {
    _ = @import("stwo_riscv_recursion").modules.outer_parent_transcript_source;
    _ = @import("stwo_riscv_recursion").modules.tests_outer_parent_transcript_source_test;
}
