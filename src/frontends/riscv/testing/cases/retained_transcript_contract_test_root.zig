//! Retained transcript parity and hostile-program checks.
test {
    _ = @import("recursion/tests/segment_leaf_local_projection_test.zig");
    _ = @import("stwo_riscv_recursion").modules.tests_transcript_program_v2_test;
}
