//! Isolated test root for authenticated recursive-parent statement custody.

test {
    _ = @import("stwo_riscv_recursion").modules.outer_parent_statement_source;
    _ = @import("stwo_riscv_recursion").modules.tests_outer_parent_statement_source_test;
}
