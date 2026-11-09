const std = @import("std");
const air = @import("stwo_riscv_recursion").segment_leaf_outer_air;
const authority = @import("stwo_riscv_recursion").segment_leaf_outer_authority;
const focused_tests = @import("stwo_riscv_recursion").tests_segment_leaf_outer_authority_test;
const statement_source_tests = @import("stwo_riscv_recursion").tests_segment_statement_outer_source_v2_test;

test "segment leaf outer V2 declarations compile" {
    std.testing.refAllDeclsRecursive(air);
    std.testing.refAllDeclsRecursive(authority);
    std.testing.refAllDeclsRecursive(focused_tests);
    std.testing.refAllDeclsRecursive(statement_source_tests);
}
