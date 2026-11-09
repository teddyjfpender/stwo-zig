//! Focused compile/test root for the V2 rows 10 and 11 statement authority.
//!
//! Keep this root at the frontend package boundary: the test exercises shared
//! AIR modules outside `recursion/`, which Zig 0.15 correctly rejects when the
//! module root itself is nested inside that directory.

const std = @import("std");
const components = @import("stwo_riscv_recursion").modules.segment_statement_outer_components;

test {
    _ = @import("stwo_riscv_recursion").modules.tests_segment_statement_outer_source_v2_test;
    std.testing.refAllDeclsRecursive(components);
}
