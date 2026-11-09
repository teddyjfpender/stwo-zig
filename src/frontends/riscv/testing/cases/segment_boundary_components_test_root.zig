const std = @import("std");
const subject = @import("stwo_riscv_recursion").modules.air_segment_boundary_components;
const focused = @import("recursion/air/tests/segment_boundary_components_test.zig");

test "segment V2 boundary component declarations compile" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(focused);
}
