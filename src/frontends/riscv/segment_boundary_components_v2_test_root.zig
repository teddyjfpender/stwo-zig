const std = @import("std");
const subject = @import("recursion/air/segment_boundary_components_v2.zig");
const focused = @import("recursion/air/segment_boundary_components_v2_test.zig");

test "segment V2 boundary component declarations compile" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(focused);
}
