const std = @import("std");
const subject = @import("recursive_segment_v2_leaf_outer.zig");
const focused = @import("recursive_segment_v2_leaf_outer_test.zig");

test "recursive segment V2 leaf-outer declarations compile" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(focused);
}
