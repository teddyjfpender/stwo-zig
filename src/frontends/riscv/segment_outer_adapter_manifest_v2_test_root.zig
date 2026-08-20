const std = @import("std");
const subject = @import("recursion/air/segment_outer_adapter_manifest_v2.zig");
const focused = @import("recursion/air/segment_outer_adapter_manifest_v2_test.zig");

test "segment V2 outer manifest declarations compile" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(focused);
}
