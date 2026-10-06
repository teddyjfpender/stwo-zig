const std = @import("std");
const direct = @import("recursion/segment_leaf_wrapper_cohort_direct_rows_v4.zig");

test "direct 47-row appended writer compiles all typed row paths" {
    std.testing.refAllDeclsRecursive(direct);
}

test {
    _ = direct;
    _ = @import("recursion/segment_leaf_wrapper_cohort_closure_v4.zig");
    _ = @import("recursion/segment_leaf_wrapper_cohort_candidate_v4.zig");
    _ = @import("recursion/segment_leaf_wrapper_range_provider_direct_v4.zig");
}
