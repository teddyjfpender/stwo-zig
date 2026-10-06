const std = @import("std");
const roster = @import("recursion/air/segment_leaf_wrapper_roster_direct_v5.zig");
const protocol = @import("recursion/segment_leaf_wrapper_protocol_direct_v5.zig");
const rows = @import("recursion/segment_leaf_wrapper_cohort_rows_v5.zig");
const closure = @import("recursion/segment_leaf_wrapper_cohort_closure_v5.zig");
const candidate = @import("recursion/segment_leaf_wrapper_cohort_candidate_v5.zig");

test {
    _ = roster;
    _ = protocol;
    _ = rows;
    std.testing.refAllDeclsRecursive(rows);
    std.testing.refAllDeclsRecursive(closure);
    std.testing.refAllDeclsRecursive(candidate);
}
