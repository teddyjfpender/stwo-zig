const std = @import("std");
const roster = @import("recursion/air/segment_leaf_wrapper_roster_direct_v5.zig");
const protocol = @import("recursion/segment_leaf_wrapper_protocol_direct_v5.zig");
const rows = @import("recursion/segment_leaf_wrapper_cohort_rows_v5.zig");
const closure = @import("recursion/segment_leaf_wrapper_cohort_closure_v5.zig");
const candidate = @import("recursion/segment_leaf_wrapper_cohort_candidate_v5.zig");
const direct_source_v6 = @import("recursion/air/ethereum_leaf_link_source_direct_v6.zig");
const statement_v6 = @import("recursion/air/segment_leaf_statement_source_direct_v6.zig");
const row5_fanout_v6 = @import("recursion/segment_leaf_wrapper_row5_fanout_v6.zig");
const global_statement_boundary_v6 = @import("recursion/segment_leaf_wrapper_global_statement_boundary_v6.zig");
const roster_v6 = @import("recursion/air/segment_leaf_wrapper_roster_direct_v6.zig");
const row36_v6 = @import("recursion/segment_leaf_wrapper_row36_direct_v6.zig");
const closure_v6 = @import("recursion/segment_leaf_wrapper_cohort_closure_v6.zig");
const protocol_v6 = @import("recursion/segment_leaf_wrapper_protocol_direct_v6.zig");

test {
    _ = roster;
    _ = protocol;
    _ = rows;
    std.testing.refAllDeclsRecursive(rows);
    std.testing.refAllDeclsRecursive(closure);
    std.testing.refAllDeclsRecursive(candidate);
    std.testing.refAllDeclsRecursive(direct_source_v6);
    std.testing.refAllDeclsRecursive(statement_v6);
    std.testing.refAllDeclsRecursive(row5_fanout_v6);
    std.testing.refAllDeclsRecursive(global_statement_boundary_v6);
    std.testing.refAllDeclsRecursive(roster_v6);
    std.testing.refAllDeclsRecursive(row36_v6);
    std.testing.refAllDeclsRecursive(closure_v6);
    std.testing.refAllDeclsRecursive(protocol_v6);
}
