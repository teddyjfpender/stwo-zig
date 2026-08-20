const std = @import("std");
const air = @import("recursion/segment_leaf_outer_air_v2.zig");
const authority = @import("recursion/segment_leaf_outer_authority_v2.zig");
const focused_tests = @import("recursion/segment_leaf_outer_authority_v2_test.zig");
const statement_source_tests = @import("recursion/segment_statement_outer_source_v2_test.zig");

test "segment leaf outer V2 declarations compile" {
    std.testing.refAllDeclsRecursive(air);
    std.testing.refAllDeclsRecursive(authority);
    std.testing.refAllDeclsRecursive(focused_tests);
    std.testing.refAllDeclsRecursive(statement_source_tests);
}
