//! Focused compile/test root for the V2 rows 10 and 11 statement authority.
//!
//! Keep this root at the frontend package boundary: the test exercises shared
//! AIR modules outside `recursion/`, which Zig 0.15 correctly rejects when the
//! module root itself is nested inside that directory.

const std = @import("std");
const components = @import("recursion/segment_statement_outer_components_v2.zig");

test {
    _ = @import("recursion/segment_statement_outer_source_v2_test.zig");
    std.testing.refAllDeclsRecursive(components);
}
