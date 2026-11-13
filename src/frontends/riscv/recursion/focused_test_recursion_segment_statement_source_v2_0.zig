//! Owner-local focused collection; selected by the maintained catalog.
const std = @import("std");
const components = @import("segment_statement_outer_components.zig");

test {
    _ = @import("tests/segment_statement_outer_source_v2_test.zig");
    std.testing.refAllDeclsRecursive(components);
}
