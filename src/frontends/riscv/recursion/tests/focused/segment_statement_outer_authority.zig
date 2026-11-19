//! Owner-local focused collection; selected by the maintained catalog.
const std = @import("std");
const components = @import("../../segment_statement_outer_components.zig");

test {
    _ = @import("../variable_boundary_statement_source_test.zig");
    std.testing.refAllDeclsRecursive(components);
}
