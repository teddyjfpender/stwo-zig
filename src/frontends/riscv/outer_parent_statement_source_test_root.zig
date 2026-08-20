//! Isolated test root for authenticated recursive-parent statement custody.

test {
    _ = @import("recursion/outer_parent_statement_source.zig");
    _ = @import("recursion/outer_parent_statement_source_test.zig");
}
