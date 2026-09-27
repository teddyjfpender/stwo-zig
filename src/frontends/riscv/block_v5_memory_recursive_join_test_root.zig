//! Source-only recursive memory join qualification root. No proof invocation.
comptime {
    _ = @import("recursion/block_v5_memory_recursive_join_test_v1.zig");
}
test "recursive memory join qualification imports" {}
