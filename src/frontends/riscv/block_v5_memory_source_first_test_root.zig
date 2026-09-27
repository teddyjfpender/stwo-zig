//! Source-only lifecycle root: no commitment/proof invocation in any fixture.
comptime {
    _ = @import("prover/block_v5_memory_source_first_test_v1.zig");
    _ = @import("block_v5_memory_source_first_codegen.zig");
}
test "source first root" {}
