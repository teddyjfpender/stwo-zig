//! Isolated source binding/replay candidate; nonproving fixtures only.
comptime {
    _ = @import("prover/block_v5_memory_source_binding_test_v1.zig");
    _ = @import("block_v5_memory_source_binding_codegen.zig");
}
test "source binding root" {}
