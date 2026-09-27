test "source batch root" {
    _ = @import("prover/block_v5_memory_source_batch_test_v1.zig");
    _ = @import("block_v5_memory_source_batch_codegen.zig");
}
