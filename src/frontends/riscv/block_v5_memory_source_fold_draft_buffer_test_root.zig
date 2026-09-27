test "source fold draft buffer root" {
    _ = @import("prover/block_v5_memory_source_fold_draft_buffer_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_fold_draft_pages_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_fold_draft_collection_test_v1.zig");
    _ = @import("block_v5_memory_source_fold_draft_buffer_codegen.zig");
}
