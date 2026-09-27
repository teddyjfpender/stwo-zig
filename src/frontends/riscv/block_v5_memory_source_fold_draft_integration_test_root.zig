test "source fold draft integration root" {
    _ = @import("prover/block_v5_memory_source_fold_draft_collection_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_fold_draft_integration_test_v1.zig");
    _ = @import("block_v5_memory_source_fold_draft_integration_codegen.zig");
    _ = @import("prover/block_v5_cpu_source_pages_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_page_job_test_v1.zig");
}
