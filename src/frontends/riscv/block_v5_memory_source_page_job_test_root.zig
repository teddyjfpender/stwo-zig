//! Independent nonproving job fixture/body root; no proving entry is invoked.
test "source PAGE job root" {
    _ = @import("prover/block_v5_memory_source_page_job_test_v1.zig");
    _ = @import("block_v5_memory_source_page_job_codegen.zig");
}
